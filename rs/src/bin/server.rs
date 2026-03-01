/// HTTP blockchain server — direct port of index.py.
///
/// Uses axum instead of Bottle. Blockchain state is behind Arc<Mutex<>>.
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use axum::{Router, ServiceExt};
use serde::{Deserialize, Serialize};
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;

use stevecoin::block::Block;
use stevecoin::blockchain::BlockChain;
use stevecoin::crypto::{hash512_from_hex, ECDSAPublicKey};
use stevecoin::errors::BlockChainError;
use stevecoin::transaction::Transaction;

type SharedChain = Arc<Mutex<BlockChain>>;

fn err_response(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": msg })))
}

// GET /ping
async fn ping() -> &'static str {
    "pong"
}

// GET /miner
#[derive(Serialize)]
struct MinerResponse {
    txlist: Vec<String>,
    num_blocks: u64,
    prev_hash: String,
    pow: usize,
}

async fn miner_info(
    State(chain): State<SharedChain>,
) -> Result<Json<MinerResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = chain.lock().unwrap();
    let txlist = chain
        .get_pending_transactions()
        .map_err(|e| err_response(StatusCode::BAD_REQUEST, &format!("Blockchain error: {e}")))?;

    let num_blocks = chain.get_num_blocks();
    if num_blocks == 0 {
        return Err(err_response(StatusCode::BAD_REQUEST, "No blocks in blockchain"));
    }
    let last_block = chain
        .get_block(num_blocks - 1)
        .map_err(|e| err_response(StatusCode::BAD_REQUEST, &format!("Blockchain error: {e}")))?;

    let txlist_serialised: Vec<String> = txlist
        .iter()
        .filter_map(|t| t.serialise().ok())
        .collect();

    Ok(Json(MinerResponse {
        txlist: txlist_serialised,
        num_blocks,
        prev_hash: last_block.hash.serialise(),
        pow: chain.blockdb.pow_difficulty,
    }))
}

// GET /block/:index
async fn get_block(
    State(chain): State<SharedChain>,
    AxumPath(index): AxumPath<u64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = chain.lock().unwrap();
    match chain.get_block(index) {
        Ok(block) => {
            let json = serde_json::to_value(block.serialise_dict()).unwrap();
            Ok(Json(json))
        }
        Err(BlockChainError::BlockNotFound(_)) => {
            Err(err_response(StatusCode::NOT_FOUND, "Block not found"))
        }
        Err(_) => Err(err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Blockchain error",
        )),
    }
}

// GET /txid/:txid
async fn get_transaction(
    State(chain): State<SharedChain>,
    AxumPath(txid_str): AxumPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = chain.lock().unwrap();
    let txid = hash512_from_hex(&txid_str)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid txid"))?;

    match chain.get_transaction(&txid) {
        Ok(tx) => {
            let json = serde_json::to_value(tx.to_json()).unwrap();
            Ok(Json(json))
        }
        Err(BlockChainError::TransactionNotFound(_)) => Err(err_response(
            StatusCode::NOT_FOUND,
            "Transaction not found",
        )),
        Err(_) => Err(err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Blockchain error",
        )),
    }
}

// POST /address/utx
#[derive(Deserialize)]
struct AddressRequest {
    pubkey: String,
    sig: String,
}

async fn txids_for_address(
    State(chain): State<SharedChain>,
    Json(body): Json<AddressRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = chain.lock().unwrap();

    let pubkey_hash = hash512_from_hex(&body.pubkey)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid pubkey"))?;
    let sig = hash512_from_hex(&body.sig)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid sig"))?;
    let pubkey = ECDSAPublicKey::from_hash(&pubkey_hash)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid pubkey"))?;

    let txids = chain
        .get_txids_for_address(&pubkey, &sig)
        .map_err(|e| match e {
            BlockChainError::PermissionDenied(_) | BlockChainError::KeyValidation(_) => {
                err_response(StatusCode::FORBIDDEN, "Permission denied")
            }
            _ => err_response(StatusCode::INTERNAL_SERVER_ERROR, "Blockchain error"),
        })?;

    let txids_str: Vec<String> = txids.iter().map(|t| t.serialise()).collect();
    Ok(Json(serde_json::json!({ "data": txids_str })))
}

// POST /address/utxo
#[derive(Deserialize)]
struct UtxoRequest {
    pubkey: String,
    txid: String,
    sig: String,
}

async fn utxo_for_address_and_txid(
    State(chain): State<SharedChain>,
    Json(body): Json<UtxoRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = chain.lock().unwrap();

    let pubkey_hash = hash512_from_hex(&body.pubkey)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid pubkey"))?;
    let txid = hash512_from_hex(&body.txid)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid txid"))?;
    let sig = hash512_from_hex(&body.sig)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid sig"))?;
    let pubkey = ECDSAPublicKey::from_hash(&pubkey_hash)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid pubkey"))?;

    let amount = chain
        .get_utxo_private(&pubkey, &txid, &sig)
        .map_err(|e| match e {
            BlockChainError::PermissionDenied(_) | BlockChainError::KeyValidation(_) => {
                err_response(StatusCode::FORBIDDEN, "Permission denied")
            }
            _ => err_response(StatusCode::INTERNAL_SERVER_ERROR, "Blockchain error"),
        })?;

    Ok(Json(serde_json::json!({ "data": amount })))
}

// POST /address/balance
async fn balance_for_address(
    State(chain): State<SharedChain>,
    Json(body): Json<AddressRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = chain.lock().unwrap();

    let pubkey_hash = hash512_from_hex(&body.pubkey)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid pubkey"))?;
    let sig = hash512_from_hex(&body.sig)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid sig"))?;
    let pubkey = ECDSAPublicKey::from_hash(&pubkey_hash)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid pubkey"))?;

    let txids = chain
        .get_txids_for_address(&pubkey, &sig)
        .map_err(|e| match e {
            BlockChainError::PermissionDenied(_) => {
                err_response(StatusCode::FORBIDDEN, "Permission denied")
            }
            _ => err_response(StatusCode::INTERNAL_SERVER_ERROR, "Blockchain error"),
        })?;

    let address = pubkey.get_address();
    let mut amount: u64 = 0;
    for txid in &txids {
        amount += chain.get_utxo(txid, &address).map_err(|_| {
            err_response(StatusCode::INTERNAL_SERVER_ERROR, "Blockchain error")
        })?;
    }

    Ok(Json(serde_json::json!({ "data": amount })))
}

// POST /tx/submit
async fn transaction_submit(
    State(chain): State<SharedChain>,
    Json(body): Json<serde_json::Value>,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = chain.lock().unwrap();

    let tx_json: stevecoin::transaction::TransactionJson =
        serde_json::from_value(body).map_err(|e| {
            err_response(
                StatusCode::BAD_REQUEST,
                &format!("Invalid transaction: {e}"),
            )
        })?;

    let tx = Transaction::deserialise_dict(&tx_json).map_err(|e| {
        err_response(
            StatusCode::BAD_REQUEST,
            &format!("Invalid transaction: {e}"),
        )
    })?;

    chain.validate_transaction(&tx).map_err(|e| match e {
        BlockChainError::TransactionValidation(msg) => err_response(
            StatusCode::BAD_REQUEST,
            &format!("Invalid transaction: {msg}"),
        ),
        _ => err_response(StatusCode::INTERNAL_SERVER_ERROR, "Blockchain error"),
    })?;

    chain.add_pending_transaction(&tx).map_err(|_| {
        err_response(StatusCode::INTERNAL_SERVER_ERROR, "Blockchain error")
    })?;

    Ok("SUCCESS".to_string())
}

// POST /block/submit
async fn block_submit(
    State(chain): State<SharedChain>,
    Json(body): Json<serde_json::Value>,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = chain.lock().unwrap();

    let block_json: stevecoin::block::BlockJson =
        serde_json::from_value(body).map_err(|e| {
            err_response(StatusCode::BAD_REQUEST, &format!("Invalid block: {e}"))
        })?;

    let block = Block::deserialise_dict(&block_json).map_err(|e| {
        err_response(StatusCode::BAD_REQUEST, &format!("Invalid block: {e}"))
    })?;

    let txids: Vec<_> = block.transactions.iter().map(|t| t.txid.clone()).collect();

    chain
        .validate_and_write_block(&block)
        .map_err(|e| match e {
            BlockChainError::BlockValidation(msg) => {
                err_response(StatusCode::BAD_REQUEST, &format!("Invalid block: {msg}"))
            }
            _ => err_response(StatusCode::INTERNAL_SERVER_ERROR, "Blockchain error"),
        })?;

    for txid in &txids {
        let _ = chain.delete_pending_transaction(txid);
    }

    Ok("SUCCESS".to_string())
}

#[tokio::main]
async fn main() {
    let cur_dir = env::current_dir().unwrap();
    let base_dir = cur_dir.join("blockdata");
    let base_dir_str = base_dir.to_string_lossy().to_string();
    let mut create_flag = false;
    let mut password = String::new();

    if !Path::new(&base_dir).exists() {
        println!("Blockchain not found. A new blockchain will be created.\n");

        loop {
            println!("NOTE: Password will not be displayed while typing.");
            let pw = rpassword::prompt_password("Please enter a password for the private key: ")
                .expect("Failed to read password");

            if pw.len() < 8 {
                println!("Password must be at least 8 characters long");
                continue;
            }

            let pw2 = rpassword::prompt_password("Please re-enter the password again: ")
                .expect("Failed to read password");

            if pw == pw2 {
                password = pw;
                break;
            }
            println!("Passwords do not match. Please try again.");
        }

        fs::create_dir_all(&base_dir).expect("Failed to create blockdata directory");
        create_flag = true;
    }

    let mut chain = BlockChain::new(&base_dir_str).expect("Failed to initialise blockchain");

    if create_flag && !password.is_empty() && chain.get_num_blocks() == 0 {
        chain
            .create(&password)
            .expect("Failed to create blockchain");
        println!("Blockchain created successfully.");
    } else if chain.get_num_blocks() < 1 {
        eprintln!(
            "Blockchain is empty. Please delete the '{}' directory to create a new one.",
            base_dir_str
        );
        eprintln!(
            "WARNING: Deleting an existing blockchain directory will destroy the blockchain!"
        );
        std::process::exit(1);
    }

    let port: u16 = env::var("BLOCKCHAIN_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5001);

    let shared_chain = Arc::new(Mutex::new(chain));

    let app = Router::new()
        .route("/ping", get(ping))
        .route("/miner", get(miner_info))
        .route("/block/{index}", get(get_block))
        .route("/txid/{txid}", get(get_transaction))
        .route("/address/utx", post(txids_for_address))
        .route("/address/utxo", post(utxo_for_address_and_txid))
        .route("/address/balance", post(balance_for_address))
        .route("/tx/submit", post(transaction_submit))
        .route("/block/submit", post(block_submit))
        .with_state(shared_chain);

    let app = NormalizePathLayer::trim_trailing_slash().layer(app);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("Starting server on port {port} ...\n");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, ServiceExt::<axum::extract::Request>::into_make_service(app))
        .await
        .unwrap();
}
