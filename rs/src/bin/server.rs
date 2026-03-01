/// HTTP blockchain server — direct port of index.py.
///
/// Uses axum instead of Bottle. Blockchain state is behind Arc<Mutex<>>.
/// Supports peer-to-peer networking: peer discovery, gossip, IBD, and chain reorg.
use std::collections::{HashSet, VecDeque};
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
use clap::Parser;
use serde::{Deserialize, Serialize};
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;

use stevecoin::block::Block;
use stevecoin::blockchain::BlockChain;
use stevecoin::crypto::{hash512_from_hex, ECDSAPublicKey};
use stevecoin::errors::BlockChainError;
use stevecoin::transaction::Transaction;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "stevecoin-server", about = "Stevecoin Server")]
struct Cli {
    /// Comma-separated list of seed peer URLs
    #[arg(long, value_delimiter = ',')]
    peers: Vec<String>,

    /// This node's publicly reachable URL (e.g. http://192.168.1.5:5001)
    #[arg(long)]
    my_url: Option<String>,
}

// ---------------------------------------------------------------------------
// PeerSet
// ---------------------------------------------------------------------------

struct PeerSet {
    peers: HashSet<String>,
    my_url: Option<String>,
    seen_blocks: VecDeque<String>,
    seen_txids: VecDeque<String>,
    reorg_in_progress: bool,
}

impl PeerSet {
    fn new(my_url: Option<String>) -> Self {
        PeerSet {
            peers: HashSet::new(),
            my_url,
            seen_blocks: VecDeque::new(),
            seen_txids: VecDeque::new(),
            reorg_in_progress: false,
        }
    }

    /// Returns true if this block hash was NOT already seen (i.e. is new).
    fn mark_block_seen(&mut self, hash: &str) -> bool {
        if self.seen_blocks.contains(&hash.to_string()) {
            return false;
        }
        self.seen_blocks.push_back(hash.to_string());
        if self.seen_blocks.len() > 200 {
            self.seen_blocks.pop_front();
        }
        true
    }

    /// Returns true if this txid was NOT already seen (i.e. is new).
    fn mark_txid_seen(&mut self, txid: &str) -> bool {
        if self.seen_txids.contains(&txid.to_string()) {
            return false;
        }
        self.seen_txids.push_back(txid.to_string());
        if self.seen_txids.len() > 1000 {
            self.seen_txids.pop_front();
        }
        true
    }
}

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    chain: Arc<Mutex<BlockChain>>,
    peers: Arc<Mutex<PeerSet>>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn err_response(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": msg })))
}

/// Fire-and-forget POST to all known peers.
fn gossip_to_peers(peers: Arc<Mutex<PeerSet>>, path: &str, body: serde_json::Value) {
    let peer_urls: Vec<String> = {
        let ps = peers.lock().unwrap();
        ps.peers.iter().cloned().collect()
    };
    let path = path.to_string();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        for peer in peer_urls {
            let url = format!("{peer}{path}");
            let _ = client
                .post(&url)
                .json(&body)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await;
        }
    });
}

// ---------------------------------------------------------------------------
// Existing endpoints
// ---------------------------------------------------------------------------

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
    State(state): State<AppState>,
) -> Result<Json<MinerResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = state.chain.lock().unwrap();
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
    State(state): State<AppState>,
    AxumPath(index): AxumPath<u64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = state.chain.lock().unwrap();
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
    State(state): State<AppState>,
    AxumPath(txid_str): AxumPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = state.chain.lock().unwrap();
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
    State(state): State<AppState>,
    Json(body): Json<AddressRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = state.chain.lock().unwrap();

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
    State(state): State<AppState>,
    Json(body): Json<UtxoRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = state.chain.lock().unwrap();

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
    State(state): State<AppState>,
    Json(body): Json<AddressRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = state.chain.lock().unwrap();

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
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let txid_hex;
    let gossip_body;
    let is_new;

    {
        let mut chain = state.chain.lock().unwrap();

        let tx_json: stevecoin::transaction::TransactionJson =
            serde_json::from_value(body.clone()).map_err(|e| {
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

        txid_hex = tx.txid.to_hex();

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

        gossip_body = serde_json::to_value(tx.to_json()).unwrap();

        let mut ps = state.peers.lock().unwrap();
        is_new = ps.mark_txid_seen(&txid_hex);
    }

    // Gossip to peers (outside lock)
    if is_new {
        gossip_to_peers(state.peers.clone(), "/tx/submit", gossip_body);
    }

    Ok("SUCCESS".to_string())
}

// POST /block/submit
async fn block_submit(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let block_hash_hex;
    let gossip_body;
    let is_new;
    let mut should_reorg = false;

    {
        let mut chain = state.chain.lock().unwrap();

        let block_json: stevecoin::block::BlockJson =
            serde_json::from_value(body.clone()).map_err(|e| {
                err_response(StatusCode::BAD_REQUEST, &format!("Invalid block: {e}"))
            })?;

        let block = Block::deserialise_dict(&block_json).map_err(|e| {
            err_response(StatusCode::BAD_REQUEST, &format!("Invalid block: {e}"))
        })?;

        block_hash_hex = block.hash.to_hex();
        let txids: Vec<_> = block.transactions.iter().map(|t| t.txid.clone()).collect();

        match chain.validate_and_write_block(&block) {
            Ok(()) => {
                for txid in &txids {
                    let _ = chain.delete_pending_transaction(txid);
                }
            }
            Err(e) => {
                // Check if this looks like a fork candidate
                let num_blocks = chain.get_num_blocks();
                let is_fork_candidate = block.verify_pow(chain.blockdb.pow_difficulty).is_ok()
                    && block.index <= num_blocks + 1
                    && block.index > 0;

                if is_fork_candidate {
                    should_reorg = true;
                } else {
                    return Err(match e {
                        BlockChainError::BlockValidation(msg) => {
                            err_response(StatusCode::BAD_REQUEST, &format!("Invalid block: {msg}"))
                        }
                        _ => err_response(StatusCode::INTERNAL_SERVER_ERROR, "Blockchain error"),
                    });
                }
            }
        }

        gossip_body = serde_json::to_value(block.serialise_dict()).unwrap();

        let mut ps = state.peers.lock().unwrap();
        is_new = ps.mark_block_seen(&block_hash_hex);
    }

    // Gossip to peers (outside lock)
    if is_new && !should_reorg {
        gossip_to_peers(state.peers.clone(), "/block/submit", gossip_body);
    }

    // Spawn reorg task if needed
    if should_reorg {
        let state_clone = state.clone();
        tokio::spawn(async move {
            handle_potential_reorg(state_clone).await;
        });
    }

    Ok("SUCCESS".to_string())
}

// ---------------------------------------------------------------------------
// New endpoints
// ---------------------------------------------------------------------------

// GET /chain/info
#[derive(Serialize, Deserialize)]
struct ChainInfoResponse {
    num_blocks: u64,
    tip_hash: String,
}

async fn chain_info(
    State(state): State<AppState>,
) -> Result<Json<ChainInfoResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut chain = state.chain.lock().unwrap();
    let num_blocks = chain.get_num_blocks();
    let tip_hash = if num_blocks > 0 {
        match chain.get_block(num_blocks - 1) {
            Ok(block) => block.hash.serialise(),
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };

    Ok(Json(ChainInfoResponse {
        num_blocks,
        tip_hash,
    }))
}

// GET /peers
async fn get_peers(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let ps = state.peers.lock().unwrap();
    let peers: Vec<&String> = ps.peers.iter().collect();
    Json(serde_json::json!({ "peers": peers }))
}

// POST /peers/register
#[derive(Deserialize)]
struct RegisterPeerRequest {
    url: String,
}

async fn register_peer(
    State(state): State<AppState>,
    Json(body): Json<RegisterPeerRequest>,
) -> StatusCode {
    let mut ps = state.peers.lock().unwrap();
    let url = body.url.trim_end_matches('/').to_string();
    // Don't add ourselves
    if ps.my_url.as_deref() == Some(&url) {
        return StatusCode::OK;
    }
    ps.peers.insert(url);
    StatusCode::OK
}

// ---------------------------------------------------------------------------
// Peer bootstrap
// ---------------------------------------------------------------------------

async fn bootstrap_peers(state: AppState, seed_peers: Vec<String>) {
    let client = reqwest::Client::new();
    let my_url = {
        let ps = state.peers.lock().unwrap();
        ps.my_url.clone()
    };

    for peer in &seed_peers {
        let peer = peer.trim_end_matches('/').to_string();

        // Add seed peer to our set
        {
            let mut ps = state.peers.lock().unwrap();
            ps.peers.insert(peer.clone());
        }

        // Register ourselves with the peer
        if let Some(ref url) = my_url {
            let _ = client
                .post(format!("{peer}/peers/register"))
                .json(&serde_json::json!({ "url": url }))
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await;
        }

        // Fetch peer's peer list
        if let Ok(resp) = client
            .get(format!("{peer}/peers"))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(peers) = data["peers"].as_array() {
                    let mut ps = state.peers.lock().unwrap();
                    for p in peers {
                        if let Some(url) = p.as_str() {
                            let url = url.trim_end_matches('/').to_string();
                            if ps.my_url.as_deref() != Some(&url) {
                                ps.peers.insert(url);
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Initial Block Download (IBD)
// ---------------------------------------------------------------------------

async fn initial_block_download(state: AppState) {
    let client = reqwest::Client::new();
    let peer_urls: Vec<String> = {
        let ps = state.peers.lock().unwrap();
        ps.peers.iter().cloned().collect()
    };

    if peer_urls.is_empty() {
        return;
    }

    // Find the peer with the longest chain
    let mut best_peer: Option<String> = None;
    let mut best_height: u64 = {
        let chain = state.chain.lock().unwrap();
        chain.get_num_blocks()
    };

    for peer in &peer_urls {
        if let Ok(resp) = client
            .get(format!("{peer}/chain/info"))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            if let Ok(info) = resp.json::<ChainInfoResponse>().await {
                if info.num_blocks > best_height {
                    best_height = info.num_blocks;
                    best_peer = Some(peer.clone());
                }
            }
        }
    }

    let peer = match best_peer {
        Some(p) => p,
        None => return, // No peer has a longer chain
    };

    let our_height = {
        let chain = state.chain.lock().unwrap();
        chain.get_num_blocks()
    };

    println!("IBD: Downloading blocks {} to {} from {peer}", our_height, best_height - 1);

    for index in our_height..best_height {
        let resp = match client
            .get(format!("{peer}/block/{index}"))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("IBD: Error fetching block {index}: {e}");
                return;
            }
        };

        if resp.status() != 200 {
            eprintln!("IBD: Failed to fetch block {index}: HTTP {}", resp.status());
            return;
        }

        let block_json: stevecoin::block::BlockJson = match resp.json().await {
            Ok(j) => j,
            Err(e) => {
                eprintln!("IBD: Error parsing block {index}: {e}");
                return;
            }
        };

        let block = match Block::deserialise_dict(&block_json) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("IBD: Error deserialising block {index}: {e}");
                return;
            }
        };

        let mut chain = state.chain.lock().unwrap();

        // For the genesis block during IBD, write directly without full validation
        if index == 0 && chain.get_num_blocks() == 0 {
            if let Err(e) = chain.write_genesis_block(&block) {
                eprintln!("IBD: Error writing genesis block: {e}");
                return;
            }
        } else {
            if let Err(e) = chain.validate_and_write_block(&block) {
                eprintln!("IBD: Error validating/writing block {index}: {e}");
                return;
            }
        }

        if index % 100 == 0 || index == best_height - 1 {
            println!("IBD: Downloaded block {index}/{}", best_height - 1);
        }
    }

    println!("IBD: Complete. Chain height: {best_height}");
}

// ---------------------------------------------------------------------------
// Fork Detection & Chain Reorganization
// ---------------------------------------------------------------------------

/// Find the block index where our chain diverges from a peer's chain.
async fn find_fork_point(
    client: &reqwest::Client,
    state: &AppState,
    peer: &str,
) -> Option<u64> {
    let our_height = {
        let chain = state.chain.lock().unwrap();
        chain.get_num_blocks()
    };

    // Walk backwards from our tip
    let mut index = our_height.saturating_sub(1);
    loop {
        let our_hash = {
            let mut chain = state.chain.lock().unwrap();
            match chain.get_block(index) {
                Ok(b) => b.hash.to_hex(),
                Err(_) => return None,
            }
        };

        // Get peer's block at this index
        let resp = match client
            .get(format!("{peer}/block/{index}"))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(r) if r.status() == 200 => r,
            _ => return None,
        };

        let peer_block: stevecoin::block::BlockJson = match resp.json().await {
            Ok(j) => j,
            Err(_) => return None,
        };

        if our_hash == peer_block.hash {
            // Chains agree at this index — fork point is the next block
            return Some(index + 1);
        }

        if index == 0 {
            return Some(0);
        }
        index -= 1;
    }
}

async fn handle_potential_reorg(state: AppState) {
    // Check reorg_in_progress flag
    {
        let mut ps = state.peers.lock().unwrap();
        if ps.reorg_in_progress {
            println!("Reorg: Already in progress, skipping");
            return;
        }
        ps.reorg_in_progress = true;
    }

    let result = do_reorg(&state).await;

    // Clear reorg flag
    {
        let mut ps = state.peers.lock().unwrap();
        ps.reorg_in_progress = false;
    }

    if let Err(e) = result {
        eprintln!("Reorg: Error during reorganization: {e}");
    }
}

async fn do_reorg(state: &AppState) -> std::result::Result<(), String> {
    let client = reqwest::Client::new();
    let peer_urls: Vec<String> = {
        let ps = state.peers.lock().unwrap();
        ps.peers.iter().cloned().collect()
    };

    // Find the peer with the longest chain
    let our_height = {
        let chain = state.chain.lock().unwrap();
        chain.get_num_blocks()
    };

    let mut best_peer: Option<String> = None;
    let mut best_height: u64 = our_height;

    for peer in &peer_urls {
        if let Ok(resp) = client
            .get(format!("{peer}/chain/info"))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            if let Ok(info) = resp.json::<ChainInfoResponse>().await {
                if info.num_blocks > best_height {
                    best_height = info.num_blocks;
                    best_peer = Some(peer.clone());
                }
            }
        }
    }

    let peer = match best_peer {
        Some(p) => p,
        None => {
            println!("Reorg: No peer has a longer chain, nothing to do");
            return Ok(());
        }
    };

    println!("Reorg: Peer {peer} has height {best_height}, ours is {our_height}");

    // Find fork point
    let fork_point = match find_fork_point(&client, state, &peer).await {
        Some(fp) => fp,
        None => {
            return Err("Could not find fork point".into());
        }
    };

    println!("Reorg: Fork point at block {fork_point}");

    // Download all blocks from fork point to peer's tip
    let mut new_blocks = Vec::new();
    for index in fork_point..best_height {
        let resp = match client
            .get(format!("{peer}/block/{index}"))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
        {
            Ok(r) if r.status() == 200 => r,
            Ok(r) => {
                return Err(format!("Failed to fetch block {index}: HTTP {}", r.status()));
            }
            Err(e) => {
                return Err(format!("Error fetching block {index}: {e}"));
            }
        };

        let block_json: stevecoin::block::BlockJson = resp
            .json()
            .await
            .map_err(|e| format!("Error parsing block {index}: {e}"))?;

        let block = Block::deserialise_dict(&block_json)
            .map_err(|e| format!("Error deserialising block {index}: {e}"))?;

        new_blocks.push(block);
    }

    // Now do the actual rollback and re-application under the chain lock
    let mut chain = state.chain.lock().unwrap();

    // Roll back to fork point, re-adding rolled-back txs to mempool
    let current_height = chain.get_num_blocks();
    println!(
        "Reorg: Rolling back {} blocks (from {} to {})",
        current_height - fork_point,
        current_height - 1,
        fork_point
    );

    for _ in fork_point..current_height {
        match chain.rollback_block() {
            Ok(rolled_back) => {
                // Re-add transactions to mempool
                for tx in &rolled_back.transactions {
                    let _ = chain.add_pending_transaction(tx);
                }
            }
            Err(e) => {
                eprintln!("Reorg: Rollback failed: {e}, running consistency check");
                let _ = chain.blockdb.consistency_check();
                return Err(format!("Rollback failed: {e}"));
            }
        }
    }

    // Apply new blocks
    println!("Reorg: Applying {} new blocks", new_blocks.len());
    for block in &new_blocks {
        if let Err(e) = chain.validate_and_write_block(block) {
            eprintln!("Reorg: Failed to apply block {}: {e}, running consistency check", block.index);
            let _ = chain.blockdb.consistency_check();
            return Err(format!("Failed to apply block {}: {e}", block.index));
        }

        // Remove transactions from mempool that are now confirmed
        for tx in &block.transactions {
            let _ = chain.delete_pending_transaction(&tx.txid);
        }
    }

    println!(
        "Reorg: Complete. New chain height: {}",
        chain.get_num_blocks()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let cur_dir = env::current_dir().unwrap();
    let base_dir = cur_dir.join("blockdata");
    let base_dir_str = base_dir.to_string_lossy().to_string();
    let mut create_flag = false;
    let mut password = String::new();
    let has_peers = !cli.peers.is_empty();

    if !Path::new(&base_dir).exists() {
        if has_peers {
            // With peers, skip genesis creation — IBD will download the chain
            println!("Blockchain not found. Will download from peers via IBD.\n");
            fs::create_dir_all(&base_dir).expect("Failed to create blockdata directory");
        } else {
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
    }

    let mut chain = BlockChain::new(&base_dir_str).expect("Failed to initialise blockchain");

    if create_flag && !password.is_empty() && chain.get_num_blocks() == 0 {
        chain
            .create(&password)
            .expect("Failed to create blockchain");
        println!("Blockchain created successfully.");
    } else if !has_peers && chain.get_num_blocks() < 1 {
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

    let peer_set = PeerSet::new(cli.my_url);
    let state = AppState {
        chain: Arc::new(Mutex::new(chain)),
        peers: Arc::new(Mutex::new(peer_set)),
    };

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
        .route("/chain/info", get(chain_info))
        .route("/peers", get(get_peers))
        .route("/peers/register", post(register_peer))
        .with_state(state.clone());

    let app = NormalizePathLayer::trim_trailing_slash().layer(app);

    // Spawn peer bootstrap and IBD
    let seed_peers = cli.peers;
    if !seed_peers.is_empty() {
        let state_clone = state.clone();
        tokio::spawn(async move {
            bootstrap_peers(state_clone.clone(), seed_peers).await;
            initial_block_download(state_clone).await;
        });
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Starting server on port {port} ...\n");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, ServiceExt::<axum::extract::Request>::into_make_service(app))
        .await
        .unwrap();
}
