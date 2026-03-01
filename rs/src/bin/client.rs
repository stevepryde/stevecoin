/// CLI wallet client — direct port of client.py.
use std::env;
use std::path::Path;
use std::process;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use stevecoin::crypto::{
    hash512_from_hex, CryptHelper, ECDSAPrivateKey, EncryptedData, Hasher,
};

const CONFIG_FILENAME: &str = "config.sc";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    server: String,
    pks: Vec<String>,
}

fn get_config_path() -> String {
    let cur_dir = env::current_dir().unwrap();
    cur_dir.join(CONFIG_FILENAME).to_string_lossy().to_string()
}

fn save_config(config: &Config, master_password: &str) -> anyhow::Result<()> {
    let config_path = get_config_path();
    let config_data = serde_json::to_vec(config)?;
    let encrypted = CryptHelper::encrypt_with_passphrase(&config_data, master_password)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    encrypted
        .write_to_file(&config_path, true)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

fn load_config(master_password: &str) -> anyhow::Result<Config> {
    let config_path = get_config_path();

    if !Path::new(&config_path).exists() {
        println!("Config file not found. It will be created...");
        let config = Config {
            server: "http://localhost:5000".to_string(),
            pks: Vec::new(),
        };
        save_config(&config, master_password)?;
        println!("Server: {}", config.server);
        return Ok(config);
    }

    let encrypted = EncryptedData::read_from_file(&config_path)
        .map_err(|e| anyhow::anyhow!("Error reading config: {e}"))?;
    let config_raw = encrypted
        .decrypt_with_passphrase(master_password)
        .map_err(|e| anyhow::anyhow!("Error decrypting config: {e}"))?;
    let config: Config = serde_json::from_slice(&config_raw)?;
    println!("Server: {}", config.server);
    Ok(config)
}

fn get_master_password(first: bool) -> String {
    // Only check env var in debug builds
    #[cfg(debug_assertions)]
    if let Ok(pw) = env::var("BLOCKCHAIN_DEBUG_PASSWORD") {
        if !pw.is_empty() {
            return pw;
        }
    }

    if first {
        loop {
            let pw = rpassword::prompt_password(
                "Please specify a master password for encrypting the configuration: ",
            )
            .expect("Failed to read password");
            if pw.len() < 8 {
                println!("Password must be at least 8 characters long");
                continue;
            }
            let pw2 = rpassword::prompt_password("Please re-enter the same password again: ")
                .expect("Failed to read password");
            if pw == pw2 {
                return pw;
            }
            println!("Passwords do not match. Please try again.");
        }
    } else {
        loop {
            let pw = rpassword::prompt_password("Please enter your master password: ")
                .expect("Failed to read password");
            if pw.len() < 8 {
                println!("Password must be at least 8 characters long");
                continue;
            }
            return pw;
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn server_post(
    config: &Config,
    path: &str,
    body: &serde_json::Value,
) -> anyhow::Result<reqwest::blocking::Response> {
    let url = format!("{}{}", config.server, path);
    let client = reqwest::blocking::Client::new();
    Ok(client.post(&url).json(body).send()?)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn set_server_address(master_password: &str, url: &str) -> anyhow::Result<()> {
    let mut config = load_config(master_password)?;
    config.server = url.to_string();
    save_config(&config, master_password)?;
    println!("Server is now set to: {url}");
    Ok(())
}

fn add_private_key(master_password: &str, filename: &str) -> anyhow::Result<()> {
    let file_password =
        rpassword::prompt_password(format!("Please enter the password for '{filename}': "))
            .expect("Failed to read password");

    let mut config = load_config(master_password)?;
    let pk = ECDSAPrivateKey::from_file(filename, &file_password)
        .map_err(|_| anyhow::anyhow!("Error loading private key (invalid password?)"))?;

    let pk_str = pk.to_hex_string();
    if config.pks.contains(&pk_str) {
        println!("Address already exists in wallet");
        return Ok(());
    }

    config.pks.push(pk_str);
    save_config(&config, master_password)?;
    println!("Added address: {}", pk.publickey().get_address().serialise());
    Ok(())
}

fn get_new_address(config: &mut Config, master_password: &str) -> anyhow::Result<String> {
    let pk = ECDSAPrivateKey::generate();
    let pk_str = pk.to_hex_string();

    if config.pks.contains(&pk_str) {
        anyhow::bail!("Address already exists in wallet?!");
    }

    config.pks.push(pk_str);
    save_config(config, master_password)?;
    Ok(pk.publickey().get_address().serialise())
}

fn create_address(master_password: &str) -> anyhow::Result<()> {
    let mut config = load_config(master_password)?;
    let address = get_new_address(&mut config, master_password)?;
    println!("Added new address: {address}");
    Ok(())
}

fn delete_address(master_password: &str, address: &str) -> anyhow::Result<()> {
    let mut config = load_config(master_password)?;

    if config.pks.is_empty() {
        anyhow::bail!("No private keys found.");
    }

    let mut found_pk: Option<ECDSAPrivateKey> = None;
    let mut found_idx: Option<usize> = None;
    for (i, pk_raw) in config.pks.iter().enumerate() {
        let pk = ECDSAPrivateKey::from_string(pk_raw)
            .map_err(|e| anyhow::anyhow!("Bad key: {e}"))?;
        if pk.publickey().get_address().serialise() == address {
            found_pk = Some(pk);
            found_idx = Some(i);
            break;
        }
    }

    let pk = found_pk.ok_or_else(|| anyhow::anyhow!("No private key found for this address."))?;
    let idx = found_idx.unwrap();
    let pubkey = pk.publickey();
    let sig = Hasher::new_with_items(&[address.into()]).sign(&pk)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let r = server_post(
        &config,
        "/address/balance",
        &serde_json::json!({
            "pubkey": pubkey.as_hash().serialise(),
            "sig": sig.serialise()
        }),
    )?;

    if r.status() != 200 {
        anyhow::bail!("Error getting balance for address: {address}");
    }

    let balance: u64 = r.json::<serde_json::Value>()?["data"]
        .as_u64()
        .unwrap_or(0);
    if balance != 0 {
        anyhow::bail!(
            "Cannot delete address '{address}' due to non-zero balance: {balance}"
        );
    }

    config.pks.remove(idx);
    save_config(&config, master_password)?;
    println!("Address '{address}' removed.");
    Ok(())
}

fn list_addresses(master_password: &str) -> anyhow::Result<()> {
    let config = load_config(master_password)?;

    if config.pks.is_empty() {
        println!("No addresses currently exist in wallet");
        return Ok(());
    }

    let mut rows: Vec<(String, String)> = vec![
        ("Address".to_string(), "Amount".to_string()),
        ("-------".to_string(), "------".to_string()),
    ];

    for pk_raw in &config.pks {
        let pk = ECDSAPrivateKey::from_string(pk_raw)
            .map_err(|e| anyhow::anyhow!("Bad key: {e}"))?;
        let pubkey = pk.publickey();
        let address = pubkey.get_address().serialise();

        let sig = Hasher::new_with_items(&[address.as_str().into()]).sign(&pk)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let r = server_post(
            &config,
            "/address/balance",
            &serde_json::json!({
                "pubkey": pubkey.as_hash().serialise(),
                "sig": sig.serialise()
            }),
        )?;

        if r.status() != 200 {
            anyhow::bail!("Error getting balance for address: {address}");
        }

        let amount: u64 = r.json::<serde_json::Value>()?["data"]
            .as_u64()
            .unwrap_or(0);
        rows.push((address, amount.to_string()));
    }

    let col_width = rows.iter().flat_map(|(a, b)| [a.len(), b.len()]).max().unwrap_or(0) + 2;
    for (a, b) in &rows {
        println!("{:<width$}{}", a, b, width = col_width);
    }
    Ok(())
}

fn submit_transaction(
    master_password: &str,
    src: &str,
    dest: &str,
    amount: Option<u64>,
    transfer_all: bool,
) -> anyhow::Result<()> {
    let mut config = load_config(master_password)?;

    if config.pks.is_empty() {
        anyhow::bail!("No src addresses found. Please create an address and transfer funds before trying again.");
    }

    // Find matching private key
    let mut pk_opt: Option<ECDSAPrivateKey> = None;
    for pk_raw in &config.pks {
        let pk = ECDSAPrivateKey::from_string(pk_raw)
            .map_err(|e| anyhow::anyhow!("Bad key: {e}"))?;
        if pk.publickey().get_address().serialise() == src {
            pk_opt = Some(pk);
            break;
        }
    }

    let pk = pk_opt.ok_or_else(|| {
        anyhow::anyhow!("Unknown src address. Please add the private key for this address.")
    })?;

    let pubkey = pk.publickey();
    let sig = Hasher::new_with_items(&[src.into()]).sign(&pk)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Get balance
    let r = server_post(
        &config,
        "/address/balance",
        &serde_json::json!({
            "pubkey": pubkey.as_hash().serialise(),
            "sig": sig.serialise()
        }),
    )?;

    if r.status() != 200 {
        anyhow::bail!("Error getting balance for address: {src}");
    }

    let total_input: u64 = r.json::<serde_json::Value>()?["data"]
        .as_u64()
        .unwrap_or(0);

    let amount = if transfer_all {
        total_input
    } else {
        let amt = amount.unwrap();
        if total_input < amt {
            anyhow::bail!("Insufficient funds in src address: {src}");
        }
        amt
    };

    // Get txids for address
    let sig = Hasher::new_with_items(&[src.into()]).sign(&pk)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let r = server_post(
        &config,
        "/address/utx",
        &serde_json::json!({
            "pubkey": pubkey.as_hash().serialise(),
            "sig": sig.serialise()
        }),
    )?;

    if r.status() != 200 {
        anyhow::bail!("Error getting transactions for src address.");
    }

    let txids: Vec<String> = r.json::<serde_json::Value>()?["data"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    // Build outputs
    let mut output_list = vec![serde_json::json!({
        "address": dest,
        "amount": amount.to_string()
    })];

    let mut remainder_address: Option<String> = None;
    let remainder = total_input.saturating_sub(amount);
    if remainder > 0 {
        let addr = get_new_address(&mut config, master_password)?;
        output_list.push(serde_json::json!({
            "address": &addr,
            "amount": remainder.to_string()
        }));
        remainder_address = Some(addr);
    }

    // Calculate output hash
    let mut output_hasher = Hasher::new();
    for output in &output_list {
        let addr = output["address"].as_str().unwrap();
        let amt = output["amount"].as_str().unwrap();
        let h = Hasher::new_with_items(&[addr.into(), amt.into()]).get_hash();
        output_hasher.update_hash(&h);
    }
    let output_hash = output_hasher.get_hash();

    // Build inputs with signatures
    let mut input_list = Vec::new();
    let mut input_hasher = Hasher::new();

    for txid_str in &txids {
        let txid = hash512_from_hex(txid_str)
            .map_err(|e| anyhow::anyhow!("Invalid txid: {e}"))?;
        let sig = Hasher::new_with_items(&[(&txid).into(), (&output_hash).into()])
            .sign(&pk)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        input_list.push(serde_json::json!({
            "txid": txid_str,
            "pubkey": pubkey.as_hash().serialise(),
            "sig": sig.serialise()
        }));

        let h = Hasher::new_with_items(&[
            (&txid).into(),
            (&pubkey.as_hash()).into(),
            (&sig).into(),
        ])
        .get_hash();
        input_hasher.update_hash(&h);
    }

    let input_hash = input_hasher.get_hash();

    let txid_hash = Hasher::new_with_items(&[
        "1".into(), // version
        (&output_hash).into(),
        (&input_hash).into(),
    ])
    .get_hash();

    let trans = serde_json::json!({
        "version": 1,
        "txid": txid_hash.serialise(),
        "inputs": input_list,
        "outputs": output_list,
        "output_hash": output_hash.serialise()
    });

    let r = server_post(&config, "/tx/submit", &trans)?;

    if r.status() != 200 {
        anyhow::bail!("Error submitting transaction: {}", r.text()?);
    }

    println!("Transaction submitted successfully:");
    println!("Input address: {src}");
    println!("Transferred {amount} to address: {dest}");

    if let Some(rem_addr) = remainder_address {
        println!(
            "Transferred remainder of {remainder} to newly created address: {rem_addr}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "stevecoin-client", about = "Stevecoin CLI Client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Set the blockchain server URL
    Server {
        #[arg(value_name = "URL")]
        url: String,
    },
    /// Add a private key from an encrypted PEM file
    AddPrivateKey {
        #[arg(value_name = "FILE")]
        file: String,
    },
    /// Create a new address
    Create,
    /// Delete an address (balance must be 0)
    Delete {
        #[arg(value_name = "ADDRESS")]
        address: String,
    },
    /// List all addresses and their current balance
    List,
    /// Transfer coins from one address to another
    Transfer {
        /// Source address
        #[arg(long)]
        src: String,
        /// Destination address
        #[arg(long)]
        dest: String,
        /// Amount to transfer
        #[arg(long, conflicts_with = "all")]
        amount: Option<u64>,
        /// Transfer all coins from src
        #[arg(long, conflicts_with = "amount")]
        all: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    // Determine if we need a first-time password
    let config_path = get_config_path();
    let first_time = !Path::new(&config_path).exists();
    let master_password = get_master_password(first_time);

    let result = match cli.command {
        Commands::Server { url } => set_server_address(&master_password, &url),
        Commands::AddPrivateKey { file } => add_private_key(&master_password, &file),
        Commands::Create => create_address(&master_password),
        Commands::Delete { address } => delete_address(&master_password, &address),
        Commands::List => list_addresses(&master_password),
        Commands::Transfer {
            src,
            dest,
            amount,
            all,
        } => {
            if !all && amount.is_none() {
                eprintln!("Error: --amount or --all is required for transfer");
                process::exit(1);
            }
            submit_transaction(&master_password, &src, &dest, amount, all)
        }
    };

    if let Err(e) = result {
        eprintln!("{e}");
        process::exit(1);
    }
}
