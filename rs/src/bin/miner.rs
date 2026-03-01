/// Block miner — direct port of miner.py.
use std::thread;
use std::time::Duration;

use clap::Parser;
use serde::Deserialize;

use stevecoin::block::Block;
use stevecoin::crypto::hash512_from_hex;
use stevecoin::transaction::Transaction;

#[derive(Parser)]
#[command(name = "stevecoin-miner", about = "Stevecoin Miner")]
struct Cli {
    /// The blockchain server URL
    #[arg(long)]
    server: String,

    /// Poll interval in seconds when waiting for transactions
    #[arg(long, default_value = "60")]
    sleep: u64,
}

#[derive(Deserialize)]
struct MinerResponse {
    txlist: Vec<String>,
    num_blocks: u64,
    prev_hash: String,
    pow: usize,
}

fn main() {
    let cli = Cli::parse();
    let server_url = &cli.server;
    let sleep_secs = cli.sleep;
    let client = reqwest::blocking::Client::new();

    println!("Server: {server_url}");
    println!("Waiting for new transactions to mine ...");

    loop {
        let r = match client.get(format!("{server_url}/miner")).send() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error contacting server: {e}");
                thread::sleep(Duration::from_secs(10));
                continue;
            }
        };

        let status = r.status();
        if status != 200 {
            eprintln!("Error getting miner info (HTTP {}): {}", status, r.text().unwrap_or_default());
            thread::sleep(Duration::from_secs(10));
            continue;
        }

        let data: MinerResponse = match r.json() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error parsing response: {e}");
                thread::sleep(Duration::from_secs(10));
                continue;
            }
        };

        if data.txlist.is_empty() {
            thread::sleep(Duration::from_secs(sleep_secs));
            continue;
        }

        let next_index = data.num_blocks;
        let prev_hash = match hash512_from_hex(&data.prev_hash) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Invalid prev_hash from server: {e}");
                thread::sleep(Duration::from_secs(10));
                continue;
            }
        };
        let pow_difficulty = data.pow;

        println!("Mining block {next_index} ...");

        let transactions: Result<Vec<Transaction>, _> = data
            .txlist
            .iter()
            .map(|s| Transaction::deserialise(s))
            .collect();

        let transactions = match transactions {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error deserialising transactions: {e}");
                thread::sleep(Duration::from_secs(10));
                continue;
            }
        };

        let mut block = match Block::new(next_index, prev_hash) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Error creating block: {e}");
                thread::sleep(Duration::from_secs(10));
                continue;
            }
        };

        block.transactions = transactions;
        block.merkle_root = block.calculate_merkle_root();
        block.hash = block.calculate_hash();
        block.ensure_difficulty(pow_difficulty);

        let block_json = block.serialise_dict();

        let r = match client
            .post(format!("{server_url}/block/submit"))
            .json(&block_json)
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error submitting block: {e}");
                continue;
            }
        };

        if r.status() != 200 {
            eprintln!("Error submitting block: {}", r.text().unwrap_or_default());
            continue;
        }

        println!("Successfully mined block {next_index}");
        println!("Waiting for new transactions to mine ...");
    }
}
