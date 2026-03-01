# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SteveCoin is a fully functioning cryptocurrency implementation. It consists of three components: a blockchain server, a CLI wallet client, and a block miner. There are two implementations: the original Python version (`py/`) and a Rust port (`rs/`).

## Commands

### Python (`py/`)

```bash
cd py
python index.py                                     # Run server (port 5000)
python client.py --help                              # Wallet CLI
python miner.py --server http://localhost:5000       # Run miner
pip install -r requirements.txt                      # Install deps
python -m pytest unit/                               # Run all tests
python -m pytest unit/test_crypto.py -k test_roundtrip  # Single test
```

### Rust (`rs/`)

```bash
cd rs
cargo run --bin server                               # Run server (port 5000)
cargo run --bin client -- --help                      # Wallet CLI
cargo run --bin miner -- --server http://localhost:5000  # Run miner
cargo build                                          # Build all
cargo test                                           # Run all tests
cargo test test_ecdsa_sig                             # Single test
```

Both versions use `BLOCKCHAIN_PORT` env var to change the server port. Data is stored in `blockdata/`. First run prompts for a genesis key password.

## Architecture

### Three-process model
- **Server** — HTTP server exposing the blockchain API. Holds a `BlockChain` instance. Python uses Bottle; Rust uses axum.
- **Client** — CLI wallet managing encrypted private keys in `config.sc`. Communicates with the server via HTTP.
- **Miner** — Polls the server for pending transactions, mines blocks (proof-of-work), and submits them back.

### Core library modules
- **`blockchain`** — Top-level orchestrator. Creates genesis block with `TOTAL_COINS = 987654321000`. Owns `BlockDB`, `TransDB`, and query functions.
- **`block`** — Block structure: serialisation, merkle root, SHA3-512 hashing, proof-of-work (nonce brute-force), validation.
- **`transaction`** — `Transaction`, `TransactionInput`, `TransactionOutput`. UTXO-based model. Inputs signed with ECDSA against `output_hash`. Remainder goes to a new address.
- **`blockdb`** — LevelDB index + flat binary block files (`bdata_*.blk`). UTXO indexes and transaction lookups. Full consistency check on startup.
- **`transdb`** — LevelDB-backed pending transaction pool.
- **`querylayer`** — Query interface: signature-authenticated address queries, pending transaction retrieval. In Rust, uses free functions instead of a struct to avoid borrow-checker issues.
- **`crypto`** — `Hash`/`Hash512`/`Hash256` wrappers, `Hasher` (SHA3-512), `CryptoAddress` (base58check), ECDSA key pairs (secp256k1), AES-EAX encryption.
- **`errors`** — Error hierarchy rooted at `BlockChainError`.

### Key design details
- All hashing uses **SHA3-512**. Addresses use SHA3-256 + RIPEMD-160 + base58check (intentionally different from Bitcoin).
- ECDSA signatures use **secp256k1** curve.
- Blocks are stored as length-prefixed JSON chunks in flat files, with LevelDB tracking offsets and UTXO state.
- Server performs full blockchain validation on every startup.
- `blockdata/` and `config.sc` are gitignored runtime state.

### Rust-specific notes
- LevelDB via `rusty-leveldb` (pure Rust). `WriteBatch` is not publicly constructable, so individual put/delete calls are used instead.
- Iterators use `LdbIterator` trait (`seek`/`advance`/`current`), not Rust's `Iterator`.
- `QueryLayer` is restructured as free functions to work with Rust's borrow checker.
- Known bugs from the Python version are tracked in `BUGS.md`.
