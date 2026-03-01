# SteveCoin (Rust)

Rust implementation of SteveCoin, ported from the [Python original](../py/).

## Requirements

- Rust 1.70+ (2021 edition)

## Building

```
cargo build --release
```

This produces three binaries in `target/release/`:

- `server` — blockchain HTTP server
- `client` — CLI wallet
- `miner` — block miner

## Usage

### Server

```
cargo run --release --bin server
```

On first run, you will be prompted for a password to encrypt the genesis
private key. The server creates a `blockdata/` directory to store the
blockchain, keys, and LevelDB indexes.

On subsequent runs, the server loads the existing blockchain and runs a
consistency check.

Set `BLOCKCHAIN_PORT` to change the listening port (default: 5000).

### Client

```
cargo run --release --bin client -- --help
```

Subcommands:

| Command | Description |
|---------|-------------|
| `server <URL>` | Set the blockchain server URL |
| `add-private-key <FILE>` | Import a private key from an encrypted PEM file |
| `create` | Generate a new address |
| `delete <ADDRESS>` | Remove an address (balance must be 0) |
| `list` | List all addresses and balances |
| `transfer --src <ADDR> --dest <ADDR> --amount <N>` | Transfer coins |
| `transfer --src <ADDR> --dest <ADDR> --all` | Transfer entire balance |

On first run, you will be prompted for a master password to encrypt the
configuration file (`config.sc`), which stores private keys.

### Miner

```
cargo run --release --bin miner -- --server http://localhost:5000
```

The miner polls the server for pending transactions every 60 seconds. When
transactions are found, it mines them into a block (solving the proof-of-work
puzzle) and submits the block to the server.

## Architecture

The crate is structured as a library (`src/lib.rs`) with three binary entry
points:

- **`crypto`** — SHA3-512 hashing, secp256k1 ECDSA (k256), AES-256-EAX
  encryption, base58check addresses
- **`block`** — Block structure, serialization, merkle tree, POW, validation
- **`transaction`** — UTXO transaction model with inputs, outputs, signatures
- **`blockdb`** — LevelDB index + flat binary block storage
- **`transdb`** — LevelDB-backed pending transaction pool
- **`querylayer`** — Read-only query interface over blockdb/transdb
- **`blockchain`** — Top-level orchestrator, genesis block creation

## Running Tests

```
cargo test
```

## Differences from Python Version

- Uses `axum` instead of Bottle for HTTP
- Uses `rusty-leveldb` instead of `plyvel`
- Uses `k256` instead of the `ecdsa` Python library
- QueryLayer is implemented as free functions rather than a class, to work
  with the Rust borrow checker
- Debug password bypass is gated behind `#[cfg(debug_assertions)]` (debug
  builds only) rather than a hardcoded flag
