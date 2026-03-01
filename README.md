# SteveCoin

A personal cryptocurrency project, built to understand how blockchains,
proof-of-work, UTXO models, and cryptographic signing work in practice.

SteveCoin is a fully functioning UTXO-based cryptocurrency with:

- SHA3-512 hashing
- secp256k1 ECDSA signatures
- AES-256-EAX encrypted key storage
- Base58Check addresses
- Proof-of-work mining
- Merkle tree block validation
- LevelDB-indexed block storage

## Implementations

| | Python | Rust |
|---|--------|------|
| Directory | [`py/`](py/) | [`rs/`](rs/) |
| README | [py/README.md](py/README.md) | [rs/README.md](rs/README.md) |
| HTTP framework | Bottle | axum |
| LevelDB binding | plyvel | rusty-leveldb |
| ECDSA library | ecdsa | k256 |

The Rust version is a direct port of the Python original. Both implementations
are interoperable — they produce identical block and transaction formats, and
a server running either version can accept blocks and transactions from clients
or miners running the other.

## Components

The project consists of three programs:

- **Server** — HTTP API that manages the blockchain, validates blocks and
  transactions, and serves data to clients and miners
- **Client** — CLI wallet for creating addresses, checking balances, and
  submitting transactions
- **Miner** — Polls the server for pending transactions, mines them into
  blocks with proof-of-work, and submits the result

## Quick Start

See the README in each implementation directory for build and usage
instructions. The general workflow is:

1. Start the server (creates a new blockchain on first run)
2. Start the miner
3. Use the client to create addresses and transfer coins