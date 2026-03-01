/// Block data structure — direct port of lib/block.py.
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::crypto::{hash512, hash512_from_hex, random_bytes, Hash, Hasher};
use crate::errors::{BlockChainError, Result};
use crate::querylayer::QueryLayer;
use crate::transaction::Transaction;

pub const BLOCK_CURRENT_VERSION: u32 = 1;
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 10;
pub const MAX_BLOCKSIZE: usize = 4096;
pub const GENESIS_HASH: &[u8] = b"There can be only one";
const NONCE_SIZE: usize = 4;

#[derive(Clone, Debug)]
pub struct Block {
    pub index: u64,
    pub version: u32,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub merkle_root: Hash,
    pub prev_hash: Hash,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub hash: Hash,
}

#[derive(Serialize, Deserialize)]
pub struct BlockJson {
    pub version: u32,
    pub index: u64,
    pub ts: u64,
    pub transactions: Vec<String>,
    pub merkle: String,
    pub prevhash: String,
    pub salt: String,
    pub nonce: String,
    pub hash: String,
}

impl Block {
    pub fn new(index: u64, prev_hash: Hash) -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Block {
            index,
            version: BLOCK_CURRENT_VERSION,
            timestamp: now,
            transactions: Vec::new(),
            merkle_root: hash512(b"")?,
            prev_hash,
            salt: random_bytes(NONCE_SIZE),
            nonce: random_bytes(NONCE_SIZE),
            hash: hash512(b"")?,
        })
    }

    pub fn deserialise(data: &str) -> Result<Self> {
        let d: BlockJson = serde_json::from_str(data)?;
        Self::deserialise_dict(&d)
    }

    pub fn deserialise_dict(d: &BlockJson) -> Result<Self> {
        if d.version != 1 {
            return Err(BlockChainError::BlockValidation(format!(
                "Unknown block version: {}",
                d.version
            )));
        }

        let transactions: Result<Vec<_>> =
            d.transactions.iter().map(|s| Transaction::deserialise(s)).collect();

        Ok(Block {
            version: d.version,
            index: d.index,
            timestamp: d.ts,
            transactions: transactions?,
            merkle_root: hash512_from_hex(&d.merkle)?,
            prev_hash: hash512_from_hex(&d.prevhash)?,
            nonce: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &d.nonce,
            )
            .map_err(|e| BlockChainError::BlockValidation(format!("Bad nonce: {e}")))?,
            salt: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &d.salt,
            )
            .map_err(|e| BlockChainError::BlockValidation(format!("Bad salt: {e}")))?,
            hash: hash512_from_hex(&d.hash)?,
        })
    }

    pub fn serialise_dict(&self) -> BlockJson {
        use base64::Engine;
        BlockJson {
            version: self.version,
            index: self.index,
            ts: self.timestamp,
            transactions: self
                .transactions
                .iter()
                .map(|t| t.serialise().unwrap_or_default())
                .collect(),
            merkle: self.merkle_root.serialise(),
            prevhash: self.prev_hash.serialise(),
            salt: base64::engine::general_purpose::STANDARD.encode(&self.salt),
            nonce: base64::engine::general_purpose::STANDARD.encode(&self.nonce),
            hash: self.hash.serialise(),
        }
    }

    pub fn serialise(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.serialise_dict())?)
    }

    pub fn calculate_merkle_root(&self) -> Hash {
        let mut hashes: Vec<Hash> = self.transactions.iter().map(|t| t.txid.clone()).collect();

        while hashes.len() > 1 {
            // If odd, repeat the last one
            if hashes.len() % 2 != 0 {
                hashes.push(hashes.last().unwrap().clone());
            }

            let mut next = Vec::new();
            for pair in hashes.chunks(2) {
                let h =
                    Hasher::new_with_items(&[(&pair[0]).into(), (&pair[1]).into()]).get_hash();
                next.push(h);
            }
            hashes = next;
        }

        hashes.into_iter().next().unwrap()
    }

    pub fn calculate_hash(&self) -> Hash {
        let ver = self.version.to_string();
        let idx = self.index.to_string();
        let ts = self.timestamp.to_string();
        let txcount = self.transactions.len().to_string();

        Hasher::new_with_items(&[
            ver.as_str().into(),
            idx.as_str().into(),
            ts.as_str().into(),
            txcount.as_str().into(),
            (&self.merkle_root).into(),
            (&self.prev_hash).into(),
            self.salt.as_slice().into(),
            self.nonce.as_slice().into(),
        ])
        .get_hash()
    }

    pub fn calculate_new_hash(&mut self) -> Hash {
        self.nonce = random_bytes(NONCE_SIZE);
        self.calculate_hash()
    }

    pub fn verify_pow(&self, pow_difficulty: usize) -> Result<()> {
        let hstr = self.hash.to_hex();
        let prefix: String = std::iter::repeat('0').take(pow_difficulty).collect();
        if !hstr.starts_with(&prefix) {
            return Err(BlockChainError::BlockDifficulty);
        }
        Ok(())
    }

    pub fn ensure_difficulty(&mut self, pow_difficulty: usize) {
        loop {
            if self.verify_pow(pow_difficulty).is_ok() {
                break;
            }
            self.hash = self.calculate_new_hash();
        }
    }

    pub fn validate(&self, q: &mut QueryLayer, pow_difficulty: usize) -> Result<()> {
        self.verify_pow(pow_difficulty)?;

        if self.index > 0 {
            let mut known_inputs: HashSet<Hash> = HashSet::new();
            for trans in &self.transactions {
                trans.validate(q)?;
                trans.check_duplicates(&mut known_inputs)?;
            }
        }

        if self.version != 1 {
            return Err(BlockChainError::BlockValidation(format!(
                "Unknown version {}", self.version
            )));
        }

        let serialised = self.serialise()?;
        if serialised.len() > MAX_BLOCKSIZE {
            return Err(BlockChainError::BlockValidation(format!(
                "Block exceeds maximum size of {MAX_BLOCKSIZE} bytes"
            )));
        }

        if self.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
            return Err(BlockChainError::BlockValidation(
                "Block contains too many transactions".into(),
            ));
        }

        // Timestamp checks
        // Must be after 2018-01-01 and before now
        let min_ts = 1_514_764_800u64; // 2018-01-01 UTC
        if self.timestamp < min_ts {
            return Err(BlockChainError::BlockValidation(
                "Block timestamp is too old".into(),
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if self.timestamp > now {
            return Err(BlockChainError::BlockValidation(
                "Block timestamp is in the future".into(),
            ));
        }

        let num_blocks = q.get_num_blocks();
        if self.index > num_blocks {
            return Err(BlockChainError::BlockValidation(
                "Invalid block index".into(),
            ));
        }

        if self.index == 0 {
            match q.get_block(0) {
                Ok(genblock) => {
                    if self.hash != genblock.hash {
                        return Err(BlockChainError::BlockValidation(
                            "Block hash mismatch".into(),
                        ));
                    }
                }
                Err(BlockChainError::BlockNotFound(_)) => {
                    if num_blocks != 0 {
                        return Err(BlockChainError::BlockValidation(
                            "Block count mismatch".into(),
                        ));
                    }
                }
                Err(e) => return Err(e),
            }
        } else if self.index <= num_blocks {
            let prev_block = q.get_block(self.index - 1)?;
            if self.prev_hash != prev_block.hash {
                return Err(BlockChainError::BlockValidation(
                    "Previous block hash mismatch".into(),
                ));
            }
        }

        if self.merkle_root != self.calculate_merkle_root() {
            return Err(BlockChainError::BlockValidation(
                "Block merkle root hash mismatch".into(),
            ));
        }

        if self.hash != self.calculate_hash() {
            return Err(BlockChainError::BlockValidation(
                "Block hash mismatch".into(),
            ));
        }

        Ok(())
    }
}
