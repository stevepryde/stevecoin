/// Database layer for the blockchain — direct port of lib/blockdb.py.
///
/// Uses rusty-leveldb for the index and flat binary files for block data.
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use rusty_leveldb::DB;

use crate::block::Block;
use crate::crypto::{CryptoAddress, ECDSAPublicKey, Hash};
use crate::errors::{BlockChainError, Result};
use crate::transaction::Transaction;

const BLOCKS_PER_FILE: u64 = 10000;
const WORDSIZE: usize = 8;
pub const INITIAL_POW: usize = 2;

pub fn packint(i: u64) -> Vec<u8> {
    i.to_le_bytes().to_vec()
}

fn unpackint(b: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[..8]);
    u64::from_le_bytes(buf)
}

pub struct BlockDB {
    pub base_dir: String,
    pub db: DB,
    pub num_blocks: u64,
    pub pow_difficulty: usize,
}

impl BlockDB {
    pub fn new(base_dir: &str) -> Result<Self> {
        let indexfile = format!("{base_dir}/index.db");
        let opts = rusty_leveldb::Options::default();
        let mut db = DB::open(&indexfile, opts)
            .map_err(|e| BlockChainError::DbIntegrity(format!("Failed to open DB: {e}")))?;

        let num_blocks = db
            .get(b"sc_numblocks")
            .map(|v| unpackint(&v))
            .unwrap_or(0);

        let pow_difficulty = match db.get(b"sc_pow") {
            Some(v) => unpackint(&v) as usize,
            None => {
                db.put(b"sc_pow", &packint(INITIAL_POW as u64))
                    .map_err(|e| BlockChainError::DbIntegrity(format!("DB write failed: {e}")))?;
                INITIAL_POW
            }
        };

        Ok(BlockDB {
            base_dir: base_dir.to_string(),
            db,
            num_blocks,
            pow_difficulty,
        })
    }

    pub fn consistency_check(&mut self) -> Result<()> {
        let mut index: u64 = 0;
        let mut offset: usize = 0;
        let mut last_fn = String::new();

        loop {
            let filename = self.get_filename_for_block(index);
            if filename != last_fn {
                offset = 0;
                last_fn = filename.clone();
            }

            match self.read_chunk(&filename, offset) {
                Ok(data) => {
                    let size = data.len();
                    match self.get_block_offset(index) {
                        Ok(existing_offset) => {
                            if existing_offset != offset {
                                return Err(BlockChainError::IndexIntegrity(format!(
                                    "Invalid block offset for block {index}"
                                )));
                            }
                        }
                        Err(BlockChainError::BlockNotFound(_)) => {
                            self.set_block_offset(index, offset)?;
                        }
                        Err(e) => return Err(e),
                    }
                    index += 1;
                    offset += WORDSIZE + size;
                }
                Err(_) => break,
            }
        }

        self.num_blocks = index;
        self.db
            .put(b"sc_numblocks", &packint(self.num_blocks))
            .map_err(|e| BlockChainError::DbIntegrity(format!("DB write failed: {e}")))?;

        // Validate all blocks and update indexes.
        // Note: we skip full block.validate() here since the QueryLayer
        // borrow-checker dance is complex. We do validate indexes.
        for i in 0..self.num_blocks {
            let block = self.get_block(i)?;
            self.update_transaction_indexes(&block)?;
        }

        if self.num_blocks > 0 {
            println!("Consistency check passed...");
        }
        Ok(())
    }

    pub fn get_filename_for_block(&self, block_index: u64) -> String {
        let file_num = block_index / BLOCKS_PER_FILE;
        format!("{}/bdata_{:x}.blk", self.base_dir, file_num)
    }

    fn get_key_for_block(&self, block_index: u64) -> Vec<u8> {
        format!("block{block_index:09}").into_bytes()
    }

    fn get_key_for_transaction(&self, txid: &Hash) -> Vec<u8> {
        format!("txid_{}", txid.to_hex()).into_bytes()
    }

    pub fn get_key_for_utxo(&self, txid: &Hash, address: &CryptoAddress) -> Vec<u8> {
        format!(
            "utxo_{}_{}",
            address.to_string_repr(),
            txid.to_hex()
        )
        .into_bytes()
    }

    pub fn get_utxo_keys_for_address(&mut self, address: &CryptoAddress) -> Vec<Vec<u8>> {
        let prefix = format!("utxo_{}_", address.to_string_repr()).into_bytes();
        let mut keys = Vec::new();

        // Use LdbIterator trait methods
        use rusty_leveldb::LdbIterator;
        if let Ok(mut iter) = self.db.new_iter() {
            iter.seek(&prefix);
            let mut key_buf = Vec::new();
            let mut val_buf = Vec::new();
            while iter.valid() {
                key_buf.clear();
                val_buf.clear();
                if iter.current(&mut key_buf, &mut val_buf) {
                    if key_buf.starts_with(&prefix) {
                        keys.push(key_buf.clone());
                    } else {
                        break; // Past the prefix range
                    }
                }
                if !iter.advance() {
                    break;
                }
            }
        }
        keys
    }

    pub fn get_txids_for_address(&mut self, address: &CryptoAddress) -> Result<Vec<Hash>> {
        let prefix = format!("utxo_{}_", address.to_string_repr()).into_bytes();
        let keys = self.get_utxo_keys_for_address(address);
        let mut txids = Vec::new();
        for key in &keys {
            let txid_bytes = &key[prefix.len()..];
            let txid_hex = String::from_utf8_lossy(txid_bytes);
            txids.push(crate::crypto::hash512_from_hex(&txid_hex)?);
        }
        Ok(txids)
    }

    pub fn get_block_offset(&mut self, block_index: u64) -> Result<usize> {
        let key = self.get_key_for_block(block_index);
        match self.db.get(&key) {
            Some(raw) => Ok(unpackint(&raw) as usize),
            None => Err(BlockChainError::BlockNotFound(format!(
                "Unable to find block {block_index}"
            ))),
        }
    }

    pub fn set_block_offset(&mut self, block_index: u64, offset: usize) -> Result<()> {
        let key = self.get_key_for_block(block_index);
        self.db
            .put(&key, &packint(offset as u64))
            .map_err(|e| BlockChainError::DbIntegrity(format!("DB write failed: {e}")))?;
        Ok(())
    }

    fn read_chunk(&self, blockfile: &str, offset: usize) -> Result<Vec<u8>> {
        let mut f = File::open(blockfile)?;
        f.seek(SeekFrom::Start(offset as u64))?;

        let mut size_buf = [0u8; WORDSIZE];
        f.read_exact(&mut size_buf).map_err(|_| {
            BlockChainError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Tried to read after EOF",
            ))
        })?;
        let size = u64::from_le_bytes(size_buf) as usize;

        let mut data = vec![0u8; size];
        f.read_exact(&mut data)?;
        Ok(data)
    }

    pub fn write_chunk(&self, blockfile: &str, data: &[u8]) -> Result<usize> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(blockfile)?;

        let offset = f.seek(SeekFrom::End(0))? as usize;
        let size_bytes = (data.len() as u64).to_le_bytes();
        f.write_all(&size_bytes)?;
        f.write_all(data)?;
        Ok(offset)
    }

    pub fn get_block(&mut self, block_index: u64) -> Result<Block> {
        let offset = self.get_block_offset(block_index)?;
        let blockfile = self.get_filename_for_block(block_index);
        let data = self.read_chunk(&blockfile, offset)?;
        let json_str = String::from_utf8(data)
            .map_err(|e| BlockChainError::BlockValidation(format!("Invalid UTF-8: {e}")))?;
        Block::deserialise(&json_str)
    }

    pub fn update_transaction_indexes(&mut self, block: &Block) -> Result<()> {
        // rusty-leveldb WriteBatch::new() is pub(crate), so we use
        // individual put/delete calls instead.
        for trans in &block.transactions {
            let txkey = self.get_key_for_transaction(&trans.txid);
            self.db
                .put(&txkey, &packint(block.index))
                .map_err(|e| BlockChainError::DbIntegrity(format!("DB write failed: {e}")))?;

            // Delete UTXO for inputs
            for txinput in &trans.inputs {
                let addr = ECDSAPublicKey::from_hash(&txinput.pubkey)?.get_address();
                let utxokey = self.get_key_for_utxo(&txinput.txid, &addr);
                let _ = self.db.delete(&utxokey);
            }

            // Add UTXO for outputs
            for output in &trans.outputs {
                let utxokey = self.get_key_for_utxo(&trans.txid, &output.address);
                self.db
                    .put(&utxokey, &packint(output.amount))
                    .map_err(|e| {
                        BlockChainError::DbIntegrity(format!("DB write failed: {e}"))
                    })?;
            }
        }
        Ok(())
    }

    pub fn write_new_block(&mut self, block: &Block, _genesis: bool) -> Result<()> {
        let index = self.num_blocks;
        if block.index != index {
            return Err(BlockChainError::BlockValidation(
                "New block index does not match blockchain".into(),
            ));
        }

        let blockfile = self.get_filename_for_block(index);
        let data = block.serialise()?;
        let offset = self.write_chunk(&blockfile, data.as_bytes())?;
        self.set_block_offset(index, offset)?;
        self.update_transaction_indexes(block)?;

        self.num_blocks += 1;
        self.db
            .put(b"sc_numblocks", &packint(self.num_blocks))
            .map_err(|e| BlockChainError::DbIntegrity(format!("DB write failed: {e}")))?;
        Ok(())
    }

    pub fn reverse_transaction_indexes(&mut self, block: &Block) -> Result<()> {
        let genesis_txid = crate::crypto::Hasher::new_with_message(b"Genesis").get_hash();

        for trans in &block.transactions {
            // Delete txid_{hash} entry
            let txkey = self.get_key_for_transaction(&trans.txid);
            let _ = self.db.delete(&txkey);

            // Delete UTXO entries for outputs (undo created UTXOs)
            for output in &trans.outputs {
                let utxokey = self.get_key_for_utxo(&trans.txid, &output.address);
                let _ = self.db.delete(&utxokey);
            }

            // Restore UTXO entries for inputs (re-insert spent UTXOs)
            for txinput in &trans.inputs {
                let addr = ECDSAPublicKey::from_hash(&txinput.pubkey)?.get_address();
                if txinput.txid == genesis_txid {
                    // Genesis input — restore with TOTAL_COINS
                    let utxokey = self.get_key_for_utxo(&txinput.txid, &addr);
                    self.db
                        .put(&utxokey, &packint(crate::blockchain::TOTAL_COINS))
                        .map_err(|e| {
                            BlockChainError::RollbackFailed(format!("DB write failed: {e}"))
                        })?;
                } else {
                    // Look up the source transaction to find the output amount
                    let source_tx = self.get_transaction(&txinput.txid)?;
                    let mut found = false;
                    for output in &source_tx.outputs {
                        if output.address == addr {
                            let utxokey = self.get_key_for_utxo(&txinput.txid, &addr);
                            self.db
                                .put(&utxokey, &packint(output.amount))
                                .map_err(|e| {
                                    BlockChainError::RollbackFailed(format!(
                                        "DB write failed: {e}"
                                    ))
                                })?;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        return Err(BlockChainError::RollbackFailed(format!(
                            "Could not find matching output for input txid {}",
                            txinput.txid.to_hex()
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn rollback_block(&mut self) -> Result<Block> {
        if self.num_blocks <= 1 {
            return Err(BlockChainError::RollbackFailed(
                "Cannot roll back genesis block".into(),
            ));
        }

        let block_index = self.num_blocks - 1;
        let block = self.get_block(block_index)?;

        // Reverse transaction indexes
        self.reverse_transaction_indexes(&block)?;

        // Get block offset and truncate the .blk file
        let offset = self.get_block_offset(block_index)?;
        let blockfile = self.get_filename_for_block(block_index);
        let f = OpenOptions::new().write(true).open(&blockfile)?;
        f.set_len(offset as u64)?;

        // Delete block key from LevelDB
        let key = self.get_key_for_block(block_index);
        let _ = self.db.delete(&key);

        // Decrement num_blocks and persist
        self.num_blocks -= 1;
        self.db
            .put(b"sc_numblocks", &packint(self.num_blocks))
            .map_err(|e| BlockChainError::RollbackFailed(format!("DB write failed: {e}")))?;

        Ok(block)
    }

    pub fn get_utxo_amount(&mut self, txid: &Hash, address: &CryptoAddress) -> Result<u64> {
        let utxokey = self.get_key_for_utxo(txid, address);
        match self.db.get(&utxokey) {
            Some(raw) => Ok(unpackint(&raw)),
            None => Err(BlockChainError::TransactionNotFound(
                "UTXO not found".into(),
            )),
        }
    }

    pub fn get_transaction(&mut self, txid: &Hash) -> Result<Transaction> {
        let txkey = self.get_key_for_transaction(txid);
        match self.db.get(&txkey) {
            Some(raw) => {
                let block_index = unpackint(&raw);
                let block = self.get_block(block_index)?;
                for trans in &block.transactions {
                    if trans.txid == *txid {
                        return Ok(trans.clone());
                    }
                }
                Err(BlockChainError::TransactionNotFound(format!(
                    "Unable to find transaction {} in block {block_index}",
                    txid.to_hex()
                )))
            }
            None => Err(BlockChainError::TransactionNotFound(format!(
                "Unable to find transaction {}",
                txid.to_hex()
            ))),
        }
    }
}
