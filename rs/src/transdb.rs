/// Database for the pending transactions pool — direct port of lib/transdb.py.
use rusty_leveldb::DB;

use crate::crypto::Hash;
use crate::errors::{BlockChainError, Result};
use crate::transaction::Transaction;

pub struct TransDB {
    pub db: DB,
}

impl TransDB {
    pub fn new(base_dir: &str) -> Result<Self> {
        let transfile = format!("{base_dir}/trans.db");
        let opts = rusty_leveldb::Options::default();
        let db = DB::open(&transfile, opts)
            .map_err(|e| BlockChainError::DbIntegrity(format!("Failed to open TransDB: {e}")))?;
        Ok(TransDB { db })
    }

    fn bump_index(&mut self) -> u64 {
        let index: u64 = self
            .db
            .get(b"nextindex")
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let next = index + 1;
        let _ = self.db.put(b"nextindex", next.to_string().as_bytes());
        index
    }

    fn get_key_for_index(index: u64) -> Vec<u8> {
        format!("trans_{index:09}").into_bytes()
    }

    fn get_key_for_txid(txid: &Hash) -> Vec<u8> {
        format!("txid_{}", txid.to_hex()).into_bytes()
    }

    pub fn add_transaction(&mut self, trans: &Transaction) -> Result<()> {
        let data = trans.serialise()?.into_bytes();
        let index = self.bump_index();
        let key = Self::get_key_for_index(index);

        self.db
            .put(&key, &data)
            .map_err(|e| BlockChainError::DbIntegrity(format!("DB write failed: {e}")))?;

        // Link txid -> key
        let txkey = Self::get_key_for_txid(&trans.txid);
        self.db
            .put(&txkey, &key)
            .map_err(|e| BlockChainError::DbIntegrity(format!("DB write failed: {e}")))?;
        Ok(())
    }

    pub fn get_transaction(&mut self, txid: &Hash) -> Result<Transaction> {
        let txkey = Self::get_key_for_txid(txid);
        let key = self.db.get(&txkey).ok_or_else(|| {
            BlockChainError::TransactionNotFound(format!(
                "Unable to find transaction {}",
                txid.to_hex()
            ))
        })?;

        let raw_data = self.db.get(&key).ok_or_else(|| {
            BlockChainError::TransactionNotFound(format!(
                "Unable to find transaction {}",
                txid.to_hex()
            ))
        })?;

        let json_str = String::from_utf8(raw_data).map_err(|e| {
            BlockChainError::TransactionNotFound(format!("Invalid UTF-8 transaction data: {e}"))
        })?;
        Transaction::deserialise(&json_str)
    }

    pub fn delete_transaction(&mut self, txid: &Hash) -> Result<()> {
        let txkey = Self::get_key_for_txid(txid);
        let key = self.db.get(&txkey).ok_or_else(|| {
            BlockChainError::TransactionNotFound(format!(
                "Unable to find transaction {}",
                txid.to_hex()
            ))
        })?;

        self.db
            .delete(&key)
            .map_err(|e| BlockChainError::DbIntegrity(format!("DB delete failed: {e}")))?;
        self.db
            .delete(&txkey)
            .map_err(|e| BlockChainError::DbIntegrity(format!("DB delete failed: {e}")))?;
        Ok(())
    }

    pub fn get_pending_transactions(&mut self) -> Vec<Transaction> {
        let prefix = b"trans_";
        let mut txs = Vec::new();

        use rusty_leveldb::LdbIterator;
        if let Ok(mut iter) = self.db.new_iter() {
            iter.seek(prefix);
            let mut key_buf = Vec::new();
            let mut val_buf = Vec::new();
            loop {
                key_buf.clear();
                val_buf.clear();
                if !iter.valid() {
                    break;
                }
                if iter.current(&mut key_buf, &mut val_buf) {
                    if !key_buf.starts_with(prefix) {
                        break;
                    }
                    if let Ok(s) = String::from_utf8(val_buf.clone()) {
                        if let Ok(tx) = Transaction::deserialise(&s) {
                            txs.push(tx);
                        }
                    }
                }
                if !iter.advance() {
                    break;
                }
            }
        }
        txs
    }
}
