/// Query layer over the blockchain — direct port of lib/querylayer.py.
///
/// In the Python version, QueryLayer holds references to both BlockDB and TransDB.
/// In Rust, we pass &mut BlockDB and &mut TransDB explicitly to avoid
/// borrow-checker issues with self-referential borrows.
use std::collections::HashSet;

use crate::block::{Block, MAX_TRANSACTIONS_PER_BLOCK};
use crate::blockdb::BlockDB;
use crate::crypto::{CryptoAddress, ECDSAPublicKey, Hash, Hasher};
use crate::errors::{BlockChainError, Result};
use crate::transaction::Transaction;
use crate::transdb::TransDB;

/// Standalone query functions that operate on BlockDB/TransDB references.
/// These mirror the Python QueryLayer methods.

pub fn get_utxo(blockdb: &mut BlockDB, txid: &Hash, address: &CryptoAddress) -> Result<u64> {
    let amount = blockdb.get_utxo_amount(txid, address)?;

    // Verify the transaction is legit (skip for genesis).
    let genesis_hash = Hasher::new_with_message(b"Genesis").get_hash();
    if *txid != genesis_hash {
        let trans = blockdb.get_transaction(txid)?;
        let mut found = false;
        for txoutput in &trans.outputs {
            if *address == txoutput.address {
                found = true;
                if txoutput.amount != amount {
                    return Err(BlockChainError::TransactionValidation(
                        "UTXO amount mismatch".into(),
                    ));
                }
            }
        }
        if !found {
            return Err(BlockChainError::TransactionNotFound(
                "UTXO not found".into(),
            ));
        }
    }
    Ok(amount)
}

pub fn get_txids_for_address(
    blockdb: &mut BlockDB,
    pubkey: &ECDSAPublicKey,
    sig: &Hash,
) -> Result<Vec<Hash>> {
    let address = pubkey.get_address();
    Hasher::new_with_items(&[address.to_string_repr().into()])
        .verify_signature(sig, pubkey)
        .map_err(|_| BlockChainError::PermissionDenied("Permission denied".into()))?;

    blockdb.get_txids_for_address(&address)
}

pub fn get_utxo_private(
    blockdb: &mut BlockDB,
    pubkey: &ECDSAPublicKey,
    txid: &Hash,
    sig: &Hash,
) -> Result<u64> {
    let address = pubkey.get_address();
    Hasher::new_with_items(&[txid.into(), address.to_string_repr().into()])
        .verify_signature(sig, pubkey)
        .map_err(|_| BlockChainError::PermissionDenied("Permission denied".into()))?;

    get_utxo(blockdb, txid, &address)
}

pub fn validate_transaction(blockdb: &mut BlockDB, tx: &Transaction) -> Result<()> {
    tx.consistency_check()?;

    let mut total_input: u64 = 0;
    let mut total_output: u64 = 0;

    for txinput in &tx.inputs {
        let txaddress = ECDSAPublicKey::from_hash(&txinput.pubkey)?.get_address();
        total_input += get_utxo(blockdb, &txinput.txid, &txaddress)?;
    }

    for txoutput in &tx.outputs {
        total_output += txoutput.amount;
    }

    if total_output > total_input {
        return Err(BlockChainError::TransactionValidation(
            "Output exceeds input".into(),
        ));
    }

    Ok(())
}

pub fn get_pending_transactions(
    blockdb: &mut BlockDB,
    transdb: &mut TransDB,
) -> Result<Vec<Transaction>> {
    let limit = MAX_TRANSACTIONS_PER_BLOCK;
    let mut known_inputs: HashSet<Hash> = HashSet::new();
    let mut txlist = Vec::new();
    let mut txdelete = Vec::new();

    let all_pending = transdb.get_pending_transactions();
    for tx in all_pending {
        match validate_transaction(blockdb, &tx) {
            Ok(()) => match tx.check_duplicates(&mut known_inputs) {
                Ok(()) => {
                    txlist.push(tx);
                    if txlist.len() >= limit {
                        break;
                    }
                }
                Err(BlockChainError::TransactionDuplicateInput(_)) => continue,
                Err(_) => {
                    txdelete.push(tx);
                }
            },
            Err(_) => {
                txdelete.push(tx);
            }
        }
    }

    for tx in &txdelete {
        let _ = transdb.delete_transaction(&tx.txid);
    }

    Ok(txlist)
}

/// Minimal QueryLayer struct for use by Block::validate and Transaction::validate.
/// Only provides read-only block access and UTXO lookups — the caller must
/// ensure consistency_check has already run.
pub struct QueryLayer<'a> {
    pub blockdb: &'a mut BlockDB,
}

impl<'a> QueryLayer<'a> {
    pub fn new(blockdb: &'a mut BlockDB) -> Self {
        QueryLayer { blockdb }
    }

    pub fn get_block(&mut self, block_index: u64) -> Result<Block> {
        self.blockdb.get_block(block_index)
    }

    pub fn get_num_blocks(&self) -> u64 {
        self.blockdb.num_blocks
    }

    pub fn get_utxo(&mut self, txid: &Hash, address: &CryptoAddress) -> Result<u64> {
        get_utxo(self.blockdb, txid, address)
    }
}
