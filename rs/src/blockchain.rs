/// Top-level blockchain orchestrator — direct port of lib/blockchain.py.
use crate::block::Block;
use crate::blockdb::BlockDB;
use crate::crypto::{ECDSAPrivateKey, Hash, Hasher};
use crate::errors::{BlockChainError, Result};
use crate::querylayer;
use crate::querylayer::QueryLayer;
use crate::transaction::{Transaction, TransactionInput, TransactionOutput};
use crate::transdb::TransDB;

pub const TOTAL_COINS: u64 = 987_654_321_000;

pub struct BlockChain {
    pub base_dir: String,
    pub blockdb: BlockDB,
    pub transdb: TransDB,
}

impl BlockChain {
    pub fn new(base_dir: &str) -> Result<Self> {
        let blockdb = BlockDB::new(base_dir)?;
        let transdb = TransDB::new(base_dir)?;

        let mut chain = BlockChain {
            base_dir: base_dir.to_string(),
            blockdb,
            transdb,
        };

        // Run consistency check
        chain.blockdb.consistency_check()?;

        Ok(chain)
    }

    pub fn get_num_blocks(&self) -> u64 {
        self.blockdb.num_blocks
    }

    pub fn get_block(&mut self, index: u64) -> Result<Block> {
        self.blockdb.get_block(index)
    }

    pub fn get_transaction(&mut self, txid: &Hash) -> Result<Transaction> {
        self.blockdb.get_transaction(txid)
    }

    pub fn validate_and_write_block(&mut self, block: &Block) -> Result<()> {
        // Validate first
        let pow = self.blockdb.pow_difficulty;
        {
            let mut q = QueryLayer::new(&mut self.blockdb);
            block.validate(&mut q, pow)?;
        }
        // Then write
        self.blockdb.write_new_block(block, false)?;
        Ok(())
    }

    pub fn write_genesis_block(&mut self, block: &Block) -> Result<()> {
        self.blockdb.write_new_block(block, true)
    }

    pub fn delete_pending_transaction(&mut self, txid: &Hash) -> Result<()> {
        self.transdb.delete_transaction(txid)
    }

    pub fn add_pending_transaction(&mut self, tx: &Transaction) -> Result<()> {
        self.transdb.add_transaction(tx)
    }

    pub fn validate_transaction(&mut self, tx: &Transaction) -> Result<()> {
        querylayer::validate_transaction(&mut self.blockdb, tx)
    }

    pub fn get_pending_transactions(&mut self) -> Result<Vec<Transaction>> {
        querylayer::get_pending_transactions(&mut self.blockdb, &mut self.transdb)
    }

    pub fn get_txids_for_address(
        &mut self,
        pubkey: &crate::crypto::ECDSAPublicKey,
        sig: &Hash,
    ) -> Result<Vec<Hash>> {
        querylayer::get_txids_for_address(&mut self.blockdb, pubkey, sig)
    }

    pub fn get_utxo(&mut self, txid: &Hash, address: &crate::crypto::CryptoAddress) -> Result<u64> {
        querylayer::get_utxo(&mut self.blockdb, txid, address)
    }

    pub fn get_utxo_private(
        &mut self,
        pubkey: &crate::crypto::ECDSAPublicKey,
        txid: &Hash,
        sig: &Hash,
    ) -> Result<u64> {
        querylayer::get_utxo_private(&mut self.blockdb, pubkey, txid, sig)
    }

    pub fn create(&mut self, passphrase: &str) -> Result<()> {
        if self.blockdb.num_blocks != 0 {
            return Err(BlockChainError::BlockValidation(
                "Blockchain already exists!".into(),
            ));
        }

        println!("Creating new blockchain...");

        // Generate genesis keys
        let pk = ECDSAPrivateKey::generate();
        let key_prefix = format!("{}/genesis_key", self.base_dir);
        pk.write_key_pair(&key_prefix, passphrase)?;

        // Build genesis block
        let mut block =
            Block::new(0, Hasher::new_with_message(b"There can be only one").get_hash())?;
        let address = pk.publickey().get_address();
        let to = TransactionOutput {
            address: address.clone(),
            amount: TOTAL_COINS,
        };

        // Fake the UTXO in
        let txid = Hasher::new_with_message(b"Genesis").get_hash();
        let utxokey = self.blockdb.get_key_for_utxo(&txid, &address);
        self.blockdb
            .db
            .put(&utxokey, &TOTAL_COINS.to_le_bytes())
            .map_err(|e| BlockChainError::DbIntegrity(format!("DB write failed: {e}")))?;

        // Sign the input
        let output_hash = Hasher::new_with_items(&[(&to.get_hash()).into()]).get_hash();
        let sig = Hasher::new_with_items(&[(&txid).into(), (&output_hash).into()]).sign(&pk)?;

        let ti = TransactionInput {
            txid: txid.clone(),
            pubkey: pk.publickey().as_hash(),
            sig,
        };

        let mut t = Transaction::new(vec![ti], vec![to])?;
        t.output_hash = t.calculate_output_hash();
        t.txid = t.calculate_txid();

        // Validate
        {
            let mut q = QueryLayer::new(&mut self.blockdb);
            t.validate(&mut q)?;
        }

        block.transactions = vec![t];
        block.merkle_root = block.calculate_merkle_root();
        block.hash = block.calculate_hash();

        println!("Mining Genesis Block...");
        block.ensure_difficulty(self.blockdb.pow_difficulty);

        println!("Writing Genesis Block...");
        self.write_genesis_block(&block)?;

        // Force another consistency check
        self.blockdb.consistency_check()?;
        Ok(())
    }
}
