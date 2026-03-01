/// Transaction types — direct port of lib/transaction.py.
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    basic_hash_check, hash512, hash512_from_hex, CryptoAddress, ECDSAPublicKey, Hash, Hasher,
};
use crate::errors::{BlockChainError, Result};
use crate::querylayer::QueryLayer;
use crate::blockdb::BlockDB;

const TRANSACTION_CURRENT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// TransactionInput
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct TransactionInput {
    pub txid: Hash,
    pub pubkey: Hash,
    pub sig: Hash,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionInputJson {
    pub txid: String,
    pub pubkey: String,
    pub sig: String,
}

impl TransactionInput {
    pub fn from_dict(d: &TransactionInputJson) -> Result<Self> {
        Ok(TransactionInput {
            txid: hash512_from_hex(&d.txid)?,
            pubkey: hash512_from_hex(&d.pubkey)?,
            sig: hash512_from_hex(&d.sig)?,
        })
    }

    pub fn to_dict(&self) -> TransactionInputJson {
        TransactionInputJson {
            txid: self.txid.serialise(),
            pubkey: self.pubkey.serialise(),
            sig: self.sig.serialise(),
        }
    }

    pub fn get_hash(&self) -> Hash {
        Hasher::new_with_items(&[
            (&self.txid).into(),
            (&self.pubkey).into(),
            (&self.sig).into(),
        ])
        .get_hash()
    }

    pub fn consistency_check(&self) -> Result<()> {
        basic_hash_check(&self.txid)?;
        // Verify pubkey is a valid ECDSA public key
        ECDSAPublicKey::from_hash(&self.pubkey)?;
        basic_hash_check(&self.sig)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TransactionOutput
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct TransactionOutput {
    pub address: CryptoAddress,
    pub amount: u64,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionOutputJson {
    pub address: String,
    pub amount: String,
}

impl TransactionOutput {
    pub fn from_dict(d: &TransactionOutputJson) -> Result<Self> {
        let amount: u64 = d.amount.parse().map_err(|_| {
            BlockChainError::TransactionValidation("Invalid amount".into())
        })?;
        Ok(TransactionOutput {
            address: CryptoAddress::deserialise(&d.address),
            amount,
        })
    }

    pub fn to_dict(&self) -> TransactionOutputJson {
        TransactionOutputJson {
            address: self.address.serialise(),
            amount: self.amount.to_string(),
        }
    }

    pub fn get_hash(&self) -> Hash {
        Hasher::new_with_items(&[
            self.address.to_string_repr().into(),
            self.amount.to_string().as_str().into(),
        ])
        .get_hash()
    }

    pub fn consistency_check(&self) -> Result<()> {
        if self.amount == 0 {
            return Err(BlockChainError::TransactionValidation(
                "Invalid output amount".into(),
            ));
        }
        self.address.validate()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Transaction {
    pub txid: Hash,
    pub version: u32,
    pub outputs: Vec<TransactionOutput>,
    pub output_hash: Hash,
    pub inputs: Vec<TransactionInput>,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionJson {
    pub txid: String,
    pub version: u32,
    pub outputs: Vec<TransactionOutputJson>,
    pub output_hash: String,
    pub inputs: Vec<TransactionInputJson>,
}

impl Transaction {
    pub fn new(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Result<Self> {
        Ok(Transaction {
            txid: hash512(b"")?,
            version: TRANSACTION_CURRENT_VERSION,
            output_hash: hash512(b"")?,
            outputs,
            inputs,
        })
    }

    pub fn deserialise(data: &str) -> Result<Self> {
        let d: TransactionJson = serde_json::from_str(data)?;
        Self::deserialise_dict(&d)
    }

    pub fn deserialise_dict(d: &TransactionJson) -> Result<Self> {
        if d.version != 1 {
            return Err(BlockChainError::TransactionValidation(format!(
                "Unknown transaction version: {}",
                d.version
            )));
        }

        let inputs: Result<Vec<_>> = d.inputs.iter().map(TransactionInput::from_dict).collect();
        let outputs: Result<Vec<_>> = d.outputs.iter().map(TransactionOutput::from_dict).collect();

        Ok(Transaction {
            txid: hash512_from_hex(&d.txid)?,
            version: d.version,
            output_hash: hash512_from_hex(&d.output_hash)?,
            outputs: outputs?,
            inputs: inputs?,
        })
    }

    pub fn serialise(&self) -> Result<String> {
        let j = self.to_json();
        Ok(serde_json::to_string(&j)?)
    }

    pub fn to_json(&self) -> TransactionJson {
        TransactionJson {
            txid: self.txid.serialise(),
            version: self.version,
            outputs: self.outputs.iter().map(|o| o.to_dict()).collect(),
            output_hash: self.output_hash.serialise(),
            inputs: self.inputs.iter().map(|i| i.to_dict()).collect(),
        }
    }

    pub fn calculate_output_hash(&self) -> Hash {
        let hashes: Vec<Hash> = self.outputs.iter().map(|o| o.get_hash()).collect();
        let mut hasher = Hasher::new();
        for h in &hashes {
            hasher.update_hash(h);
        }
        hasher.get_hash()
    }

    pub fn calculate_input_hash(&self) -> Hash {
        let hashes: Vec<Hash> = self.inputs.iter().map(|i| i.get_hash()).collect();
        let mut hasher = Hasher::new();
        for h in &hashes {
            hasher.update_hash(h);
        }
        hasher.get_hash()
    }

    pub fn calculate_txid(&self) -> Hash {
        Hasher::new_with_items(&[
            self.version.to_string().as_str().into(),
            (&self.calculate_output_hash()).into(),
            (&self.calculate_input_hash()).into(),
        ])
        .get_hash()
    }

    pub fn consistency_check(&self) -> Result<()> {
        let mut known_inputs: HashSet<Hash> = HashSet::new();

        if self.inputs.is_empty() {
            return Err(BlockChainError::TransactionValidation(
                "Invalid inputs".into(),
            ));
        }
        if self.outputs.is_empty() {
            return Err(BlockChainError::TransactionValidation(
                "Invalid outputs".into(),
            ));
        }

        self.check_duplicates(&mut known_inputs)?;

        let mut known_outputs: HashSet<CryptoAddress> = HashSet::new();
        for txoutput in &self.outputs {
            txoutput.consistency_check()?;
            if known_outputs.contains(&txoutput.address) {
                return Err(BlockChainError::TransactionValidation(
                    "Duplicate transaction output found".into(),
                ));
            }
            known_outputs.insert(txoutput.address.clone());
        }

        if self.calculate_output_hash() != self.output_hash {
            return Err(BlockChainError::TransactionValidation(
                "Transaction output hash mismatch".into(),
            ));
        }

        if self.calculate_txid() != self.txid {
            return Err(BlockChainError::TransactionValidation(
                "Transaction ID mismatch".into(),
            ));
        }

        // Verify signatures
        for txinput in &self.inputs {
            let pk = ECDSAPublicKey::from_hash(&txinput.pubkey)?;
            Hasher::new_with_items(&[(&txinput.txid).into(), (&self.output_hash).into()])
                .verify_signature(&txinput.sig, &pk)
                .map_err(|e| {
                    BlockChainError::TransactionValidation(format!("Invalid signature: {e}"))
                })?;
        }

        Ok(())
    }

    pub fn validate(&self, q: &mut QueryLayer) -> Result<()> {
        self.consistency_check()?;

        let mut total_input: u64 = 0;
        let mut total_output: u64 = 0;

        for txinput in &self.inputs {
            let txaddress = ECDSAPublicKey::from_hash(&txinput.pubkey)?.get_address();
            total_input += q.get_utxo(&txinput.txid, &txaddress)?;
        }

        for txoutput in &self.outputs {
            total_output += txoutput.amount;
        }

        if total_output > total_input {
            return Err(BlockChainError::TransactionValidation(
                "Output exceeds input".into(),
            ));
        }

        Ok(())
    }

    /// Validate using a BlockDB directly (avoids QueryLayer borrow issues).
    pub fn validate_with_blockdb(&self, blockdb: &mut BlockDB) -> Result<()> {
        crate::querylayer::validate_transaction(blockdb, self)
    }

    pub fn check_duplicates(&self, known_inputs: &mut HashSet<Hash>) -> Result<()> {
        for txinput in &self.inputs {
            txinput.consistency_check()?;

            let h = Hasher::new_with_items(&[(&txinput.txid).into(), (&txinput.pubkey).into()])
                .get_hash();

            if known_inputs.contains(&h) {
                return Err(BlockChainError::TransactionDuplicateInput(
                    "Duplicate transaction input found".into(),
                ));
            }
            known_inputs.insert(h);
        }
        Ok(())
    }
}
