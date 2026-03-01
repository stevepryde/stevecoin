/// Cryptographic helpers — direct port of lib/crypto.py.
///
/// Provides Hash types, Hasher (SHA3-512), ECDSA key pairs (secp256k1),
/// AES-EAX encryption, and CryptoAddress (base58check).
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};

use aes::Aes256;
use digest::Digest;
use eax::aead::{AeadInPlace, KeyInit};
use eax::Eax;
use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::RngCore;
use ripemd::Ripemd160;
use sha3::{Sha3_256, Sha3_512};

use crate::errors::{BlockChainError, Result};

// ---------------------------------------------------------------------------
// Random bytes
// ---------------------------------------------------------------------------

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Hash types
// ---------------------------------------------------------------------------

/// Generic hash wrapper storing raw bytes.
/// Python equivalent: Hash / Hash512 / Hash256
#[derive(Clone, Eq)]
pub struct Hash {
    pub data: Vec<u8>,
    pub bits: usize,
}

impl Hash {
    pub fn new(input: &[u8], bits: usize) -> Result<Self> {
        let num_bytes = bits / 8;
        let data = if input.len() == num_bytes * 2 {
            // Hex-encoded
            hex::decode(input).map_err(|e| {
                BlockChainError::Crypto(format!("Invalid hex hash: {e}"))
            })?
        } else if input.len() == num_bytes {
            // Raw bytes
            input.to_vec()
        } else {
            return Err(BlockChainError::Crypto(format!(
                "Invalid hash length: got {}, expected {} or {}",
                input.len(),
                num_bytes,
                num_bytes * 2,
            )));
        };
        Ok(Hash { data, bits })
    }

    pub fn from_hex(hex_str: &str, bits: usize) -> Result<Self> {
        Self::new(hex_str.as_bytes(), bits)
    }

    pub fn serialise(&self) -> String {
        self.to_hex()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.data)
    }

    pub fn digest(&self) -> &[u8] {
        &self.data
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl std::hash::Hash for Hash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// Hash512 / Hash256 convenience constructors
// ---------------------------------------------------------------------------

/// 512-bit hash (SHA3-512 output size).
pub fn hash512(input: &[u8]) -> Result<Hash> {
    if input.is_empty() {
        // Match Python: blank input -> SHA3-512 of empty bytes
        let h = Hasher::new_with_message(b"");
        return Ok(h.get_hash());
    }
    Hash::new(input, 512)
}

pub fn hash512_from_hex(hex_str: &str) -> Result<Hash> {
    if hex_str.is_empty() {
        let h = Hasher::new_with_message(b"");
        return Ok(h.get_hash());
    }
    Hash::from_hex(hex_str, 512)
}

pub fn hash256(input: &[u8]) -> Result<Hash> {
    Hash::new(input, 256)
}

// ---------------------------------------------------------------------------
// basic_hash_check
// ---------------------------------------------------------------------------

pub fn basic_hash_check(h: &Hash) -> Result<()> {
    let s = h.to_hex();
    if s.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(BlockChainError::Crypto("Hash check failed".into()))
    }
}

// ---------------------------------------------------------------------------
// CryptoAddress — base58check wallet address
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq)]
pub struct CryptoAddress {
    pub address: String,
}

impl CryptoAddress {
    pub fn new(address: &str) -> Self {
        CryptoAddress {
            address: address.to_string(),
        }
    }

    pub fn serialise(&self) -> String {
        self.address.clone()
    }

    pub fn deserialise(data: &str) -> Self {
        CryptoAddress::new(data)
    }

    pub fn to_string_repr(&self) -> &str {
        &self.address
    }

    /// Validate that this is a proper base58check address.
    pub fn validate(&self) -> Result<()> {
        bs58::decode(&self.address)
            .with_check(None)
            .into_vec()
            .map_err(|e| {
                BlockChainError::TransactionValidation(format!(
                    "Invalid output address: {e}"
                ))
            })?;
        Ok(())
    }
}

impl PartialEq for CryptoAddress {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl std::hash::Hash for CryptoAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

impl PartialEq<str> for CryptoAddress {
    fn eq(&self, other: &str) -> bool {
        self.address == other
    }
}

// ---------------------------------------------------------------------------
// EncryptedData — AES-256-EAX encryption
// ---------------------------------------------------------------------------

pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}

impl EncryptedData {
    pub fn decrypt(&self, key: &Hash) -> Result<Vec<u8>> {
        let cipher = Eax::<Aes256>::new_from_slice(key.digest())
            .map_err(|e| BlockChainError::Crypto(format!("AES init failed: {e}")))?;

        let nonce = eax::aead::Nonce::<Eax<Aes256>>::from_slice(&self.nonce);
        let tag = eax::aead::Tag::<Eax<Aes256>>::from_slice(&self.tag);

        let mut buffer = self.encrypted_data.clone();
        cipher
            .decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
            .map_err(|e| BlockChainError::Crypto(format!("Decryption failed: {e}")))?;
        Ok(buffer)
    }

    pub fn decrypt_with_passphrase(&self, passphrase: &str) -> Result<Vec<u8>> {
        let key_bytes = Sha3_256::digest(passphrase.as_bytes());
        let key = hash256(&key_bytes)?;
        self.decrypt(&key)
    }

    pub fn decrypt_json(&self, key: &Hash) -> Result<serde_json::Value> {
        let plaintext = self.decrypt(key)?;
        let v = serde_json::from_slice(&plaintext)?;
        Ok(v)
    }

    pub fn write_to_file(&self, filename: &str, overwrite: bool) -> Result<()> {
        let mut f = if overwrite {
            File::create(filename)?
        } else {
            File::options()
                .write(true)
                .create_new(true)
                .open(filename)?
        };
        write_length_prefixed(&mut f, &self.nonce)?;
        write_length_prefixed(&mut f, &self.tag)?;
        write_length_prefixed(&mut f, &self.encrypted_data)?;
        Ok(())
    }

    pub fn read_from_file(filename: &str) -> Result<Self> {
        let mut f = File::open(filename)?;
        let nonce = read_length_prefixed(&mut f)?;
        let tag = read_length_prefixed(&mut f)?;
        let encrypted_data = read_length_prefixed(&mut f)?;
        Ok(EncryptedData {
            nonce,
            tag,
            encrypted_data,
        })
    }
}

fn write_length_prefixed(f: &mut File, data: &[u8]) -> Result<()> {
    let len = (data.len() as u64).to_le_bytes();
    f.write_all(&len)?;
    f.write_all(data)?;
    Ok(())
}

fn read_length_prefixed(f: &mut File) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 8];
    f.read_exact(&mut len_buf)?;
    let len = u64::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// CryptHelper — static encryption helpers
// ---------------------------------------------------------------------------

pub struct CryptHelper;

impl CryptHelper {
    pub fn encrypt(data: &[u8]) -> Result<(Hash, EncryptedData)> {
        let key = hash256(&random_bytes(32))?;
        let cipher = Eax::<Aes256>::new_from_slice(key.digest())
            .map_err(|e| BlockChainError::Crypto(format!("AES init failed: {e}")))?;

        let nonce_bytes = random_bytes(16);
        let nonce = eax::aead::Nonce::<Eax<Aes256>>::from_slice(&nonce_bytes);

        let mut buffer = data.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|e| BlockChainError::Crypto(format!("Encryption failed: {e}")))?;

        Ok((
            key,
            EncryptedData {
                nonce: nonce_bytes,
                tag: tag.to_vec(),
                encrypted_data: buffer,
            },
        ))
    }

    pub fn encrypt_json(data: &serde_json::Value) -> Result<(Hash, EncryptedData)> {
        let json_bytes = serde_json::to_vec(data)?;
        Self::encrypt(&json_bytes)
    }

    pub fn encrypt_with_passphrase(data: &[u8], passphrase: &str) -> Result<EncryptedData> {
        let key_bytes = Sha3_256::digest(passphrase.as_bytes());
        let cipher = Eax::<Aes256>::new_from_slice(&key_bytes)
            .map_err(|e| BlockChainError::Crypto(format!("AES init failed: {e}")))?;

        let nonce_bytes = random_bytes(16);
        let nonce = eax::aead::Nonce::<Eax<Aes256>>::from_slice(&nonce_bytes);

        let mut buffer = data.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|e| BlockChainError::Crypto(format!("Encryption failed: {e}")))?;

        Ok(EncryptedData {
            nonce: nonce_bytes,
            tag: tag.to_vec(),
            encrypted_data: buffer,
        })
    }
}

// ---------------------------------------------------------------------------
// ECDSAPublicKey — secp256k1 verifying key
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ECDSAPublicKey {
    key: VerifyingKey,
}

impl ECDSAPublicKey {
    /// Create from a Hash512 containing the raw 64-byte public key (x||y).
    pub fn from_hash(h: &Hash) -> Result<Self> {
        let raw = h.digest();
        if raw.len() != 64 {
            return Err(BlockChainError::KeyValidation(format!(
                "Expected 64-byte public key, got {}",
                raw.len()
            )));
        }
        // Prepend 0x04 for uncompressed SEC1 format
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(raw);
        let key = VerifyingKey::from_sec1_bytes(&uncompressed)
            .map_err(|e| BlockChainError::KeyValidation(format!("Invalid public key: {e}")))?;
        Ok(ECDSAPublicKey { key })
    }

    pub fn from_verifying_key(key: VerifyingKey) -> Self {
        ECDSAPublicKey { key }
    }

    /// Get the raw 64-byte public key as a Hash512.
    pub fn as_hash(&self) -> Hash {
        let point = self.key.to_encoded_point(false);
        let bytes = point.as_bytes();
        // Skip 0x04 prefix to get 64-byte x||y
        Hash {
            data: bytes[1..].to_vec(),
            bits: 512,
        }
    }

    /// Get PEM-encoded public key.
    pub fn as_pem(&self) -> String {
        // Simplified: just hex-encode for the port
        // The Python version uses ECDSA PEM format
        let point = self.key.to_encoded_point(false);
        hex::encode(point.as_bytes())
    }

    /// Derive the base58check wallet address.
    /// Uses SHA3-256 (not SHA-256, intentionally different from Bitcoin).
    pub fn get_address(&self) -> CryptoAddress {
        let raw_key = self.key.to_encoded_point(false);
        // Hash with SHA3-256 (not SHA-256)
        let sha3_hash = Sha3_256::digest(&raw_key.as_bytes()[1..]);
        // Then RIPEMD-160
        let ripe_hash = Ripemd160::digest(&sha3_hash);
        // Prepend version byte 0x00
        let mut payload = vec![0x00];
        payload.extend_from_slice(&ripe_hash);
        // base58check encode
        let address = bs58::encode(&payload).with_check().into_string();
        CryptoAddress::new(&address)
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

// ---------------------------------------------------------------------------
// ECDSAPrivateKey — secp256k1 signing key
// ---------------------------------------------------------------------------

pub struct ECDSAPrivateKey {
    key: SigningKey,
}

impl ECDSAPrivateKey {
    pub fn generate() -> Self {
        ECDSAPrivateKey {
            key: SigningKey::random(&mut rand::thread_rng()),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = SigningKey::from_slice(bytes)
            .map_err(|e| BlockChainError::KeyValidation(format!("Invalid private key: {e}")))?;
        Ok(ECDSAPrivateKey { key })
    }

    pub fn from_string(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| BlockChainError::KeyValidation(format!("Invalid hex: {e}")))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_file(filename: &str, passphrase: &str) -> Result<Self> {
        let encrypted = EncryptedData::read_from_file(filename)?;
        let key_hex = encrypted.decrypt_with_passphrase(passphrase)?;
        let key_bytes = hex::decode(&key_hex)
            .map_err(|e| BlockChainError::KeyValidation(format!("Invalid key data: {e}")))?;
        let key = SigningKey::from_slice(&key_bytes)
            .map_err(|e| BlockChainError::KeyValidation(format!("Invalid private key: {e}")))?;
        Ok(ECDSAPrivateKey { key })
    }

    pub fn publickey(&self) -> ECDSAPublicKey {
        ECDSAPublicKey::from_verifying_key(*self.key.verifying_key())
    }

    pub fn to_hex_string(&self) -> String {
        hex::encode(self.key.to_bytes())
    }

    /// Write key pair to files. Returns (private_filename, public_filename).
    pub fn write_key_pair(
        &self,
        filename_prefix: &str,
        passphrase: &str,
    ) -> Result<(String, String)> {
        if passphrase.len() < 8 {
            return Err(BlockChainError::Crypto(
                "Passphrase must be at least 8 characters".into(),
            ));
        }

        let fname_private = format!("{filename_prefix}_private.pem");
        let fname_public = format!("{filename_prefix}_public.pem");

        let key_hex = hex::encode(self.key.to_bytes());
        let encrypted =
            CryptHelper::encrypt_with_passphrase(key_hex.as_bytes(), passphrase)?;
        encrypted.write_to_file(&fname_private, false)?;

        let pem = self.publickey().as_pem();
        std::fs::write(&fname_public, pem)?;

        Ok((fname_private, fname_public))
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

// ---------------------------------------------------------------------------
// Hasher — SHA3-512 hasher with signing/verification
// ---------------------------------------------------------------------------

/// Wrapper around SHA3-512 that accumulates data and supports ECDSA signing.
///
/// Mirrors the Python Hasher class. Note: the Python `ecdsa` library internally
/// hashes the digest with SHA-256 before ECDSA signing (default for secp256k1).
/// k256 does the same when using the `Signer` trait, so behaviour matches.
pub struct Hasher {
    h: Sha3_512,
}

/// Things that can be fed into a Hasher.
pub enum Hashable<'a> {
    Bytes(&'a [u8]),
    Str(&'a str),
    HashRef(&'a Hash),
}

impl<'a> From<&'a [u8]> for Hashable<'a> {
    fn from(b: &'a [u8]) -> Self {
        Hashable::Bytes(b)
    }
}

impl<'a> From<&'a str> for Hashable<'a> {
    fn from(s: &'a str) -> Self {
        Hashable::Str(s)
    }
}

impl<'a> From<&'a Hash> for Hashable<'a> {
    fn from(h: &'a Hash) -> Self {
        Hashable::HashRef(h)
    }
}

impl<'a> From<&'a CryptoAddress> for Hashable<'a> {
    fn from(a: &'a CryptoAddress) -> Self {
        Hashable::Str(&a.address)
    }
}

impl Hasher {
    pub fn new() -> Self {
        Hasher { h: Sha3_512::new() }
    }

    pub fn new_with_message(msg: &[u8]) -> Self {
        let mut hasher = Self::new();
        hasher.h.update(msg);
        hasher
    }

    pub fn new_with_items(items: &[Hashable<'_>]) -> Self {
        let mut hasher = Self::new();
        for item in items {
            hasher.update_one(item);
        }
        hasher
    }

    pub fn update_one(&mut self, item: &Hashable<'_>) {
        match item {
            Hashable::Bytes(b) => self.h.update(b),
            Hashable::Str(s) => self.h.update(s.as_bytes()),
            Hashable::HashRef(h) => self.h.update(h.digest()),
        }
    }

    pub fn update_hash(&mut self, h: &Hash) {
        self.h.update(h.digest());
    }

    pub fn update_str(&mut self, s: &str) {
        self.h.update(s.as_bytes());
    }

    pub fn update_bytes(&mut self, b: &[u8]) {
        self.h.update(b);
    }

    pub fn get_hash(self) -> Hash {
        let result = self.h.finalize();
        Hash {
            data: result.to_vec(),
            bits: 512,
        }
    }

    /// Clone the internal state and produce a hash without consuming self.
    pub fn get_hash_clone(&self) -> Hash {
        let h = self.h.clone();
        let result = h.finalize();
        Hash {
            data: result.to_vec(),
            bits: 512,
        }
    }

    /// Sign the hash with the private key.
    ///
    /// The k256 `Signer` trait hashes the message with SHA-256 internally,
    /// matching the Python ecdsa library's default behaviour for secp256k1.
    pub fn sign(self, private_key: &ECDSAPrivateKey) -> Result<Hash> {
        let digest = self.h.finalize();
        let sig: Signature = k256::ecdsa::signature::Signer::sign(
            private_key.signing_key(),
            &digest,
        );
        let sig_bytes = sig.to_bytes();
        Ok(Hash {
            data: sig_bytes.to_vec(),
            bits: 512,
        })
    }

    /// Verify a signature against the public key.
    pub fn verify_signature(
        self,
        sig: &Hash,
        public_key: &ECDSAPublicKey,
    ) -> Result<()> {
        let digest = self.h.finalize();
        let signature = Signature::from_slice(sig.digest())
            .map_err(|e| BlockChainError::KeyValidation(format!("Invalid signature: {e}")))?;

        // k256 Verifier hashes the data with SHA-256 internally
        public_key
            .verifying_key()
            .verify(&digest, &signature)
            .map_err(|e| BlockChainError::KeyValidation(format!("Signature verification failed: {e}")))?;
        Ok(())
    }
}
