/// Crypto tests — direct port of unit/test_crypto.py.
use stevecoin::crypto::{CryptHelper, ECDSAPrivateKey, ECDSAPublicKey, Hasher};

fn remove_if_exists(path: &str) {
    let _ = std::fs::remove_file(path);
}

#[test]
fn test_roundtrip_string() {
    let data = serde_json::json!("The cat sat on the mat");
    let (k, enc) = CryptHelper::encrypt_json(&data).unwrap();
    let decrypted = enc.decrypt_json(&k).unwrap();
    assert_eq!(data, decrypted, "decrypted data should match original");
}

#[test]
fn test_roundtrip_dict() {
    let data = serde_json::json!({"key": "value"});
    let (k, enc) = CryptHelper::encrypt_json(&data).unwrap();
    let decrypted = enc.decrypt_json(&k).unwrap();
    assert_eq!(data, decrypted, "decrypted data should match original");
}

#[test]
fn test_roundtrip_list() {
    let data = serde_json::json!(["hello", "one", "two", "three"]);
    let (k, enc) = CryptHelper::encrypt_json(&data).unwrap();
    let decrypted = enc.decrypt_json(&k).unwrap();
    assert_eq!(data, decrypted, "decrypted data should match original");
}

#[test]
fn test_ecdsa_sig() {
    let msg = "The cat sat on the mat";
    let key = ECDSAPrivateKey::generate();
    let sig = Hasher::new_with_message(msg.as_bytes()).sign(&key).unwrap();

    let pubkey = key.publickey();
    Hasher::new_with_message(msg.as_bytes())
        .verify_signature(&sig, &pubkey)
        .unwrap();
}

#[test]
fn test_ecdsa_sig_save_load() {
    let msg = "The cat sat on the mat";
    let key = ECDSAPrivateKey::generate();
    let sig = Hasher::new_with_message(msg.as_bytes()).sign(&key).unwrap();

    let password = "passphrase";
    let fnbase = "/tmp/stevecoin_test_keys";
    remove_if_exists(&format!("{fnbase}_private.pem"));
    remove_if_exists(&format!("{fnbase}_public.pem"));

    let (fnpriv, _) = key.write_key_pair(fnbase, password).unwrap();

    let key2 = ECDSAPrivateKey::from_file(&fnpriv, password).unwrap();
    let pubkey = key2.publickey();
    Hasher::new_with_message(msg.as_bytes())
        .verify_signature(&sig, &pubkey)
        .unwrap();

    // Cleanup
    remove_if_exists(&format!("{fnbase}_private.pem"));
    remove_if_exists(&format!("{fnbase}_public.pem"));
}

#[test]
fn test_ecdsa_serialise() {
    let msg = "The cat sat on the mat";
    let key = ECDSAPrivateKey::generate();
    let sig = Hasher::new_with_message(msg.as_bytes()).sign(&key).unwrap();

    let pk_str = key.to_hex_string();

    let key2 = ECDSAPrivateKey::from_string(&pk_str).unwrap();
    let pubkey = key2.publickey();
    Hasher::new_with_message(msg.as_bytes())
        .verify_signature(&sig, &pubkey)
        .unwrap();
}

#[test]
fn test_ecdsa_copy_pubkey() {
    let msg = "The cat sat on the mat";
    let key = ECDSAPrivateKey::generate();
    let sig = Hasher::new_with_message(msg.as_bytes()).sign(&key).unwrap();

    let pubkey1_hash = key.publickey().as_hash();
    let pubkey2 = ECDSAPublicKey::from_hash(&pubkey1_hash).unwrap();
    Hasher::new_with_message(msg.as_bytes())
        .verify_signature(&sig, &pubkey2)
        .unwrap();
}

#[test]
fn test_hasher() {
    let mut h = Hasher::new();
    h.update_str("hello");
    let digest = h.get_hash_clone().digest().to_vec();
    let hexdigest = h.get_hash().to_hex();
    assert_eq!(
        hex::encode(&digest),
        hexdigest,
        "hexdigest matches digest"
    );
}
