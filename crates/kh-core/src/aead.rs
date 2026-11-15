// crates/kh-crypto/src/aead.rs
use crate::keys::{CryptoError, Key};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Sealed {
    pub v: u8,     // format version, 1
    pub n: String, // 24-byte nonce, base64url
    pub c: String, // ciphertext + tag, base64url
}

pub fn seal(key: &Key, plaintext: &[u8], aad: &str) -> Sealed {
    let mut nonce = [0u8; 24]; // large enough to pick at random, so there is no counter to manage
    getrandom::fill(&mut nonce).expect("operating system randomness");
    seal_with_nonce(key, &nonce, plaintext, aad)
}

pub(crate) fn seal_with_nonce(key: &Key, nonce: &[u8; 24], plaintext: &[u8], aad: &str) -> Sealed {
    let ct = XChaCha20Poly1305::new(&(**key).into())
        .encrypt(&XNonce::from(*nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
        .expect("in-memory encryption does not fail");
    Sealed { v: 1, n: B64.encode(nonce), c: B64.encode(ct) }
}

pub fn open(key: &Key, sealed: &Sealed, aad: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let nonce: [u8; 24] = B64.decode(&sealed.n).ok().and_then(|n| n.try_into().ok()).ok_or(CryptoError::Tamper)?;
    let ct = B64.decode(&sealed.c).map_err(|_| CryptoError::Tamper)?;
    if sealed.v != 1 {
        return Err(CryptoError::Tamper);
    }
    XChaCha20Poly1305::new(&(**key).into())
        .decrypt(&XNonce::from(nonce), Payload { msg: &ct, aad: aad.as_bytes() })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Tamper)
}

/// Associated data ties each blob to its place and version: a swapped, copied or relabelled row fails to open.
pub mod aad {
    pub fn vault_key(vault: &str) -> String {
        format!("kh/v1/vault-key/{vault}")
    }
    pub fn item_key(vault: &str, item: &str) -> String {
        format!("kh/v1/item-key/{vault}/{item}")
    }
    pub fn item_body(vault: &str, item: &str, ver: u64) -> String {
        format!("kh/v1/item/{vault}/{item}/{ver}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../test-vectors/v1.json")).unwrap()
    }
    fn key(hex_str: &str) -> Key {
        Zeroizing::new(hex::decode(hex_str).unwrap().try_into().unwrap())
    }

    #[test]
    fn kdf_matches_libsodium() {
        let v = vectors();
        let sk: [u8; 16] = hex::decode(v["secret_key"].as_str().unwrap()).unwrap().try_into().unwrap();
        for case in v["kdf"].as_array().unwrap() {
            let p = KdfParams {
                alg: "argon2id13".into(),
                passes: case["passes"].as_u64().unwrap() as u32,
                memory_kib: case["memory_kib"].as_u64().unwrap() as u32,
                salt: v["salt_b64"].as_str().unwrap().into(),
            };
            let t = std::time::Instant::now();
            let master = stretch_and_mix(case["password"].as_str().unwrap(), &sk, &p).unwrap();
            eprintln!("argon2id {} MiB x{}: {:?}", p.memory_kib / 1024, p.passes, t.elapsed());
            assert_eq!(hex::encode(&master[..]), case["master"].as_str().unwrap());
            assert_eq!(hex::encode(&derive_subkey(&master, SUBKEY_AUTH, VAULT_CONTEXT)[..]), case["auth"].as_str().unwrap());
            assert_eq!(hex::encode(&derive_subkey(&master, SUBKEY_KEK, VAULT_CONTEXT)[..]), case["kek"].as_str().unwrap());
        }
    }

    #[test]
    fn weak_parameters_are_refused() {
        let p = KdfParams { alg: "argon2id13".into(), passes: 1, memory_kib: 8, salt: "EBESExQVFhcYGRobHB0eHw".into() };
        assert!(matches!(derive_master_key("x", &[0; 16], &p), Err(CryptoError::Params)));
    }

    #[test]
    fn aead_matches_libsodium_and_fails_closed() {
        let v = vectors();
        let a = &v["aead"];
        let k = key(a["key"].as_str().unwrap());
        let sealed: Sealed = serde_json::from_value(a["sealed"].clone()).unwrap();
        let aad = a["aad"].as_str().unwrap();
        // 1. Rust opens what libsodium sealed
        assert_eq!(&open(&k, &sealed, aad).unwrap()[..], a["plaintext"].as_str().unwrap().as_bytes());
        // 2. Rust seals byte-for-byte what libsodium sealed, given the same nonce
        let nonce: [u8; 24] = B64.decode(a["nonce_b64"].as_str().unwrap()).unwrap().try_into().unwrap();
        assert_eq!(seal_with_nonce(&k, &nonce, a["plaintext"].as_str().unwrap().as_bytes(), aad), sealed);
        // 3. any change fails closed
        assert!(open(&k, &sealed, &aad.replace("/7", "/8")).is_err()); // another version
        assert!(open(&key(&"00".repeat(32)), &sealed, aad).is_err()); // another key
        let mut flipped = sealed.clone();
        flipped.c = flipped.c.replacen('P', "Q", 1);
        assert!(open(&k, &flipped, aad).is_err()); // a changed byte
        // 4. fresh nonces differ
        assert_ne!(seal(&k, b"x", aad).n, seal(&k, b"x", aad).n);
    }
}
