// crates/kh-crypto/src/keys.rs
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use blake2::Blake2bMac;
use blake2::digest::{KeyInit, Mac, consts::U32};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Every key lives in a buffer that is wiped when it is dropped.
pub type Key = Zeroizing<[u8; 32]>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("bad parameters")]
    Params,
    #[error("wrong key, wrong associated data, or modified ciphertext")]
    Tamper,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub alg: String,     // "argon2id13"
    pub passes: u32,     // 3
    pub memory_kib: u32, // 262_144 = 256 MiB
    pub salt: String,    // base64url, 16 bytes; public by design
}

/// Both secrets are required: Argon2id(password), then BLAKE2b keyed by the Secret Key.
pub fn derive_master_key(password: &str, secret_key: &[u8; 16], p: &KdfParams) -> Result<Key, CryptoError> {
    if p.alg != "argon2id13" || p.memory_kib < 65_536 || p.passes < 3 {
        return Err(CryptoError::Params); // never accept parameters weaker than the floor
    }
    stretch_and_mix(password, secret_key, p)
}

pub(crate) fn stretch_and_mix(password: &str, secret_key: &[u8; 16], p: &KdfParams) -> Result<Key, CryptoError> {
    let salt = B64.decode(&p.salt).map_err(|_| CryptoError::Params)?;
    let params = Params::new(p.memory_kib, p.passes, 1, Some(32)).map_err(|_| CryptoError::Params)?;
    let password: Zeroizing<String> = Zeroizing::new(password.nfkc().collect());
    let mut stretched = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, &mut *stretched)
        .map_err(|_| CryptoError::Params)?;
    let mut mac = Blake2bMac::<U32>::new_from_slice(secret_key).map_err(|_| CryptoError::Params)?;
    mac.update(&*stretched);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

pub const SUBKEY_AUTH: u64 = 1; // logs in to the sync server; cannot decrypt anything
pub const SUBKEY_KEK: u64 = 2; // unwraps the vault key

/// Same construction as libsodium's crypto_kdf, so the two implementations can be cross-checked.
pub fn derive_subkey(parent: &Key, id: u64, context: &[u8; 8]) -> Key {
    let mut salt = [0u8; 16];
    salt[..8].copy_from_slice(&id.to_le_bytes());
    let mut persona = [0u8; 16];
    persona[..8].copy_from_slice(context);
    let mac = Blake2bMac::<U32>::new_with_salt_and_personal(Some(&parent[..]), &salt, &persona).expect("fixed sizes");
    Zeroizing::new(mac.finalize().into_bytes().into())
}

pub const VAULT_CONTEXT: &[u8; 8] = b"KHVAULT1";
