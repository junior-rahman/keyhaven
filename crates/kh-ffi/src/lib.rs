// crates/kh-ffi/src/lib.rs
use std::sync::{Arc, Mutex};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultError {
    #[error("the vault is locked")]
    Locked,
    #[error("wrong password or Secret Key")]
    BadCredentials,
}

#[derive(uniffi::Record)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub site: Option<String>,
    pub username: Option<String>,
}

/// The same Rust core the desktop app runs, exposed to Kotlin.
#[derive(uniffi::Object)]
pub struct Vault {
    unlocked: Mutex<bool>, // stands in for the real key store in this sketch
}

#[uniffi::export]
impl Vault {
    #[uniffi::constructor]
    pub fn open(path: String) -> Arc<Self> {
        let _ = path;
        Arc::new(Self { unlocked: Mutex::new(false) })
    }

    /// `vault_key` comes out of the Android Keystore after a biometric prompt.
    pub fn unlock_with_vault_key(&self, vault_key: Vec<u8>) -> Result<(), VaultError> {
        if vault_key.len() != 32 {
            return Err(VaultError::BadCredentials);
        }
        *self.unlocked.lock().unwrap() = true;
        Ok(())
    }

    pub fn search(&self, query: String) -> Result<Vec<ItemSummary>, VaultError> {
        if !*self.unlocked.lock().unwrap() {
            return Err(VaultError::Locked);
        }
        let _ = query;
        Ok(vec![])
    }

    pub fn lock(&self) {
        *self.unlocked.lock().unwrap() = false;
    }
}
