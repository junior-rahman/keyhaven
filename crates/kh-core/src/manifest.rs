// crates/kh-store/src/manifest.rs
use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One sealed document that lists the current version and hash of every row.
/// It is rewritten in the same SQLite transaction as the row it describes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub counter: u64,                    // +1 on every write; devices and the sync server remember the highest seen
    pub rows: BTreeMap<String, RowMark>, // item ids and sealed-document names
    pub audit_head: Option<(i64, String)>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RowMark {
    pub ver: u64,
    pub hash: String, // BLAKE2b-256 of the row's sealed body
}

#[derive(Debug, PartialEq)]
pub enum RowCheck {
    Current,
    RolledBack, // an older sealed copy was put back
    Unknown,    // a row the manifest has never seen
}

pub fn body_hash(sealed_body: &str) -> String {
    hex::encode(Blake2b::<U32>::digest(sealed_body.as_bytes()))
}

impl Manifest {
    pub fn record(&mut self, id: &str, ver: u64, sealed_body: &str) {
        self.counter += 1;
        self.rows.insert(id.to_string(), RowMark { ver, hash: body_hash(sealed_body) });
    }

    pub fn check(&self, id: &str, ver: u64, sealed_body: &str) -> RowCheck {
        match self.rows.get(id) {
            None => RowCheck::Unknown,
            Some(mark) if mark.ver == ver && mark.hash == body_hash(sealed_body) => RowCheck::Current,
            Some(_) => RowCheck::RolledBack,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{aad, open, seal};
    use zeroize::Zeroizing;

    #[test]
    fn an_old_row_put_back_on_disk_is_caught() {
        let item_key = Zeroizing::new([9u8; 32]);
        let (vault, item) = ("v1", "i1");
        let mut manifest = Manifest::default();

        // version 1: visible to AI; version 2: you turned that off
        let v1 = serde_json::to_string(&seal(&item_key, br#"{"ai":{"visible":true}}"#, &aad::item_body(vault, item, 1))).unwrap();
        manifest.record(item, 1, &v1);
        let v2 = serde_json::to_string(&seal(&item_key, br#"{"ai":{"visible":false}}"#, &aad::item_body(vault, item, 2))).unwrap();
        manifest.record(item, 2, &v2);
        assert_eq!(manifest.check(item, 2, &v2), RowCheck::Current);

        // an attacker restores the old row, with its old version number so that it still decrypts
        assert!(open(&item_key, &serde_json::from_str(&v1).unwrap(), &aad::item_body(vault, item, 1)).is_ok());
        assert_eq!(manifest.check(item, 1, &v1), RowCheck::RolledBack);
        // relabelling the old body as version 2 does not decrypt at all
        assert!(open(&item_key, &serde_json::from_str(&v1).unwrap(), &aad::item_body(vault, item, 2)).is_err());
        assert_eq!(manifest.check("planted", 1, &v1), RowCheck::Unknown);
    }
}
