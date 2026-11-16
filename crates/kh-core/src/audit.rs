// crates/kh-store/src/audit.rs
use crate::aead::seal;
use crate::keys::{Key, derive_subkey};
use blake2::Blake2bMac;
use blake2::digest::{KeyInit, Mac, consts::U32};
use rusqlite::{Connection, params};
use subtle::ConstantTimeEq;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The newest row's number and MAC. The core stores it in the sealed manifest after every write.
#[derive(Clone, Debug, PartialEq)]
pub struct Head {
    pub seq: i64,
    pub mac: String,
}

#[derive(Debug, PartialEq)]
pub enum AuditError {
    BrokenAt(i64), // a row was edited, reordered or removed from the middle
    Truncated,     // rows were cut off the end
    Db(String),
}

pub struct AuditLog<'a> {
    db: &'a Connection,
    seal_key: Key,
    mac_key: Key,
}

impl<'a> AuditLog<'a> {
    pub fn new(db: &'a Connection, vault_key: &Key) -> Self {
        Self {
            db,
            seal_key: derive_subkey(vault_key, 1, b"KHAUDIT1"),
            mac_key: derive_subkey(vault_key, 2, b"KHAUDIT1"),
        }
    }

    fn link(&self, prev: &str, body: &str) -> String {
        let mut mac = Blake2bMac::<U32>::new_from_slice(&self.mac_key[..]).expect("32-byte key");
        mac.update(prev.as_bytes());
        mac.update(body.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Appends one entry. Entries carry ids, tool names and decisions; never a secret value.
    pub fn write(&self, at: &str, entry: &serde_json::Value) -> Result<Head, AuditError> {
        let db_err = |e: rusqlite::Error| AuditError::Db(e.to_string());
        let body = serde_json::to_string(&seal(&self.seal_key, entry.to_string().as_bytes(), "kh/v1/audit"))
            .expect("plain struct");
        let prev: Option<String> = self
            .db
            .query_row("SELECT mac FROM audit ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .map(Some)
            .or_else(|e| if e == rusqlite::Error::QueryReturnedNoRows { Ok(None) } else { Err(e) })
            .map_err(db_err)?;
        let mac = self.link(prev.as_deref().unwrap_or(GENESIS), &body);
        self.db
            .execute("INSERT INTO audit (at, body, mac) VALUES (?1, ?2, ?3)", params![at, body, mac])
            .map_err(db_err)?;
        Ok(Head { seq: self.db.last_insert_rowid(), mac })
    }

    /// Walks the whole chain, then compares its end with the head saved in the sealed manifest.
    pub fn verify(&self, expected: Option<&Head>) -> Result<(), AuditError> {
        let db_err = |e: rusqlite::Error| AuditError::Db(e.to_string());
        let mut stmt = self.db.prepare("SELECT seq, body, mac FROM audit ORDER BY seq").map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .map_err(db_err)?;
        let mut prev = GENESIS.to_string();
        let mut last = None;
        for row in rows {
            let (seq, body, mac) = row.map_err(db_err)?;
            if self.link(&prev, &body).as_bytes().ct_eq(mac.as_bytes()).unwrap_u8() != 1 {
                return Err(AuditError::BrokenAt(seq));
            }
            last = Some(Head { seq, mac: mac.clone() });
            prev = mac;
        }
        if last.as_ref() == expected { Ok(()) } else { Err(AuditError::Truncated) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn chain_detects_edits_and_truncation() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE audit (seq INTEGER PRIMARY KEY, at TEXT NOT NULL, body TEXT NOT NULL, mac TEXT NOT NULL) STRICT").unwrap();
        let log = AuditLog::new(&db, &Zeroizing::new([7u8; 32]));
        assert_eq!(log.verify(None), Ok(()));
        let mut head = None;
        for n in 0..5 {
            head = Some(log.write("2026-11-10T00:00:00Z", &serde_json::json!({ "type": "mcp.call", "n": n })).unwrap());
        }
        assert_eq!(log.verify(head.as_ref()), Ok(()));

        db.execute("DELETE FROM audit WHERE seq = 5", []).unwrap(); // cut the newest row off
        assert_eq!(log.verify(head.as_ref()), Err(AuditError::Truncated));

        db.execute("UPDATE audit SET body = (SELECT body FROM audit WHERE seq = 1) WHERE seq = 3", []).unwrap();
        assert_eq!(log.verify(head.as_ref()), Err(AuditError::BrokenAt(3)));
    }
}
