-- crates/kh-store/migrations/001_init.sql
PRAGMA journal_mode = WAL;

CREATE TABLE vault (
  id          TEXT PRIMARY KEY,   -- UUIDv7
  format      INTEGER NOT NULL,   -- 1
  kdf         TEXT NOT NULL,      -- KdfParams JSON (public by design)
  wrapped_vk  TEXT NOT NULL,      -- Sealed: vault key under the KEK
  recovery_vk TEXT NOT NULL,      -- Sealed: vault key under the Recovery Key
  device_vk   TEXT,               -- Sealed: vault key under this device's Windows Hello key (quick unlock)
  created_at  TEXT NOT NULL
) STRICT;

CREATE TABLE item (
  id          TEXT PRIMARY KEY,   -- UUIDv7; says nothing about the content
  vault_id    TEXT NOT NULL REFERENCES vault(id),
  ver         INTEGER NOT NULL,   -- the item's own version: +1 on every edit, bound into the ciphertext
  seq         INTEGER,            -- the sync server's change number; NULL until uploaded
  wrapped_key TEXT NOT NULL,      -- Sealed: item key under the vault key
  body        TEXT NOT NULL,      -- Sealed: padded ItemPayload JSON
  deleted     INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
  updated_at  TEXT NOT NULL
) STRICT;
CREATE INDEX item_unsynced ON item(vault_id) WHERE seq IS NULL;

CREATE TABLE sealed_doc (         -- settings, paired clients, and the manifest
  name TEXT PRIMARY KEY,
  ver  INTEGER NOT NULL,
  body TEXT NOT NULL              -- Sealed JSON, so tampering on disk is detected
) STRICT;

CREATE TABLE audit (
  seq  INTEGER PRIMARY KEY,
  at   TEXT NOT NULL,
  body TEXT NOT NULL,             -- Sealed entry
  mac  TEXT NOT NULL              -- keyed BLAKE2b over the previous mac and this body
) STRICT;
