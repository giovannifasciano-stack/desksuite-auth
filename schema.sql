-- DeskSuite — porta di accesso unica. Database D1 "desksuite-auth".
-- Nessun dato dei gestionali qui: solo identità e accesso.

CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT UNIQUE NOT NULL,
  pwd_hash   TEXT NOT NULL,
  pwd_salt   TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- passkey / WebAuthn: una riga per dispositivo registrato
CREATE TABLE IF NOT EXISTS credentials (
  id          TEXT PRIMARY KEY,          -- credential ID (base64url)
  user_id     INTEGER NOT NULL,
  public_key  TEXT NOT NULL,             -- chiave pubblica (base64url)
  counter     INTEGER NOT NULL DEFAULT 0,
  transports  TEXT,                      -- JSON array (es. ["internal","hybrid"])
  name        TEXT,                      -- etichetta dispositivo ("iPhone di Giovanni")
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cred_user ON credentials(user_id);

-- codice di recupero offline: monouso, salvato solo come impronta
CREATE TABLE IF NOT EXISTS recovery (
  user_id    INTEGER NOT NULL,
  code_hash  TEXT NOT NULL,
  used_at    TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- sfide WebAuthn in attesa (durata brevissima), recuperate tramite cookie ds_chal
CREATE TABLE IF NOT EXISTS challenges (
  id         TEXT PRIMARY KEY,           -- id casuale, tenuto nel cookie ds_chal
  challenge  TEXT NOT NULL,              -- challenge base64url
  kind       TEXT NOT NULL,             -- 'reg' | 'auth'
  expires_at INTEGER NOT NULL            -- epoch secondi
);

-- freno ai tentativi (rate limit): 5 tentativi / 15 minuti per identità
CREATE TABLE IF NOT EXISTS throttle (
  ident    TEXT PRIMARY KEY,            -- es. 'login:<ip>'
  count    INTEGER NOT NULL,
  reset_at INTEGER NOT NULL              -- epoch secondi
);
