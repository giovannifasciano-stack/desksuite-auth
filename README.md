# desksuite-auth
Porta di accesso unica di DeskSuite (Cloudflare Worker).
- `worker.min.js` — bundle deployato (passkey WebAuthn + email/password + codice recupero, cookie JWT su .desksuite.cloud)
- `src/` — sorgente (worker.js, lib.js, page.js)
- `schema.sql` — schema del database D1 `desksuite-auth`
Registrazione chiusa dopo il primo account. Freno ai tentativi. PBKDF2 100k.
