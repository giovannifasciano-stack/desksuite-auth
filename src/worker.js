// DeskSuite — porta di accesso unica (Worker).
// Emette un cookie di sessione JWT su .desksuite.cloud, condiviso da tutte le app.
// Due ingressi: passkey (WebAuthn) e email+password. Codice di recupero offline.
// Registrazione chiusa dopo il primo account. Freno ai tentativi.

import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server';

import {
  hashPassword, verifyPassword, passwordProblem,
  signJWT, verifyJWT,
  makeSessionCookie, clearSessionCookie, readCookie, COOKIE_NAME,
  generateRecoveryCode, hashRecovery,
  b64uFromBytes, bytesFromB64u,
} from './lib.js';

import { LOGIN_HTML } from './page.js';

const RP_ID = 'desksuite.cloud';
const RP_NAME = 'DeskSuite';
const EXPECTED_ORIGINS = [
  'https://auth.desksuite.cloud',
  'https://desksuite.cloud',
  'https://hub.desksuite.cloud',
];
const SESSION_TTL = 604800; // 7 giorni
const CHAL_TTL = 300;       // 5 minuti
const RL_MAX = 5;           // tentativi
const RL_WINDOW = 900;      // 15 minuti
const CHAL_COOKIE = 'ds_chal';

const now = () => Math.floor(Date.now() / 1000);
const json = (obj, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders },
  });

function clientId(request) {
  return request.headers.get('CF-Connecting-IP') || 'anon';
}

// ---------- freno tentativi ----------
async function throttleHit(env, ident) {
  const t = now();
  const row = await env.DB.prepare('SELECT count, reset_at FROM throttle WHERE ident=?').bind(ident).first();
  if (!row || row.reset_at < t) {
    await env.DB.prepare(
      'INSERT INTO throttle (ident,count,reset_at) VALUES (?,?,?) ' +
      'ON CONFLICT(ident) DO UPDATE SET count=1, reset_at=excluded.reset_at'
    ).bind(ident, 1, t + RL_WINDOW).run();
    return { blocked: false, remaining: RL_MAX - 1 };
  }
  if (row.count >= RL_MAX) return { blocked: true, retryAfter: row.reset_at - t };
  await env.DB.prepare('UPDATE throttle SET count=count+1 WHERE ident=?').bind(ident).run();
  return { blocked: false, remaining: RL_MAX - row.count - 1 };
}
async function throttleClear(env, ident) {
  await env.DB.prepare('DELETE FROM throttle WHERE ident=?').bind(ident).run();
}

// ---------- utenti / sessione ----------
async function getUser(env) {
  // suite a utente singolo: c'è al più un account
  return env.DB.prepare('SELECT * FROM users ORDER BY id LIMIT 1').first();
}
async function sessionUser(env, request) {
  const tok = readCookie(request, COOKIE_NAME);
  if (!tok) return null;
  const payload = await verifyJWT(tok, env.JWT_SECRET);
  if (!payload) return null;
  const u = await getUser(env);
  if (!u || u.email !== payload.sub) return null;
  return u;
}
async function issueSession(env, user) {
  const jwt = await signJWT({ sub: user.email }, env.JWT_SECRET, SESSION_TTL);
  return makeSessionCookie(jwt, SESSION_TTL);
}

// ---------- challenge WebAuthn ----------
async function saveChallenge(env, challenge, kind) {
  const id = b64uFromBytes(crypto.getRandomValues(new Uint8Array(18)));
  await env.DB.prepare('INSERT INTO challenges (id,challenge,kind,expires_at) VALUES (?,?,?,?)')
    .bind(id, challenge, kind, now() + CHAL_TTL).run();
  return id;
}
async function takeChallenge(env, request, kind) {
  const id = readCookie(request, CHAL_COOKIE);
  if (!id) return null;
  const row = await env.DB.prepare('SELECT challenge,kind,expires_at FROM challenges WHERE id=?').bind(id).first();
  await env.DB.prepare('DELETE FROM challenges WHERE id=?').bind(id).run(); // monouso
  if (!row || row.kind !== kind || row.expires_at < now()) return null;
  return row.challenge;
}
function chalCookie(id) {
  return `${CHAL_COOKIE}=${id}; Domain=.desksuite.cloud; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${CHAL_TTL}`;
}

// ================= handler =================
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const m = request.method;

    // pagina di login (qualsiasi percorso non-API)
    if (m === 'GET' && !path.startsWith('/api') && !path.startsWith('/passkey') &&
        !['/me', '/login', '/register', '/logout', '/recover'].includes(path)) {
      return new Response(LOGIN_HTML, {
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow' },
      });
    }

    try {
      // ---- stato ----
      if (path === '/me' && m === 'GET') {
        const account = await getUser(env);
        const u = await sessionUser(env, request);
        let hasPasskey = false;
        if (account) {
          const c = await env.DB.prepare('SELECT COUNT(*) n FROM credentials WHERE user_id=?').bind(account.id).first();
          hasPasskey = (c?.n || 0) > 0;
        }
        return json({ authenticated: !!u, email: u?.email || null, hasAccount: !!account, hasPasskey });
      }

      // ---- primo avvio: crea l'unico account (registrazione chiusa dopo) ----
      if (path === '/register' && m === 'POST') {
        const existing = await getUser(env);
        if (existing) return json({ error: 'Registrazione chiusa.' }, 403);
        const { email, password } = await request.json();
        if (!email || !/^\S+@\S+\.\S+$/.test(email)) return json({ error: 'Email non valida.' }, 400);
        const pwProblem = passwordProblem(password);
        if (pwProblem) return json({ error: pwProblem }, 400);
        const { hash, salt } = await hashPassword(password);
        const res = await env.DB.prepare('INSERT INTO users (email,pwd_hash,pwd_salt) VALUES (?,?,?)')
          .bind(email.toLowerCase(), hash, salt).run();
        const userId = res.meta.last_row_id;
        const recovery = generateRecoveryCode();
        await env.DB.prepare('INSERT INTO recovery (user_id,code_hash) VALUES (?,?)')
          .bind(userId, await hashRecovery(recovery)).run();
        const cookie = await issueSession(env, { email: email.toLowerCase() });
        return json({ ok: true, recovery }, 200, { 'Set-Cookie': cookie });
      }

      // ---- login password ----
      if (path === '/login' && m === 'POST') {
        const ident = 'login:' + clientId(request);
        const rl = await throttleHit(env, ident);
        if (rl.blocked) return json({ error: `Troppi tentativi. Riprova tra ${Math.ceil(rl.retryAfter / 60)} minuti.` }, 429);
        const { email, password } = await request.json();
        const u = await getUser(env);
        const ok = u && u.email === String(email || '').toLowerCase() &&
                   await verifyPassword(password || '', u.pwd_salt, u.pwd_hash);
        if (!ok) return json({ error: 'Email o password non corretti.' }, 401);
        await throttleClear(env, ident);
        const cookie = await issueSession(env, u);
        return json({ ok: true }, 200, { 'Set-Cookie': cookie });
      }

      // ---- logout ----
      if (path === '/logout' && m === 'POST') {
        return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
      }

      // ---- recupero con codice offline ----
      if (path === '/recover' && m === 'POST') {
        const ident = 'recover:' + clientId(request);
        const rl = await throttleHit(env, ident);
        if (rl.blocked) return json({ error: `Troppi tentativi. Riprova tra ${Math.ceil(rl.retryAfter / 60)} minuti.` }, 429);
        const { code, newPassword } = await request.json();
        const u = await getUser(env);
        if (!u) return json({ error: 'Nessun account.' }, 400);
        const h = await hashRecovery(code || '');
        const row = await env.DB.prepare('SELECT rowid,used_at FROM recovery WHERE user_id=? AND code_hash=?')
          .bind(u.id, h).first();
        if (!row || row.used_at) return json({ error: 'Codice non valido o già usato.' }, 401);
        await env.DB.prepare('UPDATE recovery SET used_at=datetime(\'now\') WHERE rowid=?').bind(row.rowid).run();
        if (newPassword) {
          const pwProblem = passwordProblem(newPassword);
          if (pwProblem) return json({ error: pwProblem }, 400);
          const { hash, salt } = await hashPassword(newPassword);
          await env.DB.prepare('UPDATE users SET pwd_hash=?, pwd_salt=? WHERE id=?').bind(hash, salt, u.id).run();
        }
        await throttleClear(env, ident);
        const cookie = await issueSession(env, u);
        return json({ ok: true }, 200, { 'Set-Cookie': cookie });
      }

      // ---- passkey: inizio registrazione (serve sessione attiva) ----
      if (path === '/passkey/register/options' && m === 'POST') {
        const u = await sessionUser(env, request);
        if (!u) return json({ error: 'Non autenticato.' }, 401);
        const existing = await env.DB.prepare('SELECT id,transports FROM credentials WHERE user_id=?').bind(u.id).all();
        const opts = await generateRegistrationOptions({
          rpName: RP_NAME, rpID: RP_ID,
          userName: u.email,
          userID: new TextEncoder().encode(String(u.id)),
          attestationType: 'none',
          excludeCredentials: (existing.results || []).map(c => ({
            id: c.id, transports: c.transports ? JSON.parse(c.transports) : undefined,
          })),
          authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        });
        const chalId = await saveChallenge(env, opts.challenge, 'reg');
        return json(opts, 200, { 'Set-Cookie': chalCookie(chalId) });
      }

      // ---- passkey: completamento registrazione ----
      if (path === '/passkey/register/verify' && m === 'POST') {
        const u = await sessionUser(env, request);
        if (!u) return json({ error: 'Non autenticato.' }, 401);
        const expectedChallenge = await takeChallenge(env, request, 'reg');
        if (!expectedChallenge) return json({ error: 'Sfida scaduta, riprova.' }, 400);
        const { response, label } = await request.json();
        const v = await verifyRegistrationResponse({
          response, expectedChallenge, expectedOrigin: EXPECTED_ORIGINS, expectedRPID: RP_ID,
        });
        if (!v.verified || !v.registrationInfo) return json({ error: 'Registrazione passkey fallita.' }, 400);
        const cr = v.registrationInfo.credential;
        await env.DB.prepare(
          'INSERT OR REPLACE INTO credentials (id,user_id,public_key,counter,transports,name) VALUES (?,?,?,?,?,?)'
        ).bind(cr.id, u.id, b64uFromBytes(cr.publicKey), cr.counter,
               JSON.stringify(cr.transports || []), label || 'Dispositivo').run();
        return json({ ok: true });
      }

      // ---- passkey: inizio accesso (discoverable, nessun allowCredentials) ----
      if (path === '/passkey/login/options' && m === 'POST') {
        const opts = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: 'preferred' });
        const chalId = await saveChallenge(env, opts.challenge, 'auth');
        return json(opts, 200, { 'Set-Cookie': chalCookie(chalId) });
      }

      // ---- passkey: completamento accesso ----
      if (path === '/passkey/login/verify' && m === 'POST') {
        const ident = 'pk:' + clientId(request);
        const rl = await throttleHit(env, ident);
        if (rl.blocked) return json({ error: `Troppi tentativi. Riprova tra ${Math.ceil(rl.retryAfter / 60)} minuti.` }, 429);
        const expectedChallenge = await takeChallenge(env, request, 'auth');
        if (!expectedChallenge) return json({ error: 'Sfida scaduta, riprova.' }, 400);
        const { response } = await request.json();
        const cred = await env.DB.prepare('SELECT * FROM credentials WHERE id=?').bind(response.id).first();
        if (!cred) return json({ error: 'Passkey non riconosciuta.' }, 401);
        const v = await verifyAuthenticationResponse({
          response, expectedChallenge, expectedOrigin: EXPECTED_ORIGINS, expectedRPID: RP_ID,
          credential: {
            id: cred.id,
            publicKey: bytesFromB64u(cred.public_key),
            counter: cred.counter,
            transports: cred.transports ? JSON.parse(cred.transports) : undefined,
          },
          requireUserVerification: false,
        });
        if (!v.verified) return json({ error: 'Accesso passkey fallito.' }, 401);
        await env.DB.prepare('UPDATE credentials SET counter=? WHERE id=?')
          .bind(v.authenticationInfo.newCounter, cred.id).run();
        await throttleClear(env, ident);
        const u = await getUser(env);
        const cookie = await issueSession(env, u);
        return json({ ok: true }, 200, { 'Set-Cookie': cookie });
      }

      return json({ error: 'Not found' }, 404);
    } catch (err) {
      return json({ error: 'Errore interno', detail: String(err && err.message || err) }, 500);
    }
  },
};
