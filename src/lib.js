// DeskSuite porta — funzioni pure (nessuna dipendenza dal runtime Worker).
// Usano solo Web Crypto (crypto.subtle), disponibile sia su Cloudflare Workers sia su Node 18+.

const enc = new TextEncoder();

// ---------- base64url ----------
export function b64uFromBytes(bytes) {
  let s = '';
  const b = new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function bytesFromB64u(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function hex(bytes) {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------- password: PBKDF2 100k SHA-256 (stessa convenzione degli altri gestionali) ----------
const PBKDF2_ITER = 100000;

export async function hashPassword(password, saltHex) {
  // saltHex opzionale: se assente ne genera uno nuovo (32 char hex)
  if (!saltHex) {
    const s = crypto.getRandomValues(new Uint8Array(16));
    saltHex = hex(s);
  }
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    // il salt è usato come STRINGA UTF-8 (come nel resto dello stack), non come byte esadecimali
    { name: 'PBKDF2', salt: enc.encode(saltHex), iterations: PBKDF2_ITER, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return { hash: hex(bits), salt: saltHex, iter: PBKDF2_ITER };
}

// confronto a tempo costante
export function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function verifyPassword(password, saltHex, expectedHashHex) {
  const { hash } = await hashPassword(password, saltHex);
  return timingSafeEqual(hash, expectedHashHex);
}

// ---------- JWT HS256 (segreto condiviso con i Worker delle app in Fase 3) ----------
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function signJWT(payload, secret, ttlSeconds = 604800) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + ttlSeconds };
  const h = b64uFromBytes(enc.encode(JSON.stringify(header)));
  const p = b64uFromBytes(enc.encode(JSON.stringify(body)));
  const data = `${h}.${p}`;
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return `${data}.${b64uFromBytes(sig)}`;
}

export async function verifyJWT(token, secret) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const key = await hmacKey(secret);
  const ok = await crypto.subtle.verify('HMAC', key, bytesFromB64u(s), enc.encode(`${h}.${p}`));
  if (!ok) return null;
  let body;
  try { body = JSON.parse(new TextDecoder().decode(bytesFromB64u(p))); } catch { return null; }
  if (typeof body.exp !== 'number' || body.exp < Math.floor(Date.now() / 1000)) return null;
  return body;
}

// ---------- cookie di sessione su .desksuite.cloud (raggiunge tutti i sottodomini) ----------
export const COOKIE_NAME = 'ds_session';

export function makeSessionCookie(jwt, ttlSeconds = 604800) {
  return `${COOKIE_NAME}=${jwt}; Domain=.desksuite.cloud; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${ttlSeconds}`;
}
export function clearSessionCookie() {
  return `${COOKIE_NAME}=; Domain=.desksuite.cloud; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
export function readCookie(request, name = COOKIE_NAME) {
  const raw = request.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

// ---------- codice di recupero: 24 char in gruppi da 4, alfabeto senza 0/O/1/I/L ----------
const RECOVERY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // niente 0 O 1 I L
export function generateRecoveryCode() {
  const buf = crypto.getRandomValues(new Uint8Array(24));
  let out = '';
  for (let i = 0; i < 24; i++) {
    out += RECOVERY_ALPHABET[buf[i] % RECOVERY_ALPHABET.length];
    if (i % 4 === 3 && i !== 23) out += '-';
  }
  return out; // es. ABCD-EFGH-JKMN-PQRS-TUVW-XYZ2
}
export function normalizeRecovery(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}
export async function hashRecovery(code) {
  const norm = normalizeRecovery(code);
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(norm));
  return hex(digest);
}

// ---------- validazione password ----------
export function passwordProblem(pw) {
  if (typeof pw !== 'string' || pw.length < 12) return 'La password deve avere almeno 12 caratteri.';
  return null;
}
