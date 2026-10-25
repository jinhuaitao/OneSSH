// Account, session, throttle and at-rest secret encryption.
import { getJSON, putJSON, del, list } from './store.js';

const ADMIN_KEY = 'sys/admin';
const MASTER_KEY = 'sys/master';
const SESSION_PREFIX = 'sess/';
const PBKDF2_ITER = 120000;
const SESSION_TTL = 30 * 24 * 3600 * 1000;

const te = new TextEncoder();

export function toHex(u8) {
    let s = '';
    for (const b of u8) s += b.toString(16).padStart(2, '0');
    return s;
}

export function fromHex(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

export function randomHex(n) {
    return toHex(crypto.getRandomValues(new Uint8Array(n)));
}

export function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return d === 0;
}

/* --------------------------------------------------------------- password */

export async function hashPassword(password, saltHex, iterations = PBKDF2_ITER) {
    const key = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: fromHex(saltHex), iterations, hash: 'SHA-256' },
        key,
        256
    );
    return toHex(new Uint8Array(bits));
}

export async function getAdmin(env) {
    return getJSON(env, ADMIN_KEY);
}

export async function createAdmin(env, username, password) {
    const salt = randomHex(16);
    const record = {
        username,
        salt,
        iterations: PBKDF2_ITER,
        hash: await hashPassword(password, salt, PBKDF2_ITER),
        createdAt: Date.now(),
    };
    await putJSON(env, ADMIN_KEY, record);
    await ensureMasterKey(env);
    return record;
}

export async function verifyLogin(env, username, password) {
    const admin = await getAdmin(env);
    if (!admin) return null;
    if (String(admin.username).toLowerCase() !== String(username || '').toLowerCase()) return null;
    const hash = await hashPassword(password || '', admin.salt, admin.iterations || PBKDF2_ITER);
    if (!safeEqual(hash, admin.hash)) return null;
    return admin;
}

/* --------------------------------------------------------------- sessions */

export function cookieName() {
    return 'wssh_session';
}

export function parseCookies(header) {
    const out = {};
    if (!header) return out;
    for (const part of header.split(';')) {
        const i = part.indexOf('=');
        if (i < 0) continue;
        out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    }
    return out;
}

function isHttps(request) {
    return new URL(request.url).protocol === 'https:';
}

export function sessionCookie(token, request, maxAgeSec = SESSION_TTL / 1000) {
    const parts = [
        `${cookieName()}=${token}`,
        'Path=/',
        'HttpOnly',
        'SameSite=Lax',
        `Max-Age=${maxAgeSec}`,
    ];
    if (isHttps(request)) parts.push('Secure');
    return parts.join('; ');
}

export function clearCookie(request) {
    return sessionCookie('', request, 0);
}

export async function createSession(env, username, request) {
    const token = randomHex(32);
    const ip = request.headers.get('cf-connecting-ip') || '';
    await putJSON(env, SESSION_PREFIX + token, {
        u: username,
        exp: Date.now() + SESSION_TTL,
        created: Date.now(),
        ip,
        ua: (request.headers.get('user-agent') || '').slice(0, 160),
    });
    return token;
}

export async function getSession(env, request) {
    const cookies = parseCookies(request.headers.get('cookie'));
    const token = cookies[cookieName()];
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
    const rec = await getJSON(env, SESSION_PREFIX + token);
    if (!rec || !rec.exp || rec.exp < Date.now()) return null;
    return { token, ...rec };
}

export async function destroySession(env, token) {
    if (token && /^[a-f0-9]{64}$/.test(token)) await del(env, SESSION_PREFIX + token);
}

export async function pruneSessions(env) {
    const objs = await list(env, SESSION_PREFIX);
    if (objs.length < 12) return;
    for (const o of objs) {
        const rec = await getJSON(env, o.key);
        if (!rec || !rec.exp || rec.exp < Date.now()) await del(env, o.key);
    }
}

/* --------------------------------------------------------------- throttle */

const THROTTLE_LIMIT = 6;
const THROTTLE_WINDOW = 10 * 60 * 1000;
const THROTTLE_LOCK = 15 * 60 * 1000;

export async function checkThrottle(env, ip) {
    if (!ip) return { locked: false };
    const rec = await getJSON(env, 'throttle/' + ip);
    if (!rec) return { locked: false };
    if (rec.until && rec.until > Date.now()) {
        return { locked: true, retryAfter: Math.ceil((rec.until - Date.now()) / 1000) };
    }
    return { locked: false };
}

export async function recordFailure(env, ip) {
    if (!ip) return;
    const key = 'throttle/' + ip;
    const rec = (await getJSON(env, key)) || { count: 0, first: Date.now() };
    if (Date.now() - rec.first > THROTTLE_WINDOW) {
        rec.count = 0;
        rec.first = Date.now();
    }
    rec.count += 1;
    if (rec.count >= THROTTLE_LIMIT) rec.until = Date.now() + THROTTLE_LOCK;
    await putJSON(env, key, rec);
}

export async function clearFailures(env, ip) {
    if (ip) await del(env, 'throttle/' + ip);
}

/* ------------------------------------------------------- secret at rest */

let cachedMaster = null;

function b64encode(u8) {
    let s = '';
    for (const b of u8) s += String.fromCharCode(b);
    return btoa(s);
}

function b64decode(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
}

async function importMaster(raw) {
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function ensureMasterKey(env) {
    if (env.WEBSSH_MASTER_KEY) return;
    const existing = await getJSON(env, MASTER_KEY);
    if (existing && existing.key) return;
    await putJSON(env, MASTER_KEY, { key: b64encode(crypto.getRandomValues(new Uint8Array(32))), createdAt: Date.now() });
}

export async function getMasterKey(env) {
    if (cachedMaster) return cachedMaster;
    let raw = null;
    if (env.WEBSSH_MASTER_KEY) {
        const v = String(env.WEBSSH_MASTER_KEY).trim();
        raw = /^[a-f0-9]{64}$/i.test(v) ? fromHex(v) : b64decode(v);
        if (raw.length !== 32) throw new Error('WEBSSH_MASTER_KEY 必须是 32 字节的 base64 或 64 位 hex');
    } else {
        const rec = await getJSON(env, MASTER_KEY);
        if (!rec || !rec.key) throw new Error('主密钥不存在，请重新完成初始化');
        raw = b64decode(rec.key);
    }
    cachedMaster = await importMaster(raw);
    return cachedMaster;
}

export async function encryptSecret(env, plaintext) {
    if (plaintext == null || plaintext === '') return null;
    const key = await getMasterKey(env);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(String(plaintext)))
    );
    return 'v1:' + b64encode(iv) + ':' + b64encode(ct);
}

export async function decryptSecret(env, blob) {
    if (!blob) return null;
    const parts = String(blob).split(':');
    if (parts.length !== 3 || parts[0] !== 'v1') throw new Error('密文格式不正确');
    const key = await getMasterKey(env);
    const iv = b64decode(parts[1]);
    const ct = b64decode(parts[2]);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(pt);
}
