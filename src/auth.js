// Account, session, throttle and at-rest secret encryption.
import { getJSON, putJSON, del, list } from './store.js';

const ADMIN_KEY = 'sys/admin';
const MASTER_KEY = 'sys/master';
const SESSION_PREFIX = 'sess/';
// Workers 生产运行时拒绝 >100000 的 PBKDF2 迭代（NotSupportedError），本地 dev 不检查
const PBKDF2_ITER = 100000;
const SESSION_TTL = 30 * 24 * 3600 * 1000;
const SESSION_IDLE = 7 * 24 * 3600 * 1000;
const SESSION_TOUCH = 3600 * 1000;
// 用户名不存在时也跑一次 PBKDF2，避免用响应时间判断账号是否存在
const DUMMY_SALT = '00112233445566778899aabbccddeeff';

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
    return getJSON(env, ADMIN_KEY, { strict: true });
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
    const salt = admin && admin.salt ? admin.salt : DUMMY_SALT;
    const iterations = (admin && admin.iterations) || PBKDF2_ITER;
    const hash = await hashPassword(String(password || ''), salt, iterations);
    if (!admin) return null;
    if (!safeEqual(String(admin.username).toLowerCase(), String(username || '').toLowerCase())) return null;
    if (!safeEqual(hash, admin.hash)) return null;
    return admin;
}

/* --------------------------------------------------------------- sessions */

// HTTPS 下用 __Host- 前缀：浏览器会拒绝任何带 Domain 的同名 Cookie，挡住
// 同一父域（例如 *.workers.dev 上的其它租户）往我们这里种会话 Cookie 的尝试。
export function cookieName(secure) {
    return secure ? '__Host-wssh_session' : 'wssh_session';
}

export function parseCookies(header) {
    const out = {};
    if (!header) return out;
    for (const part of header.split(';')) {
        const i = part.indexOf('=');
        if (i < 0) continue;
        const name = part.slice(0, i).trim();
        let value = part.slice(i + 1).trim();
        try {
            value = decodeURIComponent(value);
        } catch (_) {
            // 保留原始值：畸形编码只影响这一个 cookie，不该让整个请求 500
        }
        out[name] = value;
    }
    return out;
}

function isHttps(request) {
    return new URL(request.url).protocol === 'https:';
}

export function sessionCookie(token, request, maxAgeSec = SESSION_TTL / 1000) {
    const secure = isHttps(request);
    const parts = [
        `${cookieName(secure)}=${token}`,
        'Path=/',
        'HttpOnly',
        'SameSite=Lax',
        `Max-Age=${maxAgeSec}`,
    ];
    if (secure) parts.push('Secure');
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
        seen: Date.now(),
        ip,
        ua: (request.headers.get('user-agent') || '').slice(0, 160),
    });
    return token;
}

export async function getSession(env, request) {
    const cookies = parseCookies(request.headers.get('cookie'));
    // 老会话仍用无前缀的名字；HTTPS 下新签发的都是 __Host-
    const token = cookies[cookieName(true)] || cookies[cookieName(false)];
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
    const rec = await getJSON(env, SESSION_PREFIX + token);
    if (!rec || !rec.exp) return null;
    const now = Date.now();
    if (rec.exp < now) {
        await del(env, SESSION_PREFIX + token);
        return null;
    }
    // 可选：把会话绑到签发时的 IP。移动网络切换会让用户重新登录，默认关闭，
    // 公开部署且在意会话被盗时可设 WEBSSH_BIND_IP=1 打开。
    if (env.WEBSSH_BIND_IP === '1' || env.WEBSSH_BIND_IP === 'true') {
        const ip = request.headers.get('cf-connecting-ip') || '';
        if (rec.ip && ip && rec.ip !== ip) {
            await del(env, SESSION_PREFIX + token);
            return null;
        }
    }
    const seen = rec.seen || rec.created || 0;
    if (now - seen > SESSION_IDLE) {
        await del(env, SESSION_PREFIX + token);
        return null;
    }
    if (now - seen > SESSION_TOUCH) {
        rec.seen = now;
        await putJSON(env, SESSION_PREFIX + token, rec);
    }
    return { token, ...rec };
}

export async function destroySession(env, token) {
    if (token && /^[a-f0-9]{64}$/.test(token)) await del(env, SESSION_PREFIX + token);
}

/** 改密后调用：让所有已登录设备失效（可保留当前 token） */
export async function destroyAllSessions(env, exceptToken) {
    for (const o of await list(env, SESSION_PREFIX)) {
        if (exceptToken && o.key === SESSION_PREFIX + exceptToken) continue;
        await del(env, o.key);
    }
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

// R2 没有 CAS：原来「读计数 → 改 → 写回」在并发下会互相覆盖，6 次锁定形同虚设。
// 改成每次失败写一个独立对象、用 list 计数 —— 并发写不同的 key 不会丢更新。
// 同一个 IP 的失败计数按用途分桶：初始化口令和登录密码各自限流，
// 免得在初始化页试错把管理员登录也一起锁掉。
function throttlePrefix(ip, scope) {
    const area = String(scope || 'login').replace(/[^a-z0-9_-]/gi, '') || 'login';
    return 'throttle/' + area + '/' + String(ip).replace(/[^0-9a-zA-Z.:\-_\[\]]/g, '_') + '/';
}

export async function checkThrottle(env, ip, scope) {
    if (!ip) return { locked: false };
    const prefix = throttlePrefix(ip, scope);
    const now = Date.now();
    const stamps = [];
    for (const o of await list(env, prefix)) {
        const ts = parseInt(o.key.slice(prefix.length), 10);
        if (!Number.isFinite(ts)) continue;
        if (now - ts <= THROTTLE_WINDOW) stamps.push(ts);
        else del(env, o.key).catch(() => {}); // 顺手清理过期记录（不阻塞判定）
    }
    if (stamps.length < THROTTLE_LIMIT) return { locked: false };
    const until = Math.max(...stamps) + THROTTLE_LOCK;
    if (until > now) return { locked: true, retryAfter: Math.ceil((until - now) / 1000) };
    return { locked: false };
}

export async function recordFailure(env, ip, scope) {
    if (!ip) return;
    await putJSON(env, throttlePrefix(ip, scope) + Date.now() + '-' + randomHex(4), 1);
}

export async function clearFailures(env, ip, scope) {
    if (!ip) return;
    const prefix = throttlePrefix(ip, scope);
    for (const o of await list(env, prefix)) await del(env, o.key).catch(() => {});
}

/* ------------------------------------------------------- secret at rest */

let cachedMaster = null;
let cachedMasterTag = null;

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
    // 缓存按「密钥来源」区分：轮换 WEBSSH_MASTER_KEY 后不能再拿旧钥继续加解密
    const tag = env.WEBSSH_MASTER_KEY ? String(env.WEBSSH_MASTER_KEY).trim() : '';
    if (cachedMaster && cachedMasterTag === tag) return cachedMaster;
    let raw = null;
    if (tag) {
        raw = /^[a-f0-9]{64}$/i.test(tag) ? fromHex(tag) : b64decode(tag);
        if (raw.length !== 32) throw new Error('WEBSSH_MASTER_KEY 必须是 32 字节的 base64 或 64 位 hex');
    } else {
        const rec = await getJSON(env, MASTER_KEY);
        if (!rec || !rec.key) throw new Error('主密钥不存在，请重新完成初始化');
        raw = b64decode(rec.key);
    }
    cachedMaster = await importMaster(raw);
    cachedMasterTag = tag;
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

/* 会话日志里可能粘着密码/令牌，落盘同样走主密钥加密：iv(12) || ciphertext */
export async function encryptBytes(env, bytes) {
    const key = await getMasterKey(env);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
    const out = new Uint8Array(12 + ct.length);
    out.set(iv, 0);
    out.set(ct, 12);
    return out;
}

export async function decryptBytes(env, buf) {
    const u8 = new Uint8Array(buf);
    if (u8.length < 13) throw new Error('密文格式不正确');
    const key = await getMasterKey(env);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.subarray(0, 12) }, key, u8.subarray(12));
    return new Uint8Array(pt);
}
