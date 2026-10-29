// Account, session, throttle and at-rest secret encryption.
import { getJSON, putJSON, putJSONIfAbsent, del, list } from './store.js';

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

/* -------------------------------------------------------------- client ip */

/** 只有显式声明「前面挂了自己的反代」才采信 XFF —— 那个头客户端可以随便写 */
function trustProxy(env) {
    const v = String((env && env.WEBSSH_TRUST_PROXY) || '').trim().toLowerCase();
    return v === 'on' || v === '1' || v === 'true';
}

/**
 * 客户端 IP：优先 Cloudflare 注入的头。
 *
 * `x-forwarded-for` / `x-real-ip` 是**客户端可写**的，默认不采信：
 * 否则攻击者每次请求换一个值就能把登录限流绕成无限次，发个空值还能让
 * 会话的 IP 绑定整层失效。只有在反代自己会覆写这两个头的部署里，才把
 * WEBSSH_TRUST_PROXY 打开。
 */
export function clientIpOf(request, env) {
    const h = request.headers;
    const direct = (h.get('cf-connecting-ip') || '').trim();
    if (direct) return direct;
    if (trustProxy(env)) {
        const forwarded = (h.get('x-forwarded-for') || h.get('x-real-ip') || '').split(',')[0].trim();
        if (forwarded) return forwarded;
    }
    return 'local';
}

/** 展开成 8 组 16 位整数；解析不了返回 null。用于把 `::`、IPv4 内嵌、大小写都归一。 */
function expandIpv6(input) {
    let s = String(input || '').trim().toLowerCase();
    const pct = s.indexOf('%'); // 去掉 zone id（fe80::1%eth0）
    if (pct >= 0) s = s.slice(0, pct);
    if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
    if (!s || !s.includes(':')) return null;
    if (s.includes('.')) {
        // IPv4 内嵌（::ffff:1.2.3.4 / ::1.2.3.4）：尾部换成两组 16 位
        const i = s.lastIndexOf(':');
        if (i < 0) return null;
        const v4 = s.slice(i + 1).split('.');
        if (v4.length !== 4) return null;
        const n = v4.map((x) => (/^\d{1,3}$/.test(x) ? Number(x) : NaN));
        if (n.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
        s = s.slice(0, i + 1) + ((n[0] << 8) | n[1]).toString(16) + ':' + ((n[2] << 8) | n[3]).toString(16);
    }
    const halves = s.split('::');
    if (halves.length > 2) return null;
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : null;
    let groups;
    if (tail === null) {
        groups = head;
    } else {
        const fill = 8 - head.length - tail.length;
        if (fill < 1) return null;
        groups = head.concat(new Array(fill).fill('0'), tail);
    }
    if (groups.length !== 8) return null;
    const out = [];
    for (const g of groups) {
        if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
        out.push(parseInt(g, 16));
    }
    return out;
}

/** 把各种写法的 IP 归一成 { v: 4|6, parts: number[] }；解析不了返回 null */
export function parseIp(raw) {
    const s = String(raw == null ? '' : raw).trim().toLowerCase();
    if (!s) return null;
    if (s.includes(':')) {
        const g = expandIpv6(s);
        if (!g) return null;
        // IPv4-mapped（::ffff:a.b.c.d）当 IPv4 处理，和裸 IPv4 才能比到一起去
        if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
            return { v: 4, parts: [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff] };
        }
        return { v: 6, parts: g };
    }
    const p = s.split('.');
    if (p.length !== 4) return null;
    const n = p.map((x) => (/^\d{1,3}$/.test(x) ? Number(x) : NaN));
    if (n.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
    return { v: 4, parts: n };
}

// IPv4 比 /24，IPv6 比 /48。
// IPv6 原来比前四组（= /64），而一个 IPv6 用户通常手握整个 /64（2^64 个地址），
// 那层绑定等于不存在 —— 攻击者在自己 /64 里随便换地址就能过。放宽到 /48 才对应
// 「同一个站点/同一个运营商前缀」。前缀会随拨号变化的话，用 WEBSSH_SESSION_IP_BIND=off。
const IPV4_GROUPS = 3;
const IPV6_GROUPS = 3;

/**
 * 会话绑定的 IP 比对。要求完全相等太容易误伤（手机切 4G 就换 IP），
 * 所以按网段比：跨城市/跨运营商基本不可能还在同一段。
 */
export function sameIpPrefix(a, b) {
    const x = parseIp(a);
    const y = parseIp(b);
    if (!x || !y) return true; // 解析不了就不在这里判断（调用方另有 fail-closed 处理）
    if (x.v !== y.v) return false;
    const n = x.v === 4 ? IPV4_GROUPS : IPV6_GROUPS;
    for (let i = 0; i < n; i++) if (x.parts[i] !== y.parts[i]) return false;
    return true;
}

/* --------------------------------------------------------------- password */

// 记录格式版本。v1 是早期部署写的 { username, salt, iterations, hash }；
// v2 多了 algo / v / peppered，用来判断这条记录该不该在登录后就地升级。
const HASH_VER = 2;
const HASH_ALGO = 'pbkdf2-sha256';
// pepper 太短就没有意义了，短于这个长度当作没配
const PEPPER_MIN = 16;

/**
 * 从 Worker secret 里取 pepper。
 *
 * 为什么需要它：Workers 生产运行时对 PBKDF2 迭代次数有 100000 的硬上限
 * （超了直接 NotSupportedError），所以「提高迭代次数抗离线爆破」这条路是堵死的。
 * 能加的是 pepper —— 一段只存在于环境变量、永远不写进 R2 的随机串，
 * 拼在密码前面一起过 PBKDF2。拿到桶转储的人没有 pepper，
 * 100000 次 PBKDF2 的哈希对他来说就是一堆随机字节。
 *
 * 这也是为什么不需要把 sys/admin 整体加密：加密密钥和 pepper 在同一个
 * 环境变量里，加密不会多挡住任何人，却会让密钥配错时管理员彻底进不去。
 */
function passwordPepper(env) {
    const raw = env && env.WEBSSH_PASSWORD_PEPPER;
    if (!raw) return '';
    const s = String(raw);
    return s.length >= PEPPER_MIN ? s : '';
}

export async function hashPassword(password, saltHex, iterations = PBKDF2_ITER, pepper = '') {
    // 用 \0 分隔：否则 pepper='ab' + password='cd' 和 pepper='a' + password='bcd'
    // 会算出同一个哈希
    const material = pepper ? pepper + '\u0000' + password : password;
    const key = await crypto.subtle.importKey('raw', te.encode(material), 'PBKDF2', false, ['deriveBits']);
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

async function buildAdminRecord(env, username, password) {
    const salt = randomHex(16);
    const pepper = passwordPepper(env);
    return {
        v: HASH_VER,
        algo: HASH_ALGO,
        username,
        salt,
        iterations: PBKDF2_ITER,
        peppered: Boolean(pepper),
        hash: await hashPassword(password, salt, PBKDF2_ITER, pepper),
        createdAt: Date.now(),
    };
}

/**
 * 这条记录要不要用当前参数重算：
 *  - 旧格式（没有 v，说明是 pepper 之前写的）
 *  - 迭代次数不是当前值
 *  - 配了 pepper，但记录里没带（最关键的升级路径：加上 pepper 后
 *    旧记录仍然能登录，登录成功那一刻顺手升级，不用把人踢出去重设密码）
 */
export function needsRehash(env, admin) {
    if (!admin) return false;
    if (admin.v !== HASH_VER) return true;
    if (Number(admin.iterations) !== PBKDF2_ITER) return true;
    return Boolean(passwordPepper(env)) && !admin.peppered;
}

/**
 * 覆盖写：仅用于改密（/api/password），初始化请用 createAdminIfAbsent。
 * 传 prev 时保留它的 createdAt —— 改密码不代表账号是刚建的。
 */
export async function createAdmin(env, username, password, prev) {
    // 先确认主密钥可用，再动管理员记录：顺序反过来的话，密钥有问题时
    // 密码已经改了、凭据却全部解不开，属于最坏的一种「半成功」。
    await ensureMasterKey(env);
    const record = await buildAdminRecord(env, username, password);
    if (prev && prev.createdAt) record.createdAt = prev.createdAt;
    await putJSON(env, ADMIN_KEY, record);
    return record;
}

/**
 * 登录成功后就地把记录升级到当前参数。
 * 调用方已经验过密码，所以这里不需要再验一次；写失败不影响本次登录，
 * 下次登录会再试一遍。
 */
export async function rehashAdmin(env, admin, password) {
    const next = await buildAdminRecord(env, admin.username, password);
    // createdAt 表示「这个账号是什么时候建的」，升级不该把它改成现在
    if (admin.createdAt) next.createdAt = admin.createdAt;
    await putJSON(env, ADMIN_KEY, next);
    return next;
}

/**
 * 首次初始化：并发请求里只有第一个能登基，其余返回 false。
 * R2 没有 CAS，但 put 支持 If-None-Match: *（条件不满足返回 null），
 * 所以这里用条件写而不是「先读后写」。写后再回读一次 initId 兜底：
 * 即使运行时忽略了 onlyIf，后写者也能发现自己没抢到。
 */
export async function createAdminIfAbsent(env, username, password) {
    // 先校验/生成主密钥，再抢管理员记录。反过来写的话，WEBSSH_MASTER_KEY 配错时
    // 会出现「管理员已创建、但每次保存凭据都失败」的半初始化状态，
    // 而且 setup 已经不能重跑了（getAdmin 非空）。
    await ensureMasterKey(env);
    const record = await buildAdminRecord(env, username, password);
    const marker = randomHex(8);
    record.initId = marker;
    const wrote = await putJSONIfAbsent(env, ADMIN_KEY, record);
    const stored = await getJSON(env, ADMIN_KEY);
    if (!wrote && !stored) throw new Error('初始化失败：管理员记录没有写入存储，请重试');
    return Boolean(stored && stored.initId === marker);
}

export async function verifyLogin(env, username, password) {
    const admin = await getAdmin(env);
    const salt = admin && admin.salt ? admin.salt : DUMMY_SALT;
    const iterations = (admin && admin.iterations) || PBKDF2_ITER;
    // 记录标了 peppered 就必须用 pepper 重算：pepper 丢了密码就永远对不上，
    // 这是有意的（有 pepper 保护时，没有 pepper 的人本来就不该能登进来），
    // 恢复手段见 README「忘记密码」——重新部署并清掉 sys/admin。
    const pepper = admin && admin.peppered ? passwordPepper(env) : '';
    const hash = await hashPassword(String(password || ''), salt, iterations, pepper);
    if (!admin) return null;
    if (!safeEqual(String(admin.username).toLowerCase(), String(username || '').toLowerCase())) return null;
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
    // 必须和 getSession 用同一个取值函数，否则反代部署下这里存空串、
    // 那边再比对，IP 这一层就静默失效了。
    const ip = clientIpOf(request, env);
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
    const token = cookies[cookieName()];
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
    const rec = await getJSON(env, SESSION_PREFIX + token);
    if (!rec || !rec.exp) return null;
    const now = Date.now();
    if (rec.exp < now) {
        await del(env, SESSION_PREFIX + token);
        return null;
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
    // 会话绑设备：Cookie 一旦泄露（共享电脑、扩展、截图），有效期还有 30 天，
    // 而进来就等于拿到整库 SSH 凭据。UA 变了直接作废 —— 同一个浏览器几乎不会换 UA。
    // 空 UA 必须算「不匹配」：写成 `rec.ua && ua && ua !== rec.ua` 的话，
    // 攻击者只要发一个不带 User-Agent 的请求就能把整层绕过去。
    const ua = (request.headers.get('user-agent') || '').slice(0, 160);
    if (rec.ua && ua !== rec.ua) {
        await del(env, SESSION_PREFIX + token);
        return null;
    }
    // IP 按网段比对（可用 WEBSSH_SESSION_IP_BIND=off 关掉，方便移动网络用户）。
    // 反向的 fail-closed：建立会话时知道 IP，这次却取不到（'local'），同样作废 ——
    // 否则「让请求不带任何 IP 头」本身就是一条绕过路径。
    if (rec.ip && rec.ip !== 'local' && (!env || env.WEBSSH_SESSION_IP_BIND !== 'off')) {
        const ip = clientIpOf(request, env);
        // 解析不出来（'local' 或畸形值）一律按不匹配处理：开了 WEBSSH_TRUST_PROXY 时
        // XFF 是可控的，随手塞个 "garbage" 不能变成免检通行证。
        if (ip === 'local' || !parseIp(ip) || !sameIpPrefix(rec.ip, ip)) {
            await del(env, SESSION_PREFIX + token);
            return null;
        }
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
function throttlePrefix(ip) {
    return 'throttle/' + String(ip).replace(/[^0-9a-zA-Z.:\-_\[\]]/g, '_') + '/';
}

export async function checkThrottle(env, ip) {
    if (!ip) return { locked: false };
    const prefix = throttlePrefix(ip);
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

export async function recordFailure(env, ip) {
    if (!ip) return;
    await putJSON(env, throttlePrefix(ip) + Date.now() + '-' + randomHex(4), 1);
}

export async function clearFailures(env, ip) {
    if (!ip) return;
    const prefix = throttlePrefix(ip);
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

/** 把 WEBSSH_MASTER_KEY 归一成 32 字节，长度不对就明确报错（不静默降级） */
function masterKeyBytes(tag) {
    let raw;
    try {
        raw = /^[a-f0-9]{64}$/i.test(tag) ? fromHex(tag) : b64decode(tag);
    } catch (_) {
        throw new Error('WEBSSH_MASTER_KEY 既不是 64 位 hex，也不是合法的 base64');
    }
    if (raw.length !== 32) throw new Error('WEBSSH_MASTER_KEY 必须是 32 字节的 base64 或 64 位 hex');
    return raw;
}

export async function ensureMasterKey(env) {
    if (env.WEBSSH_MASTER_KEY) {
        // 提前校验：格式不对的密钥如果拖到「第一次保存凭据」才炸，
        // 初始化看起来是成功的，之后每个写操作都失败，排查成本很高。
        masterKeyBytes(String(env.WEBSSH_MASTER_KEY).trim());
        return;
    }
    const existing = await getJSON(env, MASTER_KEY);
    if (existing && existing.key) return;
    // 与管理员记录同理：并发初始化只能有一份主密钥落盘。
    // 败者绝不能覆盖 —— 否则赢家用 A 钥加密的凭据会被 B 钥毁掉。
    const candidate = { key: b64encode(crypto.getRandomValues(new Uint8Array(32))), createdAt: Date.now() };
    if (await putJSONIfAbsent(env, MASTER_KEY, candidate)) return;
    const check = await getJSON(env, MASTER_KEY);
    if (!check || !check.key) throw new Error('主密钥初始化失败，请重试');
}

export async function getMasterKey(env) {
    // 缓存按「密钥来源」区分：轮换 WEBSSH_MASTER_KEY 后不能再拿旧钥继续加解密
    const tag = env.WEBSSH_MASTER_KEY ? String(env.WEBSSH_MASTER_KEY).trim() : '';
    if (cachedMaster && cachedMasterTag === tag) return cachedMaster;
    let raw = null;
    if (tag) {
        raw = masterKeyBytes(tag);
    } else {
        const rec = await getJSON(env, MASTER_KEY);
        if (!rec || !rec.key) throw new Error('主密钥不存在，请重新完成初始化');
        raw = b64decode(rec.key);
    }
    cachedMaster = await importMaster(raw);
    cachedMasterTag = tag;
    return cachedMaster;
}

/** 把「这段密文属于哪个字段」绑进 AAD：搬走别人的密文就解不开 */
function aadFor(context) {
    return te.encode('onessh|' + String(context || ''));
}

export async function encryptSecret(env, plaintext, context) {
    if (plaintext == null || plaintext === '') return null;
    const key = await getMasterKey(env);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const params = { name: 'AES-GCM', iv };
    if (context) params.additionalData = aadFor(context);
    const ct = new Uint8Array(await crypto.subtle.encrypt(params, key, te.encode(String(plaintext))));
    // 有上下文用 v2（AAD 绑定），没有上下文仍写 v1（兼容旧数据格式）
    return (context ? 'v2:' : 'v1:') + b64encode(iv) + ':' + b64encode(ct);
}

export async function decryptSecret(env, blob, context) {
    if (!blob) return null;
    const parts = String(blob).split(':');
    if (parts.length !== 3 || (parts[0] !== 'v1' && parts[0] !== 'v2')) throw new Error('密文格式不正确');
    const key = await getMasterKey(env);
    const params = { name: 'AES-GCM', iv: b64decode(parts[1]) };
    if (parts[0] === 'v2') {
        // v2 必须带上下文：拿不到就无法校验归属，宁可报错也不放行
        if (!context) throw new Error('这段密文绑定了上下文，缺少归属信息无法解密');
        params.additionalData = aadFor(context);
    }
    const pt = await crypto.subtle.decrypt(params, key, b64decode(parts[2]));
    return new TextDecoder().decode(pt);
}

/* 会话日志里可能粘着密码/令牌，落盘同样走主密钥加密：iv(12) || ciphertext */
export async function encryptBytes(env, bytes, context) {
    const key = await getMasterKey(env);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const params = { name: 'AES-GCM', iv };
    if (context) params.additionalData = aadFor(context);
    const ct = new Uint8Array(await crypto.subtle.encrypt(params, key, bytes));
    const out = new Uint8Array(12 + ct.length);
    out.set(iv, 0);
    out.set(ct, 12);
    return out;
}

export async function decryptBytes(env, buf, context) {
    const u8 = new Uint8Array(buf);
    if (u8.length < 13) throw new Error('密文格式不正确');
    const key = await getMasterKey(env);
    const params = { name: 'AES-GCM', iv: u8.subarray(0, 12) };
    if (context) params.additionalData = aadFor(context);
    const pt = await crypto.subtle.decrypt(params, key, u8.subarray(12));
    return new Uint8Array(pt);
}
