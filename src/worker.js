// WebSSH — Cloudflare Worker entry (API + WebSocket bridge + static shell)
import { Terminal, pruneOldLogs } from './session.js';
import { normalizeHost, isPublicHost } from './hostaddr.js';
import { connect } from 'cloudflare:sockets';
import * as auth from './auth.js';
import { getJSON, putJSON, del, delAll, list, getBytes, listJSON, putJSONAll } from './store.js';
import { renderShell } from './pages.js';
import { loadPrivateKey } from './ssh/keys.js';
import { fingerprint } from './ssh/crypto.js';

const VERSION = '1.0.0';

const SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=()',
    'Content-Security-Policy':
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
        "connect-src 'self'; font-src 'self' data:; object-src 'none'; frame-src 'none'; worker-src 'none'; " +
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
};

const MAX_BODY = 4 * 1024 * 1024;
// 数量上限：R2 没有配额提醒，列表接口要逐条回读，堆到几千条就是「首页打不开」
const MAX_HOSTS = 200;
const MAX_GROUPS = 50;
const MIN_PASSWORD = 10;
const WEAK_PASSWORDS = new Set([
    '1234567890', '12345678', '123456789', 'password', 'password1', 'password123',
    'qwertyuiop', 'admin12345', 'administrator', 'letmein123', 'iloveyou123', 'webssh12345',
]);

function securityHeaders(request) {
    const headers = { ...SECURITY_HEADERS };
    if (new URL(request.url).protocol === 'https:') {
        headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
    }
    return headers;
}

function json(data, status = 200, extraHeaders) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
            ...SECURITY_HEADERS,
            ...(extraHeaders || {}),
        },
    });
}

function html(body, request) {
    return new Response(body, {
        headers: {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
            ...(request ? securityHeaders(request) : SECURITY_HEADERS),
        },
    });
}

async function readJSON(request) {
    const ct = request.headers.get('content-type') || '';
    if (!ct.includes('application/json')) throw new HttpError(415, '请求必须使用 application/json');
    const declared = parseInt(request.headers.get('content-length') || '0', 10);
    if (declared > MAX_BODY) throw new HttpError(413, '请求体过大');
    const text = await request.text();
    if (text.length > MAX_BODY) throw new HttpError(413, '请求体过大');
    try {
        return JSON.parse(text);
    } catch (_) {
        throw new HttpError(400, '请求体不是合法 JSON');
    }
}

/**
 * CSRF / 跨站 WebSocket 劫持防线：浏览器发出的跨站请求一定带 Origin，
 * 只要 Origin 存在就必须与本服务同源。非浏览器客户端（无 Origin）放行。
 */
function assertSameOrigin(request) {
    const origin = request.headers.get('origin');
    if (!origin) return;
    const url = new URL(request.url);
    if (origin !== url.protocol + '//' + url.host) throw new HttpError(403, '跨站请求已被拒绝');
}

function checkPassword(password, username) {
    const pw = String(password || '');
    if (pw.length < MIN_PASSWORD) return `密码至少 ${MIN_PASSWORD} 位`;
    if (pw.length > 200) return '密码不能超过 200 位';
    if (WEAK_PASSWORDS.has(pw.toLowerCase())) return '这个密码太常见了，换一个更不容易被猜到的';
    if (username && pw.toLowerCase() === String(username).toLowerCase()) return '密码不能与用户名相同';
    return null;
}

class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}


function cleanHostInput(body) {
    const name = String(body.name || '').trim();
    const host = String(body.host || '').trim();
    const username = String(body.username || '').trim();
    const port = parseInt(body.port, 10) || 22;
    const authType = body.authType === 'key' ? 'key' : 'password';
    if (!host) throw new HttpError(400, '主机地址不能为空');
    const addr = normalizeHost(host);
    if (!addr) throw new HttpError(400, '主机地址不合法（支持域名、IPv4、IPv6）');
    // 字面私网 / 保留地址直接拒绝：不要等到 Workers connect() 才失败，
    // 也不要让它以「已保存主机」的名义躺在库里。域名解析后指向私网的
    // DNS 重绑定在这里拦不住，兜底靠 Workers connect() 只连公网（见 README）。
    if (!isPublicHost(addr)) throw new HttpError(400, '主机地址为私网或保留地址，不允许连接（只支持公网地址）');
    if (!username) throw new HttpError(400, '用户名不能为空');
    if (port < 1 || port > 65535) throw new HttpError(400, '端口范围应为 1-65535');
    if (name.length > 60) throw new HttpError(400, '名称过长');
    return {
        name: name || `${username}@${addr}`,
        host: addr,
        port,
        username,
        authType,
        group: String(body.group || '').trim().slice(0, 40),
        country: /^[A-Z]{2}$/.test(String(body.country || '')) ? body.country : '',
        city: String(body.city || '').trim().slice(0, 40),
        icon: String(body.icon || '').slice(0, 4),
        color: /^#[0-9a-fA-F]{6}$/.test(String(body.color || '')) ? body.color : '',
        note: String(body.note || '').slice(0, 300),
    };
}

function publicHost(h) {
    const { secretEnc, keyEnc, passphraseEnc, ...rest } = h;
    return { ...rest, host: normalizeHost(h.host) || h.host, hasSecret: Boolean(secretEnc || keyEnc || h.keyId || h.credId) };
}

/* ---------------------------------------------------------------- groups */

const GROUP_MAX = 40;

function cleanGroupName(v) {
    const name = String(v == null ? '' : v).trim();
    if (!name || name.length > GROUP_MAX) throw new HttpError(400, '分组名称需为 1-40 个字符');
    if (/[\\/\r\n\t]/.test(name)) throw new HttpError(400, '分组名称不能包含斜杠、制表符或换行');
    return name;
}

async function storedGroups(env) {
    const rec = await getJSON(env, 'sys/groups');
    return rec && Array.isArray(rec.groups) ? rec.groups.filter((g) => typeof g === 'string' && g.trim()) : [];
}

async function saveGroups(env, groups) {
    const rec = await getJSON(env, 'sys/groups');
    await putJSON(env, 'sys/groups', bumped(rec, { groups }));
}

async function saveKeys(env, keys) {
    const rec = await getJSON(env, 'sys/keys');
    await putJSON(env, 'sys/keys', bumped(rec, { keys }));
}

async function saveCreds(env, creds) {
    const rec = await getJSON(env, 'sys/creds');
    await putJSON(env, 'sys/creds', bumped(rec, { creds }));
}

async function saveSnippets(env, snippets) {
    const rec = await getJSON(env, 'sys/snippets');
    await putJSON(env, 'sys/snippets', bumped(rec, { snippets }));
}

async function listGroups(env) {
    const out = [];
    const seen = new Set();
    for (const g of await storedGroups(env)) {
        const name = g.trim();
        if (name && !seen.has(name)) {
            seen.add(name);
            out.push(name);
        }
    }
    // hosts saved before groups were a first-class concept still count
    for (const { rec } of await listJSON(env, 'hosts/')) {
        const name = rec && String(rec.group || '').trim();
        if (name && !seen.has(name)) {
            seen.add(name);
            out.push(name);
        }
    }
    return out;
}

async function retagHosts(env, from, to) {
    const pairs = await listJSON(env, 'hosts/');
    const changed = [];
    for (const { key, rec } of pairs) {
        if (!rec || String(rec.group || '').trim() !== from) continue;
        rec.group = to;
        rec.updatedAt = Date.now();
        changed.push({ key, rec });
    }
    await putJSONAll(env, changed);
    return changed.length;
}

/* ------------------------------------------------------------------ keys */

function cleanKeyName(v) {
    const name = String(v == null ? '' : v).trim();
    if (!name || name.length > 60) throw new HttpError(400, '密钥名称需为 1-60 个字符');
    return name;
}

async function storedKeys(env) {
    const rec = await getJSON(env, 'sys/keys');
    return rec && Array.isArray(rec.keys) ? rec.keys : [];
}

function publicKeyMeta(k) {
    return { id: k.id, name: k.name, algo: k.algo || '', fingerprint: k.fingerprint || '', createdAt: k.createdAt || 0 };
}

async function inspectKey(privateKey) {
    const key = await loadPrivateKey(privateKey);
    return { algo: key.alg, fingerprint: await fingerprint(key.publicBlob) };
}

/* ----------------------------------------------------------------- creds */

function cleanCredName(v) {
    const name = String(v == null ? '' : v).trim();
    if (!name || name.length > 60) throw new HttpError(400, '常用账号名称需为 1-60 个字符');
    return name;
}

function cleanCredUser(v) {
    const user = String(v == null ? '' : v).trim();
    if (!user || user.length > 64 || /\s/.test(user)) throw new HttpError(400, '用户名需为 1-64 个非空白字符');
    return user;
}

async function storedCreds(env) {
    const rec = await getJSON(env, 'sys/creds');
    return rec && Array.isArray(rec.creds) ? rec.creds : [];
}

function publicCredMeta(c) {
    return { id: c.id, name: c.name, username: c.username, createdAt: c.createdAt || 0 };
}

/* ------------------------------------------------------- 乐观并发（版本） */

// R2 单对象没有 CAS：sys/keys 等都是「读出来 → 改 → 整个写回」，并发写会
// 互相覆盖。补一层 version 字段：POST 可带 expectedVersion，不符返回 409。
// 残余竞态：version 校验与写回之间仍有窗口，两个带同一 expectedVersion 的
// 并发请求可能都通过、后写者覆盖前写者。真 CAS 需要 R2 的 If-Match/etag，
// getJSON 目前丢弃 etag、内存 R2 桩也不提供 etag， plumbing 改动过大，
// 本轮不做（见 SUMMARY）。version 至少让「基于旧列表的编辑」能被发现，
// 而不是静默丢数据。
function versionOf(rec) {
    return rec && Number.isInteger(rec.version) ? rec.version : 0;
}

function checkExpectedVersion(body, rec) {
    const want = body && body.expectedVersion;
    if (want == null || want === '') return null;
    const n = parseInt(want, 10);
    if (!Number.isInteger(n)) return json({ error: 'bad_version', message: 'expectedVersion 必须是整数' }, 400);
    if (n !== versionOf(rec)) {
        return json({ error: 'version_conflict', message: '数据已被其他会话修改，请刷新后重试', currentVersion: versionOf(rec) }, 409);
    }
    return null;
}

function bumped(rec, extra) {
    return { ...(rec || {}), ...extra, version: versionOf(rec) + 1, updatedAt: Date.now() };
}

/* ------------------------------------------------------------- 导出加解密 */

function b64encodeBytes(u8) {
    let s = '';
    for (const b of u8) s += String.fromCharCode(b);
    return btoa(s);
}

function b64decodeToBytes(str) {
    const s = atob(String(str || ''));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
}

async function exportEncrypt(password, plaintextObj) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        base,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    const ct = new Uint8Array(
        await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('oneshh-export-v1') },
            key,
            new TextEncoder().encode(JSON.stringify(plaintextObj))
        )
    );
    return { salt: b64encodeBytes(salt), iv: b64encodeBytes(iv), ciphertext: b64encodeBytes(ct) };
}

async function exportDecrypt(password, data) {
    const salt = b64decodeToBytes(data.salt);
    const iv = b64decodeToBytes(data.iv);
    const ct = b64decodeToBytes(data.ciphertext);
    if (salt.length !== 16 || iv.length !== 12 || !ct.length) throw new Error('导出文件格式不正确');
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        base,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('oneshh-export-v1') },
        key,
        ct
    );
    return JSON.parse(new TextDecoder().decode(pt));
}

/* -------------------------------------------------------------------- api */

async function handleApi(request, env, url) {
    const path = url.pathname;
    const method = request.method;
    if (method !== 'GET' && method !== 'HEAD') assertSameOrigin(request);

    if (path === '/api/state' && method === 'GET') {
        const admin = await auth.getAdmin(env);
        const session = admin ? await auth.getSession(env, request) : null;
        // 未登录只返回最少字段：把 version / setupTokenConfigured 无条件返回，
        // 等于给扫描器免费做指纹识别（「这台跑着 OneSSH 1.2.3，且没配初始化口令」）。
        // 初始化口令现在是无条件必需的，前端无需靠 setupTokenConfigured 判断，
        // 永远显示口令输入框即可；未配置时 setup 直接拒绝。
        if (!session) return json({ setup: Boolean(admin), authed: false });
        return json({
            setup: Boolean(admin),
            authed: true,
            user: session.u,
            totpEnabled: Boolean(admin && admin.totp && admin.totp.enabled),
            needsSetupToken: true,
            setupTokenConfigured: Boolean(env.WEBSSH_SETUP_TOKEN),
            version: VERSION,
        });
    }

    if (path === '/api/setup' && method === 'POST') {
        const admin = await auth.getAdmin(env);
        if (admin) return json({ error: 'already_setup', message: '系统已经完成初始化' }, 409);
        const ip = auth.clientIpOf(request, env);
        // 未配置初始化口令时直接拒绝，而不是退化成「先到先得」：
        // 这就是「陌生人拿到网址就能注册管理员」的唯一入口，fail-closed 比方便重要
        if (!env.WEBSSH_SETUP_TOKEN) {
            return json(
                {
                    error: 'setup_token_missing',
                    message: '必须先配置 WEBSSH_SETUP_TOKEN 才能初始化：未配置时任何知道网址的人都能抢先成为管理员。',
                },
                503
            );
        }
        // 初始化口令和登录密码走同一套失败计数：否则它就是唯一一个可以无限次猜测的口令
        const throttle = await auth.checkThrottle(env, ip);
        if (throttle.locked) {
            return json(
                { error: 'locked', message: `尝试次数过多，请 ${Math.ceil(throttle.retryAfter / 60)} 分钟后再试` },
                429,
                { 'retry-after': String(throttle.retryAfter) }
            );
        }
        const body = await readJSON(request);
        if (!auth.safeEqual(String(body.token || ''), String(env.WEBSSH_SETUP_TOKEN))) {
            await auth.recordFailure(env, ip);
            return json({ error: 'bad_token', message: '初始化口令不正确' }, 403);
        }
        const username = String(body.username || '').trim();
        const password = String(body.password || '');
        if (!/^[a-zA-Z0-9_.@-]{3,32}$/.test(username)) {
            return json({ error: 'bad_username', message: '用户名需为 3-32 位字母、数字或 _ . @ -' }, 400);
        }
        const pwError = checkPassword(password, username);
        if (pwError) return json({ error: 'weak_password', message: pwError }, 400);
        // 上面的 getAdmin() 只是快速路径：两个并发请求可能同时看到「未初始化」，
        // 所以真正决定归属的是这里的条件写，输的一方拿不到会话。
        const created = await auth.createAdminIfAbsent(env, username, password);
        if (!created) return json({ error: 'already_setup', message: '系统已经完成初始化，请直接登录' }, 409);
        await auth.clearFailures(env, ip);
        const token = await auth.createSession(env, username, request);
        return json({ ok: true }, 200, { 'set-cookie': auth.sessionCookie(token, request) });
    }

    if (path === '/api/login' && method === 'POST') {
        const ip = auth.clientIpOf(request, env);
        const throttle = await auth.checkThrottle(env, ip);
        if (throttle.locked) {
            return json(
                { error: 'locked', message: `尝试次数过多，请 ${Math.ceil(throttle.retryAfter / 60)} 分钟后再试` },
                429,
                { 'retry-after': String(throttle.retryAfter) }
            );
        }
        const body = await readJSON(request);
        const admin = await auth.verifyLogin(env, body.username, body.password);
        if (!admin) {
            await auth.recordFailure(env, ip);
            return json({ error: 'bad_credentials', message: '用户名或密码不正确' }, 401);
        }
        // 密码对了才验 TOTP：顺序反过来会让攻击者用「是否要求 TOTP」探测账号状态。
        // 启用后无码/错码/重放一律不创建会话；备用码同样走这里。
        if (admin.totp && admin.totp.enabled) {
            const totp = await auth.checkTotp(env, admin, body.totpCode);
            if (!totp.ok) {
                await auth.recordFailure(env, ip);
                if (totp.error === 'totp_required') return json({ error: 'totp_required', message: '请输入两步验证码' }, 401);
                if (totp.error === 'totp_replay') return json({ error: 'totp_invalid', message: '该验证码已被使用，请等待下一组验证码' }, 401);
                return json({ error: 'totp_invalid', message: '两步验证码不正确' }, 401);
            }
        }
        await auth.clearFailures(env, ip);
        // 旧格式记录（没带 pepper / 迭代次数变了）在登录成功这一刻顺手升级。
        // 放在登录成功之后做，失败也不影响本次登录，下次再试。
        if (auth.needsRehash(env, admin)) {
            try {
                await auth.rehashAdmin(env, admin, body.password);
            } catch (_) {}
        }
        try {
            await auth.pruneSessions(env);
        } catch (_) {}
        const token = await auth.createSession(env, admin.username, request);
        return json({ ok: true, user: admin.username }, 200, { 'set-cookie': auth.sessionCookie(token, request) });
    }

    /* -------------------------------------------------- authenticated area */

    const session = await auth.getSession(env, request);
    if (!session) return json({ error: 'unauthorized', message: '登录已过期，请重新登录' }, 401);

    /* -------------------------------------------------- totp 两步验证 */

    if (path === '/api/totp/setup' && method === 'POST') {
        const admin = await auth.getAdmin(env);
        const secret = auth.generateTotpSecret();
        const backup = await auth.generateBackupCodes();
        const pending = { secret, backupHashes: backup.hashes, createdAt: Date.now() };
        const next = { ...admin, totpPending: pending };
        // 已启用时重新 setup 只是换密钥：旧配置保留到 enable 成功那一刻。
        // 直接写记录，不走 createAdmin（它会重算密码哈希，这里不需要改密码）。
        await putJSON(env, 'sys/admin', next);
        return json({ secret, otpauthUri: auth.totpOtpauthUri(secret, admin.username), backupCodes: backup.codes, enabled: Boolean(admin.totp && admin.totp.enabled) });
    }

    if (path === '/api/totp/enable' && method === 'POST') {
        const body = await readJSON(request);
        const admin = await auth.getAdmin(env);
        const pending = admin && admin.totpPending;
        if (!pending || !pending.secret) return json({ error: 'no_pending', message: '请先获取两步验证密钥' }, 400);
        const res = await auth.verifyTotpCode(pending.secret, body.code, (admin.totp && admin.totp.lastCounter) || 0);
        if (!res.ok) return json({ error: 'totp_invalid', message: '验证码不正确，请核对时间后重试' }, 401);
        const next = { ...admin };
        next.totp = { enabled: true, secret: pending.secret, lastCounter: res.counter, backupHashes: pending.backupHashes || [] };
        delete next.totpPending;
        await putJSON(env, 'sys/admin', next);
        return json({ ok: true, backupRemaining: next.totp.backupHashes.length });
    }

    if (path === '/api/totp/disable' && method === 'POST') {
        const body = await readJSON(request);
        const admin = await auth.getAdmin(env);
        if (!admin.totp || !admin.totp.enabled) return json({ ok: true, enabled: false });
        // 停用要同时验密码和码：只拿到会话还不够，防止「借用已登录电脑关掉 2FA」
        const okPass = await auth.verifyLogin(env, session.u, body.current);
        if (!okPass) return json({ error: 'bad_credentials', message: '当前密码不正确' }, 401);
        const totp = await auth.checkTotp(env, await auth.getAdmin(env), body.totpCode);
        if (!totp.ok) return json({ error: 'totp_invalid', message: '两步验证码不正确' }, 401);
        const fresh = await auth.getAdmin(env);
        const next = { ...fresh };
        delete next.totp;
        delete next.totpPending;
        await putJSON(env, 'sys/admin', next);
        return json({ ok: true, enabled: false });
    }

    if (path === '/api/totp/status' && method === 'GET') {
        const admin = await auth.getAdmin(env);
        const totp = admin && admin.totp;
        return json({ enabled: Boolean(totp && totp.enabled), backupRemaining: totp && Array.isArray(totp.backupHashes) ? totp.backupHashes.length : 0, hasPending: Boolean(admin && admin.totpPending) });
    }

    /* -------------------------------------------------- 加密导出 / 导入 */

    if (path === '/api/export' && method === 'POST') {
        const body = await readJSON(request);
        const password = String(body.exportPassword || '');
        if (password.length < 10) return json({ error: 'weak_password', message: '导出密码至少 10 位' }, 400);
        const admin = await auth.getAdmin(env);
        if (admin.totp && admin.totp.enabled) {
            const totp = await auth.checkTotpCodeOnly(env, admin, body.totpCode);
            if (!totp.ok) return json({ error: totp.error === 'totp_required' ? 'totp_required' : 'totp_invalid', message: '导出需要提供有效的两步验证码' }, 401);
        }
        const master = await getJSON(env, 'sys/master');
        if (!master || !master.key) {
            // 主密钥在环境变量里时，R2 没有它可包：导出包解不开凭据，宁可拒绝
            // 也不要给用户一个「看着成功、导入后全是乱码」的包。
            return json({ error: 'master_key_in_env', message: '主密钥由 WEBSSH_MASTER_KEY 环境变量提供，无法打包进导出文件；请妥善保管该环境变量的值' }, 400);
        }
        const hosts = (await listJSON(env, 'hosts/')).map((p) => p.rec);
        const keysRec = await getJSON(env, 'sys/keys');
        const credsRec = await getJSON(env, 'sys/creds');
        const groupsRec = await getJSON(env, 'sys/groups');
        const snipRec = await getJSON(env, 'sys/snippets');
        const payload = {
            v: 1,
            exportedAt: Date.now(),
            masterKey: master.key,
            hosts,
            keys: (keysRec && keysRec.keys) || [],
            creds: (credsRec && credsRec.creds) || [],
            groups: (groupsRec && groupsRec.groups) || [],
            snippets: (snipRec && snipRec.snippets) || [],
        };
        return json(await exportEncrypt(password, payload));
    }

    if (path === '/api/import' && method === 'POST') {
        const body = await readJSON(request);
        if (body.confirm !== true) return json({ error: 'confirm_required', message: '导入会覆盖现有主机、密钥库、常用账号、分组与片段，请确认（confirm: true）' }, 400);
        const password = String(body.exportPassword || '');
        if (!password) return json({ error: 'bad_export', message: '请提供导出密码' }, 400);
        if (!body.data || typeof body.data !== 'object') return json({ error: 'bad_export', message: '导出文件格式不正确' }, 400);
        let payload;
        try {
            payload = await exportDecrypt(password, body.data);
        } catch (_) {
            return json({ error: 'bad_export', message: '导出密码不正确或文件已损坏' }, 400);
        }
        if (!payload || payload.v !== 1 || !Array.isArray(payload.hosts) || !Array.isArray(payload.keys) || !Array.isArray(payload.creds)) {
            return json({ error: 'bad_export', message: '导出文件内容不完整' }, 400);
        }
        if (env.WEBSSH_MASTER_KEY) {
            return json({ error: 'master_key_in_env', message: '当前部署的主密钥由 WEBSSH_MASTER_KEY 提供，导入包里的主密钥无法生效；请先移除该环境变量再导入' }, 400);
        }
        // 先全部校验完再写任何东西：密码错、格式错都不会动现有数据。
        if (!payload.masterKey || typeof payload.masterKey !== 'string') {
            return json({ error: 'bad_export', message: '导出文件里没有主密钥，无法恢复凭据' }, 400);
        }
        for (const h of payload.hosts) {
            if (!h || typeof h.id !== 'string' || !/^[a-zA-Z0-9]+$/.test(h.id) || !normalizeHost(h.host || '')) {
                return json({ error: 'bad_export', message: '导出文件里有非法的主机记录' }, 400);
            }
            if (!isPublicHost(h.host)) return json({ error: 'bad_export', message: '导出文件里包含私网地址主机，已拒绝导入' }, 400);
        }
        await putJSON(env, 'sys/master', { key: payload.masterKey, createdAt: Date.now() });
        const oldHosts = await list(env, 'hosts/');
        await delAll(env, oldHosts.map((o) => o.key));
        await putJSONAll(env, payload.hosts.map((h) => ({ key: 'hosts/' + h.id, rec: h })));
        await saveKeys(env, payload.keys);
        await saveCreds(env, payload.creds);
        await saveGroups(env, Array.isArray(payload.groups) ? payload.groups : []);
        await saveSnippets(env, Array.isArray(payload.snippets) ? payload.snippets : []);
        return json({
            ok: true,
            imported: {
                hosts: payload.hosts.length,
                keys: payload.keys.length,
                creds: payload.creds.length,
                groups: (payload.groups || []).length,
                snippets: (payload.snippets || []).length,
            },
        });
    }

    if (path === '/api/logout' && method === 'POST') {
        await auth.destroySession(env, session.token);
        return json({ ok: true }, 200, { 'set-cookie': auth.clearCookie(request) });
    }

    if (path === '/api/password' && method === 'POST') {
        const ip = auth.clientIpOf(request, env);
        const throttle = await auth.checkThrottle(env, ip);
        if (throttle.locked) {
            return json(
                { error: 'locked', message: `尝试次数过多，请 ${Math.ceil(throttle.retryAfter / 60)} 分钟后再试` },
                429,
                { 'retry-after': String(throttle.retryAfter) }
            );
        }
        const body = await readJSON(request);
        const admin = await auth.verifyLogin(env, session.u, body.current);
        if (!admin) {
            await auth.recordFailure(env, ip);
            return json({ error: 'bad_credentials', message: '当前密码不正确' }, 401);
        }
        const next = String(body.next || '');
        const pwError = checkPassword(next, admin.username);
        if (pwError) return json({ error: 'weak_password', message: pwError }, 400);
        await auth.clearFailures(env, ip);
        await auth.createAdmin(env, admin.username, next, admin);
        // 改密意味着旧凭据可能已泄露：踢掉所有设备，再给当前浏览器发一枚新 token
        await auth.destroyAllSessions(env);
        const token = await auth.createSession(env, admin.username, request);
        return json({ ok: true }, 200, { 'set-cookie': auth.sessionCookie(token, request) });
    }

    if (path === '/api/groups') {
        if (method === 'GET') {
            return json({ groups: await listGroups(env), version: versionOf(await getJSON(env, 'sys/groups')) });
        }
        if (method === 'POST') {
            const body = await readJSON(request);
            const groupRec = await getJSON(env, 'sys/groups');
            const conflict = checkExpectedVersion(body, groupRec);
            if (conflict) return conflict;
            const stored = await storedGroups(env);
            const groups = await listGroups(env);
            const op = String(body.op || '');
            if (op === 'add') {
                const name = cleanGroupName(body.name);
                if (groups.includes(name)) return json({ error: 'dup', message: '同名分组已存在' }, 409);
                if (stored.length >= MAX_GROUPS) {
                    return json({ error: 'too_many', message: `分组数量已达上限（${MAX_GROUPS} 个）` }, 409);
                }
                stored.push(name);
                await saveGroups(env, stored);
                return json({ groups: await listGroups(env), updated: 0 });
            }
            if (op === 'rename') {
                const from = String(body.from || '').trim();
                const to = cleanGroupName(body.to);
                if (!groups.includes(from)) return json({ error: 'not_found', message: '分组不存在' }, 404);
                if (to !== from && groups.includes(to)) return json({ error: 'dup', message: '同名分组已存在' }, 409);
                const next = stored.filter((g) => g !== from);
                if (!next.includes(to)) next.push(to);
                await saveGroups(env, next);
                const updated = await retagHosts(env, from, to);
                return json({ groups: await listGroups(env), updated });
            }
            if (op === 'remove') {
                const name = String(body.name || '').trim();
                if (!groups.includes(name)) return json({ error: 'not_found', message: '分组不存在' }, 404);
                await saveGroups(env, stored.filter((g) => g !== name));
                const moved = await retagHosts(env, name, '');
                return json({ groups: await listGroups(env), moved });
            }
            return json({ error: 'bad_op', message: '未知操作' }, 400);
        }
    }

    if (path === '/api/keys') {
        if (method === 'GET') {
            return json({ keys: (await storedKeys(env)).map(publicKeyMeta), version: versionOf(await getJSON(env, 'sys/keys')) });
        }
        if (method === 'POST') {
            const body = await readJSON(request);
            const keysRec = await getJSON(env, 'sys/keys');
            const conflict = checkExpectedVersion(body, keysRec);
            if (conflict) return conflict;
            const keys = await storedKeys(env);
            const id = String(body.id || '').trim();
            const name = cleanKeyName(body.name);
            const keyText = body.privateKey ? String(body.privateKey) : '';
            const entry = id ? keys.find((k) => k.id === id) : null;
            if (id && !entry) return json({ error: 'not_found', message: '密钥不存在' }, 404);
            if (keys.some((k) => k.name === name && k.id !== id)) {
                return json({ error: 'dup', message: '同名密钥已存在' }, 409);
            }
            let meta = null;
            if (keyText) {
                try {
                    meta = await inspectKey(keyText);
                } catch (e) {
                    return json({ error: 'bad_key', message: String((e && e.message) || e) }, 400);
                }
            } else if (!entry) {
                return json({ error: 'bad_key', message: '请粘贴私钥内容' }, 400);
            }
            const recId = entry ? entry.id : 'k' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
            const rec = {
                id: recId,
                name,
                algo: meta ? meta.algo : entry.algo,
                fingerprint: meta ? meta.fingerprint : entry.fingerprint,
                keyEnc: keyText ? await auth.encryptSecret(env, keyText, 'key:' + recId) : entry.keyEnc,
                createdAt: entry ? entry.createdAt : Date.now(),
                updatedAt: Date.now(),
            };
            const next = entry ? keys.map((k) => (k.id === rec.id ? rec : k)) : keys.concat(rec);
            await saveKeys(env, next);
            return json({ key: publicKeyMeta(rec) });
        }
    }

    if (path.startsWith('/api/keys/') && method === 'DELETE') {
        const id = path.slice('/api/keys/'.length);
        if (!/^[a-zA-Z0-9]+$/.test(id)) return json({ error: 'bad_id', message: '无效的密钥 ID' }, 400);
        const keys = await storedKeys(env);
        if (!keys.some((k) => k.id === id)) return json({ error: 'not_found', message: '密钥不存在' }, 404);
        const pairs = await listJSON(env, 'hosts/');
        const used = pairs.filter((p) => p.rec.keyId === id).length;
        if (used) return json({ error: 'in_use', message: `该密钥正被 ${used} 台主机使用，请先改用其他凭据` }, 409);
        await saveKeys(env, keys.filter((k) => k.id !== id));
        return json({ ok: true });
    }

    if (path === '/api/creds') {
        if (method === 'GET') {
            return json({ creds: (await storedCreds(env)).map(publicCredMeta), version: versionOf(await getJSON(env, 'sys/creds')) });
        }
        if (method === 'POST') {
            const body = await readJSON(request);
            const credsRec = await getJSON(env, 'sys/creds');
            const conflict = checkExpectedVersion(body, credsRec);
            if (conflict) return conflict;
            const creds = await storedCreds(env);
            const id = String(body.id || '').trim();
            const name = cleanCredName(body.name);
            const username = cleanCredUser(body.username);
            const password = body.password ? String(body.password) : '';
            const entry = id ? creds.find((c) => c.id === id) : null;
            if (id && !entry) return json({ error: 'not_found', message: '常用账号不存在' }, 404);
            if (creds.some((c) => c.name === name && c.id !== id)) {
                return json({ error: 'dup', message: '同名常用账号已存在' }, 409);
            }
            if (!entry && !password) return json({ error: 'bad_cred', message: '请填写密码' }, 400);
            const recId = entry ? entry.id : 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
            const rec = {
                id: recId,
                name,
                username,
                passEnc: password ? await auth.encryptSecret(env, password, 'cred:' + recId) : entry.passEnc,
                createdAt: entry ? entry.createdAt : Date.now(),
                updatedAt: Date.now(),
            };
            const next = entry ? creds.map((c) => (c.id === rec.id ? rec : c)) : creds.concat(rec);
            await saveCreds(env, next);
            // hosts keep a denormalised username for list rendering
            if (entry && entry.username !== username) {
                const pairs = await listJSON(env, 'hosts/');
                const changed = [];
                for (const { key, rec: host } of pairs) {
                    if (host && host.credId === rec.id) {
                        host.username = username;
                        host.updatedAt = Date.now();
                        changed.push({ key, rec: host });
                    }
                }
                await putJSONAll(env, changed);
            }
            return json({ cred: publicCredMeta(rec) });
        }
    }

    if (path.startsWith('/api/creds/') && method === 'DELETE') {
        const id = path.slice('/api/creds/'.length);
        if (!/^[a-zA-Z0-9]+$/.test(id)) return json({ error: 'bad_id', message: '无效的账号 ID' }, 400);
        const creds = await storedCreds(env);
        if (!creds.some((c) => c.id === id)) return json({ error: 'not_found', message: '常用账号不存在' }, 404);
        const pairs = await listJSON(env, 'hosts/');
        const used = pairs.filter((p) => p.rec.credId === id).length;
        if (used) return json({ error: 'in_use', message: `该账号正被 ${used} 台主机使用，请先改用其他凭据` }, 409);
        await saveCreds(env, creds.filter((c) => c.id !== id));
        return json({ ok: true });
    }

    if (path === '/api/hosts') {
        if (method === 'GET') {
            // list 之后并发回读（分批 24 个），串行 100 台主机要挂好几秒
            const hosts = (await listJSON(env, 'hosts/')).map((p) => publicHost(p.rec));
            hosts.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0) || (a.name || '').localeCompare(b.name || ''));
            return json({ hosts });
        }
        if (method === 'POST') {
            const body = await readJSON(request);
            const base = cleanHostInput(body);
            if (body.id != null && !/^[a-zA-Z0-9]{1,40}$/.test(String(body.id))) {
                return json({ error: 'bad_id', message: '无效的主机 ID' }, 400);
            }
            // 新建时卡上限：R2 没有配额提醒，主机列表每页都要回读一遍，
            // 无限往里塞最后是「打开首页超时」，而不是一个能看懂的报错
            if (!body.id && (await list(env, 'hosts/')).length >= MAX_HOSTS) {
                return json(
                    { error: 'too_many', message: `主机数量已达上限（${MAX_HOSTS} 台），请先删除不再使用的主机` },
                    409
                );
            }
            const id = body.id || 'h' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
            const existing = body.id ? await getJSON(env, 'hosts/' + id) : null;
            if (body.id && !existing) return json({ error: 'not_found', message: '主机不存在' }, 404);
            const rec = { id, ...base, createdAt: existing ? existing.createdAt : Date.now(), updatedAt: Date.now() };

            const saveSecret = body.saveSecret !== false;
            if (base.authType === 'password') {
                const credId = typeof body.credId === 'string' ? body.credId.trim() : '';
                if (credId) {
                    const vault = await storedCreds(env);
                    if (!vault.some((c) => c.id === credId && c.passEnc)) {
                        return json({ error: 'bad_cred', message: '所选常用账号不存在，请刷新凭据库后重试' }, 400);
                    }
                    rec.credId = credId;
                } else if (body.password) {
                    rec.secretEnc = saveSecret ? await auth.encryptSecret(env, String(body.password), 'host:' + id) : null;
                } else if (existing && existing.secretEnc && saveSecret) {
                    rec.secretEnc = existing.secretEnc;
                } else if (existing && existing.credId && saveSecret) {
                    rec.credId = existing.credId;
                }
            } else {
                const keyId = typeof body.keyId === 'string' ? body.keyId.trim() : '';
                const keyText = body.privateKey ? String(body.privateKey) : '';
                if (keyId) {
                    const vault = await storedKeys(env);
                    const entry = vault.find((k) => k.id === keyId);
                    if (!entry || !entry.keyEnc) {
                        return json({ error: 'bad_key', message: '所选密钥不存在，请刷新密钥库后重试' }, 400);
                    }
                    rec.keyId = keyId;
                } else if (keyText) {
                    if (!/BEGIN [A-Z ]*PRIVATE KEY/.test(keyText)) {
                        return json({ error: 'bad_key', message: '私钥格式无法识别（需 PEM 格式）' }, 400);
                    }
                    rec.keyEnc = saveSecret ? await auth.encryptSecret(env, keyText, 'host:' + id) : null;
                } else if (existing && existing.keyEnc && saveSecret) {
                    rec.keyEnc = existing.keyEnc;
                } else if (existing && existing.keyId && saveSecret) {
                    rec.keyId = existing.keyId;
                }
            }
            await putJSON(env, 'hosts/' + id, rec);
            return json({ host: publicHost(rec) });
        }
    }

    if (path.startsWith('/api/hosts/') && method === 'DELETE') {
        const id = path.slice('/api/hosts/'.length);
        if (!/^[a-zA-Z0-9]+$/.test(id)) return json({ error: 'bad_id', message: '无效的主机 ID' }, 400);
        // 先确认存在再删：原来无论有没有这条记录都回 200，前端会把「删了个不存在的东西」当成功
        const existing = await getJSON(env, 'hosts/' + id);
        if (!existing) return json({ error: 'not_found', message: '主机不存在，可能已被删除' }, 404);
        await del(env, 'hosts/' + id);
        return json({ ok: true });
    }

    if (path === '/api/snippets') {
        if (method === 'GET') {
            const rec = await getJSON(env, 'sys/snippets');
            return json({ snippets: (rec && rec.snippets) || [], version: versionOf(rec) });
        }
        if (method === 'POST') {
            const body = await readJSON(request);
            const snipRec = await getJSON(env, 'sys/snippets');
            const conflict = checkExpectedVersion(body, snipRec);
            if (conflict) return conflict;
            // 别叫 list：会遮住从 store.js 引入的 list()
            const incoming = Array.isArray(body.snippets) ? body.snippets.slice(0, 100) : [];
            const clean = incoming
                .filter((s) => s && typeof s.command === 'string' && s.command.trim())
                .map((s) => ({
                    id: /^[a-zA-Z0-9]{1,24}$/.test(String(s.id || '')) ? String(s.id) : 's' + auth.randomHex(4),
                    name: String(s.name || '').slice(0, 60) || s.command.slice(0, 30),
                    command: String(s.command).slice(0, 2000),
                }));
            await saveSnippets(env, clean);
            return json({ snippets: clean });
        }
    }

    if (path === '/api/known') {
        if (method === 'GET') {
            const items = (await listJSON(env, 'known/')).map((p) => ({ key: p.key, ...p.rec }));
            items.sort((a, b) => String(a.host).localeCompare(String(b.host)));
            return json({ known: items });
        }
        if (method === 'DELETE') {
            const key = url.searchParams.get('key') || '';
            if (!/^known\/[a-zA-Z0-9._:\-\[\]]{1,300}$/.test(key) || key.includes('..')) {
                return json({ error: 'bad_key', message: '无效的记录' }, 400);
            }
            await del(env, key);
            return json({ ok: true });
        }
    }

    if (path === '/api/logs') {
        if (method === 'GET') {
            // 列表时顺手清一批过期录制（默认保留 90 天，每次最多删 50 条，
            // 避免一次请求吃光 CPU 预算）；会话结束时 cleanup 里也会清。
            await pruneOldLogs(env).catch(() => {});
            const objs = await list(env, 'logs/', true);
            const logs = objs
                .map((o) => ({
                    key: o.key,
                    size: o.size,
                    uploaded: o.uploaded instanceof Date ? o.uploaded.toISOString() : o.uploaded,
                    host: o.customMetadata?.host || '',
                    port: o.customMetadata?.port || '22',
                    user: o.customMetadata?.user || '',
                    started: o.customMetadata?.started || '',
                }))
                .sort((a, b) => String(b.uploaded).localeCompare(String(a.uploaded)));
            return json({ logs });
        }
        if (method === 'DELETE') {
            const key = url.searchParams.get('key') || '';
            if (!/^logs\/[a-zA-Z0-9._\-]{1,120}$/.test(key) || key.includes('..')) {
                return json({ error: 'bad_key', message: '无效的记录' }, 400);
            }
            await del(env, key);
            return json({ ok: true });
        }
    }

    if (path.startsWith('/api/logs/') && method === 'GET') {
        let key;
        try {
            key = decodeURIComponent(path.slice('/api/logs/'.length));
        } catch (_) {
            return json({ error: 'bad_key', message: '无效的记录' }, 400);
        }
        if (!/^logs\/[a-zA-Z0-9._\-]{1,120}$/.test(key) || key.includes('..')) {
            return json({ error: 'bad_key', message: '无效的记录' }, 400);
        }
        const obj = await getBytes(env, key);
        if (!obj) return json({ error: 'not_found', message: '记录不存在' }, 404);
        // 新记录以主密钥加密落盘（v2，绑定了文件名）；补丁前的记录没有 AAD，
        // 只能退回无上下文解密 —— 元数据里新旧都写着 enc:'v1'，靠不住，
        // 所以这里用「先带上下文、失败再退回」而不是按版本号分支。
        let text;
        if (!obj.meta.enc) {
            text = new TextDecoder().decode(obj.bytes);
        } else {
            try {
                text = new TextDecoder().decode(await auth.decryptBytes(env, obj.bytes, 'log:' + key));
            } catch (_) {
                text = new TextDecoder().decode(await auth.decryptBytes(env, obj.bytes));
            }
        }
        return new Response(text, {
            // 会话日志里可能粘着密码，走和页面同一套安全头（含 HTTPS 下的 HSTS）
            headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...securityHeaders(request) },
        });
    }

    return json({ error: 'not_found', message: '接口不存在' }, 404);
}

/* ------------------------------------------------------------- websocket */

// 「快速连接」允许连任意公网 host:port —— 这也意味着登录态一旦被拿走，
// 这个 Worker 就是一台免费的端口扫描器。加个按会话的预算：10 分钟 10 个目标。
const QUICK_LIMIT = 10;
const QUICK_WINDOW = 10 * 60 * 1000;

// 连保存过的主机同样要限速：以前只有临时地址那条分支有预算，
// 拿到会话的人可以循环 /ws?hostId=... 无限往外打 TCP。
// Worker 是无状态的，没有跨 isolate 的内存计数器，所以这里限的是「新建速率」
// 而不是「同时在线数」—— 会造成伤害的是短时间内打出去几百条连接。
const CONNECT_LIMIT = 20;
const CONNECT_WINDOW = 60 * 1000;

/**
 * 滑动窗口计数：prefix 下每个 key 的剩余部分以毫秒时间戳开头，
 * 超出窗口的顺手删掉（R2 没有 TTL，不删会一直涨）。
 * 返回 true 表示还有额度，并消耗一次。
 */
async function slidingBudget(env, prefix, limit, windowMs, ctx) {
    const now = Date.now();
    let used = 0;
    const stale = [];
    for (const o of await list(env, prefix)) {
        const ts = parseInt(o.key.slice(prefix.length), 10);
        if (!Number.isFinite(ts)) continue;
        if (now - ts < windowMs) used++;
        else stale.push(o.key);
    }
    if (stale.length) ctx.waitUntil(delAll(env, stale).catch(() => {}));
    if (used >= limit) return false;
    await putJSON(env, prefix + now + '-' + auth.randomHex(3), 1);
    return true;
}

async function quickConnectBudget(env, token, ctx) {
    return slidingBudget(env, 'conn/' + String(token).slice(0, 24) + '/', QUICK_LIMIT, QUICK_WINDOW, ctx);
}

async function connectBudget(env, token, ctx) {
    return slidingBudget(env, 'connall/' + String(token).slice(0, 24) + '/', CONNECT_LIMIT, CONNECT_WINDOW, ctx);
}

/** 用一条 WebSocket 把错误送达前端（升级失败的 HTTP 响应浏览器读不到 body） */
function socketError(message) {
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    try {
        server.send(JSON.stringify({ t: 'error', message }));
    } catch (_) {}
    setTimeout(() => {
        try {
            server.close(1008, 'rejected');
        } catch (_) {}
    }, 50);
    return new Response(null, { status: 101, webSocket: client });
}

async function handleWebSocket(request, env, ctx) {
    const upgrade = request.headers.get('upgrade') || '';
    if (upgrade.toLowerCase() !== 'websocket') return json({ error: 'upgrade_required' }, 426);
    assertSameOrigin(request);
    const session = await auth.getSession(env, request);
    if (!session) return json({ error: 'unauthorized', message: '登录已过期，请重新登录' }, 401);

    // Resolve the TCP target and open the socket here, inside the fetch handler:
    // Workers only allow connect() from a request context, and this also lets us
    // report resolution errors as a normal HTTP status.
    const url = new URL(request.url);
    const hostId = url.searchParams.get('hostId') || '';
    const qHost = (url.searchParams.get('host') || '').trim();
    const qPort = parseInt(url.searchParams.get('port'), 10) || 22;

    let target;
    if (hostId) {
        if (!/^[a-zA-Z0-9]+$/.test(hostId)) return json({ error: 'bad_id', message: '无效的主机 ID' }, 400);
        // 主机记录和连接预算并发取：升级响应要等这两件事都完成才能返回，
        // 串行就是白白多等一个 R2 往返
        const [rec, budget] = await Promise.all([
            getJSON(env, 'hosts/' + hostId),
            connectBudget(env, session.token, ctx),
        ]);
        if (!rec) return json({ error: 'not_found', message: '主机不存在，可能已被删除' }, 404);
        if (!budget) {
            return socketError(`连接建立过于频繁（每分钟最多 ${CONNECT_LIMIT} 次），请稍后再试。`);
        }
        // 旧部署里可能存着私网地址（拦截上线之前写入的）：建连时同样拒绝，
        // 不要只在创建时拦、连接时放行。
        if (!isPublicHost(rec.host)) return json({ error: 'private_host', message: '该主机为私网或保留地址，不允许连接，请改为公网地址' }, 400);
        target = { host: normalizeHost(rec.host), port: rec.port || 22, hostId, hostRec: rec };
    } else {
        const addr = normalizeHost(qHost);
        if (!addr) return json({ error: 'bad_host', message: '主机地址不合法' }, 400);
        if (!isPublicHost(addr)) return json({ error: 'private_host', message: '主机地址为私网或保留地址，不允许连接（只支持公网地址）' }, 400);
        if (qPort < 1 || qPort > 65535) return json({ error: 'bad_port', message: '端口不合法' }, 400);
        const [quick, budget] = await Promise.all([
            quickConnectBudget(env, session.token, ctx),
            connectBudget(env, session.token, ctx),
        ]);
        if (!quick) {
            return socketError(`临时连接过于频繁（${QUICK_WINDOW / 60000} 分钟内最多 ${QUICK_LIMIT} 个目标）。请先把常用主机保存下来再连接。`);
        }
        if (!budget) {
            return socketError(`连接建立过于频繁（每分钟最多 ${CONNECT_LIMIT} 次），请稍后再试。`);
        }
        target = { host: addr, port: qPort };
    }

    let socket;
    try {
        socket = connect({ hostname: target.host, port: target.port });
    } catch (e) {
        return json({ error: 'connect_failed', message: '无法建立 TCP 连接: ' + String((e && e.message) || e) }, 502);
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    const term = new Terminal(server, env, session.u, socket, target);
    // 立刻开始 SSH 传输层（版本 + KEX），不等浏览器发来 init：
    // 那条消息本身要占一个浏览器↔边缘的往返，正好用握手把它填满。
    term.warm().catch(() => {});
    server.addEventListener('message', (ev) => {
        try {
            term.handleMessage(ev.data);
        } catch (e) {
            try {
                server.send(JSON.stringify({ t: 'error', message: String((e && e.message) || e) }));
            } catch (_) {}
        }
    });
    server.addEventListener('close', () => {
        term.cleanup('ws-close');
    });
    server.addEventListener('error', () => {
        term.cleanup('ws-error');
    });

    return new Response(null, { status: 101, webSocket: client });
}

/* ------------------------------------------------------------------ entry */

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        try {
            if (!env.BUCKET) {
                return html(
                    '<!doctype html><meta charset="utf-8"><body style="font-family:system-ui;padding:40px;line-height:1.7">' +
                        '<h2>缺少 R2 存储绑定</h2><p>这个 Worker 需要 R2 绑定 <code>BUCKET</code>。' +
                        '在 wrangler.jsonc 中声明 <code>{ "binding": "BUCKET" }</code> 后重新部署即可自动创建。</p></body>',
                    request
                );
            }
            if (path === '/ws') return await handleWebSocket(request, env, ctx);
            if (path.startsWith('/api/')) return await handleApi(request, env, url);
            if (path === '/' || path === '/index.html') return html(renderShell(), request);
            if (env.ASSETS) {
                const res = await env.ASSETS.fetch(request);
                const headers = new Headers(res.headers);
                // .webmanifest 的 MIME 取决于托管方的映射表，这里兜底成标准类型：
                // 类型不对时部分浏览器会直接忽略 manifest，PWA 就装不上。
                if (path.endsWith('.webmanifest') && !/manifest\+json/.test(headers.get('content-type') || '')) {
                    headers.set('content-type', 'application/manifest+json; charset=utf-8');
                }
                for (const [k, v] of Object.entries(securityHeaders(request))) {
                    if (!headers.has(k)) headers.set(k, v);
                }
                return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
            }
            return new Response('Not found', { status: 404, headers: SECURITY_HEADERS });
        } catch (e) {
            const status = e instanceof HttpError ? e.status : 500;
            if (path.startsWith('/api/') || path === '/ws') {
                return json({ error: status === 500 ? 'internal' : 'rejected', message: String((e && e.message) || e) }, status);
            }
            return new Response('Error: ' + String((e && e.message) || e), { status });
        }
    },
};
