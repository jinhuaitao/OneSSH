// WebSSH — Cloudflare Worker entry (API + WebSocket bridge + static shell)
import { Terminal } from './session.js';
import { normalizeHost } from './hostaddr.js';
import { connect } from 'cloudflare:sockets';
import * as auth from './auth.js';
import { getJSON, putJSON, del, list, getText } from './store.js';
import { renderShell } from './pages.js';
import { loadPrivateKey } from './ssh/keys.js';
import { fingerprint } from './ssh/crypto.js';

const VERSION = '1.0.0';

const SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy':
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
        "connect-src 'self' ws: wss:; font-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
};

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

function html(body) {
    return new Response(body, {
        headers: {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-cache',
            ...SECURITY_HEADERS,
        },
    });
}

async function readJSON(request) {
    const ct = request.headers.get('content-type') || '';
    if (!ct.includes('application/json')) throw new HttpError(415, '请求必须使用 application/json');
    try {
        return await request.json();
    } catch (_) {
        throw new HttpError(400, '请求体不是合法 JSON');
    }
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
    await putJSON(env, 'sys/groups', { groups, updatedAt: Date.now() });
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
    for (const o of await list(env, 'hosts/')) {
        const rec = await getJSON(env, o.key);
        const name = rec && String(rec.group || '').trim();
        if (name && !seen.has(name)) {
            seen.add(name);
            out.push(name);
        }
    }
    return out;
}

async function retagHosts(env, from, to) {
    let n = 0;
    for (const o of await list(env, 'hosts/')) {
        const rec = await getJSON(env, o.key);
        if (!rec || String(rec.group || '').trim() !== from) continue;
        rec.group = to;
        rec.updatedAt = Date.now();
        await putJSON(env, o.key, rec);
        n++;
    }
    return n;
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

/* -------------------------------------------------------------------- api */

async function handleApi(request, env, url) {
    const path = url.pathname;
    const method = request.method;

    if (path === '/api/state' && method === 'GET') {
        const admin = await auth.getAdmin(env);
        const session = admin ? await auth.getSession(env, request) : null;
        return json({
            setup: Boolean(admin),
            authed: Boolean(session),
            user: session ? session.u : null,
            version: VERSION,
            username: admin ? admin.username : null,
        });
    }

    if (path === '/api/setup' && method === 'POST') {
        const admin = await auth.getAdmin(env);
        if (admin) return json({ error: 'already_setup', message: '系统已经完成初始化' }, 409);
        const body = await readJSON(request);
        const username = String(body.username || '').trim();
        const password = String(body.password || '');
        if (!/^[a-zA-Z0-9_.@-]{3,32}$/.test(username)) {
            return json({ error: 'bad_username', message: '用户名需为 3-32 位字母、数字或 _ . @ -' }, 400);
        }
        if (password.length < 8) return json({ error: 'weak_password', message: '密码至少 8 位' }, 400);
        await auth.createAdmin(env, username, password);
        const token = await auth.createSession(env, username, request);
        return json({ ok: true }, 200, { 'set-cookie': auth.sessionCookie(token, request) });
    }

    if (path === '/api/login' && method === 'POST') {
        const ip = request.headers.get('cf-connecting-ip') || '';
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
        await auth.clearFailures(env, ip);
        try {
            await auth.pruneSessions(env);
        } catch (_) {}
        const token = await auth.createSession(env, admin.username, request);
        return json({ ok: true, user: admin.username }, 200, { 'set-cookie': auth.sessionCookie(token, request) });
    }

    /* -------------------------------------------------- authenticated area */

    const session = await auth.getSession(env, request);
    if (!session) return json({ error: 'unauthorized', message: '登录已过期，请重新登录' }, 401);

    if (path === '/api/logout' && method === 'POST') {
        await auth.destroySession(env, session.token);
        return json({ ok: true }, 200, { 'set-cookie': auth.clearCookie(request) });
    }

    if (path === '/api/password' && method === 'POST') {
        const body = await readJSON(request);
        const admin = await auth.verifyLogin(env, session.u, body.current);
        if (!admin) return json({ error: 'bad_credentials', message: '当前密码不正确' }, 401);
        if (String(body.next || '').length < 8) return json({ error: 'weak_password', message: '新密码至少 8 位' }, 400);
        await auth.createAdmin(env, admin.username, String(body.next));
        await auth.destroySession(env, session.token);
        const token = await auth.createSession(env, admin.username, request);
        return json({ ok: true }, 200, { 'set-cookie': auth.sessionCookie(token, request) });
    }

    if (path === '/api/groups') {
        if (method === 'GET') {
            return json({ groups: await listGroups(env) });
        }
        if (method === 'POST') {
            const body = await readJSON(request);
            const stored = await storedGroups(env);
            const groups = await listGroups(env);
            const op = String(body.op || '');
            if (op === 'add') {
                const name = cleanGroupName(body.name);
                if (groups.includes(name)) return json({ error: 'dup', message: '同名分组已存在' }, 409);
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
            return json({ keys: (await storedKeys(env)).map(publicKeyMeta) });
        }
        if (method === 'POST') {
            const body = await readJSON(request);
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
            const rec = {
                id: entry ? entry.id : 'k' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
                name,
                algo: meta ? meta.algo : entry.algo,
                fingerprint: meta ? meta.fingerprint : entry.fingerprint,
                keyEnc: keyText ? await auth.encryptSecret(env, keyText) : entry.keyEnc,
                passphraseEnc: body.passphrase
                    ? await auth.encryptSecret(env, String(body.passphrase))
                    : entry
                      ? entry.passphraseEnc || null
                      : null,
                createdAt: entry ? entry.createdAt : Date.now(),
                updatedAt: Date.now(),
            };
            const next = entry ? keys.map((k) => (k.id === rec.id ? rec : k)) : keys.concat(rec);
            await putJSON(env, 'sys/keys', { keys: next, updatedAt: Date.now() });
            return json({ key: publicKeyMeta(rec) });
        }
    }

    if (path.startsWith('/api/keys/') && method === 'DELETE') {
        const id = path.slice('/api/keys/'.length);
        if (!/^[a-zA-Z0-9]+$/.test(id)) return json({ error: 'bad_id', message: '无效的密钥 ID' }, 400);
        const keys = await storedKeys(env);
        if (!keys.some((k) => k.id === id)) return json({ error: 'not_found', message: '密钥不存在' }, 404);
        let used = 0;
        for (const o of await list(env, 'hosts/')) {
            const rec = await getJSON(env, o.key);
            if (rec && rec.keyId === id) used++;
        }
        if (used) return json({ error: 'in_use', message: `该密钥正被 ${used} 台主机使用，请先改用其他凭据` }, 409);
        await putJSON(env, 'sys/keys', { keys: keys.filter((k) => k.id !== id), updatedAt: Date.now() });
        return json({ ok: true });
    }

    if (path === '/api/creds') {
        if (method === 'GET') {
            return json({ creds: (await storedCreds(env)).map(publicCredMeta) });
        }
        if (method === 'POST') {
            const body = await readJSON(request);
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
            const rec = {
                id: entry ? entry.id : 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
                name,
                username,
                passEnc: password ? await auth.encryptSecret(env, password) : entry.passEnc,
                createdAt: entry ? entry.createdAt : Date.now(),
                updatedAt: Date.now(),
            };
            const next = entry ? creds.map((c) => (c.id === rec.id ? rec : c)) : creds.concat(rec);
            await putJSON(env, 'sys/creds', { creds: next, updatedAt: Date.now() });
            // hosts keep a denormalised username for list rendering
            if (entry && entry.username !== username) {
                for (const o of await list(env, 'hosts/')) {
                    const host = await getJSON(env, o.key);
                    if (host && host.credId === rec.id) {
                        host.username = username;
                        host.updatedAt = Date.now();
                        await putJSON(env, o.key, host);
                    }
                }
            }
            return json({ cred: publicCredMeta(rec) });
        }
    }

    if (path.startsWith('/api/creds/') && method === 'DELETE') {
        const id = path.slice('/api/creds/'.length);
        if (!/^[a-zA-Z0-9]+$/.test(id)) return json({ error: 'bad_id', message: '无效的账号 ID' }, 400);
        const creds = await storedCreds(env);
        if (!creds.some((c) => c.id === id)) return json({ error: 'not_found', message: '常用账号不存在' }, 404);
        let used = 0;
        for (const o of await list(env, 'hosts/')) {
            const rec = await getJSON(env, o.key);
            if (rec && rec.credId === id) used++;
        }
        if (used) return json({ error: 'in_use', message: `该账号正被 ${used} 台主机使用，请先改用其他凭据` }, 409);
        await putJSON(env, 'sys/creds', { creds: creds.filter((c) => c.id !== id), updatedAt: Date.now() });
        return json({ ok: true });
    }

    if (path === '/api/hosts') {
        if (method === 'GET') {
            const objs = await list(env, 'hosts/');
            const hosts = [];
            for (const o of objs) {
                const rec = await getJSON(env, o.key);
                if (rec) hosts.push(publicHost(rec));
            }
            hosts.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0) || (a.name || '').localeCompare(b.name || ''));
            return json({ hosts });
        }
        if (method === 'POST') {
            const body = await readJSON(request);
            const base = cleanHostInput(body);
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
                    rec.secretEnc = saveSecret ? await auth.encryptSecret(env, String(body.password)) : null;
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
                    rec.keyEnc = saveSecret ? await auth.encryptSecret(env, keyText) : null;
                    if (body.passphrase) {
                        rec.passphraseEnc = saveSecret ? await auth.encryptSecret(env, String(body.passphrase)) : null;
                    }
                } else if (existing && existing.keyEnc && saveSecret) {
                    rec.keyEnc = existing.keyEnc;
                    rec.passphraseEnc = existing.passphraseEnc || null;
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
        await del(env, 'hosts/' + id);
        return json({ ok: true });
    }

    if (path === '/api/snippets') {
        if (method === 'GET') {
            const rec = await getJSON(env, 'sys/snippets');
            return json({ snippets: (rec && rec.snippets) || [] });
        }
        if (method === 'POST') {
            const body = await readJSON(request);
            const list = Array.isArray(body.snippets) ? body.snippets.slice(0, 100) : [];
            const clean = list
                .filter((s) => s && typeof s.command === 'string' && s.command.trim())
                .map((s) => ({
                    id: String(s.id || 's' + Math.random().toString(36).slice(2, 9)).slice(0, 24),
                    name: String(s.name || '').slice(0, 60) || s.command.slice(0, 30),
                    command: String(s.command).slice(0, 2000),
                }));
            await putJSON(env, 'sys/snippets', { snippets: clean, updatedAt: Date.now() });
            return json({ snippets: clean });
        }
    }

    if (path === '/api/known') {
        if (method === 'GET') {
            const objs = await list(env, 'known/');
            const items = [];
            for (const o of objs) {
                const rec = await getJSON(env, o.key);
                if (rec) items.push({ key: o.key, ...rec });
            }
            items.sort((a, b) => String(a.host).localeCompare(String(b.host)));
            return json({ known: items });
        }
        if (method === 'DELETE') {
            const key = url.searchParams.get('key') || '';
            if (!key.startsWith('known/')) return json({ error: 'bad_key', message: '无效的记录' }, 400);
            await del(env, key);
            return json({ ok: true });
        }
    }

    if (path === '/api/logs') {
        if (method === 'GET') {
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
            if (!key.startsWith('logs/') || key.includes('..')) return json({ error: 'bad_key', message: '无效的记录' }, 400);
            await del(env, key);
            return json({ ok: true });
        }
    }

    if (path.startsWith('/api/logs/') && method === 'GET') {
        const key = decodeURIComponent(path.slice('/api/logs/'.length));
        if (!key.startsWith('logs/') || key.includes('..')) return json({ error: 'bad_key', message: '无效的记录' }, 400);
        const text = await getText(env, key);
        if (text == null) return json({ error: 'not_found', message: '记录不存在' }, 404);
        return new Response(text, {
            headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...SECURITY_HEADERS },
        });
    }

    return json({ error: 'not_found', message: '接口不存在' }, 404);
}

/* ------------------------------------------------------------- websocket */

async function handleWebSocket(request, env) {
    const upgrade = request.headers.get('upgrade') || '';
    if (upgrade.toLowerCase() !== 'websocket') return json({ error: 'upgrade_required' }, 426);
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
        const rec = await getJSON(env, 'hosts/' + hostId);
        if (!rec) return json({ error: 'not_found', message: '主机不存在，可能已被删除' }, 404);
        target = { host: normalizeHost(rec.host), port: rec.port || 22 };
    } else {
        const addr = normalizeHost(qHost);
        if (!addr) return json({ error: 'bad_host', message: '主机地址不合法' }, 400);
        if (qPort < 1 || qPort > 65535) return json({ error: 'bad_port', message: '端口不合法' }, 400);
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
                        '在 wrangler.jsonc 中声明 <code>{ "binding": "BUCKET" }</code> 后重新部署即可自动创建。</p></body>'
                );
            }
            if (path === '/ws') return await handleWebSocket(request, env);
            if (path.startsWith('/api/')) return await handleApi(request, env, url);
            if (path === '/' || path === '/index.html') return html(renderShell());
            if (env.ASSETS) return env.ASSETS.fetch(request);
            return new Response('Not found', { status: 404 });
        } catch (e) {
            const status = e instanceof HttpError ? e.status : 500;
            if (path.startsWith('/api/')) {
                return json({ error: 'internal', message: String((e && e.message) || e) }, status);
            }
            return new Response('Error: ' + String((e && e.message) || e), { status });
        }
    },
};
