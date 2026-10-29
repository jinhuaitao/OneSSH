import test from 'node:test';
import assert from 'node:assert/strict';

import worker from '../src/worker.js';
import { MemoryBucket, makeEnv, call, cookieFrom, tokenFrom, stored, ADMIN, ORIGIN } from './helpers.mjs';

const PW = ADMIN.password;

/** 新建一套干净环境并完成初始化，返回 { env, cookie } */
async function setupApp(extra) {
    const env = makeEnv(Object.assign({ __worker: worker }, extra || {}));
    const res = await call(env, '/api/setup', { method: 'POST', body: { username: ADMIN.username, password: PW } });
    assert.equal(res.status, 200, '初始化应当成功: ' + res.text);
    return { env, cookie: cookieFrom(res) };
}

async function ed25519Pem() {
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    const b64 = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n');
    return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----\n`;
}

/* ------------------------------------------------------------------ 初始化 */

test('初始状态：未初始化、未登录、没有初始化口令', async () => {
    const env = makeEnv({ __worker: worker });
    const res = await call(env, '/api/state');
    assert.equal(res.status, 200);
    assert.equal(res.json.setup, false);
    assert.equal(res.json.authed, false);
    assert.equal(res.json.needsSetupToken, false);
    assert.match(res.json.version, /^\d+\.\d+\.\d+$/);
});

test('初始化：弱口令被拒，合法口令拿到会话 Cookie', async () => {
    const env = makeEnv({ __worker: worker });

    let res = await call(env, '/api/setup', { method: 'POST', body: { username: 'admin', password: 'short' } });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'weak_password');

    res = await call(env, '/api/setup', { method: 'POST', body: { username: 'admin', password: 'password123' } });
    assert.equal(res.status, 400, '常见弱口令必须被拒');

    res = await call(env, '/api/setup', { method: 'POST', body: { username: 'admin', password: PW } });
    assert.equal(res.status, 200);
    const cookie = cookieFrom(res);
    assert.match(cookie, /^wssh_session=[a-f0-9]{64}$/);

    res = await call(env, '/api/state', { cookie });
    assert.equal(res.json.setup, true);
    assert.equal(res.json.authed, true);
    assert.equal(res.json.user, 'admin');
});

test('初始化：只能成功一次', async () => {
    const { env } = await setupApp();
    const res = await call(env, '/api/setup', { method: 'POST', body: { username: 'other', password: 'another-long-password' } });
    assert.equal(res.status, 409);
    assert.equal(res.json.error, 'already_setup');
});

test('初始化口令：设置后必须先通过校验', async () => {
    const env = makeEnv({ __worker: worker, WEBSSH_SETUP_TOKEN: 's3cret-setup-token' });

    let res = await call(env, '/api/state');
    assert.equal(res.json.needsSetupToken, true);

    res = await call(env, '/api/setup', { method: 'POST', body: { username: 'admin', password: PW } });
    assert.equal(res.status, 403);
    assert.equal(res.json.error, 'bad_token');

    res = await call(env, '/api/setup', { method: 'POST', body: { username: 'admin', password: PW, token: 's3cret-setup-token' } });
    assert.equal(res.status, 200);
});

/* -------------------------------------------------------------------- 鉴权 */

test('未登录访问受保护接口返回 401', async () => {
    const { env } = await setupApp();
    for (const path of ['/api/hosts', '/api/groups', '/api/keys', '/api/creds', '/api/snippets', '/api/known', '/api/logs']) {
        const res = await call(env, path);
        assert.equal(res.status, 401, path + ' 应当要求登录');
    }
});

test('登录：错误口令不透露账号是否存在，且成功后可拿到新会话', async () => {
    const { env } = await setupApp();

    let res = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: 'wrong-password-here' } });
    assert.equal(res.status, 401);
    const wrongUser = await call(env, '/api/login', { method: 'POST', body: { username: 'nobody', password: 'wrong-password-here' } });
    assert.equal(wrongUser.status, 401);
    assert.equal(wrongUser.json.message, res.json.message, '两种失败必须是同一句话');

    res = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW } });
    assert.equal(res.status, 200);
    assert.ok(tokenFrom(res));
});

test('登录限流：同一 IP 连续失败后锁定', async () => {
    const { env } = await setupApp();
    const ip = '203.0.113.9';
    for (let i = 0; i < 6; i++) {
        const res = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: 'bad-password-' + i }, ip });
        assert.equal(res.status, 401, '第 ' + (i + 1) + ' 次失败应当是 401');
    }
    const locked = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW }, ip });
    assert.equal(locked.status, 429);
    assert.ok(Number(locked.headers.get('retry-after')) > 0);

    // 换一个 IP 不受影响
    const other = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW }, ip: '203.0.113.10' });
    assert.equal(other.status, 200);
});

test('改密：旧会话全部失效，当前浏览器换发新 token', async () => {
    const { env, cookie } = await setupApp();
    const oldToken = cookie.split('=')[1];

    const res = await call(env, '/api/password', {
        method: 'POST',
        cookie,
        body: { current: PW, next: 'a-brand-new-long-password' },
    });
    assert.equal(res.status, 200);
    const fresh = cookieFrom(res);
    assert.notEqual(fresh.split('=')[1], oldToken, '改密必须换发新 token');

    assert.equal((await call(env, '/api/hosts', { cookie })).status, 401, '旧会话应当失效');
    assert.equal((await call(env, '/api/hosts', { cookie: fresh })).status, 200);

    const relogin = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: 'a-brand-new-long-password' } });
    assert.equal(relogin.status, 200);
});

test('改密：当前密码错误时不生效', async () => {
    const { env, cookie } = await setupApp();
    const res = await call(env, '/api/password', { method: 'POST', cookie, body: { current: 'not-the-password', next: 'another-long-password' } });
    assert.equal(res.status, 401);
    const again = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW } });
    assert.equal(again.status, 200, '密码不应被改动');
});

test('登出后会话立即失效', async () => {
    const { env, cookie } = await setupApp();
    assert.equal((await call(env, '/api/logout', { method: 'POST', cookie })).status, 200);
    assert.equal((await call(env, '/api/hosts', { cookie })).status, 401);
});

/* --------------------------------------------------------------- 跨站防护 */

test('跨站写请求被拒，同源放行', async () => {
    const { env, cookie } = await setupApp();
    const evil = await call(env, '/api/hosts', {
        method: 'POST',
        cookie,
        headers: { origin: 'https://evil.example' },
        body: { host: '192.0.2.10', username: 'root', password: 'x' },
    });
    assert.equal(evil.status, 403);

    const same = await call(env, '/api/hosts', {
        method: 'POST',
        cookie,
        headers: { origin: ORIGIN },
        body: { host: '192.0.2.10', username: 'root', password: 'x' },
    });
    assert.equal(same.status, 200);
});

test('写接口只接受 application/json，并限制请求体大小', async () => {
    const { env, cookie } = await setupApp();

    const wrongType = await call(env, '/api/hosts', {
        method: 'POST',
        cookie,
        headers: { 'content-type': 'text/plain' },
        body: '{"host":"192.0.2.10"}',
    });
    assert.equal(wrongType.status, 415);

    const huge = await call(env, '/api/hosts', {
        method: 'POST',
        cookie,
        body: { host: '192.0.2.10', username: 'root', note: 'x'.repeat(5 * 1024 * 1024) },
    });
    assert.equal(huge.status, 413);
});

test('安全响应头齐备', async () => {
    const env = makeEnv({ __worker: worker });
    const page = await call(env, '/');
    assert.equal(page.status, 200);
    const csp = page.headers.get('content-security-policy');
    assert.ok(csp && csp.includes("default-src 'self'"), '缺少 CSP');
    assert.ok(csp.includes("frame-ancestors 'none'"));
    assert.ok(csp.includes("worker-src 'none'"));
    assert.equal(page.headers.get('x-frame-options'), 'DENY');
    assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
    assert.ok(page.headers.get('permissions-policy'));

    const api = await call(env, '/api/state');
    assert.equal(api.headers.get('cache-control'), 'no-store');
});

/* ------------------------------------------------------------------- 主机 */

test('主机 CRUD：密文不外泄、更新时保留旧凭据', async () => {
    const { env, cookie } = await setupApp();

    let res = await call(env, '/api/hosts', {
        method: 'POST',
        cookie,
        body: { name: '生产机', host: '192.0.2.10', port: 2222, username: 'root', password: 'hunter2', group: 'prod' },
    });
    assert.equal(res.status, 200);
    const host = res.json.host;
    assert.equal(host.host, '192.0.2.10');
    assert.equal(host.port, 2222);
    assert.equal(host.hasSecret, true);
    assert.equal(host.secretEnc, undefined, '密文不能出现在响应里');
    assert.equal(host.keyEnc, undefined);

    // 更新时不带密码：凭据要保留
    res = await call(env, '/api/hosts', { method: 'POST', cookie, body: { id: host.id, name: '生产机 A', host: '192.0.2.10', port: 2222, username: 'root' } });
    assert.equal(res.status, 200);
    assert.equal(res.json.host.name, '生产机 A');
    assert.equal(res.json.host.hasSecret, true);

    res = await call(env, '/api/hosts', { cookie });
    assert.equal(res.json.hosts.length, 1);

    res = await call(env, '/api/hosts/' + host.id, { method: 'DELETE', cookie });
    assert.equal(res.status, 200);
    res = await call(env, '/api/hosts', { cookie });
    assert.equal(res.json.hosts.length, 0);
});

test('主机：地址与端口校验', async () => {
    const { env, cookie } = await setupApp();
    const cases = [
        [{ host: 'not a host!', username: 'root' }, 'bad host'],
        [{ host: '192.0.2.10', port: 70000, username: 'root' }, 'bad port'],
        [{ host: '192.0.2.10', username: '' }, 'empty user'],
    ];
    for (const [body, label] of cases) {
        const res = await call(env, '/api/hosts', { method: 'POST', cookie, body });
        assert.equal(res.status, 400, label);
    }

    // IPv6 统一补方括号
    const ok = await call(env, '/api/hosts', { method: 'POST', cookie, body: { host: '2001:db8::1', username: 'root', password: 'x' } });
    assert.equal(ok.json.host.host, '[2001:db8::1]');
});

test('主机：删除不存在的记录返回 404', async () => {
    const { env, cookie } = await setupApp();
    const res = await call(env, '/api/hosts/doesnotexist', { method: 'DELETE', cookie });
    assert.equal(res.status, 404);
});

test('主机：保存凭据与连接目标必须一致（防凭据钓取）', async () => {
    const { env, cookie } = await setupApp();
    const created = await call(env, '/api/hosts', {
        method: 'POST',
        cookie,
        body: { host: '192.0.2.10', username: 'root', password: 'x' },
    });
    const id = created.json.host.id;
    const saved = stored(env, 'hosts/' + id);
    assert.ok(saved.secretEnc, '密码应当以密文落盘');
    assert.equal(saved.password, undefined, '明文密码不能落盘');
});

/* ------------------------------------------------------------------- 分组 */

test('分组：新增 / 重命名同步主机 / 删除后主机回到未分组', async () => {
    const { env, cookie } = await setupApp();
    await call(env, '/api/hosts', { method: 'POST', cookie, body: { host: '192.0.2.1', username: 'root', password: 'x', group: 'prod' } });

    let res = await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'add', name: 'stage' } });
    assert.deepEqual(res.json.groups.sort(), ['prod', 'stage']);

    res = await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'rename', from: 'prod', to: 'production' } });
    assert.equal(res.json.updated, 1);

    const hosts = await call(env, '/api/hosts', { cookie });
    assert.equal(hosts.json.hosts[0].group, 'production');

    res = await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'remove', name: 'production' } });
    assert.equal(res.json.moved, 1);
    const after = await call(env, '/api/hosts', { cookie });
    assert.equal(after.json.hosts[0].group, '');
});

test('分组：重名与非法名称被拒', async () => {
    const { env, cookie } = await setupApp();
    await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'add', name: 'prod' } });
    assert.equal((await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'add', name: 'prod' } })).status, 409);
    assert.equal((await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'add', name: 'a/b' } })).status, 400);
});

/* ----------------------------------------------------------------- 凭据库 */

test('凭据库：新增常用账号并可被主机引用，占用时禁止删除', async () => {
    const { env, cookie } = await setupApp();

    const cred = await call(env, '/api/creds', { method: 'POST', cookie, body: { name: 'root@prod', username: 'root', password: 'cred-pass' } });
    assert.equal(cred.status, 200);
    const credId = cred.json.cred.id;

    const list = await call(env, '/api/creds', { cookie });
    assert.equal(list.json.creds.length, 1);
    assert.equal(list.json.creds[0].passEnc, undefined, '密码密文不能下发');

    const host = await call(env, '/api/hosts', { method: 'POST', cookie, body: { host: '192.0.2.10', username: 'root', credId } });
    assert.equal(host.status, 200);
    assert.equal(host.json.host.credId, credId);

    const blocked = await call(env, '/api/creds/' + credId, { method: 'DELETE', cookie });
    assert.equal(blocked.status, 409);
    assert.equal(blocked.json.error, 'in_use');
});

test('凭据库：私钥入库时算出指纹，非法私钥被拒', async () => {
    const { env, cookie } = await setupApp();
    const pem = await ed25519Pem();

    const key = await call(env, '/api/keys', { method: 'POST', cookie, body: { name: 'ops', privateKey: pem } });
    assert.equal(key.status, 200, key.text);
    assert.equal(key.json.key.algo, 'ssh-ed25519');
    assert.match(key.json.key.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/);

    const bad = await call(env, '/api/keys', { method: 'POST', cookie, body: { name: 'broken', privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nzzzz\n-----END OPENSSH PRIVATE KEY-----' } });
    assert.equal(bad.status, 400);
    assert.equal(bad.json.error, 'bad_key');

    const vault = stored(env, 'sys/keys');
    assert.ok(vault.keys[0].keyEnc, '私钥必须以密文落盘');
    assert.equal(vault.keys[0].privateKey, undefined);
});

/* ----------------------------------------------------------------- 片段 */

test('代码片段：保存、限制条数、过滤空命令', async () => {
    const { env, cookie } = await setupApp();
    const res = await call(env, '/api/snippets', {
        method: 'POST',
        cookie,
        body: {
            snippets: [
                { name: '磁盘', command: 'df -h' },
                { name: '空', command: '   ' },
                { id: 'abc123', name: '内存', command: 'free -m' },
            ],
        },
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.snippets.length, 2);
    assert.equal(res.json.snippets[1].id, 'abc123');

    const got = await call(env, '/api/snippets', { cookie });
    assert.equal(got.json.snippets.length, 2);
});

/* --------------------------------------------------------------- 路径安全 */

test('日志与已知主机：拒绝路径穿越与非法 key', async () => {
    const { env, cookie } = await setupApp();
    const bad = [
        '/api/logs?key=' + encodeURIComponent('logs/../../sys/admin'),
        '/api/logs?key=' + encodeURIComponent('sys/admin'),
        '/api/logs/' + encodeURIComponent('logs/../sys/admin'),
        '/api/known?key=' + encodeURIComponent('known/../sys/admin'),
    ];
    for (const p of bad) {
        const res = await call(env, p, { method: 'DELETE', cookie });
        assert.ok(res.status === 400 || res.status === 404, p + ' → ' + res.status);
    }
    // 合法 key 才能删
    const ok = await call(env, '/api/known?key=' + encodeURIComponent('known/192.0.2.10_22'), { method: 'DELETE', cookie });
    assert.equal(ok.status, 200);
});

test('日志列表为空时不报错，且带 no-store', async () => {
    const { env, cookie } = await setupApp();
    const res = await call(env, '/api/logs', { cookie });
    assert.equal(res.status, 200);
    assert.deepEqual(res.json.logs, []);
    assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('未知接口返回 404 JSON', async () => {
    const { env, cookie } = await setupApp();
    const res = await call(env, '/api/nope', { cookie });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'not_found');
});

/* ------------------------------------------------------------- 主密钥边界 */

test('主密钥：WEBSSH_MASTER_KEY 优先于 R2 里的 sys/master', async () => {
    const env = makeEnv({ __worker: worker, WEBSSH_MASTER_KEY: 'a'.repeat(64) });
    const res = await call(env, '/api/setup', { method: 'POST', body: { username: 'admin', password: PW } });
    assert.equal(res.status, 200);
    assert.equal(env.BUCKET.map.has('sys/master'), false, '自带密钥时不应再写 sys/master');

    const host = await call(env, '/api/hosts', { method: 'POST', cookie: cookieFrom(res), body: { host: '192.0.2.10', username: 'root', password: 'x' } });
    assert.equal(host.status, 200);
    const saved = stored(env, 'hosts/' + host.json.host.id);
    assert.match(saved.secretEnc, /^v1:/);
});

test('主密钥：非法长度直接报错，且不留下「半初始化」状态', async () => {
    const env = makeEnv({ __worker: worker, WEBSSH_MASTER_KEY: 'tooshort' });
    const res = await call(env, '/api/setup', { method: 'POST', body: { username: 'admin', password: PW } });
    assert.equal(res.status, 500);

    // 关键：管理员记录不能被写进去，否则 setup 再也跑不了，用户只能去 R2 里手删
    assert.equal(env.BUCKET.map.has('sys/admin'), false, '失败时不能落管理员记录');
    const state = await call(env, '/api/state');
    assert.equal(state.json.setup, false, '仍应处于未初始化状态，方便修好密钥后重试');

    // 换成合法密钥后重试应当成功
    env.WEBSSH_MASTER_KEY = 'ab'.repeat(32);
    const retry = await call(env, '/api/setup', { method: 'POST', body: { username: 'admin', password: PW } });
    assert.equal(retry.status, 200);
});

test('MemoryBucket 自身行为符合 R2 语义（条件写 + 分页）', async () => {
    const b = new MemoryBucket();
    assert.equal(await b.put('k', 'v1', { onlyIf: new Headers({ 'If-None-Match': '*' }) }) !== null, true);
    assert.equal(await b.put('k', 'v2', { onlyIf: new Headers({ 'If-None-Match': '*' }) }), null, '已存在时条件写必须失败');
    assert.equal(await (await b.get('k')).text(), 'v1');

    for (let i = 0; i < 7; i++) await b.put('p/' + i, 'x');
    const first = await b.list({ prefix: 'p/', limit: 3 });
    assert.equal(first.objects.length, 3);
    assert.equal(first.truncated, true);
    const second = await b.list({ prefix: 'p/', limit: 3, cursor: first.cursor });
    assert.equal(second.objects.length, 3);
    const third = await b.list({ prefix: 'p/', limit: 3, cursor: second.cursor });
    assert.equal(third.objects.length, 1);
    assert.equal(third.truncated, false);
});
