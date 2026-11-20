import test from 'node:test';
import assert from 'node:assert/strict';

import worker from '../src/worker.js';
import * as auth from '../src/auth.js';
import { makeEnv, call, cookieFrom, stored, ADMIN, SETUP_TOKEN } from './helpers.mjs';

const PW = ADMIN.password;

async function setupApp(extra) {
    const env = makeEnv(Object.assign({ __worker: worker }, extra || {}));
    const res = await call(env, '/api/setup', {
        method: 'POST',
        body: { username: ADMIN.username, password: PW, token: SETUP_TOKEN },
    });
    assert.equal(res.status, 200, '初始化应当成功: ' + res.text);
    return { env, cookie: cookieFrom(res) };
}

async function seedData(env, cookie) {
    await call(env, '/api/hosts', { method: 'POST', cookie, body: { host: '203.0.113.10', username: 'root', password: 'host-secret' } });
    await call(env, '/api/creds', { method: 'POST', cookie, body: { name: 'root', username: 'root', password: 'cred-secret' } });
    await call(env, '/api/snippets', { method: 'POST', cookie, body: { snippets: [{ name: '磁盘', command: 'df -h' }] } });
    await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'add', name: 'prod' } });
}

/* ------------------------------------------------------- 乐观并发版本 */

test('版本：GET 返回 version，POST 带过期 expectedVersion 返回 409', async () => {
    const { env, cookie } = await setupApp();

    let g = await call(env, '/api/groups', { cookie });
    assert.equal(g.json.version, 0, '未写过时版本为 0');
    const stale = await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'add', name: 'prod', expectedVersion: 99 } });
    assert.equal(stale.status, 409);
    assert.equal(stale.json.error, 'version_conflict');
    assert.equal(stale.json.currentVersion, 0);

    const ok = await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'add', name: 'prod', expectedVersion: 0 } });
    assert.equal(ok.status, 200, ok.text);
    g = await call(env, '/api/groups', { cookie });
    assert.equal(g.json.version, 1, '写一次版本 +1');

    const stale2 = await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'add', name: 'stage', expectedVersion: 0 } });
    assert.equal(stale2.status, 409);
    assert.equal(stale2.json.currentVersion, 1);

    // 片段同样受版本保护
    const s0 = await call(env, '/api/snippets', { cookie });
    assert.equal(s0.json.version, 0);
    const bad = await call(env, '/api/snippets', { method: 'POST', cookie, body: { snippets: [{ name: 'x', command: 'ls' }], expectedVersion: 5 } });
    assert.equal(bad.status, 409);
    const good = await call(env, '/api/snippets', { method: 'POST', cookie, body: { snippets: [{ name: 'x', command: 'ls' }], expectedVersion: 0 } });
    assert.equal(good.status, 200);
    assert.equal((await call(env, '/api/snippets', { cookie })).json.version, 1);
});

test('版本：不带 expectedVersion 的旧客户端仍可写（向后兼容）', async () => {
    const { env, cookie } = await setupApp();
    const res = await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'add', name: 'prod' } });
    assert.equal(res.status, 200);
});

/* ------------------------------------------------------- 加密导出 / 导入 */

test('导出/导入：往返恢复数据，错密码与未确认都不覆盖现有数据', async () => {
    const { env, cookie } = await setupApp();
    await seedData(env, cookie);
    const beforeHosts = (await call(env, '/api/hosts', { cookie })).json.hosts;
    assert.equal(beforeHosts.length, 1);

    const exp = await call(env, '/api/export', { method: 'POST', cookie, body: { exportPassword: 'export-pass-long' } });
    assert.equal(exp.status, 200, exp.text);
    assert.ok(exp.json.salt && exp.json.iv && exp.json.ciphertext, '导出包是 {salt, iv, ciphertext}');
    assert.equal(exp.json.masterKey, undefined, '主密钥不能明文出现在响应里');

    // 未确认拒绝
    const noConfirm = await call(env, '/api/import', { method: 'POST', cookie, body: { exportPassword: 'export-pass-long', data: exp.json } });
    assert.equal(noConfirm.status, 400);
    assert.equal(noConfirm.json.error, 'confirm_required');
    assert.equal((await call(env, '/api/hosts', { cookie })).json.hosts.length, 1, '拒绝导入后数据不动');

    // 错密码拒绝
    const wrong = await call(env, '/api/import', { method: 'POST', cookie, body: { exportPassword: 'wrong-password', data: exp.json, confirm: true } });
    assert.equal(wrong.status, 400);
    assert.equal(wrong.json.error, 'bad_export');
    assert.equal((await call(env, '/api/hosts', { cookie })).json.hosts.length, 1);

    // 先删掉主机，再导入恢复
    await call(env, '/api/hosts/' + beforeHosts[0].id, { method: 'DELETE', cookie });
    assert.equal((await call(env, '/api/hosts', { cookie })).json.hosts.length, 0);
    const imp = await call(env, '/api/import', { method: 'POST', cookie, body: { exportPassword: 'export-pass-long', data: exp.json, confirm: true } });
    assert.equal(imp.status, 200, imp.text);
    assert.deepEqual(imp.json.imported, { hosts: 1, keys: 0, creds: 1, groups: 1, snippets: 1 });
    const after = (await call(env, '/api/hosts', { cookie })).json.hosts;
    assert.equal(after.length, 1);
    assert.equal(after[0].host, '203.0.113.10');
    assert.equal(after[0].hasSecret, true, '导入后凭据仍在（主密钥一起恢复了）');
    // 凭据确实能解开：用主密钥直接解密落盘密文
    const saved = stored(env, 'hosts/' + after[0].id);
    assert.equal(await auth.decryptSecret(env, saved.secretEnc, 'host:' + after[0].id), 'host-secret');
});

test('导出：密码太短被拒；启用 TOTP 后导出需验证码', async () => {
    const { env, cookie } = await setupApp();
    const short = await call(env, '/api/export', { method: 'POST', cookie, body: { exportPassword: 'short' } });
    assert.equal(short.status, 400);

    const setup = await call(env, '/api/totp/setup', { method: 'POST', cookie });
    const secret = setup.json.secret;
    await call(env, '/api/totp/enable', { method: 'POST', cookie, body: { code: await auth.totpCodeFor(secret, auth.totpCounter()) } });

    const noCode = await call(env, '/api/export', { method: 'POST', cookie, body: { exportPassword: 'export-pass-long' } });
    assert.equal(noCode.status, 401);
    assert.equal(noCode.json.error, 'totp_required');
    const withCode = await call(env, '/api/export', {
        method: 'POST',
        cookie,
        body: { exportPassword: 'export-pass-long', totpCode: await auth.totpCodeFor(secret, auth.totpCounter() + 1) },
    });
    assert.equal(withCode.status, 200, withCode.text);
});

test('录制保留期：GET /api/logs 时清掉 90 天前的录制', async () => {
    const env = makeEnv({ __worker: worker });
    const put = async (key, daysAgo) => {
        await env.BUCKET.put(key, new Uint8Array([1, 2, 3]), { customMetadata: { enc: 'v2' } });
        env.BUCKET.map.get(key).uploaded = new Date(Date.now() - daysAgo * 24 * 3600 * 1000);
    };
    await put('logs/old.log', 100);
    await put('logs/new.log', 40);
    // 先初始化拿到会话（seed 的日志与账号无关，但 /api/logs 需要登录）
    const setup = await call(env, '/api/setup', { method: 'POST', body: { username: ADMIN.username, password: PW, token: SETUP_TOKEN } });
    assert.equal(setup.status, 200, setup.text);
    const res = await call(env, '/api/logs', { cookie: cookieFrom(setup) });
    assert.equal(res.status, 200);
    assert.deepEqual(res.json.logs.map((l) => l.key), ['logs/new.log'], '列表里不应再有过期录制');
    assert.deepEqual(env.BUCKET.keys('logs/'), ['logs/new.log']);
});
