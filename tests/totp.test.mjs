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

/** 未来一步的码：enable 已消耗当前步的计数值，登录用下一步的码才不会撞重放。 */
async function nextCode(secret) {
    return auth.totpCodeFor(secret, auth.totpCounter() + 1);
}

async function enableTotp(env, cookie) {
    const setup = await call(env, '/api/totp/setup', { method: 'POST', cookie });
    assert.equal(setup.status, 200, setup.text);
    const secret = setup.json.secret;
    const code = await auth.totpCodeFor(secret, auth.totpCounter());
    const enabled = await call(env, '/api/totp/enable', { method: 'POST', cookie, body: { code } });
    assert.equal(enabled.status, 200, enabled.text);
    return { secret, backupCodes: setup.json.backupCodes, uri: setup.json.otpauthUri };
}

/* ------------------------------------------------------------ TOTP 原语 */

test('TOTP：正确码通过、错码拒绝、同一计数值重放拒绝', async () => {
    const secret = auth.generateTotpSecret();
    assert.match(secret, /^[A-Z2-7]{32}$/);
    assert.ok(auth.totpOtpauthUri(secret, 'admin').startsWith('otpauth://totp/OneSSH:admin?secret=' + secret));

    const counter = auth.totpCounter();
    const code = await auth.totpCodeFor(secret, counter);
    assert.match(code, /^\d{6}$/);
    const ok = await auth.verifyTotpCode(secret, code, 0);
    assert.equal(ok.ok, true);
    assert.equal(ok.counter, counter);

    assert.equal((await auth.verifyTotpCode(secret, '000000', 0)).ok, false);
    // 同一计数值已被用过：数字正确也拒绝
    assert.equal((await auth.verifyTotpCode(secret, code, counter)).ok, false);
    assert.equal((await auth.verifyTotpCode(secret, code, counter)).reason, 'replay');
});

test('备用码：10 个、哈希存储、明文只在 setup 时返回一次', async () => {
    const { codes, hashes } = await auth.generateBackupCodes();
    assert.equal(codes.length, 10);
    assert.equal(hashes.length, 10);
    for (let i = 0; i < 10; i++) {
        assert.match(codes[i], /^\d{8}$/);
        assert.equal(hashes[i], await auth.sha256Hex(codes[i]));
        assert.notEqual(hashes[i], codes[i]);
    }
    assert.equal(new Set(codes).size, 10, '备用码不应重复');
});

/* ------------------------------------------------------------ API 流程 */

test('TOTP：未启用时旧登录不受影响', async () => {
    const { env } = await setupApp();
    const res = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW } });
    assert.equal(res.status, 200);
    const st = await call(env, '/api/totp/status', { cookie: cookieFrom(res) });
    assert.equal(st.json.enabled, false);
});

test('TOTP：setup → enable → 登录需码 → 备用码一次性 → 重放拒绝', async () => {
    const { env, cookie } = await setupApp();

    const setup = await call(env, '/api/totp/setup', { method: 'POST', cookie });
    assert.equal(setup.status, 200);
    assert.match(setup.json.secret, /^[A-Z2-7]{32}$/);
    assert.ok(setup.json.otpauthUri.includes('otpauth://totp/'));
    assert.equal(setup.json.backupCodes.length, 10);
    // 启用前登录仍不需要码
    assert.equal((await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW } })).status, 200);

    // 错码启用失败
    const badEnable = await call(env, '/api/totp/enable', { method: 'POST', cookie, body: { code: '000000' } });
    assert.equal(badEnable.status, 401);

    const secret = setup.json.secret;
    const good = await call(env, '/api/totp/enable', {
        method: 'POST',
        cookie,
        body: { code: await auth.totpCodeFor(secret, auth.totpCounter()) },
    });
    assert.equal(good.status, 200, good.text);
    assert.equal(good.json.backupRemaining, 10);

    // 未启用前落盘的是哈希，不是明文备用码
    const admin = stored(env, 'sys/admin');
    assert.ok(admin.totp.enabled);
    assert.equal(admin.totp.secret, secret);
    assert.ok(!JSON.stringify(admin.totp).includes(setup.json.backupCodes[0]), '备用码明文不能落盘');

    // 无码 / 错码都不创建会话
    const noCode = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW } });
    assert.equal(noCode.status, 401);
    assert.equal(noCode.json.error, 'totp_required');
    assert.equal(noCode.headers.get('set-cookie'), null);
    const wrong = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW, totpCode: '000000' } });
    assert.equal(wrong.status, 401);
    assert.equal(wrong.json.error, 'totp_invalid');

    // 备用码登录成功，且只能用一次
    const backup = setup.json.backupCodes[0];
    const byBackup = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW, totpCode: backup } });
    assert.equal(byBackup.status, 200, byBackup.text);
    const st = await call(env, '/api/totp/status', { cookie: cookieFrom(byBackup) });
    assert.equal(st.json.backupRemaining, 9);
    const reuseBackup = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW, totpCode: backup } });
    assert.equal(reuseBackup.status, 401);

    // TOTP 码登录成功；同一码再用一次是重放
    const code = await nextCode(secret);
    assert.equal((await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW, totpCode: code } })).status, 200);
    const replay = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: PW, totpCode: code } });
    assert.equal(replay.status, 401);
    assert.equal(replay.json.error, 'totp_invalid');
});

test('TOTP：改密不关掉两步验证，停用需密码+码，停用后登录恢复无码', async () => {
    const { env, cookie } = await setupApp();
    const { secret, backupCodes } = await enableTotp(env, cookie);

    // 改密后 TOTP 仍在
    const changed = await call(env, '/api/password', { method: 'POST', cookie, body: { current: PW, next: 'a-brand-new-long-password' } });
    assert.equal(changed.status, 200);
    const freshCookie = cookieFrom(changed);
    const stillRequired = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: 'a-brand-new-long-password' } });
    assert.equal(stillRequired.json.error, 'totp_required');

    // 停用：密码错 / 码错都不行
    assert.equal(
        (await call(env, '/api/totp/disable', { method: 'POST', cookie: freshCookie, body: { current: 'wrong-password', totpCode: backupCodes[1] } })).status,
        401
    );
    const disabled = await call(env, '/api/totp/disable', {
        method: 'POST',
        cookie: freshCookie,
        body: { current: 'a-brand-new-long-password', totpCode: await nextCode(secret) },
    });
    assert.equal(disabled.status, 200, disabled.text);
    assert.equal(disabled.json.enabled, false);

    const plain = await call(env, '/api/login', { method: 'POST', body: { username: 'admin', password: 'a-brand-new-long-password' } });
    assert.equal(plain.status, 200, '停用后登录不应再要求验证码');
});
