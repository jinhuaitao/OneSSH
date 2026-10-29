/**
 * 加固回归用例：会话绑设备、初始化口令必填、密文上下文绑定、签名算法降级。
 * 这些点以前是「说得出但测不到」的，现在各有一条用例守着。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import worker from '../src/worker.js';
import * as auth from '../src/auth.js';
import * as C from '../src/ssh/crypto.js';
import { Writer } from '../src/ssh/buf.js';
import { makeEnv, call, cookieFrom, ADMIN, SETUP_TOKEN } from './helpers.mjs';

const PW = ADMIN.password;

async function boot(extra) {
    const env = makeEnv(Object.assign({ __worker: worker }, extra || {}));
    const res = await call(env, '/api/setup', {
        method: 'POST',
        body: { username: ADMIN.username, password: PW, token: SETUP_TOKEN },
        headers: { 'user-agent': 'UA-A', 'cf-connecting-ip': '203.0.113.5' },
    });
    assert.equal(res.status, 200, res.text);
    return { env, cookie: cookieFrom(res) };
}

/* ------------------------------------------------------------------ 初始化 */

test('初始化口令：未配置 WEBSSH_SETUP_TOKEN 时直接拒绝，而不是先到先得', async () => {
    const env = makeEnv({ __worker: worker, WEBSSH_SETUP_TOKEN: undefined });

    const state = await call(env, '/api/state');
    assert.equal(state.json.needsSetupToken, true, '界面应当始终展示口令输入框');
    assert.equal(state.json.setupTokenConfigured, false);

    const res = await call(env, '/api/setup', { method: 'POST', body: { username: 'admin', password: PW, token: 'whatever' } });
    assert.equal(res.status, 503);
    assert.equal(res.json.error, 'setup_token_missing');
    assert.match(res.json.message, /WEBSSH_SETUP_TOKEN/);
    assert.equal(env.BUCKET.map.has('sys/admin'), false, '被拒绝时不能落下管理员记录');
});

/* ------------------------------------------------------------ 会话绑设备 */

test('会话绑定 UA：换一个浏览器（UA 不同）会话立即作废', async () => {
    const { env, cookie } = await boot();
    const ua = { 'user-agent': 'UA-A', 'cf-connecting-ip': '203.0.113.5' };

    let res = await call(env, '/api/state', { cookie, headers: ua });
    assert.equal(res.json.authed, true, '同 UA 应当仍在登录态');

    res = await call(env, '/api/state', { cookie, headers: Object.assign({}, ua, { 'user-agent': 'UA-B' }) });
    assert.equal(res.json.authed, false, 'UA 变了必须作废');

    // 作废之后原 Cookie 也不能恢复
    res = await call(env, '/api/state', { cookie, headers: ua });
    assert.equal(res.json.authed, false, '作废是不可逆的（记录已删）');
});

test('会话绑定 IP：换网段作废，同网段放行，可整体关闭', async () => {
    const { env, cookie } = await boot();
    const base = { 'user-agent': 'UA-A' };

    let res = await call(env, '/api/state', { cookie, headers: Object.assign({}, base, { 'cf-connecting-ip': '203.0.113.5' }) });
    assert.equal(res.json.authed, true);

    const sameNet = await call(env, '/api/hosts', { cookie, headers: Object.assign({}, base, { 'cf-connecting-ip': '203.0.113.77' }) });
    assert.notEqual(sameNet.status, 401, '同一 /24 内换 IP 不应被踢（手机切基站很常见）');

    const otherNet = await call(env, '/api/state', { cookie, headers: Object.assign({}, base, { 'cf-connecting-ip': '198.51.100.9' }) });
    assert.equal(otherNet.json.authed, false, '跨网段必须作废');

    // 关掉绑定后，跨网段仍可用
    const env2 = makeEnv({ __worker: worker, WEBSSH_SESSION_IP_BIND: 'off' });
    const setup = await call(env2, '/api/setup', {
        method: 'POST',
        body: { username: ADMIN.username, password: PW, token: SETUP_TOKEN },
        headers: { 'user-agent': 'UA-A', 'cf-connecting-ip': '203.0.113.5' },
    });
    const cookie2 = cookieFrom(setup);
    const relaxed = await call(env2, '/api/state', { cookie: cookie2, headers: { 'user-agent': 'UA-A', 'cf-connecting-ip': '198.51.100.9' } });
    assert.equal(relaxed.json.authed, true, 'WEBSSH_SESSION_IP_BIND=off 应当放行');
});

test('sameIpPrefix：IPv4 比前三段、IPv6 比前四组', () => {
    assert.equal(auth.sameIpPrefix('203.0.113.5', '203.0.113.200'), true);
    assert.equal(auth.sameIpPrefix('203.0.113.5', '203.0.114.5'), false);
    assert.equal(auth.sameIpPrefix('2001:db8:1:2::1', '2001:db8:1:2:ffff::9'), true);
    assert.equal(auth.sameIpPrefix('2001:db8:1:2::1', '2001:db8:1:3::1'), false);
    assert.equal(auth.sameIpPrefix('::ffff:203.0.113.5', '203.0.113.9'), true, 'IPv4-mapped 应当等价');
    assert.equal(auth.sameIpPrefix('', '1.2.3.4'), true, '取不到 IP 时不做判断');
});

/* ------------------------------------------------------- 密文上下文绑定 */

const KEYED_ENV = () => makeEnv({ WEBSSH_MASTER_KEY: 'ab'.repeat(32) });

test('密文绑定归属：把 A 的密文搬到 B 上解不开', async () => {
    const env = KEYED_ENV();
    const blob = await auth.encryptSecret(env, 'pa55word', 'host:h1');
    assert.match(blob, /^v2:/, '带上下文的密文应当是 v2');

    assert.equal(await auth.decryptSecret(env, blob, 'host:h1'), 'pa55word');
    await assert.rejects(() => auth.decryptSecret(env, blob, 'host:h2'), /解密|operation/i);
    await assert.rejects(() => auth.decryptSecret(env, blob, 'cred:c1'), /解密|operation/i);
    await assert.rejects(() => auth.decryptSecret(env, blob), /上下文/);
});

test('旧数据兼容：没有上下文的 v1 密文仍能解开', async () => {
    const env = KEYED_ENV();
    const legacy = await auth.encryptSecret(env, 'old-secret');
    assert.match(legacy, /^v1:/);
    assert.equal(await auth.decryptSecret(env, legacy), 'old-secret');
    // 有上下文时传 v1 也应当能解（旧记录被新代码读到）
    assert.equal(await auth.decryptSecret(env, legacy, 'host:legacy'), 'old-secret');
});

test('会话日志的密文同样绑定文件名', async () => {
    const env = KEYED_ENV();
    const bytes = new TextEncoder().encode('日志里可能有密码');
    const enc = await auth.encryptBytes(env, bytes, 'log:logs/a.log');
    const dec = await auth.decryptBytes(env, enc, 'log:logs/a.log');
    assert.equal(new TextDecoder().decode(dec), '日志里可能有密码');
    await assert.rejects(() => auth.decryptBytes(env, enc, 'log:logs/b.log'), /解密|operation/i);
});

/* --------------------------------------------------------- 签名算法降级 */

test('主机签名：ssh-rsa（SHA-1）一律拒绝', async () => {
    const kp = await crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['sign', 'verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const b64url = (s) => new Uint8Array(Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/') + '=', 'base64'));
    const keyBlob = new Writer().str('ssh-rsa').mpint(b64url(jwk.e)).mpint(b64url(jwk.n)).bytes();
    const H = await C.sha256(new Uint8Array([7, 8, 9]));

    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, kp.privateKey, H));
    const sigBlob = new Writer().str('ssh-rsa').str(sig).bytes();

    const res = await C.verifyHostKeySignature(keyBlob, sigBlob, H);
    assert.equal(res.verified, false);
    assert.equal(res.sigAlg, 'ssh-rsa');
    assert.match(res.reason, /SHA-1/);
});

test('主机签名：算法与密钥类型不符时拒绝，并回传实际算法', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const keyBlob = new Writer().str('ssh-ed25519').str(raw).bytes();
    const H = await C.sha256(new Uint8Array([1, 2, 3]));

    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, H));
    // 假装对方用 rsa-sha2-256 报签名算法：alg 与 key 类型不符必须被拒
    const spoofed = new Writer().str('rsa-sha2-256').str(sig).bytes();
    const res = await C.verifyHostKeySignature(keyBlob, spoofed, H);
    assert.equal(res.verified, false);
    assert.equal(res.sigAlg, 'rsa-sha2-256', '要把实际算法带出来，供上层和协商结果比对');

    // 正确的 ed25519 签名仍然通过，并带出 sigAlg
    const ok = new Writer().str('ssh-ed25519').str(sig).bytes();
    const good = await C.verifyHostKeySignature(keyBlob, ok, H);
    assert.equal(good.verified, true, good.reason);
    assert.equal(good.sigAlg, 'ssh-ed25519');
});

test('协商列表：不再提供 SHA-1 系算法', async () => {
    const src = await import('node:fs').then((fs) =>
        fs.readFileSync(new URL('../src/ssh/client.js', import.meta.url), 'utf8')
    );
    assert.equal(/hmac-sha1/.test(src), false, 'MAC 列表里不应再有 SHA-1');
    assert.equal(C.HOST_KEY_ALGS.includes('ssh-rsa'), false, '主机密钥算法里不应再有 ssh-rsa（SHA-1 签名）');
});