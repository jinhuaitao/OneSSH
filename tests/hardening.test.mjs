/**
 * 加固回归用例：会话绑设备（UA / IP 都按 fail-closed）、初始化口令必填、
 * 密文上下文绑定（含旧日志兼容）、签名算法降级。
 * 这些点以前是「说得出但测不到」的，现在各有一条用例守着。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import worker from '../src/worker.js';
import * as auth from '../src/auth.js';
import * as C from '../src/ssh/crypto.js';
import { SSHClient } from '../src/ssh/client.js';
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

test('会话绑定 UA：不带 User-Agent 也算不匹配（不能靠省略头绕过）', async () => {
    const { env, cookie } = await boot();
    const ip = '203.0.113.5';

    // 完全不带 UA 头
    let res = await call(env, '/api/state', { cookie, headers: { 'cf-connecting-ip': ip } });
    assert.equal(res.json.authed, false, '空 UA 必须作废，否则 curl -A "" 就是一条绕过路径');

    // 显式空字符串
    res = await call(env, '/api/state', { cookie, headers: { 'user-agent': '', 'cf-connecting-ip': ip } });
    assert.equal(res.json.authed, false, '空字符串 UA 同样作废');
});

test('会话绑定 IP：换网段作废，同网段放行，取不到 IP 也作废', async () => {
    const { env, cookie } = await boot();
    const base = { 'user-agent': 'UA-A' };

    let res = await call(env, '/api/state', { cookie, headers: Object.assign({}, base, { 'cf-connecting-ip': '203.0.113.5' }) });
    assert.equal(res.json.authed, true);

    const sameNet = await call(env, '/api/hosts', { cookie, headers: Object.assign({}, base, { 'cf-connecting-ip': '203.0.113.77' }) });
    assert.notEqual(sameNet.status, 401, '同一 /24 内换 IP 不应被踢（手机切基站很常见）');

    // 建立会话时知道 IP，这次一个 IP 头都不带 → 必须作废（fail-closed）
    const noIp = await call(env, '/api/state', { cookie, headers: Object.assign({}, base) });
    assert.equal(noIp.json.authed, false, '取不到 IP 时不能默默放行');

    // 换一个会话，验证跨网段
    const { env: env3, cookie: cookie3 } = await boot();
    const otherNet = await call(env3, '/api/state', {
        cookie: cookie3,
        headers: { 'user-agent': 'UA-A', 'cf-connecting-ip': '198.51.100.9' },
    });
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

test('X-Forwarded-For 默认不采信：只有开了 WEBSSH_TRUST_PROXY 才算数', async () => {
    const { env, cookie } = await boot();
    const ua = 'UA-A';

    // 默认：伪造 XFF 不生效，取不到真实 IP → fail-closed 作废
    let res = await call(env, '/api/state', { cookie, headers: { 'user-agent': ua, 'x-forwarded-for': '203.0.113.5' } });
    assert.equal(res.json.authed, false, '默认不该相信客户端自报的 XFF');

    // 打开信任开关后，反代注入的 XFF 才参与比对
    const env2 = makeEnv({ __worker: worker, WEBSSH_TRUST_PROXY: 'on' });
    const setup = await call(env2, '/api/setup', {
        method: 'POST',
        body: { username: ADMIN.username, password: PW, token: SETUP_TOKEN },
        headers: { 'user-agent': ua, 'x-forwarded-for': '203.0.113.5' },
    });
    const c2 = cookieFrom(setup);
    res = await call(env2, '/api/state', { cookie: c2, headers: { 'user-agent': ua, 'x-forwarded-for': '203.0.113.99' } });
    assert.equal(res.json.authed, true, '同 /24 应当放行');
    res = await call(env2, '/api/state', { cookie: c2, headers: { 'user-agent': ua, 'x-forwarded-for': '198.51.100.9' } });
    assert.equal(res.json.authed, false, '跨网段应当作废');

    // 开关打开后 XFF 依然可控：塞个解析不出来的值不能变成免检通行证
    const login = await call(env2, '/api/login', {
        method: 'POST',
        body: { username: ADMIN.username, password: PW },
        headers: { 'user-agent': ua, 'x-forwarded-for': '203.0.113.5' },
    });
    res = await call(env2, '/api/state', { cookie: cookieFrom(login), headers: { 'user-agent': ua, 'x-forwarded-for': 'garbage' } });
    assert.equal(res.json.authed, false, '畸形 IP 必须作废');
});

test('sameIpPrefix：IPv4 比 /24、IPv6 比 /48，并把各种写法归一', () => {
    assert.equal(auth.sameIpPrefix('203.0.113.5', '203.0.113.200'), true);
    assert.equal(auth.sameIpPrefix('203.0.113.5', '203.0.114.5'), false);
    // /64 内换地址：IPv6 隐私扩展每几小时就换一次，必须放行
    assert.equal(auth.sameIpPrefix('2001:db8:1:2::1', '2001:db8:1:2:ffff::9'), true);
    // 不同 /48 才算换站点（原来比 /64 时这条会误判成「同一段」）
    assert.equal(auth.sameIpPrefix('2001:db8:1:2::1', '2001:db8:2::1'), false);
    assert.equal(auth.sameIpPrefix('::ffff:203.0.113.5', '203.0.113.9'), true, 'IPv4-mapped 应当等价');
    assert.equal(auth.sameIpPrefix('2001:DB8:0001:0002:0:0:0:1', '2001:db8:1:2::1'), true, '展开/压缩写法要等价');
    assert.equal(auth.sameIpPrefix('', '1.2.3.4'), true, '解析不了时不在这一层判断');
    assert.equal(auth.sameIpPrefix('203.0.113.5', '2001:db8:1::1'), false, 'v4 与 v6 永不相等');
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

test('会话日志读取：补丁前的旧密文（无 AAD）不能变成 500', async () => {
    const { env, cookie } = await boot();
    const hdr = { 'user-agent': 'UA-A', 'cf-connecting-ip': '203.0.113.5' };
    const enc = new TextEncoder();

    // 补丁前写下的记录：encryptBytes 不带 context，元数据 enc:'v1'
    const oldKey = 'logs/2026-10-29T00-00-00-000Z-old0.log';
    const legacy = await auth.encryptBytes(env, enc.encode('旧录制 password=hunter2'));
    await env.BUCKET.put(oldKey, legacy, { customMetadata: { enc: 'v1', host: 'h', port: '22', user: 'u' } });

    let res = await call(env, '/api/logs/' + oldKey, { cookie, headers: hdr });
    assert.equal(res.status, 200, '旧日志必须仍能读出：' + res.text);
    assert.equal(res.text, '旧录制 password=hunter2');

    // 新记录：带 AAD，元数据 enc:'v2'
    const newKey = 'logs/2026-10-29T00-00-01-000Z-new0.log';
    const fresh = await auth.encryptBytes(env, enc.encode('新录制 ok'), 'log:' + newKey);
    await env.BUCKET.put(newKey, fresh, { customMetadata: { enc: 'v2', host: 'h', port: '22', user: 'u' } });

    res = await call(env, '/api/logs/' + newKey, { cookie, headers: hdr });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.text, '新录制 ok');

    // 把新密文搬到别的文件名上：AAD 不匹配，必须失败而不是解出内容
    const moved = 'logs/2026-10-29T00-00-02-000Z-move.log';
    await env.BUCKET.put(moved, fresh, { customMetadata: { enc: 'v2' } });
    res = await call(env, '/api/logs/' + moved, { cookie, headers: hdr });
    assert.notEqual(res.status, 200, '换了文件名就不该解出来');
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

/* --------------------------------------------------- KEXINIT / 重协商 */

/** 造一个 KEXINIT：前两个 nameList 的第一项就是服务器的「猜测」 */
function kexInitPacket(opts) {
    const w = new Writer().byte(20).raw(new Uint8Array(16));
    w.nameList([opts.kexGuess, 'curve25519-sha256']);
    w.nameList([opts.hkGuess, 'ssh-ed25519']);
    w.nameList(['aes128-ctr']);
    w.nameList(['aes128-ctr']);
    w.nameList(['hmac-sha2-256']);
    w.nameList(['hmac-sha2-256']);
    w.nameList(['none']);
    w.nameList(['none']);
    w.nameList([]);
    w.nameList([]);
    w.bool(!!opts.follows);
    w.u32(0);
    return w.bytes();
}

function fakeClient() {
    const out = [];
    const c = new SSHClient({ write: async (b) => out.push(b), onData: () => {}, onEvent: () => {} });
    c.phase = 'transport';
    return { c, out };
}

test('KEXINIT：服务器猜错算法时，它的下一包必须被丢弃', async () => {
    const { c, out } = fakeClient();
    await c._onKexInit(kexInitPacket({ kexGuess: 'diffie-hellman-group1-sha1', hkGuess: 'ssh-ed25519', follows: true }));
    assert.equal(c._dropNextKexPacket, true, '猜错就要丢包');
    assert.equal(out.at(-1)[5], 30, '客户端应当回 KEX_ECDH_INIT（报文类型在长度+填充长度之后）');
});

test('KEXINIT：猜对或没开「猜测随包」时不丢包', async () => {
    const a = fakeClient();
    await a.c._onKexInit(kexInitPacket({ kexGuess: 'curve25519-sha256', hkGuess: 'ssh-ed25519', follows: true }));
    assert.equal(a.c._dropNextKexPacket, false, '猜对了就正常处理');

    const b = fakeClient();
    await b.c._onKexInit(kexInitPacket({ kexGuess: 'diffie-hellman-group1-sha1', hkGuess: 'ssh-rsa', follows: false }));
    assert.equal(b.c._dropNextKexPacket, false, '没声明猜测就没有包可丢');
});

test('主动重协商：只有会话就绪且流量到阈值才发起', async () => {
    const { c, out } = fakeClient();
    c.bytesSinceRekey = 2 ** 30;
    c._maybeRekey();
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(out.length, 0, '还没就绪时不该发起重协商');

    c.ready = true;
    c._maybeRekey();
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(out.length, 1, '到阈值应当发一包 KEXINIT');
    assert.equal(out[0][5], 20);
    assert.equal(c.bytesSinceRekey, 0, '触发后计数归零');
});

