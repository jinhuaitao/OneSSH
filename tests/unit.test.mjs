import test from 'node:test';
import assert from 'node:assert/strict';

import { Reader, Writer, concat, toBase64, fromBase64, bytesToHex, equalBytes } from '../src/ssh/buf.js';
import * as C from '../src/ssh/crypto.js';
import { loadPrivateKey } from '../src/ssh/keys.js';
import { normalizeHost } from '../src/hostaddr.js';
import * as auth from '../src/auth.js';
import { makeEnv } from './helpers.mjs';

const b64url = (s) => fromBase64(String(s).replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (String(s).length % 4)) % 4));

/* ----------------------------------------------------------------- 主机地址 */

test('normalizeHost：域名 / IPv4 / IPv6 与非法输入', () => {
    const ok = [
        ['example.com', 'example.com'],
        ['192.0.2.10', '192.0.2.10'],
        ['  Example.COM  ', 'Example.COM'],
        ['2001:DB8::1', '[2001:db8::1]'],
        ['[2001:db8::1]', '[2001:db8::1]'],
        ['::1', '[::1]'],
        ['host-name_1.example', 'host-name_1.example'],
    ];
    for (const [input, want] of ok) assert.equal(normalizeHost(input), want, input);

    const bad = ['', '   ', 'not a host', '-bad.example', 'bad-.example', 'a..b', '[not-ipv6]', '[2001:db8::1', 'http://x.com', 'a/b', 'a'.repeat(254)];
    for (const input of bad) assert.equal(normalizeHost(input), '', JSON.stringify(input));
});

/* --------------------------------------------------------------- 二进制缓冲 */

test('Writer/Reader：各种字段往返一致', () => {
    const w = new Writer()
        .byte(0x2a)
        .bool(true)
        .u32(0xdeadbeef)
        .u64(5 * 1024 * 1024 * 1024 + 7)
        .str('hello 世界')
        .nameList(['a', 'b', 'c']);
    const r = new Reader(w.bytes());
    assert.equal(r.byte(), 0x2a);
    assert.equal(r.bool(), true);
    assert.equal(r.u32(), 0xdeadbeef);
    assert.equal(r.u64(), 5 * 1024 * 1024 * 1024 + 7);
    assert.equal(r.text(), 'hello 世界');
    assert.deepEqual(r.nameList(), ['a', 'b', 'c']);
    assert.equal(r.left, 0);
});

test('mpint：高位补零与去零', () => {
    const high = new Uint8Array([0x80, 0x01]);
    const w = new Writer().mpint(high).bytes();
    // str 长度 3：0x00 0x80 0x01
    assert.deepEqual([...w], [0, 0, 0, 3, 0x00, 0x80, 0x01]);
    assert.deepEqual([...new Reader(w).mpint()], [0x80, 0x01], '读回时去掉符号位补的 0');

    const low = new Writer().mpint(new Uint8Array([0x00, 0x00, 0x7f])).bytes();
    assert.deepEqual([...low], [0, 0, 0, 1, 0x7f], '前导零必须被裁掉');
});

test('base64 / hex 工具', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252]);
    assert.equal(bytesToHex(bytes), '000102fafbfc');
    assert.ok(equalBytes(fromBase64(toBase64(bytes)), bytes));
});

/* ------------------------------------------------------------------ 加密 */

test('AES-CTR 密钥流：分片调用与一次性调用结果一致', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const data = crypto.getRandomValues(new Uint8Array(1000));

    const whole = await new C.CtrCipher(key, iv).ready();
    const once = await whole.crypt(data);

    const split = await new C.CtrCipher(key, iv).ready();
    const parts = [];
    for (let i = 0; i < data.length; i += 37) parts.push(await split.crypt(data.subarray(i, i + 37)));
    const joined = concat(...parts);

    assert.ok(equalBytes(once, joined), 'CTR 必须按字节连续，不能每个包重置计数器');
    assert.notEqual(bytesToHex(once), bytesToHex(data));
});

test('AES-CTR peek：读包长时不推进密钥流', async () => {
    const key = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const data = crypto.getRandomValues(new Uint8Array(64));

    const a = await new C.CtrCipher(key, iv).ready();
    const peeked = await a.peek(data.subarray(0, 16));
    const full = await a.crypt(data);
    // peek 之后再 crypt 整包，结果必须与「直接 crypt 整包」相同
    const b = await new C.CtrCipher(key, iv).ready();
    assert.ok(equalBytes(full, await b.crypt(data)));
    assert.equal(peeked.length, 16);
});

test('deriveKey：长度正确、可复现、不同字母不同结果', async () => {
    const k = new Uint8Array(32).fill(7);
    const H = new Uint8Array(32).fill(9);
    const sid = new Uint8Array(32).fill(3);
    for (const len of [16, 32, 64, 96]) {
        const a = await C.deriveKey(C.sha256, k, H, 'C', sid, len);
        const b = await C.deriveKey(C.sha256, k, H, 'C', sid, len);
        assert.equal(a.length, len);
        assert.ok(equalBytes(a, b));
    }
    const c = await C.deriveKey(C.sha256, k, H, 'C', sid, 32);
    const d = await C.deriveKey(C.sha256, k, H, 'D', sid, 32);
    assert.notEqual(bytesToHex(c), bytesToHex(d));
});

test('HMAC：长度符合算法定义', async () => {
    for (const [alg, len] of [['hmac-sha2-256', 32], ['hmac-sha2-512', 64], ['hmac-sha1', 20]]) {
        const mac = await new C.Mac(alg, new Uint8Array(len).fill(1)).ready();
        assert.equal(mac.len, len);
        const sig = await mac.sign(1, new Uint8Array([1, 2, 3]));
        assert.equal(sig.length, len);
    }
});

test('fingerprint 与 ssh-keygen -lf 同形', async () => {
    const blob = new Writer().str('ssh-ed25519').str(new Uint8Array(32).fill(5)).bytes();
    const fp = await C.fingerprint(blob);
    assert.match(fp, /^SHA256:[A-Za-z0-9+/]{43}$/);
    assert.equal(fp, await C.fingerprint(blob), '同一把钥匙指纹必须稳定');
});

/* --------------------------------------------------------------- 主机密钥 */

test('ed25519 主机密钥：签名校验通过，篡改后失败', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const keyBlob = new Writer().str('ssh-ed25519').str(pub).bytes();
    const H = await C.sha256(new Uint8Array([1, 2, 3]));

    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, H));
    const sigBlob = new Writer().str('ssh-ed25519').str(sig).bytes();

    const good = await C.verifyHostKeySignature(keyBlob, sigBlob, H);
    assert.equal(good.verified, true, good.reason);

    const tampered = await C.sha256(new Uint8Array([1, 2, 4]));
    const bad = await C.verifyHostKeySignature(keyBlob, sigBlob, tampered);
    assert.equal(bad.verified, false);
});

test('ecdsa-nistp256 主机密钥：r||s 与 SSH 的 mpint 对之间能互转', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const keyBlob = new Writer().str('ecdsa-sha2-nistp256').str('nistp256').str(pub).bytes();
    const H = await C.sha256(new Uint8Array([7, 7, 7]));

    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, H));
    assert.equal(raw.length, 64);
    const inner = new Writer().mpint(raw.subarray(0, 32)).mpint(raw.subarray(32)).bytes();
    const sigBlob = new Writer().str('ecdsa-sha2-nistp256').str(inner).bytes();

    const res = await C.verifyHostKeySignature(keyBlob, sigBlob, H);
    assert.equal(res.verified, true, res.reason);
    assert.equal(res.type, 'ecdsa-sha2-nistp256');
});

test('rsa 主机密钥：spki 重建正确，rsa-sha2-256 校验通过', async () => {
    const kp = await crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['sign', 'verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const keyBlob = new Writer().str('ssh-rsa').mpint(b64url(jwk.e)).mpint(b64url(jwk.n)).bytes();
    const H = await C.sha256(new Uint8Array([4, 5, 6]));

    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, kp.privateKey, H));
    const sigBlob = new Writer().str('rsa-sha2-256').str(sig).bytes();

    const res = await C.verifyHostKeySignature(keyBlob, sigBlob, H);
    assert.equal(res.verified, true, res.reason);
    assert.equal(res.type, 'ssh-rsa');
});

test('不支持的主机密钥算法给出原因而不是崩溃', async () => {
    const keyBlob = new Writer().str('ssh-dss').str(new Uint8Array(8)).bytes();
    const res = await C.verifyHostKeySignature(keyBlob, new Writer().str('ssh-dss').str(new Uint8Array(8)).bytes(), new Uint8Array(32));
    assert.equal(res.verified, false);
    assert.match(res.reason, /unsupported/);
});

/* --------------------------------------------------------------- 私钥解析 */

test('ed25519 PKCS#8 私钥：能导出正确的公钥 blob 并签名', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    const pem = '-----BEGIN PRIVATE KEY-----\n' + Buffer.from(der).toString('base64') + '\n-----END PRIVATE KEY-----';

    const key = await loadPrivateKey(pem);
    assert.equal(key.alg, 'ssh-ed25519');

    const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const expect = new Writer().str('ssh-ed25519').str(b64url(jwk.x)).bytes();
    assert.ok(equalBytes(key.publicBlob, expect), '导出的公钥必须和私钥配对');

    const msg = new Uint8Array([1, 2, 3, 4]);
    const sig = await key.sign(msg);
    const ok = await crypto.subtle.verify({ name: 'Ed25519' }, kp.publicKey, sig, msg);
    assert.equal(ok, true);
});

test('RSA PKCS#8 私钥：解析后签名可被公钥验证', async () => {
    const kp = await crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['sign', 'verify']
    );
    const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    const pem = '-----BEGIN PRIVATE KEY-----\n' + Buffer.from(der).toString('base64') + '\n-----END PRIVATE KEY-----';

    const key = await loadPrivateKey(pem);
    assert.equal(key.alg, 'rsa-sha2-256');
    const r = new Reader(key.publicBlob);
    assert.equal(r.text(), 'ssh-rsa');

    const msg = new Uint8Array([9, 8, 7]);
    const sig = await key.sign(msg);
    assert.equal(await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, kp.publicKey, sig, msg), true);
});

test('私钥解析：带口令 / 无法识别的内容给出可操作提示', async () => {
    // 按真实格式拼一个「已加密的 OpenSSH 私钥」：cipher 不是 none 就必须明确报错，
    // 而不是继续解析出一堆乱码（那样只会得到 "ssh: truncated string" 这种无从下手的提示）
    const magic = new TextEncoder().encode('openssh-key-v1\0');
    const body = new Writer()
        .str('aes256-ctr')
        .str('bcrypt')
        .str(new Uint8Array([0, 0, 0, 16]))
        .u32(1)
        .str(new Uint8Array(4))
        .str(new Uint8Array(8))
        .bytes();
    const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\n' + Buffer.from(concat(magic, body)).toString('base64') + '\n-----END OPENSSH PRIVATE KEY-----';
    await assert.rejects(() => loadPrivateKey(pem), /口令/);

    await assert.rejects(() => loadPrivateKey('-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----'), /口令/);
    await assert.rejects(() => loadPrivateKey('not a key at all'), /无法识别/);
    await assert.rejects(() => loadPrivateKey(''), /为空/);
});

/* ------------------------------------------------------------ 口令与密文 */

test('PBKDF2：同盐同口令结果一致，不同盐不同', async () => {
    const a = await auth.hashPassword('correct-horse', '00112233445566778899aabbccddeeff', 1000);
    const b = await auth.hashPassword('correct-horse', '00112233445566778899aabbccddeeff', 1000);
    const c = await auth.hashPassword('correct-horse', 'ffeeddccbbaa99887766554433221100', 1000);
    assert.equal(a, b);
    assert.notEqual(a, c);
    assert.equal(a.length, 64);
});

test('safeEqual：长度不同或内容不同都返回 false', () => {
    assert.equal(auth.safeEqual('abc', 'abc'), true);
    assert.equal(auth.safeEqual('abc', 'abd'), false);
    assert.equal(auth.safeEqual('abc', 'abcd'), false);
    assert.equal(auth.safeEqual(null, 'abc'), false);
});

test('凭据加解密：往返一致，密文带 v1 前缀且每次 IV 不同', async () => {
    const env = makeEnv({ WEBSSH_MASTER_KEY: '11'.repeat(32) });
    const one = await auth.encryptSecret(env, 's3cret-password');
    const two = await auth.encryptSecret(env, 's3cret-password');
    assert.match(one, /^v1:/);
    assert.notEqual(one, two, '相同明文也必须产生不同密文（随机 IV）');
    assert.equal(await auth.decryptSecret(env, one), 's3cret-password');
    assert.equal(await auth.decryptSecret(env, two), 's3cret-password');
    assert.equal(await auth.encryptSecret(env, ''), null);
});

test('凭据加解密：换主密钥后旧密文解不开（不静默返回垃圾）', async () => {
    const a = makeEnv({ WEBSSH_MASTER_KEY: '22'.repeat(32) });
    const blob = await auth.encryptSecret(a, 'hello');
    const b = makeEnv({ WEBSSH_MASTER_KEY: '33'.repeat(32) });
    await assert.rejects(() => auth.decryptSecret(b, blob));
});

test('会话录制字节流：加密后可原样解回', async () => {
    const env = makeEnv({ WEBSSH_MASTER_KEY: '44'.repeat(32) });
    const raw = new TextEncoder().encode('$ ls\r\nfile1 file2\r\n中文输出 ✅\r\n');
    const enc = await auth.encryptBytes(env, raw);
    assert.ok(enc.length > raw.length);
    assert.ok(equalBytes(await auth.decryptBytes(env, enc), raw));
});

test('会话 Cookie：HTTPS 下带 Secure，HTTP 下不带', () => {
    const https = auth.sessionCookie('t', new Request('https://x.test/'));
    assert.match(https, /HttpOnly/);
    assert.match(https, /SameSite=Lax/);
    assert.match(https, /Secure/);
    const http = auth.sessionCookie('t', new Request('http://x.test/'));
    assert.equal(/Secure/.test(http), false, '本地 http 调试时不能带 Secure，否则 cookie 不落地');
});

test('parseCookies：畸形编码不影响其它 cookie', () => {
    const out = auth.parseCookies('a=1; b=%E4%BD%A0; bad=%ZZ; c=3');
    assert.equal(out.a, '1');
    assert.equal(out.b, '你');
    assert.equal(out.bad, '%ZZ');
    assert.equal(out.c, '3');
});
