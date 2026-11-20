import test from 'node:test';
import assert from 'node:assert/strict';

import { Reader, Writer, concat, toBase64, fromBase64, bytesToHex, equalBytes } from '../src/ssh/buf.js';
import * as C from '../src/ssh/crypto.js';
import { loadPrivateKey } from '../src/ssh/keys.js';
import { normalizeHost, isPrivateIP, isPublicHost } from '../src/hostaddr.js';
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

test('isPrivateIP：私网 / 环回 / 链路本地 / 保留地址，文档段不拦', () => {
    for (const ip of [
        '10.0.0.1', '10.255.255.255', '172.16.0.1', '172.31.255.255', '192.168.0.1',
        '127.0.0.1', '0.0.0.0', '169.254.1.1', '::1', '[::1]', '::', 'fc00::1', 'fd12:3456::1',
        'fe80::1', '[fe80::1]', '::ffff:10.0.0.1', '[::ffff:192.168.1.1]',
    ]) {
        assert.equal(isPrivateIP(ip), true, ip);
    }
    for (const ip of [
        '192.0.2.10', '203.0.113.5', '8.8.8.8', '2001:db8::1', '[2001:db8::1]',
        '2001:4860:4860::8888', 'example.com', 'not-an-ip',
    ]) {
        assert.equal(isPrivateIP(ip), false, ip);
    }
    // 172.32.0.1 不在 172.16/12 里，是公网
    assert.equal(isPrivateIP('172.32.0.1'), false);
});

test('isPublicHost：域名放行（DNS 重绑定靠 Workers connect 兜底），字面私网拒绝', () => {
    assert.equal(isPublicHost('example.com'), true);
    assert.equal(isPublicHost('203.0.113.5'), true);
    assert.equal(isPublicHost('2001:db8::1'), true);
    assert.equal(isPublicHost('10.0.0.1'), false);
    assert.equal(isPublicHost('[::1]'), false);
    assert.equal(isPublicHost('not a host'), false);
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

test('AES-CTR peek：大包（跨 16KB 块）peek 后 crypt 结果一致', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const data = crypto.getRandomValues(new Uint8Array(40000)); // > 16KB，跨 keystream 块

    const a = await new C.CtrCipher(key, iv).ready();
    const peeked = await a.peek(data.subarray(0, 16));
    const full = await a.crypt(data);
    const b = await new C.CtrCipher(key, iv).ready();
    assert.ok(equalBytes(full, await b.crypt(data)), 'peek 后 crypt 整包必须与直接 crypt 一致');
    assert.ok(equalBytes(peeked, full.subarray(0, 16)), 'peek 出来的包头必须等于 crypt 结果的包头');
});

test('AES-CTR：分块边界与跨块 keystream 复用', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const data = new Uint8Array(70000);
    for (let i = 0; i < data.length; i += 32768) {
        crypto.getRandomValues(data.subarray(i, Math.min(data.length, i + 32768)));
    }

    const whole = await new C.CtrCipher(key, iv).ready();
    const once = await whole.crypt(data);

    // 在 16KB 块边界两侧切：16383 / 16384 / 16385 / 32768，keystream 必须连续
    const split = await new C.CtrCipher(key, iv).ready();
    const parts = [];
    let off = 0;
    for (const cut of [37, 16383, 16384, 16385, 32768, 50000]) {
        parts.push(await split.crypt(data.subarray(off, cut)));
        off = cut;
    }
    parts.push(await split.crypt(data.subarray(off)));
    assert.ok(equalBytes(once, concat(...parts)), '跨 16KB 块的分片 crypt 必须与一次性 crypt 一致');

    // peek 发生在非零 offset（前面已 crypt 过一部分），再 crypt 剩余部分
    const c = await new C.CtrCipher(key, iv).ready();
    const first = await c.crypt(data.subarray(0, 1000));
    const peeked = await c.peek(data.subarray(1000, 1016));
    const rest = await c.crypt(data.subarray(1000));
    assert.ok(equalBytes(first, once.subarray(0, 1000)));
    assert.ok(equalBytes(peeked, once.subarray(1000, 1016)), '中途 peek 不得推进密钥流');
    assert.ok(equalBytes(rest, once.subarray(1000)), '中途 peek 后 crypt 必须接上原来的密钥流');
});

test('AES-CTR：未对齐偏移的批量 XOR 与逐字节一致', async () => {
    const key = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    // 故意让 data 的 byteOffset 不是 4 的倍数（覆盖 xorInto 的对齐前导分支）
    const backing = crypto.getRandomValues(new Uint8Array(5003));
    const data = backing.subarray(1, 5001);
    assert.equal(data.byteOffset % 4, 1);

    const whole = await new C.CtrCipher(key, iv).ready();
    const once = await whole.crypt(data);
    const split = await new C.CtrCipher(key, iv).ready();
    const parts = [];
    for (let i = 0; i < data.length; i += 7) parts.push(await split.crypt(data.subarray(i, i + 7)));
    assert.ok(equalBytes(once, concat(...parts)));
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

test('HMAC：长度符合算法定义，且 SHA-1 系已被移除', async () => {
    assert.throws(() => new C.Mac('hmac-sha1', new Uint8Array(20)), /unsupported mac/);
    for (const [alg, len] of [['hmac-sha2-256', 32], ['hmac-sha2-512', 64]]) {
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

test('rsa 主机密钥：rsa-sha2-512 校验通过，篡改后失败', async () => {
    const kp = await crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-512' },
        true,
        ['sign', 'verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const keyBlob = new Writer().str('ssh-rsa').mpint(b64url(jwk.e)).mpint(b64url(jwk.n)).bytes();
    const H = await C.sha256(new Uint8Array([4, 5, 6]));

    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, kp.privateKey, H));
    const sigBlob = new Writer().str('rsa-sha2-512').str(sig).bytes();

    const res = await C.verifyHostKeySignature(keyBlob, sigBlob, H);
    assert.equal(res.verified, true, res.reason);
    assert.equal(res.sigAlg, 'rsa-sha2-512');
    assert.equal(res.type, 'ssh-rsa');

    // 同一把 key、同一个签名，拿 SHA-256 的名义去验必须失败（key 绑定的 hash 不同）
    const wrongAlg = await C.verifyHostKeySignature(keyBlob, new Writer().str('rsa-sha2-256').str(sig).bytes(), H);
    assert.equal(wrongAlg.verified, false, 'SHA-512 的签名不能用 rsa-sha2-256 的名义通过');

    // 篡改交换哈希后必须失败（回归：单次导入不能把验签逻辑改松）
    const tampered = await C.sha256(new Uint8Array([4, 5, 7]));
    const bad = await C.verifyHostKeySignature(keyBlob, sigBlob, tampered);
    assert.equal(bad.verified, false);
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
