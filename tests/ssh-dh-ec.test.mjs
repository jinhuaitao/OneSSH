/**
 * 任务 5（DH group14-sha256）与任务 6（ECDSA P-256 私钥）的测试。
 *
 * 单元部分不依赖外部服务；E2E 部分用 ssh2 起本地服务器（与
 * tools/bench-handshake.mjs 同一模式），主机密钥用 ssh-keygen 临时生成、
 * 用完删除。测试里的口令/密钥全部是临时生成的，不含任何真实凭据。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
    getDiffieHellman,
    generateKeyPairSync,
    createPublicKey,
    verify as cryptoVerify,
    randomBytes,
} from 'node:crypto';
import { createRequire } from 'node:module';
import { dhGroup14Keypair, dhGroup14Shared, DH_GROUP14_PRIME } from '../src/ssh/crypto.js';
import { loadPrivateKey } from '../src/ssh/keys.js';
import { SSHClient } from '../src/ssh/client.js';
import { Reader } from '../src/ssh/buf.js';

const require = createRequire(import.meta.url);
const { Server } = require('ssh2');

const subtle = () => globalThis.crypto.subtle;

/* ------------------------------------------------------------------ helpers */

function pemWrap(b64, label) {
    return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
}

/** SSH 签名（mpint r || mpint s）转 WebCrypto 要的 r||s（各 32 字节） */
function sshSigToRaw(sig) {
    const r = new Reader(sig);
    const rr = r.mpint();
    const ss = r.mpint();
    const pad = (v) => {
        const out = new Uint8Array(32);
        out.set(v.subarray(Math.max(0, v.length - 32)), 32 - Math.min(32, v.length));
        return out;
    };
    const raw = new Uint8Array(64);
    raw.set(pad(rr), 0);
    raw.set(pad(ss), 32);
    return raw;
}

/** 由 JWK 的 x/y 拼未压缩公钥点 0x04||x||y */
function pointFromJwk(jwk) {
    const dec = (s) => Buffer.from(s, 'base64url');
    return Buffer.concat([Buffer.from([0x04]), dec(jwk.x), dec(jwk.y)]);
}

function hasSshKeygen() {
    for (const dir of (process.env.PATH || '').split(path.delimiter)) {
        try {
            fs.accessSync(path.join(dir, 'ssh-keygen'), fs.constants.X_OK);
            return true;
        } catch {
            // 继续找下一个 PATH 目录
        }
    }
    return false;
}

function makeTempDir(t, prefix) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
    return tmp;
}

/* ------------------------------------------------------- task 5: DH group14 */

test('DH group14：素数 p 与 Node 的 modp14 一致', () => {
    const nodePrime = getDiffieHellman('modp14').getPrime();
    assert.equal(
        DH_GROUP14_PRIME.toString(16).toUpperCase(),
        nodePrime.toString('hex').toUpperCase()
    );
});

test('DH group14：密钥对在合法范围内、每次生成不同', () => {
    const a = dhGroup14Keypair();
    const b = dhGroup14Keypair();
    assert.equal(typeof a.privateKey, 'bigint');
    assert.ok(a.privateKey >= 2n && a.privateKey <= DH_GROUP14_PRIME - 2n);
    assert.ok(a.publicKey.length === 256 || a.publicKey.length === 257);
    assert.notDeepEqual(a.publicKey, b.publicKey);
    assert.notEqual(a.privateKey, b.privateKey);
});

test('DH group14：与 Node modp14 互通（双向共享密钥一致）', () => {
    const ours = dhGroup14Keypair();
    const nodeDh = getDiffieHellman('modp14');
    const nodePub = nodeDh.generateKeys();
    // Node 算共享：用我们的公钥
    const nodeShared = nodeDh.computeSecret(Buffer.from(ours.publicKey));
    // 我们算共享：用 Node 的公钥
    const ourShared = dhGroup14Shared(ours.privateKey, new Uint8Array(nodePub));
    const toBig = (buf) => BigInt('0x' + Buffer.from(buf).toString('hex'));
    assert.equal(toBig(ourShared), toBig(nodeShared));
    assert.ok(toBig(ourShared) > 1n && toBig(ourShared) < DH_GROUP14_PRIME - 1n);
});

test('DH group14：双方各自算出的共享密钥一致', () => {
    const a = dhGroup14Keypair();
    const b = dhGroup14Keypair();
    const s1 = dhGroup14Shared(a.privateKey, b.publicKey);
    const s2 = dhGroup14Shared(b.privateKey, a.publicKey);
    assert.deepEqual(Buffer.from(s1), Buffer.from(s2));
});

test('DH group14：无效的对端公钥 f 被拒绝', () => {
    const kp = dhGroup14Keypair();
    const p = DH_GROUP14_PRIME;
    const bad = [
        new Uint8Array([0]),
        new Uint8Array([1]),
        // f = p - 1
        (() => {
            const hex = (p - 1n).toString(16);
            return new Uint8Array(Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex'));
        })(),
        // f = p
        (() => {
            const hex = p.toString(16);
            return new Uint8Array(Buffer.from(hex, 'hex'));
        })(),
    ];
    for (const f of bad) {
        assert.throws(() => dhGroup14Shared(kp.privateKey, f), /DH group14/);
    }
});

/* ------------------------------------------------- task 6: ECDSA P-256 keys */

async function expectEcdsaKeyLoads(pem, { publicPoint }) {
    const key = await loadPrivateKey(pem);
    assert.equal(key.alg, 'ecdsa-sha2-nistp256');
    const r = new Reader(key.publicBlob);
    assert.equal(r.text(), 'ecdsa-sha2-nistp256');
    assert.equal(r.text(), 'nistp256');
    assert.deepEqual(Buffer.from(r.str()), Buffer.from(publicPoint));
    const data = new TextEncoder().encode('ssh-userauth-test-payload');
    const sig = await key.sign(data);
    return { key, data, sig };
}

test('ECDSA：PKCS#8（BEGIN PRIVATE KEY）可解析、签名可被对应公钥验证', async () => {
    const pair = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pkcs8 = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey));
    const jwk = await subtle().exportKey('jwk', pair.publicKey);
    const pem = pemWrap(Buffer.from(pkcs8).toString('base64'), 'PRIVATE KEY');
    const { data, sig } = await expectEcdsaKeyLoads(pem, { publicPoint: pointFromJwk(jwk) });
    assert.equal(
        await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, sshSigToRaw(sig), data),
        true
    );
    // 篡改数据后验证必须失败
    assert.equal(
        await subtle().verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            pair.publicKey,
            sshSigToRaw(sig),
            new TextEncoder().encode('tampered')
        ),
        false
    );
});

test('ECDSA：SEC1（BEGIN EC PRIVATE KEY）可解析、签名可被对应公钥验证', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const sec1Pem = privateKey.export({ type: 'sec1', format: 'pem' });
    const jwkPub = publicKey.export({ format: 'jwk' });
    const pubKey = await subtle().importKey('jwk', jwkPub, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
        'verify',
    ]);
    const { data, sig } = await expectEcdsaKeyLoads(sec1Pem, { publicPoint: pointFromJwk(jwkPub) });
    assert.equal(
        await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sshSigToRaw(sig), data),
        true
    );
});

test('ECDSA：不带 [1] 公钥的 SEC1 也能解析（公钥从 JWK 导出推导）', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const sec1Der = privateKey.export({ type: 'sec1', format: 'der' });
    // 手工拼一份最小 SEC1：只有 version + privateKey，没有 [0]/[1]
    //（取原 DER 里 version 与 privateKey OCTET STRING 两段）
    const d = extractSec1Scalar(sec1Der);
    const minimal = derSeq(derInt(new Uint8Array([1])), derOctet(d));
    const pem = pemWrap(Buffer.from(minimal).toString('base64'), 'EC PRIVATE KEY');
    const jwkPub = publicKey.export({ format: 'jwk' });
    const pubKey = await subtle().importKey('jwk', jwkPub, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
        'verify',
    ]);
    const { data, sig } = await expectEcdsaKeyLoads(pem, { publicPoint: pointFromJwk(jwkPub) });
    assert.equal(
        await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sshSigToRaw(sig), data),
        true
    );
});

test('ECDSA：P-384 密钥明确拒绝（只支持 P-256）', async () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    await assert.rejects(loadPrivateKey(privateKey.export({ type: 'sec1', format: 'pem' })), /P-256/);
    await assert.rejects(loadPrivateKey(privateKey.export({ type: 'pkcs8', format: 'pem' })), /P-256/);
});

/** 从 SEC1 DER 里取 privateKey OCTET STRING 的内容（测试用的最小 DER 解析） */
function extractSec1Scalar(der) {
    let p = 0;
    const readHeader = () => {
        const tag = der[p++];
        let len = der[p++];
        if (len & 0x80) {
            const n = len & 0x7f;
            len = 0;
            for (let i = 0; i < n; i++) len = (len << 8) | der[p++];
        }
        return { tag, len, start: p };
    };
    const seq = readHeader(); // SEQUENCE：只读头部，子节点在其内容区内
    assert.equal(seq.tag, 0x30);
    const readNode = () => {
        const h = readHeader();
        const value = der.subarray(h.start, h.start + h.len);
        p = h.start + h.len;
        return { tag: h.tag, value };
    };
    readNode(); // version INTEGER
    return readNode().value; // privateKey OCTET STRING
}

/* 测试用的最小 DER 构造（只用于拼不带 [1] 公钥的 SEC1） */
function derTLV(tag, content) {
    const len = content.length;
    const hdr = len < 0x80 ? [tag, len] : len < 0x100 ? [tag, 0x81, len] : [tag, 0x82, len >> 8, len & 0xff];
    return Buffer.concat([Buffer.from(hdr), Buffer.from(content)]);
}
function derInt(raw) {
    let v = Buffer.from(raw);
    while (v.length > 1 && v[0] === 0) v = v.subarray(1);
    if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0]), v]);
    return derTLV(0x02, v);
}
function derOctet(u8) {
    return derTLV(0x04, u8);
}
function derSeq(...items) {
    return derTLV(0x30, Buffer.concat(items.map((i) => Buffer.from(i))));
}

test('ECDSA：OpenSSH 格式（ssh-keygen 生成）可解析，公钥与 ssh-keygen -y 一致', async (t) => {
    if (!hasSshKeygen()) {
        t.skip('本机没有 ssh-keygen');
        return;
    }
    const tmp = makeTempDir(t, 'onessh-ec-openssh-');
    const keyPath = path.join(tmp, 'id_ecdsa');
    execFileSync('ssh-keygen', ['-t', 'ecdsa', '-b', '256', '-f', keyPath, '-N', '', '-q']);
    const pem = fs.readFileSync(keyPath, 'utf8');
    const pubLine = execFileSync('ssh-keygen', ['-y', '-f', keyPath], { encoding: 'utf8' }).trim();
    const [type, b64] = pubLine.split(/\s+/);
    assert.equal(type, 'ecdsa-sha2-nistp256');
    const expectedBlob = Buffer.from(b64, 'base64');
    const key = await loadPrivateKey(pem);
    assert.equal(key.alg, 'ecdsa-sha2-nistp256');
    assert.deepEqual(Buffer.from(key.publicBlob), expectedBlob);
    // 用 -y 公钥里的点验签名
    const r = new Reader(expectedBlob);
    r.text();
    r.text();
    const point = Buffer.from(r.str());
    const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: point.subarray(1, 33).toString('base64url'),
        y: point.subarray(33, 65).toString('base64url'),
    };
    const pubKey = await subtle().importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const data = new TextEncoder().encode('openssh-ecdsa-sign-check');
    const sig = await key.sign(data);
    assert.equal(
        await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sshSigToRaw(sig), data),
        true
    );
});

test('ECDSA：带口令的 OpenSSH 私钥仍明确拒绝（不在本次任务范围）', async (t) => {
    if (!hasSshKeygen()) {
        t.skip('本机没有 ssh-keygen');
        return;
    }
    const tmp = makeTempDir(t, 'onessh-ec-encrypted-');
    const keyPath = path.join(tmp, 'id_ecdsa');
    execFileSync('ssh-keygen', ['-t', 'ecdsa', '-b', '256', '-f', keyPath, '-N', 'temporary-passphrase', '-q']);
    await assert.rejects(loadPrivateKey(fs.readFileSync(keyPath, 'utf8')), /口令/);
});

/* ------------------------------------------------------------- E2E：本地 ssh2 */

function startTestServer({ kex, onAuth }) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'onessh-e2e-'));
    const keyPath = path.join(tmp, 'host_ed25519');
    execFileSync('ssh-keygen', ['-t', 'ed25519', '-f', keyPath, '-N', '', '-q']);
    const hostKey = fs.readFileSync(keyPath);
    const opts = { hostKeys: [hostKey] };
    if (kex) opts.algorithms = { kex };
    const server = new Server(opts, (client) => {
        client.on('authentication', onAuth);
        client.on('ready', () => {
            client.on('session', (accept) => {
                const session = accept();
                session.on('pty', (a) => a && a());
                session.on('env', (a) => a && a());
                session.on('shell', (a) => a().write('ready\r\n'));
                session.on('exec', (acceptExec, _reject, info) => {
                    const stream = acceptExec();
                    stream.write('exec-ok:' + info.command + '\n');
                    stream.exit(0);
                    stream.end();
                });
            });
        });
    });
    return new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, tmp }));
    });
}

function connectClient(port, { username, auth }) {
    return new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1');
        let settled = false;
        const timer = setTimeout(() => done(new Error('E2E 连接超时（20 秒内未 ready）')), 20000);
        // 注意：ready 后不能像 bench 工具那样立刻销毁 socket，
        // 后面的 exec 还要走这条连接；socket 由调用方在 finally 里销毁。
        const done = (err, client) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (err) {
                socket.destroy();
                reject(err);
            } else {
                resolve({ client, socket });
            }
        };
        const client = new SSHClient({
            username,
            auth,
            cols: 80,
            rows: 24,
            write: (bytes) => {
                socket.write(Buffer.from(bytes));
                return Promise.resolve();
            },
            onData: () => {},
            onEvent: (ev) => {
                if (ev.type === 'ready') done(null, client);
                if (ev.type === 'error') done(new Error(ev.message));
            },
            onHostKey: async () => true,
            onKeyboardInteractive: async () => null,
        });
        socket.on('error', (e) => done(e));
        socket.on('connect', () => client.connect());
        socket.on('data', (d) => client.feed(new Uint8Array(d)));
    });
}

async function stopServer({ server, tmp }) {
    await new Promise((res) => server.close(res));
    fs.rmSync(tmp, { recursive: true, force: true });
}

function passwordAuthHandler(password) {
    return (ctx) => {
        if (ctx.method === 'password' && ctx.username === 'testuser' && ctx.password === password) ctx.accept();
        else ctx.reject(['password']);
    };
}

test('E2E：只支持 group14 的服务器能完成握手 + 密码认证 + exec', { timeout: 30000 }, async (t) => {
    if (!hasSshKeygen()) {
        t.skip('本机没有 ssh-keygen');
        return;
    }
    const password = 'pw-' + randomBytes(8).toString('hex');
    const srv = await startTestServer({
        kex: ['diffie-hellman-group14-sha256'],
        onAuth: passwordAuthHandler(password),
    });
    let conn;
    try {
        conn = await connectClient(srv.port, { username: 'testuser', auth: { password } });
        assert.equal(conn.client.neg.kex, 'diffie-hellman-group14-sha256');
        const res = await conn.client.exec('echo dh14-ok');
        assert.match(res.stdout, /exec-ok:echo dh14-ok/);
        assert.equal(res.code, 0);
    } finally {
        if (conn) conn.socket.destroy();
        await stopServer(srv);
    }
});

test('E2E：只支持 curve25519 的服务器行为不变（回归）', { timeout: 30000 }, async (t) => {
    if (!hasSshKeygen()) {
        t.skip('本机没有 ssh-keygen');
        return;
    }
    const password = 'pw-' + randomBytes(8).toString('hex');
    const srv = await startTestServer({
        kex: ['curve25519-sha256'],
        onAuth: passwordAuthHandler(password),
    });
    let conn;
    try {
        conn = await connectClient(srv.port, { username: 'testuser', auth: { password } });
        assert.equal(conn.client.neg.kex, 'curve25519-sha256');
        const res = await conn.client.exec('echo c25519-ok');
        assert.match(res.stdout, /exec-ok:echo c25519-ok/);
        assert.equal(res.code, 0);
    } finally {
        if (conn) conn.socket.destroy();
        await stopServer(srv);
    }
});

test('E2E：只支持 curve25519-sha256@libssh.org 的服务器能握手（猜包重发路径）', { timeout: 30000 }, async (t) => {
    if (!hasSshKeygen()) {
        t.skip('本机没有 ssh-keygen');
        return;
    }
    const password = 'pw-' + randomBytes(8).toString('hex');
    const srv = await startTestServer({
        kex: ['curve25519-sha256@libssh.org'],
        onAuth: passwordAuthHandler(password),
    });
    let conn;
    try {
        conn = await connectClient(srv.port, { username: 'testuser', auth: { password } });
        assert.equal(conn.client.neg.kex, 'curve25519-sha256@libssh.org');
        const res = await conn.client.exec('echo libssh-ok');
        assert.match(res.stdout, /exec-ok:echo libssh-ok/);
        assert.equal(res.code, 0);
    } finally {
        if (conn) conn.socket.destroy();
        await stopServer(srv);
    }
});

test('E2E：group14 服务器 + ECDSA P-256 公钥认证（服务端验签）', { timeout: 30000 }, async (t) => {
    if (!hasSshKeygen()) {
        t.skip('本机没有 ssh-keygen');
        return;
    }
    // 临时生成 P-256 密钥对（PKCS#8 PEM 给客户端用）
    const pair = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pkcs8 = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey));
    const privatePem = pemWrap(Buffer.from(pkcs8).toString('base64'), 'PRIVATE KEY');
    const loaded = await loadPrivateKey(privatePem);
    const expectedBlob = Buffer.from(loaded.publicBlob);

    // ssh2 服务端不代验公钥签名：这里用 Node crypto 自行验签，
    // 只有签名真正有效且公钥匹配时才放行。
    const srv = await startTestServer({
        kex: ['diffie-hellman-group14-sha256'],
        onAuth: (ctx) => {
            if (ctx.method !== 'publickey' || ctx.username !== 'testuser' || !ctx.signature) {
                ctx.reject(['publickey']);
                return;
            }
            try {
                assert.equal(ctx.key.algo, 'ecdsa-sha2-nistp256');
                assert.deepEqual(Buffer.from(ctx.key.data), expectedBlob);
                const r = new Reader(new Uint8Array(ctx.key.data));
                r.text();
                r.text();
                const point = Buffer.from(r.str());
                const jwk = {
                    kty: 'EC',
                    crv: 'P-256',
                    x: point.subarray(1, 33).toString('base64url'),
                    y: point.subarray(33, 65).toString('base64url'),
                };
                const pub = createPublicKey({ key: jwk, format: 'jwk' });
                // ctx.blob 为被签数据（session id + 请求体），ctx.signature 为 DER 格式
                assert.equal(cryptoVerify('sha256', ctx.blob, pub, ctx.signature), true);
                ctx.accept();
            } catch {
                ctx.reject(['publickey']);
            }
        },
    });
    let conn;
    try {
        conn = await connectClient(srv.port, { username: 'testuser', auth: { privateKey: privatePem } });
        assert.equal(conn.client.neg.kex, 'diffie-hellman-group14-sha256');
        const res = await conn.client.exec('echo ecdsa-ok');
        assert.match(res.stdout, /exec-ok:echo ecdsa-ok/);
        assert.equal(res.code, 0);
    } finally {
        if (conn) conn.socket.destroy();
        await stopServer(srv);
    }
});
