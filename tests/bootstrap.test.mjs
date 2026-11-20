import test from 'node:test';
import assert from 'node:assert/strict';

import worker from '../src/worker.js';
import { MemoryBucket, makeEnv, call, cookieFrom, ADMIN, SETUP_TOKEN } from './helpers.mjs';
import { putJSON, putJSONAll, list, listLimited } from '../src/store.js';
import { encryptSecret, decryptSecret, invalidateMasterKeyCache, cachedMasterKeyFingerprint } from '../src/auth.js';

const PW = ADMIN.password;

/** 新建一套干净环境并完成初始化，返回 { env, cookie } */
async function setupApp(extra) {
    const env = makeEnv(Object.assign({ __worker: worker }, extra || {}));
    const res = await call(env, '/api/setup', {
        method: 'POST',
        body: { username: ADMIN.username, password: PW, token: SETUP_TOKEN },
    });
    assert.equal(res.status, 200, '初始化应当成功: ' + res.text);
    return { env, cookie: cookieFrom(res) };
}

async function ed25519Pem() {
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    const b64 = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n');
    return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----\n`;
}

/* ------------------------------------------------------------- bootstrap */

test('bootstrap：未登录返回 401', async () => {
    const env = makeEnv({ __worker: worker });
    const res = await call(env, '/api/bootstrap');
    assert.equal(res.status, 401);
});

test('bootstrap：已登录一次返回全量，且与逐个接口一致、keys/creds 去敏', async () => {
    const { env, cookie } = await setupApp();

    // 种子：2 台主机（1 台带分组）、1 个分组、1 把密钥、1 个常用账号、片段、known
    let r = await call(env, '/api/hosts', {
        method: 'POST', cookie,
        body: { name: 'web-1', host: '203.0.113.10', port: 22, username: 'root', authType: 'password', password: 'host-secret-1', group: 'prod' },
    });
    assert.equal(r.status, 200, r.text);
    r = await call(env, '/api/hosts', {
        method: 'POST', cookie,
        body: { name: 'web-2', host: '203.0.113.11', port: 22, username: 'root', authType: 'password', password: 'host-secret-2' },
    });
    assert.equal(r.status, 200, r.text);
    r = await call(env, '/api/groups', { method: 'POST', cookie, body: { op: 'add', name: 'ops' } });
    assert.equal(r.status, 200, r.text);
    r = await call(env, '/api/keys', { method: 'POST', cookie, body: { name: 'deploy', privateKey: await ed25519Pem() } });
    assert.equal(r.status, 200, r.text);
    r = await call(env, '/api/creds', { method: 'POST', cookie, body: { name: 'shared', username: 'deploy', password: 'cred-secret-1' } });
    assert.equal(r.status, 200, r.text);
    r = await call(env, '/api/snippets', { method: 'POST', cookie, body: { snippets: [{ name: 'uptime', command: 'uptime' }] } });
    assert.equal(r.status, 200, r.text);
    await putJSON(env, 'known/203.0.113.10:22', { host: '203.0.113.10', port: 22, algo: 'ssh-ed25519', fingerprint: 'SHA256:testfp' });

    const boot = await call(env, '/api/bootstrap', { cookie });
    assert.equal(boot.status, 200, boot.text);

    // 与逐个接口逐项比对
    const hosts = await call(env, '/api/hosts', { cookie });
    const groups = await call(env, '/api/groups', { cookie });
    const keys = await call(env, '/api/keys', { cookie });
    const creds = await call(env, '/api/creds', { cookie });
    const snippets = await call(env, '/api/snippets', { cookie });
    const known = await call(env, '/api/known', { cookie });
    const state = await call(env, '/api/state', { cookie });
    assert.deepEqual(boot.json.hosts, hosts.json.hosts);
    assert.deepEqual(boot.json.groups, groups.json.groups);
    assert.deepEqual(boot.json.keys, keys.json.keys);
    assert.deepEqual(boot.json.creds, creds.json.creds);
    assert.deepEqual(boot.json.snippets, snippets.json.snippets);
    assert.deepEqual(boot.json.known, known.json.known);
    assert.equal(boot.json.versions.groups, groups.json.version);
    assert.equal(boot.json.versions.keys, keys.json.version);
    assert.equal(boot.json.versions.creds, creds.json.version);
    assert.equal(boot.json.versions.snippets, snippets.json.version);
    assert.equal(boot.json.state.version, state.json.version);
    assert.equal(boot.json.state.user, state.json.user);
    assert.equal(boot.json.state.authed, true);
    assert.equal(boot.json.state.totpEnabled, false);
    assert.deepEqual([...boot.json.groups].sort(), ['ops', 'prod']);

    // 去敏：keys/creds/hosts 里不能出现任何密文或明文凭据
    const body = JSON.stringify(boot.json);
    assert.ok(!body.includes('PRIVATE KEY'), 'bootstrap 不能泄露私钥明文');
    assert.ok(!body.includes('host-secret-1') && !body.includes('host-secret-2'), 'bootstrap 不能泄露主机密码');
    assert.ok(!body.includes('cred-secret-1'), 'bootstrap 不能泄露常用账号密码');
    for (const k of boot.json.keys) assert.equal(k.keyEnc, undefined);
    for (const c of boot.json.creds) assert.equal(c.passEnc, undefined);
    for (const h of boot.json.hosts) {
        assert.equal(h.secretEnc, undefined);
        assert.equal(h.keyEnc, undefined);
    }
    assert.equal(boot.json.hosts.find((h) => h.name === 'web-1').hasSecret, true);
});

/* --------------------------------------------------------- 主密钥缓存 */

class CountingBucket extends MemoryBucket {
    constructor() {
        super();
        this.masterGets = 0;
    }
    async get(key) {
        if (key === 'sys/master') this.masterGets++;
        return super.get(key);
    }
}

function newMasterKeyB64() {
    return Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64');
}

test('主密钥缓存：同一 isolate 内多次解密只读一次 R2，TTL 过期后重新读', async () => {
    invalidateMasterKeyCache();
    const env = makeEnv({ __worker: worker, BUCKET: new CountingBucket() });
    const res = await call(env, '/api/setup', {
        method: 'POST',
        body: { username: ADMIN.username, password: PW, token: SETUP_TOKEN },
    });
    assert.equal(res.status, 200, res.text);

    env.BUCKET.masterGets = 0;
    const blob = await encryptSecret(env, 'pw-123', 'host:h1');
    assert.equal(env.BUCKET.masterGets, 1, '第一次加解密应读一次 sys/master');
    const fp1 = cachedMasterKeyFingerprint();
    assert.match(fp1, /^[a-f0-9]{64}$/);

    env.BUCKET.masterGets = 0;
    assert.equal(await decryptSecret(env, blob, 'host:h1'), 'pw-123');
    assert.equal(await decryptSecret(env, blob, 'host:h1'), 'pw-123');
    assert.equal(env.BUCKET.masterGets, 0, '缓存命中时两次解密都不应再读 R2');
    assert.equal(cachedMasterKeyFingerprint(), fp1, '缓存命中时指纹不变');

    // TTL 过期（把 Date.now 拨快 61 秒）：下一次解密必须重新读 R2
    const realNow = Date.now;
    try {
        Date.now = () => realNow() + 61 * 1000;
        env.BUCKET.masterGets = 0;
        assert.equal(await decryptSecret(env, blob, 'host:h1'), 'pw-123');
        assert.equal(env.BUCKET.masterGets, 1, 'TTL 过期后应重新读一次 sys/master');
    } finally {
        Date.now = realNow;
    }
    invalidateMasterKeyCache();
});

test('主密钥缓存：轮换后显式失效，旧密文解不开、新密钥立即生效', async () => {
    invalidateMasterKeyCache();
    const env = makeEnv({ __worker: worker, BUCKET: new CountingBucket() });
    const res = await call(env, '/api/setup', {
        method: 'POST',
        body: { username: ADMIN.username, password: PW, token: SETUP_TOKEN },
    });
    assert.equal(res.status, 200, res.text);

    const blob = await encryptSecret(env, 'pw-123', 'host:h1');
    assert.equal(await decryptSecret(env, blob, 'host:h1'), 'pw-123');
    const fpBefore = cachedMasterKeyFingerprint();

    // 模拟轮换：直接换掉 R2 里的 sys/master（不走失效路径时，TTL 内仍用旧缓存）
    await putJSON(env, 'sys/master', { key: newMasterKeyB64(), createdAt: Date.now() });
    assert.equal(await decryptSecret(env, blob, 'host:h1'), 'pw-123', 'TTL 内缓存未失效前，旧密钥仍可用');

    // 导入/轮换路径显式失效后，旧密文必须解不开，新密钥立即生效
    invalidateMasterKeyCache();
    await assert.rejects(decryptSecret(env, blob, 'host:h1'), '轮换并失效后，旧主密钥加密的密文必须解不开');
    const blob2 = await encryptSecret(env, 'pw-456', 'host:h1');
    assert.equal(await decryptSecret(env, blob2, 'host:h1'), 'pw-456');
    assert.notEqual(cachedMasterKeyFingerprint(), fpBefore, '失效后重新加载，指纹应变为新密钥');
    invalidateMasterKeyCache();
});

/* ------------------------------------------------------------ listLimited */

test('listLimited：只取到上限就停，不全扫', async () => {
    const env = makeEnv({ __worker: worker });
    const now = Date.now();
    await putJSONAll(env, Array.from({ length: 60 }, (_, i) => ({ key: `conn/tok/${now - i * 1000}-x${i}`, rec: 1 })));
    assert.equal((await list(env, 'conn/')).length, 60);
    const limited = await listLimited(env, 'conn/', 11);
    assert.equal(limited.length, 11, '只要 limit 条就停');
    assert.equal((await listLimited(env, 'conn/', 100)).length, 60, 'limit 大于总量时返回全部');
    assert.equal((await listLimited(env, 'conn/', 0)).length, 0);
});
