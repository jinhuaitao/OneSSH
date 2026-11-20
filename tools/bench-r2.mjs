/**
 * R2 读写面性能基准：tools/bench-r2.mjs
 *
 * 用法：node --import ./tests/register.mjs tools/bench-r2.mjs
 *
 * 用 tests/helpers.mjs 的 MemoryBucket 包一层人工延迟（每次 R2 操作 20ms，
 * list 每页最多 10 条，模拟真实 R2 的分页往返），种子 100 台主机，
 * 测以下场景，各跑 3 次取中位，输出 JSON：
 *   - listJSON_hosts：列出并回读 100 台主机（对照项，改动前后应基本不变）
 *   - startup_sequential：启动时 7 个接口逐个 fetch（/api/hosts、groups、
 *     keys、creds、snippets、known、state）
 *   - bootstrap：单次 GET /api/bootstrap（改动前不存在，记 null）
 *   - decrypt_x10_shared：同一模块实例内 decryptSecret ×10（主密钥缓存命中）
 *   - decrypt_x10_cold_each：每次 decrypt 都用全新模块实例（模拟无缓存，
 *     每次都要读一次 sys/master，作为缓存价值的参照）
 *   - conn_scan_full：slidingBudget 原来的全量 list（60 条 conn 记录）
 *   - conn_scan_limited：listLimited(limit+1)（改动前不存在，记 null）
 *
 * 注意：不要用 git stash 跑基线——直接在改动前跑一次、改动后再跑一次对比。
 */
import worker from '../src/worker.js';
import { MemoryBucket, makeEnv, call, cookieFrom, ADMIN, SETUP_TOKEN } from '../tests/helpers.mjs';
import { listJSON, list, putJSONAll } from '../src/store.js';
import * as store from '../src/store.js';

const DELAY_MS = 20;
const PAGE_SIZE = 10;
const HOST_COUNT = 100;
const REPS = 3;

/** 每次 R2 操作固定延迟；list 每页只给 10 条，模拟真实 R2 分页。 */
class DelayBucket extends MemoryBucket {
    async get(key) {
        await sleep(DELAY_MS);
        return super.get(key);
    }
    async put(key, value, opts) {
        await sleep(DELAY_MS);
        return super.put(key, value, opts);
    }
    async delete(key) {
        await sleep(DELAY_MS);
        return super.delete(key);
    }
    async list(query) {
        await sleep(DELAY_MS);
        const q = { ...(query || {}), limit: Math.min(query && query.limit ? query.limit : 1000, PAGE_SIZE) };
        return super.list(q);
    }
}

function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
}

function median(xs) {
    const s = [...xs].sort((a, b) => a - b);
    return s[Math.floor(s.length / 2)];
}

async function timed(fn) {
    const t0 = performance.now();
    await fn();
    return performance.now() - t0;
}

async function setupEnv() {
    const env = makeEnv({ __worker: worker, BUCKET: new DelayBucket() });
    const res = await call(env, '/api/setup', {
        method: 'POST',
        body: { username: ADMIN.username, password: ADMIN.password, token: SETUP_TOKEN },
    });
    if (res.status !== 200) throw new Error('setup 失败: ' + res.text);
    const cookie = cookieFrom(res);
    // 种子数据：100 台主机、10 密钥、10 常用账号、20 片段、10 条 known-host
    const hosts = [];
    for (let i = 0; i < HOST_COUNT; i++) {
        hosts.push({
            key: 'hosts/h' + String(i).padStart(3, '0'),
            rec: {
                id: 'h' + String(i).padStart(3, '0'),
                name: 'host-' + i,
                host: '203.0.113.' + ((i % 250) + 1),
                port: 22,
                username: 'root',
                authType: 'password',
                group: i % 3 === 0 ? 'prod' : i % 3 === 1 ? 'dev' : '',
                createdAt: 1700000000000 + i,
            },
        });
    }
    const keys = Array.from({ length: 10 }, (_, i) => ({
        id: 'k' + i, name: 'key-' + i, algo: 'ed25519', fingerprint: 'SHA256:xxxx' + i, keyEnc: 'v1:AAAAAAAAAAAAAAAA:bbbbbbbbbbbbbbbbbbbbbbbb', createdAt: 1700000000000,
    }));
    const creds = Array.from({ length: 10 }, (_, i) => ({
        id: 'c' + i, name: 'cred-' + i, username: 'user' + i, passEnc: 'v1:AAAAAAAAAAAAAAAA:bbbbbbbbbbbbbbbbbbbbbbbb', createdAt: 1700000000000,
    }));
    const snippets = Array.from({ length: 20 }, (_, i) => ({ id: 's' + i, name: 'snip-' + i, command: 'echo ' + i }));
    const known = Array.from({ length: 10 }, (_, i) => ({
        key: 'known/203.0.113.' + (i + 1) + ':22',
        rec: { host: '203.0.113.' + (i + 1), port: 22, algo: 'ssh-ed25519', fingerprint: 'SHA256:yyyy' + i },
    }));
    await putJSONAll(env, [
        ...hosts,
        ...known,
        { key: 'sys/keys', rec: { keys, version: 1 } },
        { key: 'sys/creds', rec: { creds, version: 1 } },
        { key: 'sys/groups', rec: { groups: ['prod', 'dev'], version: 1 } },
        { key: 'sys/snippets', rec: { snippets, version: 1 } },
    ]);
    // 60 条连接预算记录（供 slidingBudget 全扫 vs limit 对照）
    const now = Date.now();
    const token = 'a'.repeat(24);
    const conn = Array.from({ length: 60 }, (_, i) => ({ key: `conn/${token}/${now - i * 1000}-abc${i}`, rec: 1 }));
    await putJSONAll(env, conn);
    return { env, cookie, connPrefix: `conn/${token}/` };
}

async function runScenario(name, fn) {
    const runs = [];
    for (let i = 0; i < REPS; i++) runs.push(Math.round((await timed(fn)) * 10) / 10);
    return { runs, median_ms: median(runs) };
}

async function main() {
    const { env, cookie, connPrefix } = await setupEnv();
    const results = {};

    results.listJSON_hosts = await runScenario('listJSON_hosts', () => listJSON(env, 'hosts/'));

    results.startup_sequential = await runScenario('startup_sequential', async () => {
        for (const p of ['/api/hosts', '/api/groups', '/api/keys', '/api/creds', '/api/snippets', '/api/known', '/api/state']) {
            const r = await call(env, p, { cookie });
            if (r.status !== 200) throw new Error(p + ' -> ' + r.status + ' ' + r.text);
        }
    });

    if (typeof worker.fetch === 'function') {
        const probe = await call(env, '/api/bootstrap', { cookie });
        if (probe.status === 200) {
            results.bootstrap = await runScenario('bootstrap', async () => {
                const r = await call(env, '/api/bootstrap', { cookie });
                if (r.status !== 200) throw new Error('/api/bootstrap -> ' + r.status + ' ' + r.text);
            });
        } else {
            results.bootstrap = { runs: null, median_ms: null, note: 'endpoint 不存在（HTTP ' + probe.status + '），改动前基线' };
        }
    }

    // decrypt：每次 rep 用全新模块实例拿冷缓存；共享实例内 10 次调用只读一次 R2。
    const { encryptSecret } = await import('../src/auth.js?bench=shared');
    const blob = await encryptSecret(env, 's3cret-password', 'host:h000');
    results.decrypt_x10_shared = await runScenario('decrypt_x10_shared', async () => {
        const { decryptSecret } = await import('../src/auth.js?bench=shared');
        for (let i = 0; i < 10; i++) await decryptSecret(env, blob, 'host:h000');
    });
    results.decrypt_x10_cold_each = await runScenario('decrypt_x10_cold_each', async () => {
        for (let i = 0; i < 10; i++) {
            const { decryptSecret } = await import(`../src/auth.js?bench=cold-${Date.now()}-${i}-${Math.random()}`);
            await decryptSecret(env, blob, 'host:h000');
        }
    });

    results.conn_scan_full = await runScenario('conn_scan_full', () => list(env, connPrefix));
    if (typeof store.listLimited === 'function') {
        results.conn_scan_limited = await runScenario('conn_scan_limited', () => store.listLimited(env, connPrefix, 11));
    } else {
        results.conn_scan_limited = { runs: null, median_ms: null, note: 'listLimited 不存在，改动前基线' };
    }

    const out = {
        config: { r2_delay_ms: DELAY_MS, r2_page_size: PAGE_SIZE, hosts: HOST_COUNT, reps: REPS },
        results,
    };
    console.log(JSON.stringify(out, null, 2));
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
