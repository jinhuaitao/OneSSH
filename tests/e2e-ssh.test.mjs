/**
 * E2E 冒烟：真实 SSHClient（src/ssh/client.js）对真实 ssh2 本地 sshd。
 *
 *   npm run test:e2e
 *
 * 关键点：
 * - 不 import worker/session，SSHClient 本身不 import `cloudflare:sockets`，
 *   所以不需要 tests/register.mjs 的 sockets 桩，直接用 node:net 做传输
 *  （socket.write / socket.on('data') -> client.feed，模式见 tools/bench-handshake.mjs）。
 * - 服务器：ssh2 的 Server，127.0.0.1 随机端口，密码认证；
 *   主机密钥用本机 ssh-keygen 临时生成到 os.tmpdir()，跑完清理，不落库。
 * - 用户名/密码是固定测试值（e2e / e2e-test-password），非真实凭据。
 * - 若本机没有 ssh-keygen，测试自动跳过，保证 npm test 在无 ssh-keygen
 *   的 CI 沙箱里仍全绿；npm run test:e2e 在有 ssh-keygen 的本机必须真实跑通。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { SSHClient } from '../src/ssh/client.js';

const require = createRequire(import.meta.url);
const { Server } = require('ssh2');

const USERNAME = 'e2e';
const PASSWORD = 'e2e-test-password'; // 仅测试用固定值，非真实凭据

// 环境探测：ssh-keygen 是否存在。注意不能用 `ssh-keygen -h` 探测——
// 本机 OpenSSH 会把 -h 当成别的选项，交互式提示输入文件路径而挂起。
// 用 `-l -f <不存在的文件>`：无提示、立即退出；缺失时 spawnSync 返回 ENOENT。
const HAS_SSH_KEYGEN = (() => {
    try {
        const r = spawnSync('ssh-keygen', ['-l', '-f', path.join(os.tmpdir(), 'one-ssh-e2e-no-such-key')], {
            stdio: 'ignore',
        });
        return !r.error;
    } catch {
        return false;
    }
})();
const SKIP = HAS_SSH_KEYGEN ? false : 'ssh-keygen 不可用，跳过 E2E（需要本机 ssh-keygen 生成临时主机密钥）';

function withTimeout(promise, ms, message) {
    let timer;
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error(message)), ms);
        }),
    ]).finally(() => clearTimeout(timer));
}

async function waitFor(predicate, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (predicate()) return true;
        await new Promise((r) => setTimeout(r, 50));
    }
    return predicate();
}

async function startTestServer() {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-e2e-'));
    const keyPath = path.join(tmp, 'host_ed25519');
    execFileSync('ssh-keygen', ['-t', 'ed25519', '-f', keyPath, '-N', '', '-q']);
    const hostKey = fs.readFileSync(keyPath);
    const server = new Server({ hostKeys: [hostKey] }, (client) => {
        client.on('error', () => {});
        client.on('authentication', (ctx) => {
            if (ctx.method === 'password' && ctx.username === USERNAME && ctx.password === PASSWORD) ctx.accept();
            else ctx.reject(['password']);
        });
        client.on('ready', () => {
            client.on('session', (accept) => {
                const session = accept();
                session.on('pty', (a) => a && a());
                session.on('env', (a) => a && a());
                session.on('shell', (a) => {
                    const stream = a();
                    stream.write('ready\r\n');
                });
                session.on('exec', (acceptExec, _reject, info) => {
                    const stream = acceptExec();
                    stream.write(`hello-e2e:${info.command}\n`);
                    stream.exit(0);
                    stream.end();
                });
            });
        });
    });
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    return { server, port: server.address().port, tmp };
}

function connectClient(port) {
    const socket = net.connect(port, '127.0.0.1');
    socket.setNoDelay(true);
    const shellChunks = [];
    let readyResolve;
    let readyReject;
    const readyPromise = new Promise((resolve, reject) => {
        readyResolve = resolve;
        readyReject = reject;
    });
    const client = new SSHClient({
        username: USERNAME,
        auth: { password: PASSWORD },
        cols: 80,
        rows: 24,
        write: (bytes) => {
            socket.write(Buffer.from(bytes));
            return Promise.resolve();
        },
        onData: (data) => shellChunks.push(Buffer.from(data)),
        onEvent: (ev) => {
            if (ev.type === 'ready') readyResolve();
            if (ev.type === 'error') readyReject(new Error(ev.message));
        },
        onHostKey: async () => true,
        onKeyboardInteractive: async () => null,
    });
    socket.on('error', (e) => readyReject(e));
    socket.on('connect', () => client.connect());
    socket.on('data', (d) => client.feed(new Uint8Array(d)));
    return { client, socket, shellChunks, readyPromise };
}

async function cleanup({ client, socket, server, tmp }) {
    try {
        await client.close();
    } catch {}
    socket.destroy();
    await Promise.race([new Promise((r) => server.close(r)), new Promise((r) => setTimeout(r, 2000))]);
    fs.rmSync(tmp, { recursive: true, force: true });
}

test('E2E: 密码认证 + exec 回显', { skip: SKIP, timeout: 15000 }, async () => {
    const { server, port, tmp } = await startTestServer();
    const conn = connectClient(port);
    try {
        await withTimeout(conn.readyPromise, 10000, 'SSH 握手/认证超时（10 秒内未 ready）');
        const res = await conn.client.exec('echo hello-e2e', 8000);
        assert.equal(res.code, 0, `exec 应返回 exit 0，实际 ${res.code}，stdout=${JSON.stringify(res.stdout)}`);
        assert.match(res.stdout, /hello-e2e:echo hello-e2e/);
        assert.match(res.stdout, /hello-e2e/);
    } finally {
        await cleanup({ ...conn, server, tmp });
    }
});

test('E2E: shell ready 且收到服务端问候', { skip: SKIP, timeout: 15000 }, async () => {
    const { server, port, tmp } = await startTestServer();
    const conn = connectClient(port);
    try {
        await withTimeout(conn.readyPromise, 10000, 'SSH 握手/认证超时（10 秒内未 ready）');
        const got = await waitFor(
            () => Buffer.concat(conn.shellChunks).toString().includes('ready'),
            5000
        );
        assert.ok(got, 'shell 未在 5 秒内收到服务端 ready 问候');
    } finally {
        await cleanup({ ...conn, server, tmp });
    }
});
