/**
 * SFTP chmod E2E：真实 SSHClient + 真实 SFTPClient，对 ssh2 起的本地服务器。
 *
 *   npm run test:e2e
 *
 * 本机没有 sshd / sftp-server 二进制，所以服务器端用 ssh2 的 Server +
 * 一个内存里的最小 SFTP 子系统（只实现 chmod 测试需要的 STAT / LSTAT /
 * SETSTAT / REALPATH，权限存在内存 Map 里）。它仍然走真实 SSH 传输、
 * 真实通道与真实 SFTP 帧：SETSTAT 的路径与权限位由服务端断言。
 *
 * 注意：ssh2 的服务端 SFTP 对象自己解析 SFTP 帧并按事件分发（STAT /
 * SETSTAT 等），无监听的请求会自动回 OP_UNSUPPORTED——所以这里必须用
 * 它的事件 API（sftp.on('SETSTAT', …)），而不是把 accept() 当原始字
 * 节流去读；后者收不到任何数据。
 * 无 ssh-keygen 的环境自动跳过（与 tests/e2e-ssh.test.mjs 同款探测）。
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
import { SFTPClient } from '../src/ssh/sftp.js';

const require = createRequire(import.meta.url);
const { Server } = require('ssh2');

const USERNAME = 'e2e';
const PASSWORD = 'e2e-test-password'; // 仅测试用固定值，非真实凭据

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

/* ---------------------------------------------------------- 迷你 SFTP 服务端 */

// SFTP 状态码（ssh2 的 SFTP 对象用数字；只用到这两个）
const S = { OK: 0, NO_SUCH_FILE: 2 };

/** 内存文件：路径 -> 完整 perms（含文件类型位） */
function makeFileStore() {
    return new Map([
        ['/tmp/chmod-test.txt', 0o100644],
        ['/tmp/chmod-dir', 0o040755],
    ]);
}

/** 给 ssh2 的服务端 SFTP 对象接上 STAT / LSTAT / SETSTAT / REALPATH。 */
function handleSftp(sftp, files, seen) {
    sftp.on('error', () => {});
    const stat = (reqid, p) => {
        const perms = files.get(p);
        if (perms == null) sftp.status(reqid, S.NO_SUCH_FILE);
        else sftp.attrs(reqid, { mode: perms });
    };
    sftp.on('STAT', stat);
    sftp.on('LSTAT', stat);
    sftp.on('SETSTAT', (reqid, p, attrs) => {
        seen.push({ type: 9, path: p, perms: attrs ? attrs.mode : null });
        const old = files.get(p);
        if (old == null || !attrs || attrs.mode == null) {
            sftp.status(reqid, S.NO_SUCH_FILE);
            return;
        }
        // 保留文件类型位，只改 0o7777 权限位
        files.set(p, (old & 0o170000) | (attrs.mode & 0o7777));
        sftp.status(reqid, S.OK);
    });
    sftp.on('REALPATH', (reqid, p) => {
        sftp.name(reqid, [{ filename: p, longname: p, attrs: {} }]);
    });
}

async function startTestServer() {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-chmod-e2e-'));
    const keyPath = path.join(tmp, 'host_ed25519');
    execFileSync('ssh-keygen', ['-t', 'ed25519', '-f', keyPath, '-N', '', '-q']);
    const hostKey = fs.readFileSync(keyPath);
    const files = makeFileStore();
    const seen = [];
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
                session.on('sftp', (acceptSftp) => {
                    handleSftp(acceptSftp(), files, seen);
                });
            });
        });
    });
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    return { server, port: server.address().port, tmp, files, seen };
}

function connectSftp(port) {
    const socket = net.connect(port, '127.0.0.1');
    socket.setNoDelay(true);
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
        onData: () => {},
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
    return { client, socket, readyPromise };
}

async function cleanup({ client, socket, server, tmp }) {
    try {
        await client.close();
    } catch {}
    socket.destroy();
    await Promise.race([new Promise((r) => server.close(r)), new Promise((r) => setTimeout(r, 2000))]);
    fs.rmSync(tmp, { recursive: true, force: true });
}

function withTimeout(promise, ms, message) {
    let timer;
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error(message)), ms);
        }),
    ]).finally(() => clearTimeout(timer));
}

test('E2E: SFTP chmod 644→600→755，stat 读回新权限', { skip: SKIP, timeout: 20000 }, async () => {
    const srv = await startTestServer();
    const conn = connectSftp(srv.port);
    try {
        await withTimeout(conn.readyPromise, 10000, 'SSH 握手/认证超时');
        const sftp = new SFTPClient(conn.client);
        await sftp.ready();
        assert.equal((await sftp.stat('/tmp/chmod-test.txt')).perms, 0o100644, '初始权限应为 0644');
        await sftp.chmod('/tmp/chmod-test.txt', 0o600);
        assert.equal((await sftp.stat('/tmp/chmod-test.txt')).perms, 0o100600, 'chmod 600 后 stat 应读回 0600');
        await sftp.chmod('/tmp/chmod-test.txt', 0o755);
        assert.equal((await sftp.stat('/tmp/chmod-test.txt')).perms, 0o100755, 'chmod 755 后 stat 应读回 0755');
        await sftp.chmod('/tmp/chmod-dir', 0o700);
        assert.equal((await sftp.stat('/tmp/chmod-dir')).perms, 0o040700, '目录也能 chmod，类型位 040000 保留');
        const setstats = srv.seen.filter((s) => s.type === 9);
        assert.equal(setstats.length, 3, '应恰好发 3 个 SETSTAT');
        assert.deepEqual(
            setstats.map((s) => [s.path, s.perms]),
            [
                ['/tmp/chmod-test.txt', 0o600],
                ['/tmp/chmod-test.txt', 0o755],
                ['/tmp/chmod-dir', 0o700],
            ],
            '服务端收到的 SETSTAT 权限位必须与请求一致（flags=4 的断言在 tests/sftp.test.mjs 的 FakeSSH 用例里）'
        );
    } finally {
        await cleanup({ ...conn, server: srv.server, tmp: srv.tmp });
    }
});

test('E2E: 非法 mode 在客户端就拒绝，不发 SETSTAT', { skip: SKIP, timeout: 20000 }, async () => {
    const srv = await startTestServer();
    const conn = connectSftp(srv.port);
    try {
        await withTimeout(conn.readyPromise, 10000, 'SSH 握手/认证超时');
        const sftp = new SFTPClient(conn.client);
        await sftp.ready();
        await assert.rejects(() => sftp.chmod('/tmp/chmod-test.txt', 0o10000), /0-7777/);
        assert.equal(srv.seen.length, 0, '非法 mode 一个包都不该发到服务端');
        assert.equal((await sftp.stat('/tmp/chmod-test.txt')).perms, 0o100644, '失败后权限不变');
    } finally {
        await cleanup({ ...conn, server: srv.server, tmp: srv.tmp });
    }
});
