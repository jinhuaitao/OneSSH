/**
 * 握手延迟基准：本地起一个 ssh2 服务器，在「每方向固定延迟」的链路上测量
 * 从 TCP 已连接到 shell ready 的耗时，用来对比优化前后的往返数。
 *
 *   node tools/bench-handshake.mjs --delay=50 --rounds=5
 *
 * 依赖 devDependency ssh2；主机密钥用本机 ssh-keygen 临时生成（不落库）。
 */
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { SSHClient } from '../src/ssh/client.js';

const require = createRequire(import.meta.url);
const { Server } = require('ssh2');

const args = Object.fromEntries(
    process.argv.slice(2).map((a) => {
        const [k, v] = a.replace(/^--/, '').split('=');
        return [k, v ?? 'true'];
    })
);
const DELAY = Number(args.delay ?? 50);
const ROUNDS = Number(args.rounds ?? 5);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-bench-'));
const keyPath = path.join(tmp, 'host_ed25519');
execFileSync('ssh-keygen', ['-t', 'ed25519', '-f', keyPath, '-N', '', '-q']);
const hostKey = fs.readFileSync(keyPath);

const server = new Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => {
        if (ctx.method === 'password' && ctx.username === 'bench' && ctx.password === 'bench') ctx.accept();
        else ctx.reject(['password']);
    });
    client.on('ready', () => {
        client.on('session', (accept) => {
            const session = accept();
            session.on('pty', (a) => a && a());
            session.on('env', (a) => a && a());
            session.on('shell', (a) => a().write('ready\r\n'));
        });
    });
});
await new Promise((res) => server.listen(0, '127.0.0.1', res));
const port = server.address().port;

function attempt() {
    return new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1');
        socket.setNoDelay(true);
        const t0 = process.hrtime.bigint();
        // 模拟链路：写出的字节攒够一个延迟窗口再发；收到的字节也延迟同样时间
        let pending = [];
        let flushTimer = null;
        let settled = false;
        const done = (err) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            socket.destroy();
            err ? reject(err) : resolve(Number(process.hrtime.bigint() - t0) / 1e6);
        };
        const timer = setTimeout(() => done(new Error('timeout')), 15000);

        const client = new SSHClient({
            username: 'bench',
            auth: { password: 'bench' },
            cols: 80,
            rows: 24,
            write: (bytes) => {
                pending.push(Buffer.from(bytes));
                if (!flushTimer && DELAY) {
                    flushTimer = setTimeout(() => {
                        flushTimer = null;
                        socket.write(Buffer.concat(pending));
                        pending = [];
                    }, DELAY);
                } else if (!DELAY) {
                    socket.write(Buffer.concat(pending));
                    pending = [];
                }
                return Promise.resolve();
            },
            onData: () => {},
            onEvent: (ev) => {
                if (ev.type === 'ready') done();
                if (ev.type === 'error') done(new Error(ev.message));
            },
            onHostKey: async () => true,
            onKeyboardInteractive: async () => ['bench'],
        });
        socket.on('error', (e) => done(e));
        socket.on('connect', () => client.connect());
        socket.on('data', (d) => {
            if (!DELAY) return client.feed(new Uint8Array(d));
            setTimeout(() => client.feed(new Uint8Array(d)), DELAY);
        });
    });
}

const samples = [];
for (let i = 0; i < ROUNDS; i++) samples.push(Math.round(await attempt()));
samples.sort((a, b) => a - b);
console.log(
    JSON.stringify({ oneWayDelayMs: DELAY, rttMs: DELAY * 2, samples, medianMs: samples[Math.floor(samples.length / 2)] })
);
server.close();
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);