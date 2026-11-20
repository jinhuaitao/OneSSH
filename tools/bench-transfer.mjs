/**
 * 传输面基准：本地起一个 ssh2 服务器（密码认证 + 本文件内的最小 SFTP 服务端），测
 *   - sftp-download：10MB 文件 SFTP 下载（并发 N 个 READ 请求，每请求 READ_CHUNK 字节）
 *   - sftp-upload：10MB 文件 SFTP 上传（顺序 WRITE，每请求 WRITE_CHUNK 字节）
 *   - shell-cat：exec `cat` 一个 5MB 文件，计收到字节数与耗时
 * 各跑 3 次取中位。用来对比 READ_CHUNK / SFTP 并发 / WRITE_CHUNK 三档。
 *
 *   node tools/bench-transfer.mjs [--read-chunk=131072] [--concurrency=4]
 *     [--write-chunk=65536] [--delay=0] [--rounds=3] [--only=sftp-download,shell-cat]
 *
 * 注意：bench 直接驱动 SSHClient + SFTPClient（与 e2e 测试同一层），
 * session.js 的 READ_CHUNK / WRITE_CHUNK / SFTP_CONCURRENCY 三个常量
 * 只是把同样的数值传进这一层；bench 的档位结果可直接对应回 session.js。
 * 依赖 devDependency ssh2；主机密钥用本机 ssh-keygen 临时生成（不落库）。
 * SFTP 服务端是本文件内最小实现（INIT/OPEN/READ/WRITE/CLOSE/STAT/REALPATH/FSTAT），
 * 文件内容为确定性伪随机字节，下载后校验 SHA-256。
 */
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { SSHClient } from '../src/ssh/client.js';
import { SFTPClient, OPEN } from '../src/ssh/sftp.js';

const require = createRequire(import.meta.url);
const { Server } = require('ssh2');

const args = Object.fromEntries(
    process.argv.slice(2).map((a) => {
        const [k, v] = a.replace(/^--/, '').split('=');
        return [k, v ?? 'true'];
    })
);
const READ_CHUNK = Number(args['read-chunk'] ?? 128 * 1024);
const CONCURRENCY = Number(args.concurrency ?? 4);
const WRITE_CHUNK = Number(args['write-chunk'] ?? 64 * 1024);
const DELAY = Number(args.delay ?? 0);
const ROUNDS = Number(args.rounds ?? 3);
const ONLY = String(args.only ?? 'all')
    .split(',')
    .map((s) => s.trim());

const FILE_10MB = 10 * 1024 * 1024;
const FILE_5MB = 5 * 1024 * 1024;

// 确定性伪随机内容：下载后校验哈希用
function makeData(n) {
    const buf = Buffer.alloc(n);
    let x = 0x12345678;
    for (let i = 0; i < n; i++) {
        x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
        buf[i] = x >>> 24;
    }
    return buf;
}
const data10 = makeData(FILE_10MB);
const data5 = data10.subarray(0, FILE_5MB);
const sha10 = crypto.createHash('sha256').update(data10).digest('hex');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-bench-xfer-'));
const keyPath = path.join(tmp, 'host_ed25519');
execFileSync('ssh-keygen', ['-t', 'ed25519', '-f', keyPath, '-N', '', '-q']);
const hostKey = fs.readFileSync(keyPath);

/* ------------------------------------------------- 最小 SFTP 服务端 */

// ssh2 的 sftp accept() 返回服务端模式的 SFTPStream：它自己解析 SFTP 报文、
// 自动回 VERSION，未挂 handler 的请求自动回 OP_UNSUPPORTED；
// 所以这里只挂事件，不自己解析帧。
const S = { OK: 0, EOF: 1, FAILURE: 4 };

function serveSftp(sftp) {
    let nextHandle = 1;
    const handles = new Map(); // handle 文本 -> { received: number }
    const attrs = { mode: 0o100644, uid: 0, gid: 0, size: data10.length, atime: 0, mtime: 0 };
    sftp.on('OPEN', (reqid, filename, flags, attrsIn) => {
        const h = Buffer.from('h' + nextHandle++);
        handles.set(h.toString(), { received: 0 });
        sftp.handle(reqid, h);
    });
    sftp.on('READ', (reqid, handle, offset, len) => {
        const off = Number(offset);
        if (!handles.has(handle.toString())) return sftp.status(reqid, S.FAILURE, 'bad handle');
        if (off >= data10.length) return sftp.status(reqid, S.EOF, 'eof');
        const n = Math.min(len, data10.length - off);
        sftp.data(reqid, data10.subarray(off, off + n));
    });
    sftp.on('WRITE', (reqid, handle, offset, data) => {
        const rec = handles.get(handle.toString());
        if (rec) rec.received = Math.max(rec.received, Number(offset) + data.length);
        sftp.status(reqid, S.OK);
    });
    sftp.on('CLOSE', (reqid, handle) => {
        handles.delete(handle.toString());
        sftp.status(reqid, S.OK);
    });
    sftp.on('STAT', (reqid, path) => sftp.attrs(reqid, attrs));
    sftp.on('LSTAT', (reqid, path) => sftp.attrs(reqid, attrs));
    sftp.on('FSTAT', (reqid, handle) => sftp.attrs(reqid, attrs));
    sftp.on('REALPATH', (reqid, path) =>
        sftp.name(reqid, [
            { filename: '/bench.bin', longname: '-rw-r--r-- 1 0 0 10485760 Jan  1 00:00 /bench.bin', attrs },
        ])
    );
}

const server = new Server({ hostKeys: [hostKey] }, (client) => {
    // 两端都关 Nagle：否则小包往返会被 Linux 延迟 ACK（40ms 定时器）拖住，
    // 顺序 SFTP 请求的耗时就全是 TCP 假象，量不到 chunk/并发的真实差别。
    client.setNoDelay(true);
    client.on('error', () => {});
    client.on('authentication', (ctx) => {
        if (ctx.method === 'password' && ctx.username === 'bench' && ctx.password === 'bench') ctx.accept();
        else ctx.reject(['password']);
    });
    client.on('ready', () => {
        client.on('session', (accept) => {
            const session = accept();
            session.on('pty', (a) => a && a());
            session.on('env', (a) => a && a());
            session.on('shell', (a) => a && a());
            session.on('exec', (acceptExec, _reject, info) => {
                const stream = acceptExec();
                if (String(info.command).startsWith('cat ')) {
                    stream.write(data5);
                }
                stream.exit(0);
                stream.end();
            });
            session.on('sftp', (acceptSftp) => {
                serveSftp(acceptSftp());
            });
        });
    });
});
await new Promise((res) => server.listen(0, '127.0.0.1', res));
const port = server.address().port;

function connectClient() {
    return new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1');
        socket.setNoDelay(true);
        let pending = [];
        let flushTimer = null;
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
                if (ev.type === 'ready') resolve({ client, socket });
                if (ev.type === 'error') reject(new Error(ev.message));
            },
            onHostKey: async () => true,
            onKeyboardInteractive: async () => ['bench'],
        });
        socket.on('error', reject);
        socket.on('connect', () => client.connect());
        socket.on('data', (d) => {
            if (!DELAY) return client.feed(new Uint8Array(d));
            setTimeout(() => client.feed(new Uint8Array(d)), DELAY);
        });
        setTimeout(() => reject(new Error('connect timeout')), 15000);
    });
}

const median = (a) => {
    const s = [...a].sort((x, y) => x - y);
    return s[Math.floor(s.length / 2)];
};
const timed = async (fn) => {
    const t0 = process.hrtime.bigint();
    const out = await fn();
    return { ms: Number(process.hrtime.bigint() - t0) / 1e6, out };
};

async function benchDownload(sftp) {
    const st = await sftp.stat('/bench.bin');
    const size = st.size;
    const got = Buffer.alloc(size);
    let next = 0;
    const take = () => {
        if (next >= size) return null;
        const off = next;
        next = Math.min(size, next + READ_CHUNK);
        return { off, len: next - off };
    };
    // SFTPClient.read 需要真实句柄：这里用 open 拿到的句柄
    const handle = await sftp.open('/bench.bin', OPEN.READ);
    try {
        const worker = async () => {
            for (;;) {
                const job = take();
                if (!job) return;
                const res = await sftp.read(handle, job.off, job.len);
                if (res.eof) throw new Error('unexpected EOF at ' + job.off);
                got.set(res.data, job.off);
            }
        };
        const { ms } = await timed(async () => {
            await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
        });
        const hash = crypto.createHash('sha256').update(got).digest('hex');
        if (hash !== sha10) throw new Error('下载内容哈希不一致');
        return ms;
    } finally {
        await sftp.close(handle).catch(() => {});
    }
}

async function benchUpload(sftp) {
    const handle = await sftp.open('/upload.bin', OPEN.WRITE | OPEN.CREAT | OPEN.TRUNC);
    try {
        const { ms } = await timed(async () => {
            for (let off = 0; off < data10.length; off += WRITE_CHUNK) {
                await sftp.write(handle, off, data10.subarray(off, off + WRITE_CHUNK));
            }
        });
        return ms;
    } finally {
        await sftp.close(handle).catch(() => {});
    }
}

async function benchShell(client) {
    let received = 0;
    const ch = await client.openChannel({
        onData: (data) => {
            received += data.length;
        },
    });
    const { ms } = await timed(async () => {
        const ok = await client.channelRequest(ch, 'exec', true, (w) => {
            w.str('cat /bench-5mb.bin');
        });
        if (ok === false) throw new Error('服务器拒绝执行命令');
        await Promise.race([ch.done.promise, new Promise((r) => setTimeout(r, 30000))]);
    });
    if (received !== FILE_5MB) throw new Error(`shell 输出字节数不对：${received} != ${FILE_5MB}`);
    return ms;
}

const results = {};
const { client, socket } = await connectClient();
try {
    const sftp = new SFTPClient(client);
    await sftp.ready();

    if (ONLY.includes('all') || ONLY.includes('sftp-download')) {
        const samples = [];
        for (let i = 0; i < ROUNDS; i++) samples.push(await benchDownload(sftp));
        results['sftp-download-10MB'] = { samplesMs: samples.map((v) => Math.round(v)), medianMs: Math.round(median(samples)), mibPerSec: +(FILE_10MB / 1048576 / (median(samples) / 1000)).toFixed(1) };
    }
    if (ONLY.includes('all') || ONLY.includes('sftp-upload')) {
        const samples = [];
        for (let i = 0; i < ROUNDS; i++) samples.push(await benchUpload(sftp));
        results['sftp-upload-10MB'] = { samplesMs: samples.map((v) => Math.round(v)), medianMs: Math.round(median(samples)), mibPerSec: +(FILE_10MB / 1048576 / (median(samples) / 1000)).toFixed(1) };
    }
    if (ONLY.includes('all') || ONLY.includes('shell-cat')) {
        const samples = [];
        for (let i = 0; i < ROUNDS; i++) samples.push(await benchShell(client));
        results['shell-cat-5MB'] = { samplesMs: samples.map((v) => Math.round(v)), medianMs: Math.round(median(samples)), mibPerSec: +(FILE_5MB / 1048576 / (median(samples) / 1000)).toFixed(1) };
    }
} finally {
    socket.destroy();
}
server.close();
console.log(
    JSON.stringify({ readChunk: READ_CHUNK, concurrency: CONCURRENCY, writeChunk: WRITE_CHUNK, delayMs: DELAY, rounds: ROUNDS, ...results })
);
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);
