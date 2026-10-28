#!/usr/bin/env node
/**
 * End-to-end test: real browser + wrangler dev (local R2) + an in-process
 * SSH/SFTP server. Run with `npm test`, add `--headful` to watch.
 *
 * Nothing here touches a real remote host: the ssh2 server implements just
 * enough shell/exec/sftp for the UI to drive, over a temp directory.
 */
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import ssh2 from 'ssh2';
import { chromium } from 'playwright-core';

const { Server, utils } = ssh2;

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const HEADFUL = process.argv.includes('--headful');
const PORT = Number(process.env.E2E_PORT || 8791);
const RACE_PORT = PORT + 1;
const BASE = `http://127.0.0.1:${PORT}`;
const STATE_DIR = path.join(ROOT, '.wrangler', 'e2e');
const RACE_STATE_DIR = path.join(ROOT, '.wrangler', 'e2e-race');

const SETUP_TOKEN = 'e2e-setup-token-2026';
const ADMIN = { username: 'e2e-admin', password: 'E2e-Passw0rd-2026' };
const NEW_PASSWORD = 'E2e-Passw0rd-2027';
const SSH_USER = 'root';
const SSH_PASS = 'e2e-pass';
const HOST_NAME = 'E2E 主机';
const CRED_NAME = 'e2e 账号';

const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(...a);

/* ------------------------------------------------------------------ worker */

function wranglerBin() {
    const candidates = [
        path.join(ROOT, 'node_modules', 'wrangler', 'bin', 'wrangler.js'),
        path.join(ROOT, 'node_modules', '.bin', 'wrangler'),
    ];
    for (const p of candidates) if (fs.existsSync(p)) return p;
    throw new Error('找不到 wrangler，请先 npm install');
}

async function startWorker({ port, stateDir }) {
    await fsp.rm(stateDir, { recursive: true, force: true });
    const child = spawn(
        process.execPath,
        [
            wranglerBin(),
            'dev',
            '--ip', '127.0.0.1',
            '--port', String(port),
            '--persist-to', stateDir,
            '--var', `WEBSSH_SETUP_TOKEN:${SETUP_TOKEN}`,
            '--log-level', 'warn',
        ],
        {
            cwd: ROOT,
            env: { ...process.env, CI: '1', NO_COLOR: '1', WRANGLER_SEND_METRICS: 'false' },
            stdio: ['ignore', 'pipe', 'pipe'],
        }
    );
    let output = '';
    const collect = (d) => {
        output += d.toString();
        if (output.length > 64 * 1024) output = output.slice(-32 * 1024);
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);

    let exited = false;
    child.once('exit', () => {
        exited = true;
    });

    const base = `http://127.0.0.1:${port}`;
    async function waitReady(timeoutMs = 90000) {
        const started = Date.now();
        for (;;) {
            if (exited) throw new Error(`wrangler dev 提前退出：\n${output}`);
            try {
                const res = await fetch(base + '/api/state');
                if (res.ok) return;
            } catch (_) {}
            if (Date.now() - started > timeoutMs) throw new Error(`wrangler dev 启动超时：\n${output}`);
            await delay(500);
        }
    }

    async function stop() {
        if (!exited) {
            child.kill('SIGTERM');
            await Promise.race([once(child, 'exit'), delay(5000)]);
            if (!exited) child.kill('SIGKILL');
            await Promise.race([once(child, 'exit'), delay(2000)]);
        }
        try {
            const pids = execFileSync('lsof', ['-ti', `tcp:${port}`], { encoding: 'utf8' }).trim();
            if (pids) execFileSync('kill', ['-9', ...pids.split(/\s+/)]);
        } catch (_) {}
    }

    return { base, waitReady, stop, output: () => output };
}

/* --------------------------------------------------------------------- api */

async function apiFetch(base, pathname, opts = {}) {
    const headers = {};
    if (opts.body !== undefined) headers['content-type'] = 'application/json';
    if (opts.origin) headers.origin = opts.origin;
    if (opts.cookie) headers.cookie = opts.cookie;
    const res = await fetch(base + pathname, {
        method: opts.method || 'GET',
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
    const text = await res.text();
    let data = null;
    try {
        data = JSON.parse(text);
    } catch (_) {}
    const setCookie = res.headers.getSetCookie?.()[0] || res.headers.get('set-cookie') || '';
    return { status: res.status, data, text, cookie: setCookie.split(';')[0] };
}

const setupRequest = (base, body) => apiFetch(base, '/api/setup', { method: 'POST', body });
const loginRequest = (base, username, password) => apiFetch(base, '/api/login', { method: 'POST', body: { username, password } });

function rawUpgrade(port, { cookie, origin, host, sshPort }) {
    return new Promise((resolve) => {
        const sock = net.connect(port, '127.0.0.1');
        let buf = '';
        const done = () => {
            try {
                sock.destroy();
            } catch (_) {}
            resolve((buf.split('\r\n')[0] || 'timeout').trim());
        };
        sock.setEncoding('utf8');
        sock.on('error', done);
        sock.on('connect', () => {
            const lines = [
                `GET /ws?host=${host}&port=${sshPort} HTTP/1.1`,
                `Host: 127.0.0.1:${port}`,
                'Upgrade: websocket',
                'Connection: Upgrade',
                'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version: 13',
                origin ? `Origin: ${origin}` : null,
                cookie ? `Cookie: ${cookie}` : null,
                '',
                '',
            ].filter((l) => l !== null);
            sock.write(lines.join('\r\n'));
        });
        sock.on('data', (d) => {
            buf += d;
            if (buf.includes('\r\n\r\n')) done();
        });
        setTimeout(done, 5000);
    });
}

/* --------------------------------------------------------------- ssh test */

const STATUS = { OK: 0, EOF: 1, NO_SUCH_FILE: 2, PERMISSION_DENIED: 3, FAILURE: 4, BAD_MESSAGE: 5, OP_UNSUPPORTED: 8 };
const OPEN_FLAGS = { READ: 0x1, WRITE: 0x2, APPEND: 0x4, CREAT: 0x8, TRUNC: 0x10, EXCL: 0x20 };

function attrsOf(st) {
    return {
        mode: st.mode,
        uid: st.uid,
        gid: st.gid,
        size: st.size,
        atime: Math.floor(st.atimeMs / 1000),
        mtime: Math.floor(st.mtimeMs / 1000),
    };
}

function createSftpSession(sftp, root) {
    const handles = new Map();
    let nextHandle = 1;

    const real = (p) => {
        const raw = String(p == null || p === '' ? '.' : p).replace(/\\/g, '/');
        const norm = path.posix.normalize('/' + raw);
        return path.join(root, norm);
    };

    const fail = (reqid, e) => {
        const code =
            e && e.code === 'ENOENT'
                ? STATUS.NO_SUCH_FILE
                : e && (e.code === 'EACCES' || e.code === 'EPERM')
                  ? STATUS.PERMISSION_DENIED
                  : STATUS.FAILURE;
        sftp.status(reqid, code, String((e && e.message) || e));
    };

    const handleOf = (buf) => {
        if (!Buffer.isBuffer(buf) || buf.length !== 4) return null;
        return handles.get(buf.readUInt32BE(0)) || null;
    };

    sftp.on('REALPATH', (reqid, p) => {
        try {
            const raw = String(p == null || p === '' ? '.' : p).replace(/\\/g, '/');
            const norm = path.posix.normalize('/' + raw);
            const st = fs.statSync(real(norm));
            sftp.name(reqid, [{ filename: norm, longname: norm, attrs: attrsOf(st) }]);
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('STAT', onStat);
    sftp.on('LSTAT', onStat);
    function onStat(reqid, p) {
        try {
            const st = fs.statSync(real(p));
            sftp.attrs(reqid, attrsOf(st));
        } catch (e) {
            fail(reqid, e);
        }
    }

    sftp.on('FSTAT', (reqid, handle) => {
        const h = handleOf(handle);
        if (!h || h.dir) return sftp.status(reqid, STATUS.FAILURE);
        try {
            sftp.attrs(reqid, attrsOf(fs.fstatSync(h.fd)));
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('OPEN', (reqid, filename, flags) => {
        try {
            const { READ, WRITE, APPEND, CREAT, TRUNC, EXCL } = OPEN_FLAGS;
            let mode;
            if (flags & READ && flags & WRITE) mode = 'r+';
            else if (flags & READ) mode = 'r';
            else if (flags & WRITE) mode = flags & APPEND ? 'a' : flags & TRUNC ? 'w' : 'r+';
            else mode = 'r';
            if (flags & CREAT && !/[wa]/.test(mode)) mode = mode.includes('+') ? 'w+' : 'w';
            if (flags & EXCL && flags & CREAT) mode = 'wx';
            const fd = fs.openSync(real(filename), mode);
            const id = nextHandle++;
            handles.set(id, { fd, dir: null });
            const buf = Buffer.alloc(4);
            buf.writeUInt32BE(id, 0);
            sftp.handle(reqid, buf);
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('READ', (reqid, handle, offset, length) => {
        const h = handleOf(handle);
        if (!h || h.dir) return sftp.status(reqid, STATUS.FAILURE);
        try {
            const buf = Buffer.alloc(Math.max(1, Math.min(length, 256 * 1024)));
            const n = fs.readSync(h.fd, buf, 0, buf.length, Number(offset));
            if (n === 0) sftp.status(reqid, STATUS.EOF);
            else sftp.data(reqid, buf.subarray(0, n));
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('WRITE', (reqid, handle, offset, data) => {
        const h = handleOf(handle);
        if (!h || h.dir) return sftp.status(reqid, STATUS.FAILURE);
        try {
            fs.writeSync(h.fd, data, 0, data.length, Number(offset));
            sftp.status(reqid, STATUS.OK);
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('CLOSE', (reqid, handle) => {
        const h = handleOf(handle);
        if (!h) return sftp.status(reqid, STATUS.FAILURE);
        try {
            if (h.dir) h.dir.closeSync();
            else fs.closeSync(h.fd);
            handles.delete(handle.readUInt32BE(0));
            sftp.status(reqid, STATUS.OK);
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('FSETSTAT', (reqid, handle, attrs) => {
        const h = handleOf(handle);
        if (!h || h.dir) return sftp.status(reqid, STATUS.FAILURE);
        try {
            if (attrs && attrs.mode != null) fs.fchmodSync(h.fd, attrs.mode & 0o7777);
            sftp.status(reqid, STATUS.OK);
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('OPENDIR', (reqid, p) => {
        try {
            const id = nextHandle++;
            handles.set(id, { fd: null, dir: fs.opendirSync(real(p)) });
            const buf = Buffer.alloc(4);
            buf.writeUInt32BE(id, 0);
            sftp.handle(reqid, buf);
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('READDIR', (reqid, handle) => {
        const h = handleOf(handle);
        if (!h || !h.dir) return sftp.status(reqid, STATUS.EOF);
        try {
            const names = [];
            let dirent;
            while (names.length < 100 && (dirent = h.dir.readSync())) {
                const full = path.join(h.dir.path, dirent.name);
                let st;
                try {
                    st = fs.lstatSync(full);
                } catch (_) {
                    continue;
                }
                names.push({ filename: dirent.name, longname: dirent.name, attrs: attrsOf(st) });
            }
            if (!names.length) sftp.status(reqid, STATUS.EOF);
            else sftp.name(reqid, names);
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('MKDIR', (reqid, p) => {
        try {
            fs.mkdirSync(real(p));
            sftp.status(reqid, STATUS.OK);
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('RMDIR', (reqid, p) => {
        try {
            fs.rmdirSync(real(p));
            sftp.status(reqid, STATUS.OK);
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('REMOVE', (reqid, p) => {
        try {
            fs.unlinkSync(real(p));
            sftp.status(reqid, STATUS.OK);
        } catch (e) {
            fail(reqid, e);
        }
    });

    sftp.on('RENAME', (reqid, from, to) => {
        try {
            fs.renameSync(real(from), real(to));
            sftp.status(reqid, STATUS.OK);
        } catch (e) {
            fail(reqid, e);
        }
    });
}

function startSshServer(root) {
    const hostKey = utils.generateKeyPairSync('ed25519');
    let cpuTicks = [1000, 0, 300, 8000, 100, 0, 0, 0];

    const statsOutput = () => {
        cpuTicks = cpuTicks.map((v, i) => v + (i === 0 ? 40 : i === 3 ? 60 : 0));
        return (
            `@@CPU ${cpuTicks.join(' ')}\n` +
            '@@MEM 2048000 1024000 0 0\n' +
            '@@NET 5000 3000\n' +
            '@@LOAD 0.15 0.22 0.30 1/120 4242\n' +
            '@@UP 123456.78 98765.43\n' +
            '@@WHO 1\n'
        );
    };

    const execOutput = (command) => {
        if (command.includes('@@CPU')) return statsOutput();
        if (command.includes('uname -s')) {
            return 'Linux\n6.1.0-e2e\nx86_64\nPRETTY_NAME="E2E Linux"\nVERSION_ID="1"\n';
        }
        return '';
    };

    const server = new Server({ hostKeys: [hostKey.private] }, (client) => {
        client.on('authentication', (ctx) => {
            if (ctx.method === 'none') return ctx.reject(['password', 'publickey']);
            if (ctx.username !== SSH_USER) return ctx.reject();
            if (ctx.method === 'password') {
                if (ctx.password === SSH_PASS) return ctx.accept();
                return ctx.reject();
            }
            if (ctx.method === 'publickey') return ctx.accept();
            return ctx.reject();
        });

        client.on('ready', () => {
            client.on('session', (accept) => {
                const session = accept();
                session.on('pty', (a) => a && a());
                session.on('window-change', (a) => a && a());
                session.on('env', (a) => a && a());

                session.on('shell', (accept) => {
                    const stream = accept();
                    let line = '';
                    const prompt = () => stream.write('$ ');
                    stream.write('E2E shell ready\r\n');
                    prompt();
                    stream.on('data', (chunk) => {
                        for (const ch of chunk.toString('utf8')) {
                            if (ch === '\r' || ch === '\n') {
                                stream.write('\r\n');
                                const cmd = line.trim();
                                line = '';
                                if (cmd === 'exit') {
                                    stream.exit(0);
                                    stream.end();
                                    return;
                                }
                                if (cmd === 'uptime') stream.write('up 1 day, e2e-shell-ok\r\n');
                                else if (cmd === 'whoami') stream.write(SSH_USER + '\r\n');
                                else if (cmd.startsWith('echo ')) stream.write(cmd.slice(5) + '\r\n');
                                else if (cmd) stream.write(`bash: ${cmd}: command not found\r\n`);
                                prompt();
                            } else if (ch === '\x7f') {
                                if (line) {
                                    line = line.slice(0, -1);
                                    stream.write('\b \b');
                                }
                            } else if (ch === '\x03') {
                                line = '';
                                stream.write('^C\r\n');
                                prompt();
                            } else {
                                line += ch;
                                stream.write(ch);
                            }
                        }
                    });
                    stream.on('close', () => {
                        try {
                            stream.end();
                        } catch (_) {}
                    });
                });

                session.on('exec', (accept, reject, info) => {
                    const stream = accept();
                    stream.end(execOutput(String(info.command || '')));
                });

                session.on('sftp', (accept) => {
                    createSftpSession(accept(), root);
                });
            });
        });
    });

    return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            server.removeListener('error', reject);
            resolve({ server, port: server.address().port });
        });
    });
}

/* ------------------------------------------------------------------ chrome */

function chromePath() {
    const candidates = [
        process.env.CHROME_PATH,
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        '/usr/bin/google-chrome',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
    ];
    for (const p of candidates) if (p && fs.existsSync(p)) return p;
    throw new Error('找不到 Chrome；用 CHROME_PATH 指定可执行文件');
}

/* ------------------------------------------------------------------- page */

function topModal(page) {
    return page.locator('.modal-backdrop').last();
}

async function waitModal(page, title) {
    const m = topModal(page);
    await m.locator('h3').filter({ hasText: title }).waitFor({ state: 'visible', timeout: 20000 });
    return m;
}

async function waitText(page, selector, text, timeout = 20000) {
    await page.waitForFunction(
        ([sel, needle]) => {
            const node = document.querySelector(sel);
            return Boolean(node && (node.innerText || node.textContent || '').includes(needle));
        },
        [selector, text],
        { timeout }
    );
}

async function pageState(page) {
    return page.evaluate(async () => (await fetch('/api/state', { credentials: 'same-origin' })).json());
}

async function uiLogin(page, username, password) {
    await page.waitForSelector('#form-login:not([hidden])', { timeout: 20000 });
    await page.fill('#form-login input[name="username"]', username);
    await page.fill('#form-login input[name="password"]', password);
    await page.click('#form-login button[type="submit"]');
    await page.waitForSelector('#view-dash:not([hidden])', { timeout: 20000 });
}

/* ------------------------------------------------------------------- main */

let debugPage = null;
let debugErrors = [];

async function dumpDebug() {
    if (!debugPage) return;
    try {
        console.error('\n页面错误：\n' + debugErrors.join('\n'));
        console.error('\n当前提示：\n' + (await debugPage.locator('#toasts').innerText({ timeout: 2000 }).catch(() => '（无）')));
        const sheets = debugPage.locator('.modal-backdrop');
        const sheetCount = await sheets.count().catch(() => 0);
        const sheetText = sheetCount ? await sheets.last().innerText({ timeout: 2000 }).catch(() => '（无）') : '（无）';
        console.error('\n当前弹窗：\n' + sheetText.slice(0, 2000));
        const shot = path.join(os.tmpdir(), 'webssh-e2e-failure.png');
        await debugPage.screenshot({ path: shot, fullPage: true });
        console.error('\n截图：' + shot);
    } catch (d) {
        console.error('（无法抓取页面状态：' + d.message + '）');
    }
}

async function main() {
    const fsRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'webssh-e2e-fs-'));
    await fsp.writeFile(path.join(fsRoot, 'readme.txt'), 'hello from e2e\n');
    await fsp.writeFile(path.join(fsRoot, 'secret.txt'), 'top secret\n', { mode: 0o600 });
    await fsp.mkdir(path.join(fsRoot, 'sub'));
    await fsp.writeFile(path.join(fsRoot, 'sub', 'inner.txt'), 'inner file\n');

    const ssh = await startSshServer(fsRoot);

    let raceWorker = null;
    let worker = null;
    let browser = null;
    let ctx2 = null;

    try {
        log(`\n▶ 初始化并发竞争（端口 ${RACE_PORT}）`);
        {
            raceWorker = await startWorker({ port: RACE_PORT, stateDir: RACE_STATE_DIR });
            await raceWorker.waitReady();
            const usernames = Array.from({ length: 6 }, (_, i) => `racer${i}`);
            const results = await Promise.all(
                usernames.map((username) => setupRequest(raceWorker.base, { username, password: 'Race-Passw0rd-2026', token: SETUP_TOKEN }))
            );
            const winners = results.map((r, i) => ({ r, username: usernames[i] })).filter((x) => x.r.status === 200);
            assert.equal(winners.length, 1, `并发初始化应当只有一个赢家，实际 ${winners.length}: ${results.map((r) => r.status).join(',')}`);
            assert.equal(results.filter((r) => r.status === 409).length, 5, '其余请求都应是 409');
            const winner = winners[0];
            const login = await loginRequest(raceWorker.base, winner.username, 'Race-Passw0rd-2026');
            assert.equal(login.status, 200, '竞争胜出者应该能登录');
            assert.ok(login.cookie.startsWith('wssh_session='), '应当签发会话 Cookie');
            const state = await apiFetch(raceWorker.base, '/api/state');
            assert.equal(state.data.setup, true);
            log('  ✓ 只有一个初始化赢家，其余 409');
            await raceWorker.stop();
            raceWorker = null;
            await fsp.rm(RACE_STATE_DIR, { recursive: true, force: true });
        }

        log(`\n▶ 启动 WebSSH（端口 ${PORT}）`);
        worker = await startWorker({ port: PORT, stateDir: STATE_DIR });
        await worker.waitReady();

        log('\n▶ 静态资源安全头与 MIME');
        {
            const page = await fetch(BASE + '/');
            assert.equal(page.status, 200);
            assert.match(page.headers.get('content-type'), /text\/html/);
            const csp = page.headers.get('content-security-policy') || '';
            assert.match(csp, /default-src 'self'/);
            assert.match(csp, /frame-ancestors 'none'/);
            assert.equal(page.headers.get('x-frame-options'), 'DENY');
            assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
            assert.equal(page.headers.get('referrer-policy'), 'no-referrer');

            const asset = await fetch(BASE + '/js/app.js');
            assert.equal(asset.status, 200);
            assert.match(asset.headers.get('content-type'), /javascript/);
            assert.match(asset.headers.get('content-security-policy') || '', /object-src 'none'/);
            assert.equal(asset.headers.get('x-frame-options'), 'DENY');

            const manifest = await fetch(BASE + '/manifest.webmanifest');
            assert.match(manifest.headers.get('content-type') || '', /manifest\+json/);
            log('  ✓ 页面 / 脚本 / manifest 都带安全头，manifest MIME 正确');
        }

        log('\n▶ 初始化口令校验');
        {
            const bad = await setupRequest(BASE, { username: ADMIN.username, password: ADMIN.password, token: 'wrong-token' });
            assert.equal(bad.status, 403, '错误的初始化口令必须拒绝');
            const state = await apiFetch(BASE, '/api/state');
            assert.equal(state.data.setup, false);
            log('  ✓ 错误口令 403，系统仍未初始化');
        }

        log('\n▶ 浏览器启动 + 初始化（UI）');
        browser = await chromium.launch({ executablePath: chromePath(), headless: !HEADFUL });
        const context = await browser.newContext({
            viewport: { width: 1440, height: 900 },
            acceptDownloads: true,
        });
        const page = await context.newPage();
        page.setDefaultTimeout(25000);
        const pageErrors = [];
        debugPage = page;
        debugErrors = pageErrors;
        page.on('pageerror', (e) => pageErrors.push(String(e)));
        page.on('console', (msg) => {
            if (msg.type() === 'error') pageErrors.push('console: ' + msg.text());
        });

        await page.goto(BASE + '/');
        await page.waitForSelector('#form-setup:not([hidden])');
        await page.fill('#form-setup input[name="username"]', ADMIN.username);
        await page.fill('#form-setup input[name="token"]', SETUP_TOKEN);
        await page.fill('#form-setup input[name="password"]', ADMIN.password);
        await page.fill('#form-setup input[name="password2"]', ADMIN.password);
        await page.click('#form-setup button[type="submit"]');
        await page.waitForSelector('#view-dash:not([hidden])');
        log('  ✓ 初始化成功并进入仪表盘');

        log('\n▶ 刷新保持登录');
        await page.reload();
        await page.waitForSelector('#view-dash:not([hidden])');
        log('  ✓ 刷新后仍在登录状态');

        const cookies = await context.cookies(BASE);
        const sessionCookieValue = cookies.find((c) => c.name === 'wssh_session')?.value;
        assert.ok(sessionCookieValue, '浏览器里应有会话 Cookie');
        const cookieHeader = 'wssh_session=' + sessionCookieValue;

        log('\n▶ 跨站请求 / 跨站 WebSocket 被拒');
        {
            const cross = await apiFetch(BASE, '/api/hosts', {
                method: 'POST',
                body: { name: 'evil', host: 'example.com', username: 'root', port: 22 },
                origin: 'https://evil.example',
                cookie: cookieHeader,
            });
            assert.equal(cross.status, 403, '跨站写请求必须拒绝');

            const same = await apiFetch(BASE, '/api/hosts', { cookie: cookieHeader });
            assert.equal(same.status, 200, '同源读取应当正常');

            const wsCross = await rawUpgrade(PORT, {
                cookie: cookieHeader,
                origin: 'https://evil.example',
                host: '127.0.0.1',
                sshPort: ssh.port,
            });
            assert.match(wsCross, /403/, `跨站 WebSocket 应当 403，实际 ${wsCross}`);

            const wsAnon = await rawUpgrade(PORT, {
                cookie: '',
                origin: BASE,
                host: '127.0.0.1',
                sshPort: ssh.port,
            });
            assert.match(wsAnon, /401/, `未登录 WebSocket 应当 401，实际 ${wsAnon}`);
            log('  ✓ 跨站写请求 403，跨站 WS 403，未登录 WS 401');
        }

        log('\n▶ 分组（新建 / 改名 / 删除）');
        {
            await page.click('.rail-item[data-nav="groups"]');
            const groups = await waitModal(page, '分组');
            await groups.getByRole('button', { name: /新建分组/ }).click();
            let prompt = await waitModal(page, '新建分组');
            await prompt.locator('input').fill('e2e-group');
            await prompt.getByRole('button', { name: '创建', exact: true }).click();
            await waitText(page, '.modal-backdrop', 'e2e-group');

            const row = topModal(page).locator('.list-row').filter({ hasText: 'e2e-group' });
            await row.locator('button[title="重命名"]').click();
            prompt = await waitModal(page, '重命名分组');
            await prompt.locator('input').fill('e2e-group-2');
            await prompt.getByRole('button', { name: '保存', exact: true }).click();
            await waitText(page, '.modal-backdrop', 'e2e-group-2');

            const row2 = topModal(page).locator('.list-row').filter({ hasText: 'e2e-group-2' });
            await row2.locator('button[title="删除"]').click();
            const confirm = await waitModal(page, '删除分组');
            await confirm.getByRole('button', { name: '删除', exact: true }).click();
            await page.waitForFunction(() => !document.querySelector('.modal-backdrop')?.innerText.includes('e2e-group-2'));
            await page.keyboard.press('Escape');
            await page.waitForSelector('.modal-backdrop', { state: 'detached' });
            log('  ✓ 分组新建 / 改名 / 删除都同步到界面');
        }

        log('\n▶ 凭据库（新建常用账号）');
        {
            await page.click('.rail-item[data-nav="keys"]');
            const vault = await waitModal(page, '凭据库');
            await vault.getByRole('button', { name: /常用账号/ }).click();
            const editor = await waitModal(page, '新建常用账号');
            await editor.locator('input').nth(0).fill(CRED_NAME);
            await editor.locator('input').nth(1).fill(SSH_USER);
            await editor.locator('input[type="password"]').fill(SSH_PASS);
            await editor.getByRole('button', { name: '保存', exact: true }).click();
            await waitText(page, '.modal-backdrop', CRED_NAME);
            await page.keyboard.press('Escape');
            await page.waitForSelector('.modal-backdrop', { state: 'detached' });
            log('  ✓ 常用账号已保存');
        }

        log('\n▶ 设置：开启会话录制');
        {
            await page.click('.rail-item[data-nav="settings"]');
            const settings = await waitModal(page, '设置');
            await settings.locator('input[type="checkbox"]').check();
            await settings.getByRole('button', { name: '保存设置', exact: true }).click();
            await page.waitForSelector('.modal-backdrop', { state: 'detached' });
            const record = await page.evaluate(() => JSON.parse(localStorage.getItem('webssh.settings') || '{}').record);
            assert.equal(record, true);
            log('  ✓ 录制已开启');
        }

        log('\n▶ 添加主机（引用凭据库）');
        {
            await page.click('#btn-add-host');
            const editor = await waitModal(page, '添加主机');
            await editor.locator('input[placeholder="例如 香港生产机"]').fill(HOST_NAME);
            await editor.locator('input[name="host"]').fill('127.0.0.1');
            await editor.locator('input[type="number"]').fill(String(ssh.port));
            await editor.locator('select[name="credId"]').selectOption({ index: 1 });
            await editor.getByRole('button', { name: '添加主机', exact: true }).click();
            await page.waitForSelector('.host-row', { timeout: 20000 });
            await waitText(page, '.host-row', HOST_NAME);
            await waitText(page, '.host-row', `root@127.0.0.1:${ssh.port}`);
            log('  ✓ 主机已添加，用户名来自凭据库');
        }

        log('\n▶ 连接主机：主机密钥确认 + shell + 监控');
        {
            await page.locator('.host-row').filter({ hasText: HOST_NAME }).click();
            await page.waitForSelector('#view-term:not([hidden])');

            const keyModal = await waitModal(page, '验证主机密钥');
            const fp = await keyModal.locator('.fp').innerText();
            assert.match(fp, /ssh-ed25519/);
            assert.match(fp, /SHA256:/);
            await keyModal.getByRole('button', { name: '信任并保存', exact: true }).click();

            await waitText(page, '.xterm-rows', 'E2E shell ready');
            await page.locator('.xterm-helper-textarea').focus();
            await page.keyboard.type('uptime', { delay: 15 });
            await page.keyboard.press('Enter');
            await waitText(page, '.xterm-rows', 'e2e-shell-ok');

            await page.waitForFunction(() => (document.querySelector('#hb-os')?.textContent || '').includes('E2E Linux'));
            await page.waitForFunction(() => (document.querySelector('#hb-stats')?.textContent || '').includes('%'));
            log('  ✓ 主机密钥确认、命令执行、/proc 监控都正常');
        }

        log('\n▶ 代码片段：新建并发送到当前会话');
        {
            await page.click('#btn-snippets');
            const list = await waitModal(page, '代码片段');
            await list.getByRole('button', { name: /新建片段/ }).click();
            const editor = await waitModal(page, '新建片段');
            await editor.locator('input').first().fill('E2E 片段');
            await editor.locator('textarea').fill('echo snippet-sent-ok');
            await editor.getByRole('button', { name: '保存', exact: true }).click();
            await waitText(page, '.modal-backdrop', 'E2E 片段');
            await topModal(page).locator('.snip').filter({ hasText: 'E2E 片段' }).click();
            await page.waitForSelector('.modal-backdrop', { state: 'detached' });
            await waitText(page, '.xterm-rows', 'snippet-sent-ok');
            log('  ✓ 片段已发送并执行');
        }

        log('\n▶ 文件管理：浏览 / 在线编辑 / 上传 / 下载');
        {
            await page.click('#btn-files');
            const fm = await waitModal(page, '文件管理');
            await fm.locator('.fm-row').filter({ hasText: 'readme.txt' }).waitFor();

            await fm.locator('.fm-row').filter({ hasText: 'readme.txt' }).locator('.fm-name').click();
            let editor = await waitModal(page, '在线编辑');
            assert.match(await editor.locator('.fm-edit').inputValue(), /hello from e2e/);
            await editor.locator('.fm-edit').fill('hello from e2e\nedited by e2e\n');
            await editor.getByRole('button', { name: '保存', exact: true }).click();
            await page.waitForSelector('.modal-backdrop h3:text-is("在线编辑")', { state: 'detached' });

            await fm.locator('.fm-row').filter({ hasText: 'readme.txt' }).locator('.fm-name').click();
            editor = await waitModal(page, '在线编辑');
            assert.match(await editor.locator('.fm-edit').inputValue(), /edited by e2e/);
            await editor.getByRole('button', { name: '取消', exact: true }).click();
            await page.waitForSelector('.modal-backdrop h3:text-is("在线编辑")', { state: 'detached' });

            const upFile = path.join(fsRoot, '..', `webssh-upload-${Date.now()}.txt`);
            await fsp.writeFile(upFile, 'upload-ok');
            await fm.locator('input[type="file"]').setInputFiles(upFile);
            await fm.locator('.fm-row').filter({ hasText: path.basename(upFile) }).waitFor();

            await page.evaluate(() => {
                window.showSaveFilePicker = undefined;
            });
            const downloadPromise = page.waitForEvent('download');
            await fm.locator('.fm-row').filter({ hasText: 'readme.txt' }).locator('button[title="下载"]').click();
            const download = await downloadPromise;
            const savedTo = path.join(fsRoot, '..', `webssh-download-${Date.now()}.txt`);
            await download.saveAs(savedTo);
            const downloaded = await fsp.readFile(savedTo, 'utf8');
            assert.match(downloaded, /edited by e2e/);
            await fsp.rm(upFile, { force: true });
            await fsp.rm(savedTo, { force: true });

            await topModal(page).locator('.modal-head .icon-btn').click();
            await page.waitForSelector('.modal-backdrop', { state: 'detached' });
            log('  ✓ 目录浏览 / 编辑保存 / 上传 / 下载均通过');
        }

        log('\n▶ 关闭会话后录制写回 R2（加密日志读回）');
        {
            await page.click('#btn-disconnect');
            await page.waitForSelector('#view-dash:not([hidden])');

            let entries = [];
            for (let i = 0; i < 20; i++) {
                const res = await page.evaluate(async () => (await fetch('/api/logs', { credentials: 'same-origin' })).json());
                entries = res.logs || [];
                if (entries.length) break;
                await delay(500);
            }
            assert.ok(entries.length, '关闭会话后应生成一条录制');
            assert.equal(entries[0].host, '127.0.0.1');
            assert.equal(String(entries[0].port), String(ssh.port));

            const text = await page.evaluate(
                async (key) => (await fetch('/api/logs/' + encodeURIComponent(key), { credentials: 'same-origin' })).text(),
                entries[0].key
            );
            assert.match(text, /E2E shell ready/);
            assert.match(text, /snippet-sent-ok/);

            await page.locator('.host-row').filter({ hasText: HOST_NAME }).locator('button[title="连接记录"]').click();
            const logsModal = await waitModal(page, '连接记录');
            await logsModal.locator('.list-row').first().click();
            await logsModal.locator('pre.fp').waitFor();
            assert.match(await logsModal.locator('pre.fp').innerText(), /snippet-sent-ok/);
            await page.keyboard.press('Escape');
            await page.waitForSelector('.modal-backdrop', { state: 'detached' });
            log('  ✓ 录制能用主密钥解密读回，列表和详情都能打开');
        }

        log('\n▶ 删除主机后，被引用的凭据才允许删除');
        {
            const row = page.locator('.host-row').filter({ hasText: HOST_NAME });
            await row.locator('button[title="删除"]').click();
            const confirm = await waitModal(page, '删除主机');
            await confirm.getByRole('button', { name: '删除', exact: true }).click();
            await page.waitForFunction((name) => !document.querySelector('.host-row')?.innerText.includes(name), HOST_NAME);

            await page.click('.rail-item[data-nav="keys"]');
            const vault = await waitModal(page, '凭据库');
            const credRow = vault.locator('.list-row').filter({ hasText: CRED_NAME });
            const delBtn = credRow.locator('button[title="删除"]');
            assert.equal(await delBtn.isDisabled(), false, '没有主机引用后删除按钮应当可用');
            await delBtn.click();
            const confirm2 = await waitModal(page, '删除常用账号');
            await confirm2.getByRole('button', { name: '删除', exact: true }).click();
            await page.waitForFunction((name) => !document.querySelector('.modal-backdrop')?.innerText.includes(name), CRED_NAME);
            await page.keyboard.press('Escape');
            await page.waitForSelector('.modal-backdrop', { state: 'detached' });
            log('  ✓ 主机删除后凭据可删，删除流程完整');
        }

        log('\n▶ 改密踢掉其它设备，当前浏览器保持登录');
        {
            ctx2 = await browser.newContext({ viewport: { width: 1200, height: 800 } });
            const page2 = await ctx2.newPage();
            await page2.goto(BASE + '/');
            await uiLogin(page2, ADMIN.username, ADMIN.password);
            assert.equal((await pageState(page2)).authed, true);

            await page.click('.rail-item[data-nav="settings"]');
            const settings = await waitModal(page, '设置');
            const pwInputs = settings.locator('input[type="password"]');
            await pwInputs.nth(0).fill(ADMIN.password);
            await pwInputs.nth(1).fill(NEW_PASSWORD);
            await settings.getByRole('button', { name: '修改密码', exact: true }).click();
            await waitText(page, '.toast', '密码已更新');

            const kicked = await pageState(page2);
            assert.equal(kicked.authed, false, '其它设备的会话应当被踢掉');
            await page2.reload();
            await page2.waitForSelector('#form-login:not([hidden])');

            const stillIn = await pageState(page);
            assert.equal(stillIn.authed, true, '当前浏览器应保持登录');
            ADMIN.password = NEW_PASSWORD;
            await page.keyboard.press('Escape');
            await page.waitForSelector('.modal-backdrop', { state: 'detached' });
            await ctx2.close();
            ctx2 = null;
            log('  ✓ 改密后其它设备掉线，当前会话换成新 token');
        }

        log('\n▶ 退出登录与重新登录');
        {
            await page.click('.rail-item[data-nav="logout"]');
            await page.waitForSelector('#form-login:not([hidden])');
            await page.reload();
            await page.waitForSelector('#form-login:not([hidden])');
            await page.waitForSelector('#form-setup', { state: 'hidden' });
            await uiLogin(page, ADMIN.username, ADMIN.password);
            assert.equal((await pageState(page)).authed, true);
            log('  ✓ 退出后刷新仍是登录页，重新登录成功');
        }

        assert.deepEqual(pageErrors.filter((e) => !/favicon|WebGL|earth\.jpg/i.test(e)), [], '页面不应有 JS 错误');
        await context.close();
        log('\n全部通过 ✔');
    } catch (e) {
        await dumpDebug();
        throw e;
    } finally {
        if (ctx2) await ctx2.close().catch(() => {});
        if (browser) await browser.close().catch(() => {});
        if (worker) await worker.stop().catch(() => {});
        if (raceWorker) await raceWorker.stop().catch(() => {});
        ssh.server.close();
        await fsp.rm(fsRoot, { recursive: true, force: true });
    }
}

main().catch((e) => {
    console.error('\n✖ 测试失败：');
    console.error(e && (e.stack || e.message || e));
    process.exitCode = 1;
});
