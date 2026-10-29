// WebSocket <-> SSH bridge. One Durable-less session per socket.
import { connect } from 'cloudflare:sockets';
import { SSHClient } from './ssh/client.js';
import { SFTPClient, OPEN, b64encode, b64decode, isDirMode, isLinkMode, modeString, tempName } from './ssh/sftp.js';
import { getJSON, putJSON, putBytes } from './store.js';
import { decryptSecret, randomHex, encryptBytes } from './auth.js';
import { normalizeHost } from './hostaddr.js';

const MAX_FILE = 64 * 1024 * 1024;
const READ_CHUNK = 128 * 1024;
const WRITE_CHUNK = 64 * 1024;
const EDIT_MAX = 512 * 1024;
// 单会话内并发的 SFTP 请求上限 / 同时打开的文件句柄上限
const SFTP_CONCURRENCY = 4;
const MAX_HANDLES = 64;

export function knownKey(host, port) {
    return 'known/' + String(host).toLowerCase().replace(/[^a-z0-9.\-:\[\]]/g, '_') + '_' + port;
}

// Single round-trip sample of the remote /proc counters.
const STATS_CMD =
    "awk '/^cpu /{print \"@@CPU\",$2,$3,$4,$5,$6,$7,$8,$9}' /proc/stat 2>/dev/null; " +
    "awk '/^MemTotal:/{t=$2}/^MemAvailable:/{a=$2}/^SwapTotal:/{st=$2}/^SwapFree:/{sf=$2}END{print \"@@MEM\",t,a,st,sf}' /proc/meminfo 2>/dev/null; " +
    'awk \'NR>2 && $1!="lo:"{rx+=$2;tx+=$10}END{print "@@NET",rx+0,tx+0}\' /proc/net/dev 2>/dev/null; ' +
    "sed 's/^/@@LOAD /' /proc/loadavg 2>/dev/null; " +
    "sed 's/^/@@UP /' /proc/uptime 2>/dev/null; " +
    'echo "@@WHO $(who 2>/dev/null | wc -l)"';

function parseStats(stdout, prev) {
    const vals = {};
    for (const line of stdout.split('\n')) {
        const m = line.trim().match(/^@@([A-Z]+)\s*(.*)$/);
        if (m) vals[m[1]] = m[2].trim();
    }
    if (!vals.CPU) return null;
    const cpu = vals.CPU.split(/\s+/).map(Number);
    const total = cpu.reduce((a, b) => a + (b || 0), 0);
    const idle = (cpu[3] || 0) + (cpu[4] || 0);
    const at = Date.now();
    const raw = { total, idle, at, rx: 0, tx: 0 };

    const mem = (vals.MEM || '').split(/\s+/).map(Number);
    const net = (vals.NET || '').split(/\s+/).map(Number);
    raw.rx = net[0] || 0;
    raw.tx = net[1] || 0;

    const out = { at };
    out.cpu = prev && total > prev.total ? Math.max(0, Math.min(100, Math.round((1 - (idle - prev.idle) / (total - prev.total)) * 100))) : null;

    const load = (vals.LOAD || '').split(/\s+/).slice(0, 3).map(Number);
    if (load.length === 3 && load.every((n) => Number.isFinite(n))) out.load = load;

    if (mem.length >= 4 && mem[0] > 0) {
        out.mem = { total: mem[0] * 1024, used: (mem[0] - mem[1]) * 1024, pct: Math.round(((mem[0] - mem[1]) / mem[0]) * 100) };
        if (mem[2] > 0) out.swap = { total: mem[2] * 1024, used: (mem[2] - mem[3]) * 1024, pct: Math.round(((mem[2] - mem[3]) / mem[2]) * 100) };
        else out.swap = { total: 0, used: 0, pct: 0 };
    }
    if (prev && prev.rx != null) {
        const dt = Math.max(0.5, (at - prev.at) / 1000);
        out.net = { rx: Math.max(0, (raw.rx - prev.rx) / dt), tx: Math.max(0, (raw.tx - prev.tx) / dt) };
    }
    const up = parseFloat(vals.UP || '0');
    if (up) out.uptime = up;
    out.users = parseInt(vals.WHO, 10) || 0;
    return { out, raw };
}

export class Terminal {
    /**
     * @param {WebSocket} ws  server side of the pair
     * @param {object} env    worker env (BUCKET)
     * @param {string} user   logged in username
     * @param {object|null} socket  TCP socket already opened by the fetch handler
     * @param {object|null} target  { host, port } resolved before the upgrade
     */
    constructor(ws, env, user, socket, target) {
        this.ws = ws;
        this.env = env;
        this.user = user;
        this.socket = socket || null;
        this.target = target || null;
        this.client = null;
        this.writer = null;
        this.writeChain = Promise.resolve();
        this.waiters = new Map();
        this.waiterId = 0;
        this.recording = false;
        this.recChunks = [];
        this.recBytes = 0;
        this.startedAt = 0;
        this.closed = false;
        this.keepaliveTimer = null;
        this.statsTimer = null;
        this.sampling = false;
        this.prevSample = null;
        this.meta = { host: '', port: 22, user: '' };
        // 指纹不一致时留下的上下文，供前端直接给出「删除旧记录并重连」
        this.hostKeyMismatch = null;
        this.hostKeyMismatchSent = false;
        this.sftp = null;
        this.sftpPromise = null;
        this.sftpActive = 0;
        this.sftpWaiters = [];
        this.handles = new Map();
        this.handleSeq = 0;
        this.started = false;
    }

    /* ------------------------------------------------------------- plumbing */

    send(obj) {
        if (this.closed) return;
        try {
            this.ws.send(JSON.stringify(obj));
        } catch (_) {}
    }

    sendData(u8) {
        if (this.closed) return;
        try {
            this.ws.send(u8);
        } catch (_) {}
    }

    ask(payload, kind, timeoutMs = 120000) {
        const id = ++this.waiterId;
        payload.id = id;
        const promise = new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.waiters.delete(id);
                reject(new Error('等待客户端响应超时'));
            }, timeoutMs);
            this.waiters.set(id, {
                kind,
                resolve: (v) => {
                    clearTimeout(timer);
                    this.waiters.delete(id);
                    resolve(v);
                },
                reject: (e) => {
                    clearTimeout(timer);
                    this.waiters.delete(id);
                    reject(e);
                },
            });
        });
        this.send(payload);
        return promise;
    }

    answer(msg) {
        const w = this.waiters.get(msg.id);
        if (!w) return false;
        if (w.kind === 'hostkey') w.resolve(!!msg.accept);
        else if (w.kind === 'kbd') w.resolve(Array.isArray(msg.answers) ? msg.answers : null);
        return true;
    }

    async write(bytes) {
        this.writeChain = this.writeChain.then(
            () => this.writer.write(bytes),
            () => this.writer.write(bytes)
        );
        return this.writeChain;
    }

    /* ----------------------------------------------------------------- init */

    async start(cfg) {
        try {
            await this._connect(cfg);
        } catch (e) {
            const message = String((e && e.message) || e);
            // 指纹不一致时，_fail() 通常已经把带 hostKeyMismatch 上下文的 error 发出去过一次了；
            // 万一那条路径没走到（比如 client 已关闭），这里补发，避免变成「静默失败」。
            if (!this.hostKeyMismatch) this.send({ t: 'error', message });
            else if (!this.hostKeyMismatchSent) {
                this.send({ t: 'error', message, hostKeyMismatch: this.hostKeyMismatch });
            }
            await this.cleanup(message);
        }
    }

    async _connect(cfg) {
        let host = this.target ? this.target.host : String(cfg.host || '').trim();
        let port = this.target ? this.target.port : parseInt(cfg.port, 10) || 22;
        let username = String(cfg.username || '').trim();
        let password = cfg.password || '';
        let privateKey = cfg.privateKey || '';
        let record = !!cfg.record;

        if (cfg.hostId) {
            const saved = await getJSON(this.env, 'hosts/' + String(cfg.hostId));
            if (!saved) throw new Error('主机配置不存在');
            // 目标一律以记录为准。TCP 已经按 URL 参数连上了，所以这里必须核对：
            // 允许「记录里的凭据 + 查询参数里的地址」混用，等于把存好的 SSH 密码
            // 送去任意 host:port（会话被偷后可以借此把整库凭据钓走）。
            if (this.target && (normalizeHost(saved.host) !== this.target.host || (saved.port || 22) !== this.target.port)) {
                throw new Error('主机配置与连接目标不一致，已中止（请从主机列表重新连接）');
            }
            host = saved.host;
            port = saved.port || 22;
            username = saved.username;
            if (!password && !privateKey) {
                if (saved.authType === 'key' && saved.keyId) {
                    const vault = await getJSON(this.env, 'sys/keys');
                    const key = vault && Array.isArray(vault.keys) ? vault.keys.find((k) => k.id === saved.keyId) : null;
                    if (!key || !key.keyEnc) throw new Error('密钥库里找不到该主机使用的密钥，请在主机设置中重新选择');
                    privateKey = await decryptSecret(this.env, key.keyEnc, 'key:' + key.id);
                } else if (saved.authType === 'key' && saved.keyEnc) {
                    privateKey = await decryptSecret(this.env, saved.keyEnc, 'host:' + (saved.id || cfg.hostId));
                } else if (saved.authType === 'password' && saved.credId) {
                    const vault = await getJSON(this.env, 'sys/creds');
                    const cred = vault && Array.isArray(vault.creds) ? vault.creds.find((c) => c.id === saved.credId) : null;
                    if (!cred || !cred.passEnc) throw new Error('凭据库里找不到该主机使用的账号，请在主机设置中重新选择');
                    password = await decryptSecret(this.env, cred.passEnc, 'cred:' + cred.id);
                    if (cred.username) username = cred.username;
                } else if (saved.secretEnc) {
                    password = await decryptSecret(this.env, saved.secretEnc, 'host:' + (saved.id || cfg.hostId));
                }
            }
        }

        host = normalizeHost(host);
        if (!host) throw new Error('主机地址不合法（支持域名、IPv4、IPv6）');
        if (!username) throw new Error('缺少用户名');
        if (port < 1 || port > 65535) throw new Error('端口不合法');

        this.meta = { host, port, user: username };
        this.recording = record;
        // 录制元数据的「开始时间」要取连接建立的时刻，而不是 cleanup 的时刻
        this.startedAt = Date.now();
        if (this.socket) {
            this.send({ t: 'status', phase: 'tcp', message: `TCP 已连接 ${host}:${port}，正在协商 SSH 会话 …` });
        } else {
            this.send({ t: 'status', phase: 'tcp', message: `正在连接 ${host}:${port} …` });
            this.socket = connect({ hostname: host, port });
        }
        await this.socket.opened;
        this.writer = this.socket.writable.getWriter();

        this.client = new SSHClient({
            username,
            auth: { password, privateKey },
            cols: clampInt(cfg.cols, 20, 500, 80),
            rows: clampInt(cfg.rows, 5, 200, 24),
            term: 'xterm-256color',
            write: (b) => this.write(b),
            onData: (data) => {
                this.sendData(data);
                this._record(data);
            },
            onEvent: (ev) => this._onEvent(ev),
            onBanner: (text) => this.send({ t: 'banner', message: text }),
            onHostKey: (info) => this._hostKeyPolicy(host, port, info),
            onKeyboardInteractive: (req) => this._kbd(username, password, req),
        });

        this._readLoop();
        await this.client.connect();
        this.send({ t: 'ready' });
        this.keepaliveTimer = setInterval(() => {
            try {
                // 一直在发保活却长时间收不到任何报文 → 连接已假死。主动断开，
                // 而不是让界面永远显示「已连接」却打不出字。
                if (Date.now() - (this.client.lastInbound || 0) > 150000) {
                    this.send({ t: 'error', message: '连接已无响应（保活超时 150 秒），已断开' });
                    this.cleanup('keepalive-timeout');
                    return;
                }
                this.client.keepalive();
            } catch (_) {}
        }, 45000);
        this._startMonitor();
    }

    /* ------------------------------------------------------------- monitor */

    async _startMonitor() {
        try {
            const { stdout } = await this.client.exec(
                'uname -s 2>/dev/null; uname -r 2>/dev/null; uname -m 2>/dev/null; ' +
                    'grep -E "^(PRETTY_NAME|VERSION_ID)=" /etc/os-release 2>/dev/null | head -2',
                6000
            );
            const lines = stdout.split('\n').map((l) => l.trim());
            const system = lines[0] || '';
            const pretty = (stdout.match(/PRETTY_NAME="?([^"\n]+)"?/) || [])[1] || '';
            this.send({
                t: 'os',
                system,
                release: lines[1] || '',
                arch: lines[2] || '',
                pretty,
            });
            if (!/^Linux/i.test(system)) {
                this.send({ t: 'stats-off', reason: 'non-linux' });
                return;
            }
            await this._sample();
            this.statsTimer = setInterval(() => this._sample(), 3000);
        } catch (_) {
            this.send({ t: 'stats-off', reason: 'unavailable' });
        }
    }

    async _sample() {
        if (this.sampling || this.closed || !this.client || this.client.closed) return;
        this.sampling = true;
        try {
            const { stdout } = await this.client.exec(STATS_CMD, 5000);
            const stats = parseStats(stdout, this.prevSample);
            if (!stats) return;
            this.prevSample = stats.raw;
            this.send({ t: 'stats', stats: stats.out });
        } catch (_) {
        } finally {
            this.sampling = false;
        }
    }

    /* ---------------------------------------------------------------- sftp */

    _sftpClient() {
        if (!this.client || !this.client.ready) return Promise.reject(new Error('SSH 会话尚未就绪'));
        if (this.sftp) return Promise.resolve(this.sftp);
        if (!this.sftpPromise) {
            const c = new SFTPClient(this.client);
            this.sftpPromise = c
                .ready()
                .then(() => {
                    this.sftp = c;
                    return c;
                })
                .catch((e) => {
                    this.sftpPromise = null;
                    throw e;
                });
        }
        return this.sftpPromise;
    }

    async _trackHandle(h) {
        if (this.handles.size >= MAX_HANDLES) {
            // 句柄表不设上限的话，客户端只要 open 不 close 就能把服务端 fd 吃光
            try {
                await this.sftp.close(h);
            } catch (_) {}
            throw new Error('同时打开的文件过多（上限 ' + MAX_HANDLES + '），请先关闭部分文件');
        }
        const token = 'h' + ++this.handleSeq;
        this.handles.set(token, h);
        return token;
    }

    async _closeHandle(token) {
        const h = this.handles.get(token);
        if (!h) return;
        this.handles.delete(token);
        try {
            await this.sftp.close(h);
        } catch (_) {}
    }

    async _acquireSftp() {
        while (this.sftpActive >= SFTP_CONCURRENCY) {
            await new Promise((r) => this.sftpWaiters.push(r));
        }
        this.sftpActive++;
    }

    _releaseSftp() {
        this.sftpActive--;
        const next = this.sftpWaiters.shift();
        if (next) next();
    }

    /** 入口：限制并发，避免客户端一次灌上千个请求把内存和通道打满 */
    async _sftpOp(msg) {
        await this._acquireSftp();
        try {
            return await this._sftpOpInner(msg);
        } finally {
            this._releaseSftp();
        }
    }

    async _sftpOpInner(msg) {
        const sftp = await this._sftpClient();
        const cleanPath = (v) => {
            const p = String(v == null ? '' : v);
            if (!p || p.length > 4096 || p.includes('\0')) throw new Error('路径不合法');
            return p;
        };
        const reply = (extra) => this.send(Object.assign({ t: 'sftp', id: msg.id, ok: true }, extra));

        switch (msg.op) {
            case 'realpath': {
                reply({ path: await sftp.realpath(cleanPath(msg.path)) });
                return;
            }
            case 'list': {
                const real = await sftp.realpath(cleanPath(msg.path));
                const raw = await sftp.list(real);
                const entries = [];
                let links = 0;
                for (const e of raw) {
                    const attrs = e.attrs || {};
                    const link = isLinkMode(attrs.perms);
                    let dir = isDirMode(attrs.perms);
                    if (link && links++ < 20) {
                        try {
                            const st = await sftp.stat(real.replace(/\/+$/, '') + '/' + e.name);
                            dir = isDirMode(st.perms);
                        } catch (_) {}
                    }
                    entries.push({
                        name: e.name,
                        size: attrs.size == null ? null : attrs.size,
                        modeText: modeString(attrs.perms),
                        mtime: attrs.mtime ? attrs.mtime * 1000 : null,
                        isDir: dir,
                        isLink: link,
                    });
                }
                reply({ path: real, entries });
                return;
            }
            case 'mkdir': {
                await sftp.mkdir(cleanPath(msg.path));
                reply({});
                return;
            }
            case 'remove': {
                const p = cleanPath(msg.path);
                if (msg.isDir) await sftp.rmdir(p);
                else await sftp.remove(p);
                reply({});
                return;
            }
            case 'rename': {
                const from = cleanPath(msg.from);
                const to = cleanPath(msg.to);
                try {
                    await sftp.rename(from, to);
                } catch (e) {
                    throw new Error('重命名失败（' + from + ' → ' + to + '）：' + ((e && e.message) || e) + '。目标已存在时请先删除同名文件');
                }
                reply({});
                return;
            }
            case 'open-read': {
                const p = cleanPath(msg.path);
                const st = await sftp.stat(p);
                if (isDirMode(st.perms)) throw new Error('不能下载目录');
                if ((st.size || 0) > MAX_FILE) throw new Error('文件超过 64 MB，暂不支持在浏览器中下载');
                const handle = await sftp.open(p, OPEN.READ);
                reply({ handle: await this._trackHandle(handle), size: st.size || 0 });
                return;
            }
            case 'read': {
                const h = this.handles.get(String(msg.handle));
                if (!h) throw new Error('文件句柄无效，请重新打开');
                const offset = Math.max(0, Number(msg.offset) || 0);
                const len = Math.min(262144, Math.max(1, parseInt(msg.len, 10) || READ_CHUNK));
                const res = await sftp.read(h, offset, len);
                if (res.eof) reply({ eof: true });
                else reply({ data: b64encode(res.data), length: res.data.length });
                return;
            }
            case 'open-write': {
                const handle = await sftp.open(cleanPath(msg.path), OPEN.WRITE | OPEN.CREAT | OPEN.TRUNC);
                reply({ handle: await this._trackHandle(handle) });
                return;
            }
            /**
             * 原子上传：先在同目录建临时文件，写完再 rename 覆盖目标。
             * 直接 open(TRUNC) 目标文件的话，传到一半断线/报错，原文件就没了 ——
             * 上传一个同名配置文件时这一点尤其致命。
             */
            case 'open-upload': {
                const target = cleanPath(msg.path);
                const tmp = tempName(target, 'webssh-upload');
                const handle = await sftp.open(tmp, OPEN.WRITE | OPEN.CREAT | OPEN.TRUNC | OPEN.EXCL);
                reply({ handle: await this._trackHandle(handle), tmp });
                return;
            }
            case 'commit-upload': {
                const token = String(msg.handle);
                const h = this.handles.get(token);
                if (!h) throw new Error('文件句柄无效，请重新打开');
                const target = cleanPath(msg.path);
                const tmp = cleanPath(msg.tmp);
                // rename 换的是 inode：不还原权限位的话，0600 的密钥上传一次就变 0644
                const prev = await sftp.stat(target).catch(() => null);
                if (prev && prev.perms != null) {
                    try {
                        await sftp.fchmod(h, prev.perms & 0o7777);
                    } catch (_) {}
                }
                await this._closeHandle(token);
                try {
                    await sftp.renameOverwrite(tmp, target);
                } catch (e) {
                    await sftp.remove(tmp).catch(() => {});
                    throw new Error('保存 ' + target + ' 失败：' + ((e && e.message) || e) + '（原文件未受影响）');
                }
                reply({ path: target });
                return;
            }
            case 'write': {
                const h = this.handles.get(String(msg.handle));
                if (!h) throw new Error('文件句柄无效，请重新打开');
                const data = b64decode(msg.data);
                if (data.length > 1024 * 1024) throw new Error('单次写入的数据过大');
                await sftp.write(h, Math.max(0, Number(msg.offset) || 0), data);
                reply({});
                return;
            }
            case 'close': {
                await this._closeHandle(String(msg.handle));
                reply({});
                return;
            }
            case 'read-text': {
                const p = cleanPath(msg.path);
                const st = await sftp.stat(p);
                if (isDirMode(st.perms)) throw new Error('这是一个目录');
                const cap = Math.min(2 * 1024 * 1024, Math.max(1, parseInt(msg.max, 10) || EDIT_MAX));
                if ((st.size || 0) > cap) throw new Error('文件超过 ' + Math.round(cap / 1024) + ' KB，暂不支持在线编辑');
                const handle = await sftp.open(p, OPEN.READ);
                try {
                    const chunks = [];
                    let offset = 0;
                    for (;;) {
                        const res = await sftp.read(handle, offset, READ_CHUNK);
                        if (res.eof) break;
                        if (!res.data || !res.data.length) break;
                        chunks.push(res.data);
                        offset += res.data.length;
                        if (offset > cap) throw new Error('文件超过在线编辑上限');
                    }
                    const all = new Uint8Array(offset);
                    let o = 0;
                    for (const c of chunks) {
                        all.set(c, o);
                        o += c.length;
                    }
                    reply({ data: b64encode(all), size: offset });
                } finally {
                    await sftp.close(handle).catch(() => {});
                }
                return;
            }
            case 'write-text': {
                const data = b64decode(msg.data);
                if (data.length > 2 * 1024 * 1024) throw new Error('内容超过 2 MB，无法保存');
                await this._writeAtomic(sftp, cleanPath(msg.path), data);
                reply({ size: data.length });
                return;
            }
            default:
                throw new Error('未知的文件操作: ' + msg.op);
        }
    }

    async _writeAtomic(sftp, path, data) {
        const tmp = tempName(path, 'webssh');
        // rename 换的是 inode：不还原 mode 的话，0600 的私钥保存一次就变成 0644（全局可读），
        // sshd 还会拒绝使用。先记住原文件的权限位，写临时文件时就套上。
        const prev = await sftp.stat(path).catch(() => null);
        let handle = null;
        let step = '创建临时文件';
        try {
            handle = await sftp.open(tmp, OPEN.WRITE | OPEN.CREAT | OPEN.TRUNC | OPEN.EXCL);
            step = '套用原文件权限';
            if (prev && prev.perms != null) {
                try {
                    await sftp.fchmod(handle, prev.perms & 0o7777);
                } catch (_) {}
            }
            step = '写入内容';
            for (let off = 0; off < data.length; off += WRITE_CHUNK) {
                await sftp.write(handle, off, data.subarray(off, off + WRITE_CHUNK));
            }
            step = '关闭临时文件';
            await sftp.close(handle);
            handle = null;
            step = '替换目标文件';
            await sftp.renameOverwrite(tmp, path);
        } catch (e) {
            if (handle) await sftp.close(handle).catch(() => {});
            await sftp.remove(tmp).catch(() => {});
            // 只回「服务器拒绝了该操作：Failure」等于没说，把路径和失败的步骤一起带出去
            throw new Error('保存 ' + path + ' 失败（' + step + '）：' + ((e && e.message) || e));
        }
    }

    async _hostKeyPolicy(host, port, info) {
        const key = knownKey(host, port);
        const known = await getJSON(this.env, key);
        if (known) {
            if (known.fingerprint === info.fingerprint) return true;
            // 仍然默认拒绝（fail-closed），但把「哪条记录、旧指纹、新指纹」一并带上，
            // 前端才能直接给一个「删除并重连」，不用让人自己去「主机密钥」页里翻。
            this.hostKeyMismatch = {
                key,
                host,
                port,
                type: info.type || known.type || '',
                saved: known.fingerprint,
                current: info.fingerprint,
                savedAt: known.addedAt || 0,
            };
            throw new Error(
                `主机密钥与已保存的不一致！\n已保存: ${known.fingerprint}\n服务器: ${info.fingerprint}\n` +
                    '如确认服务器已重装，请先在「主机密钥」中删除该记录后重试。'
            );
        }
        const accepted = await this.ask({
            t: 'hostkey',
            host,
            port,
            type: info.type,
            fingerprint: info.fingerprint,
            signatureValid: info.signatureValid,
            signatureError: info.signatureError || null,
        }, 'hostkey');
        if (accepted) {
            await putJSON(this.env, key, {
                host,
                port,
                type: info.type,
                fingerprint: info.fingerprint,
                addedAt: Date.now(),
                addedBy: this.user,
            });
            this.send({ t: 'toast', message: '已将该主机密钥保存到信任列表' });
        }
        return accepted;
    }

    async _kbd(username, password, req) {
        const prompts = req.prompts || [];
        const onlySecret = prompts.length === 1 && !prompts[0].echo;
        if (password && prompts.every((p) => !p.echo)) return prompts.map(() => password);
        if (!prompts.length) return [];
        const answers = await this.ask(
            {
                t: 'kbd',
                name: req.name,
                instruction: req.instruction,
                prompts: prompts.map((p) => ({ prompt: p.prompt, echo: p.echo })),
            },
            'kbd'
        );
        if (!answers) throw new Error('已取消键盘交互认证');
        return answers;
    }

    _onEvent(ev) {
        switch (ev.type) {
            case 'kex-done':
                this.send({ t: 'status', phase: 'auth', message: '已建立加密通道，正在认证 …', fingerprint: ev.fingerprint, hostKeyType: ev.hostKeyType });
                break;
            case 'eof':
                this.send({ t: 'eof' });
                break;
            case 'close':
                this.send({ t: 'exit', code: ev.code });
                // the remote shell is gone: flush the exit notice, then tear down
                setTimeout(() => this.cleanup('channel-closed'), 150);
                break;
            case 'exit-status':
                this.send({ t: 'exit-status', code: ev.code });
                break;
            case 'error': {
                // 指纹变更时把上下文附在同一条 error 上：认识它的前端弹窗，
                // 不认识的老前端照旧显示文本，不会变成「什么都没发生」。
                const mismatch = this.hostKeyMismatch;
                if (mismatch) this.hostKeyMismatchSent = true;
                this.send(mismatch ? { t: 'error', message: ev.message, hostKeyMismatch: mismatch } : { t: 'error', message: ev.message });
                break;
            }
            default:
                break;
        }
    }

    async _readLoop() {
        try {
            const reader = this.socket.readable.getReader();
            for (;;) {
                const { value, done } = await reader.read();
                if (done) break;
                if (value && value.length) this.client.feed(value);
            }
            this.send({ t: 'status', phase: 'closed', message: '连接已被服务器关闭' });
            await this.cleanup('eof');
        } catch (e) {
            const message = String((e && e.message) || e);
            this.send({ t: 'error', message });
            await this.cleanup(message);
        }
    }

    /* --------------------------------------------------------------- events */

    handleMessage(msg) {
        if (msg instanceof ArrayBuffer || ArrayBuffer.isView(msg)) {
            if (this.client) this.client.write(new Uint8Array(msg instanceof ArrayBuffer ? msg : msg.buffer, msg.byteOffset || 0, msg.byteLength));
            return;
        }
        let data;
        try {
            data = JSON.parse(typeof msg === 'string' ? msg : new TextDecoder().decode(msg));
        } catch (_) {
            return;
        }
        switch (data.t) {
            case 'init':
                // 只接受一次：重复 init 会二次 getWriter() 抛错，把好好的连接拆掉
                if (this.started) return;
                this.started = true;
                this.start(data);
                break;
            case 'input':
                if (this.client && typeof data.data === 'string' && data.data.length <= 1024 * 1024) {
                    this.client.write(data.data);
                }
                break;
            case 'resize':
                if (this.client) this.client.resize(clampInt(data.cols, 20, 500, 80), clampInt(data.rows, 5, 200, 24));
                break;
            case 'hostkey':
            case 'kbd':
                this.answer(data);
                break;
            case 'ping':
                this.send({ t: 'pong', ts: data.ts });
                break;
            case 'sftp':
                if (!data.id) break;
                this._sftpOp(data).catch((e) => this.send({ t: 'sftp', id: data.id, ok: false, error: String((e && e.message) || e) }));
                break;
            case 'close':
                this.cleanup('client');
                break;
            default:
                break;
        }
    }

    _record(data) {
        if (!this.recording || this.recBytes > 4 * 1024 * 1024) return;
        // 按原始字节累积。一个 UTF-8 字符（中文 3 字节、emoji 4 字节）完全可能跨 SSH
        // 包边界，逐包 decode 会把它拆成 U+FFFD；收齐后一次性解码才不会打断字符。
        // slice() 不能省：data 是 SSH 接收缓冲上的视图，缓冲区会被后续数据复用。
        this.recChunks.push(data.slice());
        this.recBytes += data.length;
    }

    async cleanup(reason) {
        if (this.closed) return;
        this.closed = true;
        if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
        if (this.statsTimer) clearInterval(this.statsTimer);
        for (const w of this.waiters.values()) w.reject(new Error('连接已关闭'));
        this.waiters.clear();
        for (const w of this.sftpWaiters.splice(0)) w(); // 放行排队中的 SFTP 请求，让它们自己失败
        this.sftpWaiters = [];
        try {
            for (const token of Array.from(this.handles.keys())) await this._closeHandle(token);
        } catch (_) {}
        try {
            if (this.sftp) this.sftp.closeChannel();
        } catch (_) {}
        try {
            if (this.client && !this.client.closed) await this.client.close('bye');
        } catch (_) {}
        try {
            if (this.socket) await this.socket.close();
        } catch (_) {}
        try {
            this.ws.close(1000, 'closed');
        } catch (_) {}
        if (this.recording && this.recBytes > 0) {
            try {
                // 记录的是会话开始的时刻；文件名也用它，便于按会话时间排序
                const startedAt = this.startedAt || Date.now();
                const id = new Date(startedAt).toISOString().replace(/[:.]/g, '-') + '-' + randomHex(4);
                const bytes = joinBytes(this.recChunks, this.recBytes);
                await putBytes(this.env, 'logs/' + id + '.log', await encryptBytes(this.env, bytes, 'log:logs/' + id + '.log'), {
                    host: this.meta.host,
                    port: String(this.meta.port),
                    user: this.meta.user,
                    started: new Date(startedAt).toISOString(),
                    bytes: String(this.recBytes),
                    reason: String(reason || ''),
                    enc: 'v1',
                });
            } catch (_) {}
        }
        this.recChunks = [];
    }
}

function clampInt(v, min, max, dflt) {
    const n = parseInt(v, 10);
    if (!Number.isFinite(n)) return dflt;
    return Math.min(max, Math.max(min, n));
}

/** 把录制分片按顺序拼成一个字节流（解码留到读日志时整体进行） */
function joinBytes(chunks, total) {
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
        out.set(c, off);
        off += c.length;
    }
    return out;
}
