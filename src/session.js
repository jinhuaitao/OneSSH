// WebSocket <-> SSH bridge. One Durable-less session per socket.
import { connect } from 'cloudflare:sockets';
import { SSHClient } from './ssh/client.js';
import { getJSON, putJSON, putText } from './store.js';
import { decryptSecret, randomHex } from './auth.js';

export function knownKey(host, port) {
    return 'known/' + String(host).toLowerCase().replace(/[^a-z0-9.\-:]/g, '_') + '_' + port;
}

const enc = new TextEncoder();

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
        this.closed = false;
        this.keepaliveTimer = null;
        this.statsTimer = null;
        this.sampling = false;
        this.prevSample = null;
        this.meta = { host: '', port: 22, user: '' };
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
        else if (w.kind === 'passphrase') w.resolve(msg.value || '');
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
            this.send({ t: 'error', message });
            await this.cleanup(message);
        }
    }

    async _connect(cfg) {
        let host = this.target ? this.target.host : String(cfg.host || '').trim();
        let port = this.target ? this.target.port : parseInt(cfg.port, 10) || 22;
        let username = String(cfg.username || '').trim();
        let password = cfg.password || '';
        let privateKey = cfg.privateKey || '';
        let passphrase = cfg.passphrase || '';
        let record = !!cfg.record;

        if (cfg.hostId) {
            const saved = await getJSON(this.env, 'hosts/' + cfg.hostId);
            if (!saved) throw new Error('主机配置不存在');
            if (!this.target) {
                host = saved.host;
                port = saved.port || 22;
            }
            username = saved.username;
            if (!password && !privateKey) {
                if (saved.authType === 'key' && saved.keyEnc) {
                    privateKey = await decryptSecret(this.env, saved.keyEnc);
                    if (saved.passphraseEnc) passphrase = await decryptSecret(this.env, saved.passphraseEnc);
                } else if (saved.secretEnc) {
                    password = await decryptSecret(this.env, saved.secretEnc);
                }
            }
        }

        if (!host) throw new Error('缺少主机地址');
        if (!username) throw new Error('缺少用户名');
        if (!/^[a-zA-Z0-9._\-:\[\]]+$/.test(host)) throw new Error('主机地址包含非法字符');
        if (port < 1 || port > 65535) throw new Error('端口不合法');

        this.meta = { host, port, user: username };
        this.recording = record;
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
            auth: { password, privateKey, passphrase },
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

    async _hostKeyPolicy(host, port, info) {
        const key = knownKey(host, port);
        const known = await getJSON(this.env, key);
        if (known) {
            if (known.fingerprint === info.fingerprint) return true;
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
            case 'error':
                this.send({ t: 'error', message: ev.message });
                break;
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
                this.start(data);
                break;
            case 'input':
                if (this.client && data.data) this.client.write(data.data);
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
            case 'close':
                this.cleanup('client');
                break;
            default:
                break;
        }
    }

    _record(data) {
        if (!this.recording || this.recBytes > 4 * 1024 * 1024) return;
        this.recChunks.push(new TextDecoder().decode(data));
        this.recBytes += data.length;
    }

    async cleanup(reason) {
        if (this.closed) return;
        this.closed = true;
        if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
        if (this.statsTimer) clearInterval(this.statsTimer);
        for (const w of this.waiters.values()) w.reject(new Error('连接已关闭'));
        this.waiters.clear();
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
                const id = new Date().toISOString().replace(/[:.]/g, '-') + '-' + randomHex(4);
                await putText(this.env, 'logs/' + id + '.log', this.recChunks.join(''), {
                    host: this.meta.host,
                    port: String(this.meta.port),
                    user: this.meta.user,
                    started: new Date().toISOString(),
                    bytes: String(this.recBytes),
                    reason: String(reason || ''),
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
