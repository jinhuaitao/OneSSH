// Minimal-but-complete SSH-2 client (RFC 4253/4252/4254) on WebCrypto.
// Runs unchanged in Cloudflare Workers and Node 22+.
import { Reader, Writer, concat, randomBytes, fromUtf8, equalBytes } from './buf.js';
import * as C from './crypto.js';
import { loadPrivateKey, signUserauth } from './keys.js';

export const MSG = {
    DISCONNECT: 1,
    IGNORE: 2,
    UNIMPLEMENTED: 3,
    DEBUG: 4,
    SERVICE_REQUEST: 5,
    SERVICE_ACCEPT: 6,
    KEXINIT: 20,
    NEWKEYS: 21,
    KEX_ECDH_INIT: 30,
    KEX_ECDH_REPLY: 31,
    USERAUTH_REQUEST: 50,
    USERAUTH_FAILURE: 51,
    USERAUTH_SUCCESS: 52,
    USERAUTH_BANNER: 53,
    USERAUTH_PK_OK: 60, // also SSH_MSG_USERAUTH_INFO_REQUEST (RFC 4256)
    USERAUTH_INFO_RESPONSE: 61,
    GLOBAL_REQUEST: 80,
    REQUEST_SUCCESS: 81,
    REQUEST_FAILURE: 82,
    CHANNEL_OPEN: 90,
    CHANNEL_OPEN_CONFIRMATION: 91,
    CHANNEL_OPEN_FAILURE: 92,
    CHANNEL_WINDOW_ADJUST: 93,
    CHANNEL_DATA: 94,
    CHANNEL_EXTENDED_DATA: 95,
    CHANNEL_EOF: 96,
    CHANNEL_CLOSE: 97,
    CHANNEL_REQUEST: 98,
    CHANNEL_SUCCESS: 99,
    CHANNEL_FAILURE: 100,
};

const KEX_ALGS = ['curve25519-sha256', 'curve25519-sha256@libssh.org'];
// 只用来「通告」，不参与 pick()：这两个不是真正的密钥交换算法
const KEX_EXTRA = ['ext-info-c', 'kex-strict-c-v00@openssh.com'];
const CIPHERS = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr'];
// 只保留 SHA-2 系 MAC：会 SHA-1 的 HMAC 已经不该出现在 2026 年的协商列表里
const MACS = ['hmac-sha2-256', 'hmac-sha2-512'];
const CIPHER_KEYLEN = { 'aes128-ctr': 16, 'aes192-ctr': 24, 'aes256-ctr': 32 };
const MAC_LEN = { 'hmac-sha2-256': 32, 'hmac-sha2-512': 64 };

const WINDOW = 2 * 1024 * 1024;
const MAX_PACKET = 32 * 1024;

/** 给任意 promise 加超时：SSH 里"对方不说话"是最常见的失败方式，不能无限等 */
function withTimeout(promise, ms, message) {
    let timer;
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error(message)), ms);
        }),
    ]).finally(() => clearTimeout(timer));
}

function deferred() {
    let resolve, reject;
    const promise = new Promise((res, rej) => {
        resolve = res;
        reject = rej;
    });
    return { promise, resolve, reject };
}

function pick(clientList, serverList) {
    for (const a of clientList) if (serverList.includes(a)) return a;
    return null;
}

export class SSHClient {
    /**
     * @param {object} opts
     * @param {(bytes:Uint8Array)=>Promise<void>} opts.write  sink for raw bytes
     * @param {(data:Uint8Array)=>void} opts.onData            shell stdout/stderr
     * @param {(ev:object)=>void} [opts.onEvent]
     * @param {(info:object)=>Promise<boolean>} [opts.onHostKey]
     * @param {(banner:string)=>void} [opts.onBanner]
     * @param {(req:object)=>Promise<string[]|null>} [opts.onKeyboardInteractive]
     */
    constructor(opts) {
        this.opts = opts;
        this.onData = opts.onData || (() => {});
        this.onEvent = opts.onEvent || (() => {});
        this.onBanner = opts.onBanner || (() => {});
        this.onHostKey = opts.onHostKey || (async () => false);
        this.onKeyboardInteractive = opts.onKeyboardInteractive || (async () => null);

        this.clientVersion = opts.clientVersion || 'SSH-2.0-WorkerSSH_1.0';
        this.phase = 'version';
        this.vbuf = new Uint8Array(0);
        this.buf = new Uint8Array(0);
        this.off = 0;
        this.seqOut = 0;
        this.seqIn = 0;
        this.encOut = null;
        this.encIn = null;
        this.macOut = null;
        this.macIn = null;
        this.blockOut = 8;
        this.blockIn = 8;
        this.macOutLen = 0;
        this.macInLen = 0;
        this.sendChain = Promise.resolve();
        this.drainChain = Promise.resolve();
        this.flowChain = Promise.resolve();
        this.closed = false;
        this.kexInitSent = false;
        this.sessionId = null;
        this.channels = new Map();
        this.nextLocalChannel = 0;
        this.shell = null;
        this.exitCode = null;
        this.ready = false;
        this.authFailures = [];
        this.readyDeferred = deferred();
        this.lastInbound = Date.now();
        this.strictKex = false;
        this.kexActive = false;
        this._watchdog = null;
    }

    /** resolves once the interactive shell is up */
    connect() {
        // 总超时兜底：连 banner 都不发的服务器也必须能被放弃，否则连接会一直挂着
        this._watchdog = setTimeout(() => this._fail(new Error('SSH 握手超时（40 秒内未完成）')), 40000);
        const done = () => clearTimeout(this._watchdog);
        this.readyDeferred.promise.then(done, done);
        return this.readyDeferred.promise;
    }

    /** 外部主动放弃（例如保活超时） */
    abort(reason) {
        this._fail(new Error(String(reason || '连接已中止')));
    }

    /* ================================================================ input */

    feed(chunk) {
        if (this.closed) return;
        if (this.phase === 'version') {
            this.vbuf = this.vbuf.length ? concat(this.vbuf, chunk) : chunk;
            let idx;
            while ((idx = this.vbuf.indexOf(10)) !== -1) {
                const line = fromUtf8(this.vbuf.subarray(0, idx)).replace(/\r$/, '');
                this.vbuf = this.vbuf.subarray(idx + 1);
                if (line.startsWith('SSH-')) {
                    this.serverVersion = line;
                    this.phase = 'transport';
                    const rest = this.vbuf;
                    this.vbuf = new Uint8Array(0);
                    this._beginHandshake().catch((e) => this._fail(e));
                    if (rest.length) this.feed(rest);
                    return;
                }
                this.onEvent({ type: 'prebanner', text: line });
            }
            if (this.vbuf.length > 8192) this._fail(new Error('banner too long'));
            return;
        }
        this.buf = this.buf.length === this.off ? chunk : concat(this.buf.subarray(this.off), chunk);
        this.off = 0;
        this.drainChain = this.drainChain.then(() => this._drain()).catch((e) => this._fail(e));
    }

    async _drain() {
        if (this.closed) return;
        for (;;) {
            const payload = await this._readPacket();
            if (!payload) return;
            await this._dispatch(payload);
        }
    }

    async _readPacket() {
        const avail = this.buf.length - this.off;
        if (avail < this.blockIn + this.macInLen) return null;
        const head = this.buf.subarray(this.off, this.off + this.blockIn);
        let packetLen;
        if (this.encIn) {
            const peeked = await this.encIn.peek(head);
            packetLen = new DataView(peeked.buffer, peeked.byteOffset, 4).getUint32(0);
        } else {
            packetLen = new DataView(head.buffer, head.byteOffset, 4).getUint32(0);
        }
        if (packetLen < 5 || packetLen > 256 * 1024) throw new Error('bad packet length ' + packetLen);
        const total = 4 + packetLen;
        if (avail < total + this.macInLen) return null;
        let pkt = this.buf.subarray(this.off, this.off + total);
        if (this.encIn) pkt = await this.encIn.crypt(pkt);
        if (this.macIn) {
            const mac = this.buf.subarray(this.off + total, this.off + total + this.macInLen);
            const expect = await this.macIn.sign(this.seqIn, pkt);
            if (!equalBytes(mac, expect)) throw new Error('message authentication failed (bad MAC)');
        }
        this.seqIn = (this.seqIn + 1) >>> 0;
        this.off += total + this.macInLen;
        if (this.off > 1 << 16) {
            this.buf = this.buf.slice(this.off);
            this.off = 0;
        }
        this.lastInbound = Date.now();
        const padLen = pkt[4];
        // RFC 4253 §6：padding 至少 4 字节，且必须给 payload 留出至少 1 字节（报文类型）
        if (padLen < 4 || padLen > packetLen - 1) throw new Error('bad padding length ' + padLen);
        return pkt.subarray(5, 4 + packetLen - padLen);
    }

    async send(payload, opts) {
        const run = async () => {
            const block = this.encOut ? 16 : 8;
            let padLen = block - ((payload.length + 5) % block);
            if (padLen < 4) padLen += block;
            const packetLen = payload.length + padLen + 1;
            const pkt = new Uint8Array(4 + packetLen);
            new DataView(pkt.buffer).setUint32(0, packetLen);
            pkt[4] = padLen;
            pkt.set(payload, 5);
            pkt.set(randomBytes(padLen), 5 + payload.length);
            let mac = null;
            if (this.macOut) mac = await this.macOut.sign(this.seqOut, pkt);
            this.seqOut = (this.seqOut + 1) >>> 0;
            let out = pkt;
            if (this.encOut) out = await this.encOut.crypt(pkt);
            if (mac) out = concat(out, mac);
            await this.opts.write(out);
            // strict kex：NEWKEYS 之后序号从 0 重新开始。必须在本包写完之后重置，
            // 且要和发包在同一个串行任务里，否则后面的包会用错序号。
            if (opts && opts.resetSeq) this.seqOut = 0;
        };
        this.sendChain = this.sendChain.then(run, run);
        return this.sendChain;
    }

    _fail(err) {
        if (this.closed) return;
        this.closed = true;
        this.onEvent({ type: 'error', message: String((err && err.message) || err) });
        this.readyDeferred.reject(err);
        if (this.kexDone) this.kexDone.reject(err);
    }

    /* ============================================================ handshake */

    async _beginHandshake() {
        await this.opts.write(concat(new TextEncoder().encode(this.clientVersion + '\r\n')));
        await this._sendKexInit();
        await withTimeout(this.kexDone.promise, 20000, '密钥交换超时：服务器 20 秒内没有完成 KEX');
        await withTimeout(this._authenticate(), 45000, '认证超时：服务器 45 秒内没有回应');
        await withTimeout(this._openShell(), 15000, '打开 shell 超时');
    }

    async _sendKexInit() {
        const w = new Writer();
        w.byte(MSG.KEXINIT);
        w.raw(randomBytes(16));
        // 后两个只是能力通告（ext-info-c / strict-kex），不参与 pick()
        w.nameList(KEX_ALGS.concat(KEX_EXTRA));
        w.nameList(C.HOST_KEY_ALGS);
        w.nameList(CIPHERS);
        w.nameList(CIPHERS);
        w.nameList(MACS);
        w.nameList(MACS);
        w.nameList(['none']);
        w.nameList(['none']);
        w.nameList([]);
        w.nameList([]);
        w.bool(false);
        w.u32(0);
        const payload = w.bytes();
        this.iC = payload;
        this.kexInitSent = true;
        this.kexActive = true;
        this.kexDone = deferred();
        await this.send(payload);
    }

    async _dispatch(p) {
        const type = p[0];
        switch (type) {
            case MSG.DISCONNECT: {
                const r = new Reader(p, 1);
                const code = r.u32();
                const desc = r.text();
                throw new Error(`服务器断开连接 (${code}): ${desc}`);
            }
            case MSG.IGNORE:
            case MSG.DEBUG:
            case MSG.UNIMPLEMENTED:
                // strict kex 下，KEX 期间出现这类报文只可能是中间人注入（Terrapin）
                if (this.strictKex && this.kexActive) {
                    throw new Error('strict kex: 密钥交换期间收到非法报文 (type ' + type + ')，已中止连接');
                }
                return;
            case MSG.KEXINIT:
                return this._onKexInit(p);
            case MSG.KEX_ECDH_REPLY:
                return this._onKexReply(p);
            case MSG.NEWKEYS:
                return this._onNewKeys();
            case MSG.SERVICE_ACCEPT:
                if (this.serviceWaiter) this.serviceWaiter.resolve();
                return;
            case MSG.USERAUTH_BANNER: {
                const r = new Reader(p, 1);
                this.onBanner(r.text());
                return;
            }
            case MSG.USERAUTH_FAILURE: {
                const r = new Reader(p, 1);
                const methods = r.nameList();
                const partial = r.bool();
                if (this.authWaiter) this.authWaiter.resolve({ ok: false, methods, partial });
                return;
            }
            case MSG.USERAUTH_SUCCESS:
                if (this.authWaiter) this.authWaiter.resolve({ ok: true });
                return;
            case MSG.USERAUTH_PK_OK: // 60, shared with keyboard-interactive
                if (this.pkWaiter) {
                    this.pkWaiter.resolve(p);
                    return;
                }
                return this._onKeyboardInteractive(p);
            case MSG.GLOBAL_REQUEST: {
                const r = new Reader(p, 1);
                r.text();
                const wantReply = r.bool();
                if (wantReply) this.send(new Writer().byte(MSG.REQUEST_FAILURE).bytes());
                return;
            }
            case MSG.REQUEST_SUCCESS:
            case MSG.REQUEST_FAILURE:
                return;
            case MSG.CHANNEL_OPEN_CONFIRMATION: {
                const r = new Reader(p, 1);
                const localId = r.u32();
                const ch = this.channels.get(localId);
                const remoteId = r.u32();
                if (!ch) return;
                ch.remoteId = remoteId;
                ch.window = r.u32();
                ch.maxPacket = r.u32();
                ch.openWaiter.resolve(ch);
                return;
            }
            case MSG.CHANNEL_OPEN_FAILURE: {
                const r = new Reader(p, 1);
                const localId = r.u32();
                const code = r.u32();
                const desc = r.text();
                const ch = this.channels.get(localId);
                if (ch) {
                    ch.openWaiter.reject(new Error(`无法打开通道 (${code}): ${desc}`));
                    this.channels.delete(localId);
                }
                return;
            }
            case MSG.CHANNEL_WINDOW_ADJUST: {
                const r = new Reader(p, 1);
                const ch = this.channels.get(r.u32());
                const inc = r.u32();
                if (ch) {
                    ch.window += inc;
                    this._pumpWindow(ch);
                }
                return;
            }
            case MSG.CHANNEL_DATA: {
                const r = new Reader(p, 1);
                const ch = this.channels.get(r.u32());
                const data = r.str();
                if (!ch) return;
                // 注意：这里只维护「本地接收窗口」（localUsed）。ch.window 是
                // 对端允许我们发多少的发送额度，收到数据绝不能扣它 —— 否则下载
                // 累计到服务端初始窗口（OpenSSH 2MB）后，后续 writeChannelFlow 会死等。
                ch.localUsed += data.length;
                if (ch.localUsed >= WINDOW / 2) {
                    const inc = ch.localUsed;
                    ch.localUsed = 0;
                    const w = new Writer().byte(MSG.CHANNEL_WINDOW_ADJUST).u32(ch.remoteId).u32(inc);
                    this.send(w.bytes()).catch(() => {});
                }
                if (ch.handlers.onData) ch.handlers.onData(data, ch);
                return;
            }
            case MSG.CHANNEL_EXTENDED_DATA: {
                const r = new Reader(p, 1);
                const ch = this.channels.get(r.u32());
                r.u32();
                const data = r.str();
                if (ch && ch.handlers.onData) ch.handlers.onData(data, ch, true);
                return;
            }
            case MSG.CHANNEL_EOF: {
                const r = new Reader(p, 1);
                const ch = this.channels.get(r.u32());
                if (ch && ch.handlers.onEof) ch.handlers.onEof(ch);
                return;
            }
            case MSG.CHANNEL_CLOSE: {
                const r = new Reader(p, 1);
                const ch = this.channels.get(r.u32());
                if (!ch) return;
                ch.closed = true;
                this.send(new Writer().byte(MSG.CHANNEL_CLOSE).u32(ch.remoteId).bytes()).catch(() => {});
                if (ch.windowWaiters) {
                    for (const w of ch.windowWaiters.splice(0)) w.resolve();
                }
                if (ch.handlers.onClose) ch.handlers.onClose(ch);
                ch.done.resolve();
                this.channels.delete(ch.localId);
                return;
            }
            case MSG.CHANNEL_REQUEST: {
                const r = new Reader(p, 1);
                const ch = this.channels.get(r.u32());
                const req = r.text();
                const wantReply = r.bool();
                let code = null;
                if (req === 'exit-status') {
                    code = r.u32();
                    if (ch) ch.exitCode = code;
                    if (ch && ch.handlers.onExit) ch.handlers.onExit(code, ch);
                    if (ch && ch.isShell) this.onEvent({ type: 'exit-status', code });
                } else if (req === 'exit-signal') {
                    r.text();
                    r.text();
                }
                if (wantReply && ch) this.send(new Writer().byte(MSG.CHANNEL_FAILURE).u32(ch.remoteId).bytes()).catch(() => {});
                return;
            }
            case MSG.CHANNEL_SUCCESS:
            case MSG.CHANNEL_FAILURE: {
                const r = new Reader(p, 1);
                const ch = this.channels.get(r.u32());
                if (ch && ch.reqWaiter) ch.reqWaiter.resolve(type === MSG.CHANNEL_SUCCESS);
                return;
            }
            default:
                return;
        }
    }

    /* ================================================================== kex */

    async _onKexInit(p) {
        const r = new Reader(p, 1);
        r.p += 16; // cookie (raw 16 bytes, not length-prefixed)
        const kexAlgs = r.nameList();
        const hostKeyAlgs = r.nameList();
        const encC2S = r.nameList();
        const encS2C = r.nameList();
        const macC2S = r.nameList();
        const macS2C = r.nameList();
        r.nameList();
        r.nameList();
        r.nameList();
        r.nameList();
        r.bool();
        r.u32();

        this.iS = p;
        const kex = pick(KEX_ALGS, kexAlgs);
        const enc1 = pick(CIPHERS, encC2S);
        const enc2 = pick(CIPHERS, encS2C);
        const mac1 = pick(MACS, macC2S);
        const mac2 = pick(MACS, macS2C);
        const hostKeyAlg = pick(C.HOST_KEY_ALGS, hostKeyAlgs);
        if (!kex) throw new Error('没有共同支持的密钥交换算法: ' + kexAlgs.join(','));
        if (!enc1 || !enc2) throw new Error('没有共同支持的加密算法');
        if (!mac1 || !mac2) throw new Error('没有共同支持的 MAC 算法');
        if (!hostKeyAlg) throw new Error('没有共同支持的主机密钥算法');

        this.neg = { kex, encC2S: enc1, encS2C: enc2, macC2S: mac1, macS2C: mac2, hostKeyAlg };
        // Terrapin（CVE-2023-48795）：双方都通告 strict-kex 时，KEX 期间禁止注入
        // IGNORE/DEBUG/UNIMPLEMENTED，且 NEWKEYS 之后序号归零。只在首次 KEX 决定一次。
        if (this.strictDecided === undefined) {
            this.strictDecided = true;
            this.strictKex = kexAlgs.includes('kex-strict-s-v00@openssh.com');
        }
        this.kexActive = true;
        if (!this.kexInitSent) await this._sendKexInit();

        const kp = await C.curve25519Keypair();
        this.kex = { privateKey: kp.privateKey, publicKey: kp.publicKey };
        this.kexReply = deferred();
        const w = new Writer().byte(MSG.KEX_ECDH_INIT).str(kp.publicKey);
        await this.send(w.bytes());
        // resolve when KEX_ECDH_REPLY arrives (handled in _onKexReply)
    }

    async _onKexReply(p) {
        const r = new Reader(p, 1);
        const hostKeyBlob = r.str();
        const serverPub = r.str();
        const sigBlob = r.str();

        const shared = await C.curve25519Shared(this.kex.privateKey, serverPub);
        // RFC 8731 §3：共享密钥全零说明服务器用了低阶点，密钥协商已被降级（典型中间人）
        if (!shared.length || shared.every((b) => b === 0)) {
            throw new Error('密钥交换失败：X25519 共享密钥全零，已中止连接（可能是中间人攻击）');
        }
        const kMpint = new Writer().mpint(shared).bytes();
        const str = (b) => new Writer().str(b).bytes();
        const H = await C.sha256(
            concat(
                str(new TextEncoder().encode(this.clientVersion)),
                str(new TextEncoder().encode(this.serverVersion)),
                str(this.iC),
                str(this.iS),
                str(hostKeyBlob),
                str(this.kex.publicKey),
                str(serverPub),
                kMpint
            )
        );

        const sigResult = await C.verifyHostKeySignature(hostKeyBlob, sigBlob, H);
        // 签名对不上说明对面拿不出这把主机私钥（典型 MITM），无论用户怎么点都不该继续
        if (!sigResult.verified) {
            throw new Error(
                '主机密钥签名校验失败：' + (sigResult.reason || '无有效签名') + '，已中止连接（可能是中间人攻击）'
            );
        }
        // 协商了什么就必须用什么：签名算法若由服务器单方面决定，
        // 攻击者可以把 rsa-sha2-512 压回 ssh-rsa（SHA-1）而界面毫无异常
        if (sigResult.sigAlg && sigResult.sigAlg !== this.neg.hostKeyAlg) {
            throw new Error(
                '主机密钥签名算法与协商结果不一致（协商 ' +
                    this.neg.hostKeyAlg +
                    '，实际 ' +
                    sigResult.sigAlg +
                    '），已中止连接'
            );
        }
        const fp = await C.fingerprint(hostKeyBlob);
        const accepted = await this.onHostKey({
            type: sigResult.type,
            fingerprint: fp,
            keyBlob: hostKeyBlob,
            signatureValid: true,
            signatureError: null,
        });
        if (!accepted) throw new Error('主机密钥未被接受，连接已中止');

        if (!this.sessionId) this.sessionId = H;
        const n = this.neg;
        const keyLenC2S = CIPHER_KEYLEN[n.encC2S];
        const keyLenS2C = CIPHER_KEYLEN[n.encS2C];
        const ivC2S = await C.deriveKey(C.sha256, kMpint, H, 'A', this.sessionId, 16);
        const ivS2C = await C.deriveKey(C.sha256, kMpint, H, 'B', this.sessionId, 16);
        const keyC2S = await C.deriveKey(C.sha256, kMpint, H, 'C', this.sessionId, keyLenC2S);
        const keyS2C = await C.deriveKey(C.sha256, kMpint, H, 'D', this.sessionId, keyLenS2C);
        const macKeyC2S = await C.deriveKey(C.sha256, kMpint, H, 'E', this.sessionId, MAC_LEN[n.macC2S]);
        const macKeyS2C = await C.deriveKey(C.sha256, kMpint, H, 'F', this.sessionId, MAC_LEN[n.macS2C]);

        const encOut = await new C.CtrCipher(keyC2S, ivC2S).ready();
        const macOut = await new C.Mac(n.macC2S, macKeyC2S).ready();
        const encIn = await new C.CtrCipher(keyS2C, ivS2C).ready();
        const macIn = await new C.Mac(n.macS2C, macKeyS2C).ready();

        // outgoing keys take effect right after NEWKEYS is flushed
        await this.send(new Writer().byte(MSG.NEWKEYS).bytes(), { resetSeq: this.strictKex });
        this.encOut = encOut;
        this.macOut = macOut;
        this.blockOut = 16;
        this.macOutLen = macOut.len;
        this._pendingIn = { encIn, macIn };
        this.onEvent({ type: 'kex-done', hostKeyType: sigResult.type, fingerprint: fp });
    }

    _onNewKeys() {
        if (!this._pendingIn) throw new Error('unexpected NEWKEYS');
        this.encIn = this._pendingIn.encIn;
        this.macIn = this._pendingIn.macIn;
        this.blockIn = 16;
        this.macInLen = this.macIn.len;
        this._pendingIn = null;
        if (this.strictKex) this.seqIn = 0; // NEWKEYS 自身已用旧序号校验，之后归零
        this.kexActive = false;
        if (this.kexDone) this.kexDone.resolve();
        this.kexInitSent = false;
    }

    /* ================================================================= auth */

    async _requestService(name) {
        this.serviceWaiter = deferred();
        const w = new Writer().byte(MSG.SERVICE_REQUEST).str(name);
        await this.send(w.bytes());
        await this.serviceWaiter.promise;
        this.serviceWaiter = null;
    }

    async _authenticate() {
        await this._requestService('ssh-userauth');
        const auth = this.opts.auth || {};
        const user = this.opts.username;
        const service = 'ssh-connection';

        // probe supported methods with a "none" request
        const probe = await this._userauthRequest(user, service, 'none', null);
        if (probe.ok) return;
        let methods = probe.methods || [];
        const tried = new Set();

        const order = [];
        if (auth.privateKey) order.push('publickey');
        if (auth.password) order.push('password');
        order.push('keyboard-interactive');

        for (const method of order) {
            if (tried.has(method)) continue;
            if (methods.length && !methods.includes(method)) continue;
            tried.add(method);
            let res = null;
            if (method === 'publickey' && auth.privateKey) {
                res = await this._authPublicKey(user, service, auth);
            } else if (method === 'password' && auth.password) {
                res = await this._userauthRequest(user, service, 'password', (w) => {
                    w.bool(false).str(auth.password);
                });
            } else if (method === 'keyboard-interactive') {
                res = await this._authKeyboard(user, service);
            }
            if (!res) continue;
            if (res.ok) return;
            methods = res.methods || [];
        }
        throw new Error('认证失败，服务器支持的方式: ' + (methods.join(', ') || '未知'));
    }

    async _userauthRequest(user, service, method, extra) {
        this.authWaiter = deferred();
        const w = new Writer().byte(MSG.USERAUTH_REQUEST).str(user).str(service).str(method);
        if (extra) extra(w);
        const payload = w.bytes();
        await this.send(payload);
        const res = await this.authWaiter.promise;
        this.authWaiter = null;
        return res;
    }

    async _authKeyboard(user, service) {
        this.kbd = { user, service };
        const res = await this._userauthRequest(user, service, 'keyboard-interactive', (w) => {
            w.str('').str('');
        });
        return res;
    }

    async _onKeyboardInteractive(p) {
        const r = new Reader(p, 1);
        const name = r.text();
        const instruction = r.text();
        const lang = r.text();
        const count = r.u32();
        const prompts = [];
        for (let i = 0; i < count; i++) prompts.push({ prompt: r.text(), echo: r.bool() });
        const answers = await this.onKeyboardInteractive({ name, instruction, lang, prompts });
        const w = new Writer().byte(MSG.USERAUTH_INFO_RESPONSE).u32(answers ? answers.length : 0);
        if (answers) for (const a of answers) w.str(a);
        await this.send(w.bytes());
    }

    async _authPublicKey(user, service, auth) {
        const key = await loadPrivateKey(auth.privateKey);
        const blob = key.publicBlob;
        const alg = key.alg;
        // 1) query whether the key is acceptable
        this.pkWaiter = deferred();
        const probeW = new Writer()
            .byte(MSG.USERAUTH_REQUEST)
            .str(user)
            .str(service)
            .str('publickey')
            .bool(false)
            .str(alg)
            .str(blob);
        this.authWaiter = deferred();
        await this.send(probeW.bytes());
        const first = await Promise.race([
            this.authWaiter.promise,
            this.pkWaiter.promise.then(() => ({ pkOk: true })),
        ]);
        this.authWaiter = null;
        this.pkWaiter = null;
        if (first.ok) return first; // some servers accept straight away

        // 2) sign the request
        const data = new Writer()
            .str(this.sessionId)
            .byte(MSG.USERAUTH_REQUEST)
            .str(user)
            .str(service)
            .str('publickey')
            .bool(true)
            .str(alg)
            .str(blob)
            .bytes();
        const sig = await signUserauth(key, data);
        const sigBlob = new Writer().str(alg).str(sig).bytes();
        return this._userauthRequest(user, service, 'publickey', (w) => {
            w.bool(true).str(alg).str(blob).str(sigBlob);
        });
    }

    /* ============================================================== channel */

    async openChannel(handlers = {}) {
        const localId = this.nextLocalChannel++;
        const ch = {
            localId,
            remoteId: null,
            window: WINDOW,
            maxPacket: MAX_PACKET,
            localUsed: 0,
            closed: false,
            exitCode: null,
            handlers,
            openWaiter: deferred(),
            reqWaiter: null,
            windowWaiters: [],
            done: deferred(),
        };
        this.channels.set(localId, ch);
        const w = new Writer().byte(MSG.CHANNEL_OPEN).str('session').u32(localId).u32(WINDOW).u32(MAX_PACKET);
        await this.send(w.bytes());
        // 服务端不回 CONFIRMATION/FAILURE 时不能永远挂着：15 秒放弃并清理通道表
        let timer;
        try {
            return await Promise.race([
                ch.openWaiter.promise,
                new Promise((_, reject) => {
                    timer = setTimeout(() => reject(new Error('打开通道超时：服务器 15 秒内没有响应')), 15000);
                }),
            ]);
        } catch (e) {
            this.channels.delete(localId);
            throw e;
        } finally {
            clearTimeout(timer);
        }
    }

    async channelRequest(ch, type, wantReply, extra) {
        const w = new Writer().byte(MSG.CHANNEL_REQUEST).u32(ch.remoteId).str(type).bool(!!wantReply);
        if (extra) extra(w);
        if (wantReply) ch.reqWaiter = deferred();
        await this.send(w.bytes());
        if (!wantReply) return true;
        const res = await Promise.race([
            ch.reqWaiter.promise,
            new Promise((r) => setTimeout(() => r(true), 4000)),
        ]);
        ch.reqWaiter = null;
        return res;
    }

    writeChannel(ch, data) {
        if (!ch || ch.closed || this.closed) return;
        const u8 = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const max = Math.min(ch.maxPacket || MAX_PACKET, 16384);
        for (let i = 0; i < u8.length; i += max) {
            const chunk = u8.subarray(i, i + max);
            ch.window -= chunk.length;
            const w = new Writer().byte(MSG.CHANNEL_DATA).u32(ch.remoteId).str(chunk);
            this.send(w.bytes()).catch((e) => this._fail(e));
        }
    }

    _pumpWindow(ch) {
        if (!ch.windowWaiters) return;
        while (ch.windowWaiters.length && ch.window >= ch.windowWaiters[0].n) {
            ch.windowWaiters.shift().resolve();
        }
    }

    _waitWindow(ch, n, timeoutMs = 30000) {
        if (ch.closed || this.closed) return Promise.reject(new Error('通道已关闭'));
        if (ch.window >= n) return Promise.resolve();
        return new Promise((resolve, reject) => {
            let wrapped;
            const timer = setTimeout(() => {
                const i = ch.windowWaiters.findIndex((w) => w.resolve === wrapped);
                if (i >= 0) ch.windowWaiters.splice(i, 1);
                reject(new Error('等待对端窗口超时（连接可能已假死）'));
            }, timeoutMs);
            wrapped = () => {
                clearTimeout(timer);
                resolve();
            };
            ch.windowWaiters.push({ n, resolve: wrapped });
        });
    }

    /** write data respecting the remote window (needed for bulk transfers) */
    async writeChannelFlow(ch, data) {
        if (!ch || ch.closed || this.closed) throw new Error('通道已关闭');
        const u8 = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const max = Math.min(ch.maxPacket || MAX_PACKET, 16384);
        for (let i = 0; i < u8.length; i += max) {
            const chunk = u8.subarray(i, i + max);
            await this._waitWindow(ch, chunk.length);
            if (ch.closed || this.closed) throw new Error('通道已关闭');
            ch.window -= chunk.length;
            const w = new Writer().byte(MSG.CHANNEL_DATA).u32(ch.remoteId).str(chunk);
            await this.send(w.bytes());
        }
    }

    /** close a non-shell channel opened with openChannel() */
    closeChannel(ch) {
        if (!ch || ch.closed) return;
        ch.closed = true;
        this.send(new Writer().byte(MSG.CHANNEL_CLOSE).u32(ch.remoteId).bytes()).catch(() => {});
        if (ch.windowWaiters) for (const w of ch.windowWaiters.splice(0)) w.resolve();
        this.channels.delete(ch.localId);
    }

    async _openShell() {
        const ch = await this.openChannel({
            isShell: true,
            onData: (data) => this.onData(data),
            onEof: () => this.onEvent({ type: 'eof' }),
            onExit: (code) => {
                this.exitCode = code;
            },
            onClose: (c) => this.onEvent({ type: 'close', code: c.exitCode }),
        });
        ch.isShell = true;
        this.shell = ch;

        const cols = this.opts.cols || 80;
        const rows = this.opts.rows || 24;
        const term = this.opts.term || 'xterm-256color';
        await this.channelRequest(ch, 'pty-req', false, (w) => {
            w.str(term).u32(cols).u32(rows).u32(0).u32(0).str(new Uint8Array([0]));
        });
        await this.channelRequest(ch, 'env', false, (w) => {
            w.str('LANG').str('en_US.UTF-8');
        });
        const started = await this.channelRequest(ch, 'shell', true);
        if (started === false) throw new Error('服务器拒绝启动 shell');
        this.ready = true;
        this.onEvent({ type: 'ready' });
        this.readyDeferred.resolve();
    }

    /** run a one-shot command on a fresh channel and collect its output */
    async exec(command, timeoutMs = 8000) {
        const chunks = [];
        let total = 0;
        let exitCode = null;
        const ch = await this.openChannel({
            onData: (data) => {
                if (total < 512 * 1024) {
                    chunks.push(data.slice());
                    total += data.length;
                }
            },
            onExit: (code) => {
                exitCode = code;
            },
        });
        try {
            const ok = await this.channelRequest(ch, 'exec', true, (w) => {
                w.str(command);
            });
            if (ok === false) throw new Error('服务器拒绝执行命令');
            await Promise.race([ch.done.promise, new Promise((r) => setTimeout(r, timeoutMs))]);
        } finally {
            if (!ch.closed) {
                ch.closed = true;
                this.send(new Writer().byte(MSG.CHANNEL_CLOSE).u32(ch.remoteId).bytes()).catch(() => {});
                this.channels.delete(ch.localId);
            }
        }
        const buf = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) {
            buf.set(c, off);
            off += c.length;
        }
        return { stdout: new TextDecoder().decode(buf), code: exitCode };
    }

    write(data) {
        if (!this.ready || this.closed) return;
        const u8 = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        if (!u8.length) return;
        // 小块（按键、短命令）走「发了就不管」的快路径，不额外等一次微任务。
        if (u8.length <= 16384) {
            this.writeChannel(this.shell, u8);
            return;
        }
        // 大块（粘贴、cat 大文件）必须等对端窗口：writeChannel 会把整段数据一次性
        // 塞进管道并同步扣减 ch.window，超过剩余窗口时 OpenSSH 直接判
        // "channel window exceeded" 断开整条连接 —— 表现就是「一粘贴就掉线」。
        // 同时用一条链串行化，避免两个并发大写入各自看到足够的窗口、一起把额度透支。
        const run = () => this.writeChannelFlow(this.shell, u8);
        this.flowChain = this.flowChain.then(run, run).catch((e) => {
            // 通道已经正常关闭时不必再判连接失败，否则用户按 Ctrl+D 退出后会被报错
            if (!this.closed && this.shell && !this.shell.closed) this._fail(e);
        });
    }

    resize(cols, rows) {
        if (!this.shell || this.closed) return;
        this.channelRequest(this.shell, 'window-change', false, (w) => {
            w.u32(cols).u32(rows).u32(0).u32(0);
        }).catch(() => {});
    }

    keepalive() {
        if (this.closed) return;
        const w = new Writer().byte(MSG.GLOBAL_REQUEST).str('keepalive@openssh.com').bool(true);
        this.send(w.bytes()).catch(() => {});
    }

    async close(reason) {
        if (this.closed) return;
        this.closed = true;
        try {
            const w = new Writer().byte(MSG.DISCONNECT).u32(11).str(reason || 'byebye').str('');
            await this.send(w.bytes());
        } catch (_) {}
    }
}
