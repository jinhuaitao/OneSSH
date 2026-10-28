// Minimal SFTP v3 client (draft-ietf-secsh-filexfer-02) over an SSH session channel.
import { Reader, Writer, concat, bytesToHex } from './buf.js';

const T = {
    INIT: 1,
    VERSION: 2,
    OPEN: 3,
    CLOSE: 4,
    READ: 5,
    WRITE: 6,
    LSTAT: 7,
    FSTAT: 8,
    FSETSTAT: 10,
    OPENDIR: 11,
    READDIR: 12,
    REMOVE: 13,
    MKDIR: 14,
    RMDIR: 15,
    REALPATH: 16,
    STAT: 17,
    RENAME: 18,
    EXTENDED: 200,
    STATUS: 101,
    HANDLE: 102,
    DATA: 103,
    NAME: 104,
    ATTRS: 105,
};

const S = {
    OK: 0,
    EOF: 1,
    NO_SUCH_FILE: 2,
    PERMISSION_DENIED: 3,
    FAILURE: 4,
    BAD_MESSAGE: 5,
    NO_CONNECTION: 6,
    CONNECTION_LOST: 7,
    OP_UNSUPPORTED: 8,
};

export const OPEN = { READ: 0x01, WRITE: 0x02, APPEND: 0x04, CREAT: 0x08, TRUNC: 0x10, EXCL: 0x20 };

// OpenSSH 的「原子覆盖改名」扩展；普通 RENAME 在 v3 里不允许覆盖已存在的目标
const POSIX_RENAME = 'posix-rename@openssh.com';

/** 同目录下的隐藏临时文件名：跨目录 rename 会 EXDEV，所以目录必须和原文件一致 */
export function tempName(path, tag) {
    const slash = path.lastIndexOf('/');
    const dir = slash > 0 ? path.slice(0, slash) : slash === 0 ? '' : '.';
    const base = path.slice(slash + 1);
    return dir + '/.' + base + '.' + tag + '-' + bytesToHex(crypto.getRandomValues(new Uint8Array(3)));
}

const STATUS_TEXT = {
    2: '文件或目录不存在',
    3: '没有权限',
    4: '服务器拒绝了该操作',
    5: 'SFTP 报文错误',
    8: '服务器不支持该操作',
};

export class SFTPError extends Error {
    constructor(code, message) {
        super(STATUS_TEXT[code] ? STATUS_TEXT[code] + (message ? '：' + message : '') : message || 'SFTP 错误 (' + code + ')');
        this.code = code;
    }
}

export function b64encode(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) {
        s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    }
    return btoa(s);
}

export function b64decode(str) {
    const bin = atob(String(str || ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

export function isDirMode(mode) {
    return ((mode || 0) & 0o170000) === 0o040000;
}

export function isLinkMode(mode) {
    return ((mode || 0) & 0o170000) === 0o120000;
}

export function modeString(perms) {
    if (perms == null) return '';
    let s = '';
    for (const shift of [6, 3, 0]) {
        const b = (perms >> shift) & 7;
        s += b & 4 ? 'r' : '-';
        s += b & 2 ? 'w' : '-';
        s += b & 1 ? 'x' : '-';
    }
    return s;
}

function readAttrs(r) {
    const flags = r.u32();
    const a = {};
    if (flags & 1) a.size = r.u64();
    if (flags & 2) {
        a.uid = r.u32();
        a.gid = r.u32();
    }
    if (flags & 4) a.perms = r.u32();
    if (flags & 8) {
        a.atime = r.u32();
        a.mtime = r.u32();
    }
    if (flags & 0x80000000) {
        const n = r.u32();
        for (let i = 0; i < n; i++) {
            r.str();
            r.str();
        }
    }
    return a;
}

function readNames(r, limit) {
    const count = r.u32();
    const out = [];
    for (let i = 0; i < count && out.length < limit; i++) {
        out.push({ name: r.text(), longname: r.text(), attrs: readAttrs(r) });
    }
    return out;
}

export class SFTPClient {
    constructor(client) {
        this.client = client;
        this.ch = null;
        this.nextId = 1;
        this.pending = new Map();
        this.buf = new Uint8Array(0);
        this.closed = false;
        this.version = null;
        this.extensions = new Map();
        this.readyPromise = null;
    }

    ready() {
        if (!this.readyPromise) this.readyPromise = this._open();
        return this.readyPromise;
    }

    async _open() {
        // the waiter must exist before the subsystem request: servers may send
        // their VERSION as soon as they accept it, before channelRequest resolves
        const versionWaiter = {};
        versionWaiter.promise = new Promise((resolve, reject) => {
            versionWaiter.resolve = resolve;
            versionWaiter.reject = reject;
        });
        versionWaiter.promise.catch(() => {}); // 失败路径可能没人 await，避免 unhandled rejection
        const ch = await this.client.openChannel({
            onData: (data) => this._feed(data),
            onClose: () => this._abortAll(new Error('SFTP 通道已关闭')),
        });
        this.ch = ch;
        this._versionWaiter = versionWaiter;
        let timer = null;
        try {
            const ok = await this.client.channelRequest(ch, 'subsystem', true, (w) => w.str('sftp'));
            if (ok === false) throw new Error('服务器拒绝启动 SFTP 子系统（可能未启用 sftp-server）');

            timer = setTimeout(() => versionWaiter.reject(new Error('SFTP 握手超时')), 15000);
            // INIT has no request id: byte type + uint32 version
            await this._frame(T.INIT, null, (w) => w.u32(3));
            this.version = await versionWaiter.promise;
            if (this.version < 3) throw new Error('服务器只支持 SFTP v' + this.version + '，需要 v3 及以上');
            return this;
        } catch (e) {
            // 握手失败必须把通道关掉，否则每重试一次就漏一条 SSH 通道
            this._abortAll(e);
            try {
                this.client.closeChannel(ch);
            } catch (_) {}
            throw e;
        } finally {
            if (timer) clearTimeout(timer);
            this._versionWaiter = null;
        }
    }

    _frame(type, id, fill) {
        const body = new Writer().byte(type);
        if (id !== null) body.u32(id);
        if (fill) fill(body);
        const payload = body.bytes();
        const out = new Uint8Array(4 + payload.length);
        new DataView(out.buffer).setUint32(0, payload.length);
        out.set(payload, 4);
        return this.client.writeChannelFlow(this.ch, out);
    }

    _request(type, fill, timeoutMs, label) {
        const id = this.nextId++;
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(id);
                reject(new Error((label || 'SFTP 请求') + '超时'));
            }, timeoutMs || 30000);
            this.pending.set(id, { resolve, reject, timer });
            this._frame(type, id, fill).catch((e) => {
                this.pending.delete(id);
                clearTimeout(timer);
                reject(e);
            });
        });
    }

    _feed(data) {
        if (this.closed) return;
        this.buf = this.buf.length ? concat(this.buf, data) : data;
        for (;;) {
            if (this.buf.length < 4) return;
            const len = new DataView(this.buf.buffer, this.buf.byteOffset, 4).getUint32(0);
            if (len < 5 || len > 1024 * 1024) {
                this._abortAll(new Error('SFTP 报文长度异常: ' + len));
                return;
            }
            if (this.buf.length < 4 + len) return;
            const pkt = this.buf.subarray(4, 4 + len);
            this.buf = this.buf.subarray(4 + len);
            this._packet(pkt);
        }
    }

    _packet(pkt) {
        const r = new Reader(pkt);
        const type = r.byte();
        if (type === T.VERSION) {
            const v = r.u32();
            // VERSION 后面跟着成对的 extension_name / extension_data，能力判断靠它
            try {
                while (r.left >= 8) {
                    const name = r.text();
                    const data = r.text();
                    this.extensions.set(name, data);
                }
            } catch (_) {}
            if (this._versionWaiter) this._versionWaiter.resolve(v);
            return;
        }
        const id = r.u32();
        const p = this.pending.get(id);
        if (!p) return;
        this.pending.delete(id);
        clearTimeout(p.timer);
        if (type === T.STATUS) {
            const code = r.u32();
            const message = r.text();
            if (code === S.OK) p.resolve({ type, code });
            else if (code === S.EOF) p.resolve({ type, code, eof: true });
            else p.reject(new SFTPError(code, message));
            return;
        }
        if (type === T.HANDLE) return p.resolve({ type, handle: r.str() });
        if (type === T.DATA) return p.resolve({ type, data: r.str() });
        if (type === T.NAME) return p.resolve({ type, entries: readNames(r, 10000) });
        if (type === T.ATTRS) return p.resolve({ type, attrs: readAttrs(r) });
        p.reject(new Error('未知的 SFTP 响应类型: ' + type));
    }

    _abortAll(err) {
        this.closed = true;
        for (const p of this.pending.values()) {
            clearTimeout(p.timer);
            p.reject(err);
        }
        this.pending.clear();
        if (this._versionWaiter) this._versionWaiter.reject(err);
    }

    /* ------------------------------------------------------------ requests */

    async realpath(path) {
        const res = await this._request(T.REALPATH, (w) => w.str(path), 15000, '解析路径');
        if (!res.entries || !res.entries.length) throw new Error('服务器没有返回真实路径');
        return res.entries[0].name;
    }

    async list(path) {
        const open = await this._request(T.OPENDIR, (w) => w.str(path), 15000, '打开目录');
        const entries = [];
        try {
            for (let i = 0; i < 500; i++) {
                const res = await this._request(T.READDIR, (w) => w.str(open.handle), 20000, '读取目录');
                if (res.eof) break;
                for (const e of res.entries || []) {
                    if (e.name === '.' || e.name === '..') continue;
                    entries.push(e);
                }
                if (entries.length >= 10000) break;
            }
        } finally {
            await this._closeHandleQuiet(open.handle);
        }
        return entries;
    }

    async stat(path, followLink = true) {
        const res = await this._request(followLink ? T.STAT : T.LSTAT, (w) => w.str(path), 15000, '读取属性');
        return res.attrs || {};
    }

    async mkdir(path) {
        await this._request(
            T.MKDIR,
            (w) => {
                w.str(path);
                w.u32(0); // no attrs: server defaults + umask
            },
            15000,
            '新建目录'
        );
    }

    async remove(path) {
        await this._request(T.REMOVE, (w) => w.str(path), 15000, '删除文件');
    }

    async rmdir(path) {
        await this._request(T.RMDIR, (w) => w.str(path), 15000, '删除目录');
    }

    async rename(from, to) {
        await this._request(
            T.RENAME,
            (w) => {
                w.str(from);
                w.str(to);
            },
            20000,
            '重命名'
        );
    }

    supports(name) {
        return this.extensions.has(name);
    }

    /** SSH_FXP_EXTENDED：服务器在 VERSION 里声明过的扩展才发，响应同样是 STATUS */
    async _extended(name, args, label) {
        await this._request(
            T.EXTENDED,
            (w) => {
                w.str(name);
                for (const a of args) w.str(a);
            },
            20000,
            label
        );
    }

    /**
     * 覆盖式改名，给「原子保存」用。
     * draft-ietf-secsh-filexfer-02 明确规定目标已存在时 RENAME 必须报错，只有 OpenSSH
     * 按 POSIX 语义覆盖；所以不能直接 rename(tmp, path)，否则合规的服务器（dropbear、
     * 各类 NAS / 嵌入式 sshd）一律回 SSH_FX_FAILURE，保存就变成「服务器拒绝了该操作：Failure」。
     */
    async renameOverwrite(from, to) {
        if (this.supports(POSIX_RENAME)) {
            try {
                await this._extended(POSIX_RENAME, [from, to], '覆盖重命名');
                return;
            } catch (e) {
                if (!(e instanceof SFTPError) || e.code !== S.OP_UNSUPPORTED) throw e;
            }
        }
        try {
            await this.rename(from, to);
            return;
        } catch (e) {
            // 目标已存在时合规服务器就是回 FAILURE；别的失败（跨设备、权限）照旧抛出
            if (!(e instanceof SFTPError) || e.code !== S.FAILURE) throw e;
        }
        const backup = tempName(to, 'webssh-bak');
        try {
            await this.rename(to, backup);
        } catch (e) {
            throw new Error('目标已存在，服务器不支持覆盖重命名，备份旧文件也失败：' + e.message);
        }
        try {
            await this.rename(from, to);
        } catch (e) {
            try {
                await this.rename(backup, to);
            } catch (_) {
                throw new Error('目标已存在，服务器不支持覆盖重命名，换名失败：' + e.message + '；旧文件保留在 ' + backup);
            }
            throw new Error('目标已存在，服务器不支持覆盖重命名，换名失败：' + e.message + '（旧文件已还原）');
        }
        await this.remove(backup).catch(() => {});
    }

    async open(path, pflags) {
        const res = await this._request(
            T.OPEN,
            (w) => {
                w.str(path);
                w.u32(pflags);
                w.u32(0); // attrs
            },
            20000,
            '打开文件'
        );
        if (!res.handle) throw new Error('服务器没有返回文件句柄');
        return res.handle;
    }

    async close(handle) {
        await this._request(T.CLOSE, (w) => w.str(handle), 15000, '关闭文件');
    }

    /** 按句柄改权限位（原子保存后还原原文件 mode 用） */
    async fchmod(handle, mode) {
        await this._request(
            T.FSETSTAT,
            (w) => {
                w.str(handle);
                w.u32(4); // SSH_FILEXFER_ATTR_PERMISSIONS
                w.u32(mode >>> 0);
            },
            15000,
            '设置文件权限'
        );
    }

    async _closeHandleQuiet(handle) {
        try {
            await this.close(handle);
        } catch (_) {}
    }

    async read(handle, offset, len) {
        const res = await this._request(
            T.READ,
            (w) => {
                w.str(handle);
                w.u64(offset);
                w.u32(len);
            },
            60000,
            '读取文件'
        );
        if (res.eof) return { eof: true };
        return { data: res.data || new Uint8Array(0) };
    }

    async write(handle, offset, data) {
        await this._request(
            T.WRITE,
            (w) => {
                w.str(handle);
                w.u64(offset);
                w.str(data);
            },
            60000,
            '写入文件'
        );
    }

    closeChannel() {
        if (this.ch && !this.ch.closed) {
            try {
                this.client.closeChannel(this.ch);
            } catch (_) {}
        }
        this._abortAll(new Error('SFTP 会话已结束'));
    }
}
