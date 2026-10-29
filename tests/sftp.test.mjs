import test from 'node:test';
import assert from 'node:assert/strict';

import { Reader, Writer } from '../src/ssh/buf.js';
import { SFTPClient, OPEN, SFTPError, modeString, isDirMode, isLinkMode, tempName, b64encode, b64decode } from '../src/ssh/sftp.js';

/* --------------------------------------------------------------- 报文构造 */

const T = { INIT: 1, VERSION: 2, CLOSE: 4, READ: 5, WRITE: 6, FSTAT: 8, OPENDIR: 11, READDIR: 12, REMOVE: 13, MKDIR: 14, RMDIR: 15, REALPATH: 16, STAT: 17, RENAME: 18, EXTENDED: 200, STATUS: 101, HANDLE: 102, DATA: 103, NAME: 104, ATTRS: 105 };
const S = { OK: 0, EOF: 1, NO_SUCH_FILE: 2, FAILURE: 4, OP_UNSUPPORTED: 8 };

function frame(type, id, fill) {
    const w = new Writer().byte(type);
    if (id !== null && id !== undefined) w.u32(id);
    if (fill) fill(w);
    const payload = w.bytes();
    const out = new Uint8Array(4 + payload.length);
    new DataView(out.buffer).setUint32(0, payload.length);
    out.set(payload, 4);
    return out;
}

const status = (id, code, msg) => frame(T.STATUS, id, (w) => w.u32(code).str(msg || '').str(''));
const handle = (id, h) => frame(T.HANDLE, id, (w) => w.str(h));
const data = (id, d) => frame(T.DATA, id, (w) => w.str(d));

function attrs(w, a) {
    let flags = 0;
    if (a.size != null) flags |= 1;
    if (a.uid != null) flags |= 2;
    if (a.perms != null) flags |= 4;
    if (a.mtime != null) flags |= 8;
    w.u32(flags);
    if (flags & 1) w.u64(a.size);
    if (flags & 2) w.u32(a.uid).u32(a.gid || 0);
    if (flags & 4) w.u32(a.perms);
    if (flags & 8) w.u32(a.atime || a.mtime).u32(a.mtime);
}

const namePacket = (id, entries) =>
    frame(T.NAME, id, (w) => {
        w.u32(entries.length);
        for (const e of entries) {
            w.str(e.name).str(e.longname || e.name);
            attrs(w, e.attrs || {});
        }
    });

const attrsPacket = (id, a) => frame(T.ATTRS, id, (w) => attrs(w, a));

/** 假 SSH 会话：只实现 SFTPClient 用到的那几个方法，并按脚本回应。 */
class FakeSSH {
    constructor(responder) {
        this.responder = responder;
        this.ch = { remoteId: 42, closed: false };
        this.requests = [];
        this.handlers = null;
    }
    openChannel(handlers) {
        this.handlers = handlers;
        return Promise.resolve(this.ch);
    }
    channelRequest(ch, type) {
        this.requests.push({ type: 'req:' + type });
        return Promise.resolve(true);
    }
    closeChannel() {
        this.ch.closed = true;
    }
    writeChannelFlow(ch, bytes) {
        const len = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0);
        const p = bytes.subarray(4, 4 + len);
        const type = p[0];
        const id = type === T.INIT ? null : new DataView(p.buffer, p.byteOffset + 1, 4).getUint32(0);
        const req = { type, id, payload: p };
        this.requests.push(req);
        const resp = this.responder(req, this);
        if (resp) queueMicrotask(() => this.handlers.onData(resp));
        return Promise.resolve();
    }
    /** 记录下来的请求类型序列，便于断言「先备份再换名」这类顺序 */
    types() {
        return this.requests.map((r) => r.type);
    }
    strs(req, skip) {
        const r = new Reader(req.payload, 1 + 4 + (skip || 0));
        const out = [];
        while (r.left >= 4) {
            try {
                out.push(r.text());
            } catch (_) {
                break;
            }
        }
        return out;
    }
}

const withExtensions = (req, self) => {
    if (req.type === T.INIT) {
        return frame(T.VERSION, null, (w) => {
            w.u32(3);
            w.str('posix-rename@openssh.com').str('1');
            w.str('statvfs@openssh.com').str('2');
        });
    }
    return null;
};

/* ------------------------------------------------------------------ 用例 */

test('握手：解析 VERSION 与扩展能力', async () => {
    const ssh = new FakeSSH(withExtensions);
    const sftp = new SFTPClient(ssh);
    await sftp.ready();
    assert.equal(sftp.version, 3);
    assert.equal(sftp.supports('posix-rename@openssh.com'), true);
    assert.equal(sftp.supports('nope@example.com'), false);
    assert.ok(ssh.types().includes('req:subsystem'), '必须先申请 sftp 子系统');
});

test('握手：服务器只支持 v2 时明确报错并关掉通道', async () => {
    const ssh = new FakeSSH((req) => (req.type === T.INIT ? frame(T.VERSION, null, (w) => w.u32(2)) : null));
    const sftp = new SFTPClient(ssh);
    await assert.rejects(() => sftp.ready(), /v3/);
    assert.equal(ssh.ch.closed, true, '握手失败必须回收通道，否则每重试一次漏一条');
});

test('list：跳过 . 与 ..，带出 size / 权限 / 时间', async () => {
    let readdirs = 0;
    const ssh = new FakeSSH((req) => {
        switch (req.type) {
            case T.INIT:
                return withExtensions(req, ssh);
            case T.OPENDIR:
                return handle(req.id, 'h-dir');
            case T.READDIR:
                readdirs++;
                if (readdirs === 1) {
                    return namePacket(req.id, [
                        { name: '.', attrs: { perms: 0o040755 } },
                        { name: '..', attrs: { perms: 0o040755 } },
                        { name: 'a.txt', attrs: { size: 10, perms: 0o100644, mtime: 1700000000 } },
                        { name: 'sub', attrs: { perms: 0o040755 } },
                    ]);
                }
                return status(req.id, S.EOF);
            case T.CLOSE:
                return status(req.id, S.OK);
            default:
                return null;
        }
    });
    const sftp = new SFTPClient(ssh);
    await sftp.ready();
    const entries = await sftp.list('/tmp');
    assert.deepEqual(entries.map((e) => e.name), ['a.txt', 'sub']);
    assert.equal(entries[0].attrs.size, 10);
    assert.equal(entries[0].attrs.mtime, 1700000000);
    assert.equal(isDirMode(entries[1].attrs.perms), true);
    assert.equal(isDirMode(entries[0].attrs.perms), false);
});

test('stat：属性按位解析', async () => {
    const ssh = new FakeSSH((req) => {
        if (req.type === T.INIT) return withExtensions(req, ssh);
        if (req.type === T.STAT) return attrsPacket(req.id, { size: 12345, uid: 1000, gid: 1000, perms: 0o100600, mtime: 1700000123 });
        return null;
    });
    const sftp = new SFTPClient(ssh);
    await sftp.ready();
    const st = await sftp.stat('/root/.ssh/id_ed25519');
    assert.equal(st.size, 12345);
    assert.equal(st.perms, 0o100600);
    assert.equal(st.mtime, 1700000123);
});

test('read：DATA 后遇到 EOF 停止', async () => {
    let reads = 0;
    const ssh = new FakeSSH((req) => {
        if (req.type === T.INIT) return withExtensions(req, ssh);
        if (req.type === 3) return handle(req.id, 'h-file');
        if (req.type === T.READ) {
            reads++;
            return reads === 1 ? data(req.id, new Uint8Array([1, 2, 3])) : status(req.id, S.EOF);
        }
        return null;
    });
    const sftp = new SFTPClient(ssh);
    await sftp.ready();
    const h = await sftp.open('/etc/hostname', OPEN.READ);
    const first = await sftp.read(h, 0, 128);
    assert.deepEqual([...first.data], [1, 2, 3]);
    const second = await sftp.read(h, 3, 128);
    assert.equal(second.eof, true);
});

test('错误映射：SFTP 状态码翻译成中文并保留 code', async () => {
    const ssh = new FakeSSH((req) => {
        if (req.type === T.INIT) return withExtensions(req, ssh);
        if (req.type === T.STAT) return status(req.id, S.NO_SUCH_FILE, 'No such file');
        return null;
    });
    const sftp = new SFTPClient(ssh);
    await sftp.ready();
    await assert.rejects(
        () => sftp.stat('/nope'),
        (e) => {
            assert.ok(e instanceof SFTPError);
            assert.equal(e.code, S.NO_SUCH_FILE);
            assert.match(e.message, /文件或目录不存在/);
            return true;
        }
    );
});

test('renameOverwrite：服务器声明了 posix-rename 就直接用扩展', async () => {
    const ssh = new FakeSSH((req) => {
        if (req.type === T.INIT) return withExtensions(req, ssh);
        if (req.type === T.EXTENDED) return status(req.id, S.OK);
        return null;
    });
    const sftp = new SFTPClient(ssh);
    await sftp.ready();
    await sftp.renameOverwrite('/tmp/.x', '/tmp/x');
    const ext = ssh.requests.find((r) => r.type === T.EXTENDED);
    assert.ok(ext);
    assert.deepEqual(ssh.strs(ext), ['posix-rename@openssh.com', '/tmp/.x', '/tmp/x']);
    assert.equal(ssh.types().includes(T.RENAME), false, '不该再走普通 RENAME');
});

test('renameOverwrite：没有扩展时退化成「备份 → 换名 → 删备份」', async () => {
    let renames = 0;
    const ssh = new FakeSSH((req) => {
        if (req.type === T.INIT) return frame(T.VERSION, null, (w) => w.u32(3)); // 不声明任何扩展
        if (req.type === T.RENAME) {
            renames++;
            // 第一次是 tmp → 目标，按 v3 规范目标已存在就报 FAILURE
            return status(req.id, renames === 1 ? S.FAILURE : S.OK);
        }
        if (req.type === T.REMOVE) return status(req.id, S.OK);
        return null;
    });
    const sftp = new SFTPClient(ssh);
    await sftp.ready();
    await sftp.renameOverwrite('/tmp/.x', '/tmp/x');

    const order = ssh.requests.filter((r) => r.type === T.RENAME || r.type === T.REMOVE);
    assert.deepEqual(order.map((r) => r.type), [T.RENAME, T.RENAME, T.RENAME, T.REMOVE]);

    const backupName = ssh.strs(order[1])[1];
    assert.match(backupName, /^\/tmp\/\.x\.webssh-bak-/, '备份文件必须落在同目录（跨目录 rename 会 EXDEV）');
    assert.deepEqual(ssh.strs(order[2]), ['/tmp/.x', '/tmp/x']);
});

test('renameOverwrite：posix-rename 返回 OP_UNSUPPORTED 时继续降级', async () => {
    let renames = 0;
    const ssh = new FakeSSH((req) => {
        if (req.type === T.INIT) return withExtensions(req, ssh);
        if (req.type === T.EXTENDED) return status(req.id, S.OP_UNSUPPORTED);
        if (req.type === T.RENAME) {
            renames++;
            return status(req.id, renames === 1 ? S.FAILURE : S.OK);
        }
        if (req.type === T.REMOVE) return status(req.id, S.OK);
        return null;
    });
    const sftp = new SFTPClient(ssh);
    await sftp.ready();
    await sftp.renameOverwrite('/a/.x', '/a/x');
    assert.equal(ssh.types().filter((t) => t === T.RENAME).length, 3);
});

/* ---------------------------------------------------------------- 小工具 */

test('modeString / tempName', () => {
    assert.equal(modeString(0o100644), 'rw-r--r--');
    assert.equal(modeString(0o040755), 'rwxr-xr-x');
    assert.equal(modeString(null), '');
    assert.equal(isLinkMode(0o120777), true);
    assert.equal(isLinkMode(0o100777), false);

    const t = tempName('/var/log/app.log', 'webssh');
    assert.match(t, /^\/var\/log\/\.app\.log\.webssh-[0-9a-f]{6}$/);
    assert.equal(tempName('/app.log', 'webssh').startsWith('/.app.log.webssh-'), true);
    assert.equal(tempName('app.log', 'webssh').startsWith('./.app.log.webssh-'), true);
    assert.notEqual(tempName('/a/b', 'webssh'), tempName('/a/b', 'webssh'), '临时名必须随机');
});

test('b64 往返：跨 32KB 分片不出错', () => {
    const big = new Uint8Array(100000);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
    const round = b64decode(b64encode(big));
    assert.equal(round.length, big.length);
    assert.deepEqual(round.subarray(0, 4), big.subarray(0, 4));
});
