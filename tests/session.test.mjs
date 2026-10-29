import test from 'node:test';
import assert from 'node:assert/strict';

import { Terminal, knownKey } from '../src/session.js';
import { makeEnv } from './helpers.mjs';

/** 收集 Terminal 发给浏览器的 JSON 消息 */
class FakeWs {
    constructor() {
        this.sent = [];
        this.closed = false;
    }
    send(data) {
        if (typeof data === 'string') {
            try {
                this.sent.push(JSON.parse(data));
            } catch (_) {
                this.sent.push({ raw: data });
            }
        } else {
            this.sent.push({ binary: data });
        }
    }
    close() {
        this.closed = true;
    }
}

function makeSftp(opts) {
    const o = opts || {};
    const calls = [];
    return {
        calls,
        async open(path, flags) {
            calls.push(['open', path, flags]);
            if (o.openError) throw new Error(o.openError);
            return 'H1';
        },
        async close(h) {
            calls.push(['close', h]);
        },
        async fchmod(h, mode) {
            calls.push(['fchmod', h, mode]);
        },
        async stat(path) {
            calls.push(['stat', path]);
            if (o.statMissing) throw new Error('no such file');
            return { perms: o.perms == null ? 0o100600 : o.perms, size: 12 };
        },
        async renameOverwrite(from, to) {
            calls.push(['renameOverwrite', from, to]);
            if (o.renameError) throw new Error(o.renameError);
        },
        async remove(path) {
            calls.push(['remove', path]);
        },
        async write(h, offset, data) {
            calls.push(['write', offset, data.length]);
        },
        async list() {
            return [];
        },
        async realpath(p) {
            return p;
        },
    };
}

function makeTerm(sftp) {
    const ws = new FakeWs();
    const term = new Terminal(ws, makeEnv(), 'admin', null, null);
    term.sftp = sftp;
    term.client = { ready: true, closed: false };
    return { ws, term };
}

const tick = () => new Promise((r) => setTimeout(r, 15));

async function call(term, ws, payload) {
    term.handleMessage(JSON.stringify(Object.assign({ t: 'sftp', id: 'q1' }, payload)));
    await tick();
    const reply = ws.sent.filter((m) => m.t === 'sftp').pop();
    assert.ok(reply, '没有收到 sftp 回包');
    return reply;
}

test('knownKey：IPv6 与端口都进 key，且不含路径分隔符', () => {
    assert.equal(knownKey('192.0.2.10', 22), 'known/192.0.2.10_22');
    assert.equal(knownKey('[2001:db8::1]', 2222), 'known/[2001:db8::1]_2222');
    assert.equal(knownKey('EXAMPLE.com', 22), 'known/example.com_22');
    assert.equal(knownKey('a/b', 22), 'known/a_b_22', '斜杠必须被替换，否则会写到别的目录');
});

test('原子上传：open-upload 建同目录临时文件并返回句柄', async () => {
    const sftp = makeSftp();
    const { ws, term } = makeTerm(sftp);
    const reply = await call(term, ws, { op: 'open-upload', path: '/etc/nginx/nginx.conf' });

    assert.equal(reply.ok, true);
    assert.equal(reply.handle, 'h1');
    assert.match(reply.tmp, /^\/etc\/nginx\/\.nginx\.conf\.webssh-upload-[0-9a-f]{6}$/);
    const open = sftp.calls.find((c) => c[0] === 'open');
    assert.equal(open[1], reply.tmp, '必须先写临时文件，而不是直接开目标文件');
});

test('原子上传：commit 先还原权限位再覆盖改名', async () => {
    const sftp = makeSftp({ perms: 0o100600 });
    const { ws, term } = makeTerm(sftp);
    const opened = await call(term, ws, { op: 'open-upload', path: '/root/.ssh/authorized_keys' });
    sftp.calls.length = 0;

    const reply = await call(term, ws, { op: 'commit-upload', handle: opened.handle, tmp: opened.tmp, path: '/root/.ssh/authorized_keys' });
    assert.equal(reply.ok, true);
    assert.deepEqual(
        sftp.calls.map((c) => c[0]),
        ['stat', 'fchmod', 'close', 'renameOverwrite'],
        '顺序：读原权限 → 套到临时文件 → 关句柄 → 覆盖改名'
    );
    assert.equal(sftp.calls[1][2], 0o600, '0600 的密钥上传后不能变成 0644');
    assert.deepEqual(sftp.calls[3].slice(1), [opened.tmp, '/root/.ssh/authorized_keys']);
});

test('原子上传：改名失败时清掉临时文件并保留原文件', async () => {
    const sftp = makeSftp({ renameError: '磁盘已满' });
    const { ws, term } = makeTerm(sftp);
    const opened = await call(term, ws, { op: 'open-upload', path: '/tmp/app.conf' });
    sftp.calls.length = 0;

    const reply = await call(term, ws, { op: 'commit-upload', handle: opened.handle, tmp: opened.tmp, path: '/tmp/app.conf' });
    assert.equal(reply.ok, false);
    assert.match(reply.error, /原文件未受影响/);
    assert.ok(sftp.calls.some((c) => c[0] === 'remove' && c[1] === opened.tmp), '临时文件必须被清理');
});

test('原子上传：句柄失效时给出可读错误', async () => {
    const sftp = makeSftp();
    const { ws, term } = makeTerm(sftp);
    const reply = await call(term, ws, { op: 'commit-upload', handle: 'nope', tmp: '/tmp/.x', path: '/tmp/x' });
    assert.equal(reply.ok, false);
    assert.match(reply.error, /句柄无效/);
});

test('SFTP 路径校验：空字节与超长路径被拒', async () => {
    const sftp = makeSftp();
    const { ws, term } = makeTerm(sftp);
    let reply = await call(term, ws, { op: 'list', path: '/tmp/\u0000evil' });
    assert.equal(reply.ok, false);
    assert.match(reply.error, /路径不合法/);

    reply = await call(term, ws, { op: 'list', path: '/' + 'a'.repeat(5000) });
    assert.equal(reply.ok, false);
    assert.match(reply.error, /路径不合法/);
});

test('SFTP 未知操作返回错误而不是挂住', async () => {
    const sftp = makeSftp();
    const { ws, term } = makeTerm(sftp);
    const reply = await call(term, ws, { op: 'rm-rf-everything', path: '/' });
    assert.equal(reply.ok, false);
    assert.match(reply.error, /未知的文件操作/);
});

test('清理：关闭会话时释放所有文件句柄', async () => {
    const sftp = makeSftp();
    const { ws, term } = makeTerm(sftp);
    const opened = await call(term, ws, { op: 'open-upload', path: '/tmp/a' });
    assert.equal(opened.ok, true);
    sftp.calls.length = 0;

    await term.cleanup('test');
    assert.ok(sftp.calls.some((c) => c[0] === 'close'), '句柄必须被关掉，否则远端 fd 泄漏');
    assert.equal(term.closed, true);
});
