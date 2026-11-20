/* File manager: browse, transfer and edit remote files over the session's SFTP channel. */
import { el, icon, toast, modal, confirmModal, fmtBytes, fmtDate, esc } from './ui.js';

const READ_CHUNK = 128 * 1024;
const WRITE_CHUNK = 64 * 1024;
const MAX_FILE = 64 * 1024 * 1024;

function joinPath(dir, name) {
    const base = String(dir || '/').replace(/\/+$/, '');
    return (base || '') + '/' + name;
}

function parentPath(p) {
    const s = String(p || '/').replace(/\/+$/, '');
    const i = s.lastIndexOf('/');
    return i <= 0 ? '/' : s.slice(0, i);
}

function b64(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
}

function unb64(text) {
    const bin = atob(text || '');
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function sortEntries(items) {
    return items.slice().sort((a, b) => {
        if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
        return a.name.localeCompare(b.name, 'zh-CN');
    });
}

/**
 * openFiles({ request, title, path })
 * request(payload, timeoutMs) resolves with the server's sftp reply.
 */
export function openFiles(cfg) {
    const request = cfg.request;
    let path = cfg.path || '.';
    let entries = [];
    let busy = false;
    let closed = false;

    const pathIn = el('input', { type: 'text', class: 'fm-path', spellcheck: 'false', value: path, title: '输入路径后回车跳转' });
    const listBox = el('div', { class: 'fm-list' });
    const statusEl = el('div', { class: 'fm-status', text: '正在读取目录 …' });

    const upBtn = el('button', { class: 'act icon-only', type: 'button', title: '上一级', html: icon('up', 15) });
    const refreshBtn = el('button', { class: 'act icon-only', type: 'button', title: '刷新', html: icon('refresh', 15) });
    const mkdirBtn = el('button', { class: 'btn sm', type: 'button', html: icon('folder', 14) + ' 新建文件夹' });
    const uploadBtn = el('button', { class: 'btn sm primary', type: 'button', html: icon('upload', 14) + ' 上传' });
    const fileInput = el('input', { type: 'file', multiple: true, style: 'display:none' });

    function setStatus(text, isErr) {
        statusEl.textContent = text || '';
        statusEl.classList.toggle('err', !!isErr);
    }

    function entryRow(entry) {
        const row = el('div', { class: 'fm-row' + (entry.isDir ? ' dir' : '') });
        const ic = el('span', { class: 'fm-ic', html: icon(entry.isDir ? 'folder' : 'file', 15) });
        const name = el('span', { class: 'fm-name', text: entry.name, title: entry.name + (entry.isLink ? '（符号链接）' : '') });
        const size = el('span', { class: 'fm-size', text: entry.isDir ? '' : entry.size == null ? '—' : fmtBytes(entry.size) });
        const time = el('span', { class: 'fm-time', text: entry.mtime ? fmtDate(entry.mtime) : '' });

        const acts = el('div', { class: 'fm-acts' });
        if (!entry.isDir) {
            const dl = el('button', { class: 'act icon-only', type: 'button', title: '下载', html: icon('download', 14) });
            dl.addEventListener('click', (ev) => {
                ev.stopPropagation();
                download(entry);
            });
            acts.appendChild(dl);
        }
        const chmodBtn = el('button', { class: 'act icon-only', type: 'button', title: '修改权限', html: icon('lock', 14) });
        chmodBtn.addEventListener('click', (ev) => {
            ev.stopPropagation();
            chmodEntry(entry);
        });
        const ren = el('button', { class: 'act icon-only', type: 'button', title: '重命名', html: icon('edit', 14) });
        ren.addEventListener('click', (ev) => {
            ev.stopPropagation();
            renameEntry(entry);
        });
        const del = el('button', { class: 'act icon-only', type: 'button', title: '删除', html: icon('trash', 14) });
        del.addEventListener('click', (ev) => {
            ev.stopPropagation();
            removeEntry(entry);
        });
        acts.appendChild(chmodBtn);
        acts.appendChild(ren);
        acts.appendChild(del);

        row.appendChild(ic);
        row.appendChild(name);
        row.appendChild(size);
        row.appendChild(time);
        row.appendChild(acts);
        row.addEventListener('click', () => {
            if (entry.isDir) navigate(joinPath(path, entry.name));
            else editFile(entry);
        });
        return row;
    }

    function render() {
        listBox.textContent = '';
        if (busy && !entries.length) {
            listBox.appendChild(el('div', { class: 'empty-hint', text: '读取中 …' }));
            return;
        }
        if (!entries.length) {
            listBox.appendChild(el('div', { class: 'empty-hint', text: '这个目录是空的' }));
            return;
        }
        for (const entry of entries) listBox.appendChild(entryRow(entry));
    }

    async function navigate(target) {
        if (closed) return;
        busy = true;
        render();
        setStatus('读取 ' + target + ' …');
        try {
            const res = await request({ op: 'list', path: target }, 60000);
            path = res.path || target;
            entries = sortEntries(res.entries || []);
            pathIn.value = path;
            setStatus(entries.length + ' 项');
        } catch (e) {
            entries = [];
            setStatus(e.message, true);
        } finally {
            busy = false;
            render();
        }
    }

    async function download(entry) {
        const full = joinPath(path, entry.name);
        let handle = null;
        setStatus('读取 ' + entry.name + ' …');
        try {
            const opened = await request({ op: 'open-read', path: full }, 120000);
            handle = opened.handle;
            const chunks = [];
            let offset = 0;
            for (;;) {
                const res = await request({ op: 'read', handle, offset, len: READ_CHUNK }, 120000);
                if (res.eof) break;
                const data = unb64(res.data);
                if (!data.length) break;
                chunks.push(data);
                offset += data.length;
                setStatus('下载 ' + entry.name + ' · ' + fmtBytes(offset) + (opened.size ? ' / ' + fmtBytes(opened.size) : ''));
            }
            const blob = new Blob(chunks, { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = el('a', { href: url, download: entry.name, style: 'display:none' });
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 5000);
            setStatus('已下载 ' + entry.name + '（' + fmtBytes(offset) + '）');
        } catch (e) {
            setStatus(e.message, true);
            toast(e.message, 'err');
        } finally {
            if (handle) request({ op: 'close', handle }).catch(() => {});
        }
    }

    async function uploadOne(full, file) {
        // 原子上传：服务端先在同目录写临时文件，全部写完才 rename 覆盖目标。
        // 中途失败（网络断、磁盘满、用户关掉页面）时原文件完好无损。
        const opened = await request({ op: 'open-upload', path: full }, 60000);
        const handle = opened.handle;
        const tmp = opened.tmp;
        let committed = false;
        try {
            const total = file.size || 1;
            for (let offset = 0; offset < file.size; offset += WRITE_CHUNK) {
                const buf = await file.slice(offset, offset + WRITE_CHUNK).arrayBuffer();
                await request({ op: 'write', handle, offset, data: b64(new Uint8Array(buf)) }, 120000);
                const done = Math.min(file.size, offset + WRITE_CHUNK);
                setStatus(
                    '上传 ' + file.name + ' · ' + fmtBytes(done) + ' / ' + fmtBytes(file.size) + ' · ' + Math.round((done / total) * 100) + '%'
                );
            }
            await request({ op: 'commit-upload', handle, tmp, path: full }, 120000);
            committed = true;
        } finally {
            if (!committed) {
                await request({ op: 'close', handle }).catch(() => {});
                await request({ op: 'remove', path: tmp }).catch(() => {});
            }
        }
    }

    async function runUploads() {
        const files = Array.from(fileInput.files || []);
        fileInput.value = '';
        if (!files.length) return;
        let done = 0;
        for (const file of files) {
            if (file.size > MAX_FILE) {
                toast(file.name + ' 超过 64 MB，已跳过', 'err');
                continue;
            }
            try {
                await uploadOne(joinPath(path, file.name), file);
                done++;
            } catch (e) {
                toast(file.name + '：' + e.message, 'err');
            }
        }
        if (done) toast('已上传 ' + done + ' 个文件');
        await navigate(path);
    }

    function mkdir() {
        const name = el('input', { type: 'text', placeholder: '文件夹名称' });
        let finish;
        let done = false;
        const submit = () => {
            const v = name.value.trim();
            if (!v || v === '.' || v === '..' || /[\/\0]/.test(v)) {
                toast('请输入合法的文件夹名称', 'err');
                return;
            }
            finish(v);
        };
        const form = el('form', { onsubmit: (ev) => { ev.preventDefault(); submit(); } }, [el('label', { text: '新建文件夹' }, [name])]);
        const foot = el('div', { style: 'display:flex;gap:8px' }, [
            el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => finish(null) }),
            el('button', { class: 'btn primary', type: 'submit', text: '创建', onclick: submit }),
        ]);
        const sub = modal({ title: '新建文件夹', body: form, footer: foot, onClose: () => finish(null) });
        finish = (v) => {
            if (done) return;
            done = true;
            sub.close();
            if (v) {
                request({ op: 'mkdir', path: joinPath(path, v) })
                    .then(() => navigate(path))
                    .catch((e) => toast(e.message, 'err'));
            }
        };
    }

    function renameEntry(entry) {
        const full = joinPath(path, entry.name);
        const name = el('input', { type: 'text', value: entry.name });
        let finish;
        let done = false;
        const submit = () => {
            const v = name.value.trim();
            if (!v || v === '.' || v === '..' || /[\/\0]/.test(v)) {
                toast('请输入合法的名称', 'err');
                return;
            }
            finish(v);
        };
        const form = el('form', { onsubmit: (ev) => { ev.preventDefault(); submit(); } }, [el('label', { text: '新名称' }, [name])]);
        const foot = el('div', { style: 'display:flex;gap:8px' }, [
            el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => finish(null) }),
            el('button', { class: 'btn primary', type: 'submit', text: '重命名', onclick: submit }),
        ]);
        const sub = modal({ title: '重命名', body: form, footer: foot, onClose: () => finish(null) });
        finish = (v) => {
            if (done) return;
            done = true;
            sub.close();
            if (!v || v === entry.name) return;
            request({ op: 'rename', from: full, to: joinPath(path, v) })
                .then(() => {
                    toast('已重命名');
                    navigate(path);
                })
                .catch((e) => toast(e.message, 'err'));
        };
    }

    function chmodEntry(entry) {
        const full = joinPath(path, entry.name);
        // 列表没给数值 mode（旧服务端）时按类型给个合理初值，不影响已返回的真实值
        let mode = entry.mode != null ? entry.mode : entry.isDir ? 0o755 : 0o644;
        const oct = (m) => {
            const s = m.toString(8);
            return m >= 0o1000 ? s.padStart(4, '0') : s.padStart(3, '0');
        };
        const octIn = el('input', { type: 'text', value: oct(mode), style: 'width:90px;font-family:monospace', spellcheck: 'false' });

        // 9 个 rwx 复选框 + 3 个特殊位，key 为权限位数值
        const boxes = {};
        function bitBox(label, bit) {
            const cb = el('input', { type: 'checkbox', checked: !!(mode & bit) });
            cb.addEventListener('change', syncFromBoxes);
            boxes[bit] = cb;
            return el('label', { style: 'display:flex;gap:4px;align-items:center' }, [cb, el('span', { text: label })]);
        }
        function syncBoxes(m) {
            for (const bit of Object.keys(boxes)) boxes[bit].checked = !!(m & Number(bit));
        }
        function syncFromBoxes() {
            let m = 0;
            for (const bit of Object.keys(boxes)) if (boxes[bit].checked) m |= Number(bit);
            mode = m;
            octIn.value = oct(m);
        }
        function syncFromMode(m) {
            mode = m;
            syncBoxes(m);
            octIn.value = oct(m);
        }
        octIn.addEventListener('input', () => {
            const v = octIn.value.trim();
            if (!/^[0-7]{1,4}$/.test(v)) return; // 非法时不更新复选框，提交时再报错
            mode = parseInt(v, 8);
            syncBoxes(mode); // 只同步复选框，不改输入框内容，避免打字时光标跳动
        });

        const permRow = (label, shift) =>
            el('div', { style: 'display:flex;gap:14px;align-items:center;margin:6px 0' }, [
                el('span', { style: 'width:52px', text: label }),
                bitBox('读', 0o400 >> shift),
                bitBox('写', 0o200 >> shift),
                bitBox('执行', 0o100 >> shift),
            ]);
        const presets = [0o644, 0o755, 0o600, 0o700, 0o777].map((p) =>
            el('button', { class: 'btn sm', type: 'button', text: oct(p), onclick: () => syncFromMode(p) })
        );
        const body = el('div', { style: 'display:flex;flex-direction:column;gap:4px' }, [
            el('p', { style: 'margin:0', text: entry.name + (entry.isLink ? '（符号链接：改的是链接目标的权限，不是链接本身）' : '') }),
            el('p', { style: 'margin:0', class: 'muted-sm', text: '当前权限：' + oct(mode) + (entry.modeText ? '（' + entry.modeText + '）' : '') }),
            el('div', { style: 'display:flex;gap:8px;align-items:center;margin-top:6px' }, [
                el('span', { text: '八进制' }),
                octIn,
                el('span', { class: 'muted-sm', text: '0-7777，只允许 0-7' }),
            ]),
            permRow('所有者', 0),
            permRow('群组', 3),
            permRow('其他', 6),
            el('div', { style: 'display:flex;gap:14px;align-items:center;margin:6px 0' }, [
                el('span', { style: 'width:52px', text: '特殊位' }),
                bitBox('setuid', 0o4000),
                bitBox('setgid', 0o2000),
                bitBox('sticky', 0o1000),
            ]),
            el('div', { style: 'display:flex;gap:8px;align-items:center' }, [el('span', { text: '常用' }), ...presets]),
        ]);

        let finish;
        let done = false;
        const submit = () => {
            const v = octIn.value.trim();
            if (!/^[0-7]{1,4}$/.test(v)) {
                toast('权限必须是 0-7777 的八进制数', 'err');
                return;
            }
            finish(parseInt(v, 8));
        };
        const foot = el('div', { style: 'display:flex;gap:8px' }, [
            el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => finish(null) }),
            el('button', { class: 'btn primary', type: 'button', text: '确定', onclick: submit }),
        ]);
        const sub = modal({ title: '修改权限', body, footer: foot, onClose: () => finish(null) });
        finish = (v) => {
            if (done) return;
            done = true;
            sub.close();
            if (v == null) return;
            request({ op: 'chmod', path: full, mode: v })
                .then((res) => {
                    toast('已修改权限为 ' + oct(res && res.mode != null ? res.mode : v));
                    navigate(path);
                })
                .catch((e) => toast(e.message, 'err'));
        };
    }

    async function removeEntry(entry) {
        const full = joinPath(path, entry.name);
        const ok = await confirmModal(
            entry.isDir ? '删除目录' : '删除文件',
            '确定删除 <b>' + esc(entry.name) + '</b> 吗？此操作不可撤销。' +
                (entry.isDir ? '<br>目录必须为空才能删除。' : ''),
            '删除',
            true
        );
        if (!ok) return;
        try {
            await request({ op: 'remove', path: full, isDir: !!entry.isDir });
            toast('已删除');
            await navigate(path);
        } catch (e) {
            toast(e.message, 'err');
        }
    }

    async function editFile(entry) {
        const full = joinPath(path, entry.name);
        setStatus('读取 ' + entry.name + ' …');
        let res;
        try {
            res = await request({ op: 'read-text', path: full }, 120000);
        } catch (e) {
            setStatus(e.message, true);
            toast(e.message, 'err');
            return;
        }
        setStatus(entry.name + ' · ' + fmtBytes(res.size || 0));

        const bytes = unb64(res.data);
        let text = '';
        try {
            text = new TextDecoder('utf-8').decode(bytes);
        } catch (_) {
            text = '';
        }
        const binary = text.indexOf('\u0000') >= 0 || text.indexOf('\ufffd') >= 0;
        const area = el('textarea', { class: 'fm-edit', spellcheck: 'false' });
        area.value = text;

        const bits = [el('span', { class: 'muted-sm', text: entry.name + ' · ' + fmtBytes(bytes.length) })];
        bits.push(el('span', { style: 'flex:1' }));
        const saveBtn = el('button', { class: 'btn primary', type: 'button', text: '保存' });
        const sub = modal({
            title: '在线编辑',
            width: '820px',
            body: el('div', { class: 'fm-edit-wrap' }, [
                binary
                    ? el('p', {
                          class: 'note-box',
                          style: 'margin:0;color:#c98a12',
                          text: '这个文件看起来是二进制内容，编辑会按 UTF-8 保存，可能损坏原文件。',
                      })
                    : null,
                area,
            ]),
            footer: el('div', { style: 'display:flex;gap:8px;align-items:center;width:100%' }, [
                ...bits,
                el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => sub.close() }),
                saveBtn,
            ]),
        });

        saveBtn.addEventListener('click', async () => {
            const out = new TextEncoder().encode(area.value);
            if (out.length > 2 * 1024 * 1024) {
                toast('内容超过 2 MB，无法保存', 'err');
                return;
            }
            saveBtn.disabled = true;
            saveBtn.textContent = '保存中…';
            try {
                await request({ op: 'write-text', path: full, data: b64(out) }, 120000);
                sub.close();
                toast('已保存');
                await navigate(path);
            } catch (e) {
                toast(e.message, 'err');
                saveBtn.disabled = false;
                saveBtn.textContent = '保存';
            }
        });
        area.addEventListener('keydown', (ev) => {
            if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 's') {
                ev.preventDefault();
                saveBtn.click();
            }
        });
    }

    upBtn.addEventListener('click', () => navigate(parentPath(path)));
    refreshBtn.addEventListener('click', () => navigate(path));
    pathIn.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter') navigate(pathIn.value.trim() || path);
    });
    mkdirBtn.addEventListener('click', mkdir);
    uploadBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', runUploads);

    const body = el('div', { class: 'fm' }, [
        el('div', { class: 'fm-bar' }, [upBtn, pathIn, refreshBtn, mkdirBtn, uploadBtn, fileInput]),
        listBox,
        statusEl,
    ]);

    const m = modal({
        title: cfg.title || '文件管理',
        body,
        width: '820px',
        onClose: () => {
            closed = true;
            if (cfg.onClose) cfg.onClose();
        },
    });
    navigate(path);
    return {
        close: m.close,
        refresh: () => navigate(path),
        get path() {
            return path;
        },
    };
}
