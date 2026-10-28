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
        let handle = null;
        try {
            const opened = await request({ op: 'open-write', path: full }, 60000);
            handle = opened.handle;
            for (let offset = 0; offset < file.size; offset += WRITE_CHUNK) {
                const buf = await file.slice(offset, offset + WRITE_CHUNK).arrayBuffer();
                await request({ op: 'write', handle, offset, data: b64(new Uint8Array(buf)) }, 120000);
                setStatus('上传 ' + file.name + ' · ' + fmtBytes(Math.min(file.size, offset + WRITE_CHUNK)) + ' / ' + fmtBytes(file.size));
            }
        } finally {
            if (handle) {
                try {
                    await request({ op: 'close', handle });
                } catch (_) {}
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
