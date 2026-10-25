/* Small DOM / API helpers shared by every view. */

export const $ = (sel, root) => (root || document).querySelector(sel);
export const $$ = (sel, root) => Array.prototype.slice.call((root || document).querySelectorAll(sel));

export function el(tag, attrs, kids) {
    const node = document.createElement(tag);
    if (attrs) {
        for (const k in attrs) {
            const v = attrs[k];
            if (v == null || v === false) continue;
            if (k === 'class') node.className = v;
            else if (k === 'html') node.innerHTML = v;
            else if (k === 'text') node.textContent = v;
            else if (k === 'style') node.setAttribute('style', v);
            else if (k.slice(0, 2) === 'on' && typeof v === 'function') node.addEventListener(k.slice(2), v);
            else if (v === true) node.setAttribute(k, '');
            else node.setAttribute(k, v);
        }
    }
    if (kids != null) {
        for (const kid of [].concat(kids)) {
            if (kid == null || kid === false) continue;
            node.appendChild(typeof kid === 'string' || typeof kid === 'number' ? document.createTextNode(String(kid)) : kid);
        }
    }
    return node;
}

export function esc(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/* ---------------------------------------------------------------- icons */

const PATHS = {
    home: '<path d="M4 10.6 12 4l8 6.6V19a1 1 0 0 1-1 1h-4.5v-6h-5v6H5a1 1 0 0 1-1-1z"/>',
    server: '<rect x="3.5" y="4.5" width="17" height="6" rx="2"/><rect x="3.5" y="13.5" width="17" height="6" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    code: '<path d="m8.5 8.5-4 3.5 4 3.5M15.5 8.5l4 3.5-4 3.5"/>',
    terminal: '<path d="m5 8 4 4-4 4M12.5 16h6"/>',
    gear: '<circle cx="12" cy="12" r="3.2"/><path d="M19.4 14.5a7.7 7.7 0 0 0 0-5l1.6-1.2-1.8-3.1-1.9.8a7.6 7.6 0 0 0-4.3-2.5L12.6 1h-1.2l-.4 2.5a7.6 7.6 0 0 0-4.3 2.5l-1.9-.8L3 8.3l1.6 1.2a7.7 7.7 0 0 0 0 5L3 15.7l1.8 3.1 1.9-.8a7.6 7.6 0 0 0 4.3 2.5l.4 2.5h1.2l.4-2.5a7.6 7.6 0 0 0 4.3-2.5l1.9.8 1.8-3.1z"/>',
    logout: '<path d="M14 5.5h4a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1h-4M10 8.5 6 12l4 3.5M6 12h9"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    refresh: '<path d="M20 11a8 8 0 1 0-2.3 6.3M20 5v6h-6"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M15 6.5V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h1.5"/>',
    back: '<path d="M10 6.5 4.5 12l5.5 5.5M4.5 12H20"/>',
    power: '<path d="M12 4v7"/><path d="M7.5 6.8a7 7 0 1 0 9 0"/>',
    expand: '<path d="M9 4H4v5M15 4h5v5M15 20h5v-5M9 20H4v-5"/>',
    bolt: '<path d="M13.5 3 5 13.5h6L10.5 21 19 10.5h-6z"/>',
    key: '<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H21M17.5 12v3M20 12v2.5"/>',
    close: '<path d="m6 6 12 12M18 6 6 18"/>',
    edit: '<path d="m4 16.5-.8 4 4-.8L19 8a2.1 2.1 0 0 0-3-3z"/>',
    log: '<path d="M6 3.5h7l5 5v12H6z"/><path d="M13 3.5v5h5M9 13h6M9 16.5h4"/>',
    trash: '<path d="M4.5 7h15M9.5 7V5.5h5V7M6.5 7l.8 12h9.4l.8-12M10 10.5v6M14 10.5v6"/>',
    down: '<path d="M12 4.5v14M6.5 13 12 18.5 17.5 13"/>',
    check: '<path d="m5 12.5 4.5 4.5L19 7"/>',
    folder: '<path d="M3.5 6.5h6l1.8 2h9.2v10.5a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1z"/>',
    file: '<path d="M6.5 3.5h7l4.5 4.5v12.5h-11.5z"/><path d="M13.5 3.5V8H18"/>',
    upload: '<path d="M12 19.5v-14M6.5 11 12 5.5 17.5 11M5 21h14"/>',
    download: '<path d="M12 4.5v14M6.5 13 12 18.5 17.5 13M5 21h14"/>',
    up: '<path d="m6.5 14.5 5.5-5.5 5.5 5.5"/>',
    lock: '<rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
};

export function icon(name, size) {
    const s = size || 16;
    return (
        '<svg class="ic" width="' + s + '" height="' + s + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
        'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">' + (PATHS[name] || '') + '</svg>'
    );
}

/* ---------------------------------------------------------------- toast */

export function toast(message, kind) {
    const host = $('#toasts');
    if (!host) return;
    const node = el('div', { class: 'toast' + (kind === 'err' ? ' err' : ''), text: String(message) });
    host.appendChild(node);
    setTimeout(() => {
        node.style.transition = 'opacity .25s ease, transform .25s ease';
        node.style.opacity = '0';
        node.style.transform = 'translateY(6px)';
        setTimeout(() => node.remove(), 260);
    }, kind === 'err' ? 5200 : 3000);
}

/* ------------------------------------------------------------------ api */

export async function api(path, opts) {
    const o = opts || {};
    const headers = {};
    let body;
    if (o.body !== undefined) {
        headers['content-type'] = 'application/json';
        body = JSON.stringify(o.body);
    }
    const res = await fetch(path, { method: o.method || 'GET', headers, body, credentials: 'same-origin' });
    const text = await res.text();
    let data = null;
    if (text) {
        try {
            data = JSON.parse(text);
        } catch (_) {
            data = null;
        }
    }
    if (!res.ok) {
        const err = new Error((data && data.message) || '请求失败 (' + res.status + ')');
        err.status = res.status;
        err.data = data;
        throw err;
    }
    return data;
}

/* ---------------------------------------------------------------- modal */

/**
 * modal({ title, body, footer, onClose, width })
 * body/footer may be a Node or an HTML string.
 * Returns { root, body, footer, close }.
 */
export function modal(cfg) {
    const root = $('#modal-root');
    const closeBtn = el('button', { class: 'icon-btn', type: 'button', html: icon('close', 15), 'aria-label': '关闭' });
    const bodyEl = el('div', { class: 'modal-body' });
    if (typeof cfg.body === 'string') bodyEl.innerHTML = cfg.body;
    else if (cfg.body) bodyEl.appendChild(cfg.body);

    const footEl = el('div', { class: 'modal-foot' });
    if (cfg.footer) {
        if (typeof cfg.footer === 'string') footEl.innerHTML = cfg.footer;
        else footEl.appendChild(cfg.footer);
    }

    const box = el('div', { class: 'modal', style: cfg.width ? 'width:min(' + cfg.width + ',100%)' : null }, [
        el('div', { class: 'modal-head' }, [el('h3', { text: cfg.title || '' }), closeBtn]),
        bodyEl,
        cfg.footer ? footEl : null,
    ]);
    const backdrop = el('div', { class: 'modal-backdrop' }, [box]);

    let closed = false;
    function close() {
        if (closed) return;
        closed = true;
        document.removeEventListener('keydown', onKey, true);
        backdrop.remove();
        if (cfg.onClose) cfg.onClose();
    }
    function onKey(ev) {
        if (ev.key === 'Escape') {
            if (root.lastElementChild !== backdrop) return; // only the top-most sheet closes
            ev.stopPropagation();
            close();
        }
    }
    closeBtn.addEventListener('click', close);
    backdrop.addEventListener('mousedown', (ev) => {
        if (ev.target === backdrop) close();
    });
    document.addEventListener('keydown', onKey, true);
    root.appendChild(backdrop);

    const first = bodyEl.querySelector('input,textarea,select,button');
    if (first && cfg.autofocus !== false) setTimeout(() => first.focus(), 30);

    return { root: backdrop, box, body: bodyEl, footer: footEl, close };
}

export function confirmModal(title, text, okLabel, danger) {
    return new Promise((resolve) => {
        let done = false;
        const finish = (v) => {
            if (done) return;
            done = true;
            m.close();
            resolve(v);
        };
        const foot = el('div', { style: 'display:flex;gap:8px' }, [
            el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => finish(false) }),
            el('button', {
                class: 'btn ' + (danger ? 'danger' : 'primary'),
                type: 'button',
                text: okLabel || '确定',
                onclick: () => finish(true),
            }),
        ]);
        const m = modal({
            title,
            body: el('p', { class: 'note-box', style: 'margin:0', html: text }),
            footer: foot,
            onClose: () => finish(false),
        });
    });
}

/* -------------------------------------------------------------- formats */

export function fmtBytes(n) {
    const v = Number(n) || 0;
    if (v < 1024) return v + ' B';
    const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
    let i = -1;
    let x = v;
    do {
        x /= 1024;
        i++;
    } while (x >= 1024 && i < units.length - 1);
    return (x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x.toFixed(2)) + ' ' + units[i];
}

export function fmtRate(n) {
    return fmtBytes(n) + '/s';
}

export function fmtUptime(sec) {
    const s = Math.max(0, Math.floor(Number(sec) || 0));
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return d + '天' + h + '小时';
    if (h > 0) return h + '小时' + m + '分';
    return m + '分钟';
}

export function timeAgo(ts) {
    const n = typeof ts === 'number' ? ts : Date.parse(ts);
    if (!n) return '';
    const diff = Date.now() - n;
    if (diff < 60000) return '刚刚';
    if (diff < 3600000) return Math.floor(diff / 60000) + ' 分钟前';
    if (diff < 86400000) return Math.floor(diff / 3600000) + ' 小时前';
    if (diff < 86400000 * 30) return Math.floor(diff / 86400000) + ' 天前';
    return new Date(n).toLocaleDateString('zh-CN');
}

export function fmtDate(ts) {
    const n = typeof ts === 'number' ? ts : Date.parse(ts);
    if (!n) return '';
    const d = new Date(n);
    const p = (x) => String(x).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

/* --------------------------------------------------------------- misc */

export function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    const ta = el('textarea', { style: 'position:fixed;opacity:0;top:0;left:0' });
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try {
        document.execCommand('copy');
    } catch (_) {}
    ta.remove();
    return Promise.resolve();
}

export function debounce(fn, ms) {
    let t = 0;
    return function () {
        const args = arguments;
        clearTimeout(t);
        t = setTimeout(() => fn.apply(null, args), ms || 120);
    };
}

export function initials(name) {
    const s = String(name || '?').trim();
    if (!s) return '?';
    const m = s.match(/[a-zA-Z0-9]/);
    if (m) return s.slice(0, 1).toUpperCase();
    return s.slice(0, 1);
}

export const PALETTE = ['#ff4a17', '#1f9d55', '#2f6fb5', '#7c5cff', '#c98a12', '#0f9b8e', '#d9402f', '#5b6472'];
