/* WebSSH front-end: auth, host manager, dotted globe, multi-tab terminal. */

import { $, $$, el, esc, icon, toast, api, modal, confirmModal, fmtBytes, fmtDate, timeAgo, initials, PALETTE, copyText } from './ui.js';
import { COUNTRIES, CITIES, countryOf, flagOf, regionLabel, locate } from './geo.js';
import { createGlobe } from './globe.js';
import { createTerminalView } from './term.js';
import { openFiles } from './files.js';

const SETTINGS_KEY = 'webssh.settings';

const state = {
    setup: false,
    authed: false,
    user: null,
    hosts: [],
    groups: [],
    keys: [],
    creds: [],
    snippets: [],
    filter: 'all',
    settings: { fontSize: 13, record: false },
    term: null,
    globe: null,
    nav: 'overview',
};

/* --------------------------------------------------------------- settings */

function loadSettings() {
    try {
        const raw = localStorage.getItem(SETTINGS_KEY);
        if (raw) Object.assign(state.settings, JSON.parse(raw));
    } catch (_) {}
}

function saveSettings() {
    try {
        localStorage.setItem(SETTINGS_KEY, JSON.stringify(state.settings));
    } catch (_) {}
}

/* ------------------------------------------------------------------ views */

function hideBoot() {
    const boot = $('#boot');
    if (!boot) return;
    boot.style.opacity = '0';
    setTimeout(() => boot.remove(), 260);
}

function showAuth(mode) {
    $('#view-auth').hidden = false;
    $('#view-dash').hidden = true;
    $('#view-term').hidden = true;
    $('#form-setup').hidden = mode !== 'setup';
    $('#form-login').hidden = mode !== 'login';
    const first = mode === 'setup' ? $('#form-setup input') : $('#form-login input');
    if (first) setTimeout(() => first.focus(), 60);
}

function showDash() {
    $('#view-auth').hidden = true;
    $('#view-term').hidden = true;
    $('#view-dash').hidden = false;
    setNav('overview');
    renderDash();
    ensureGlobe();
}

function showTerm() {
    $('#view-auth').hidden = true;
    $('#view-dash').hidden = true;
    $('#view-term').hidden = false;
    if (state.term) setTimeout(() => state.term.fitActive(), 30);
}

async function safe(fn) {
    try {
        return await fn();
    } catch (e) {
        if (e && e.status === 401) {
            state.authed = false;
            showAuth('login');
            return null;
        }
        toast((e && e.message) || '操作失败', 'err');
        return null;
    }
}

function promptText(title, label, value, okLabel, hint) {
    return new Promise((resolve) => {
        let done = false;
        const finish = (v) => {
            if (done) return;
            done = true;
            m.close();
            resolve(v);
        };
        const input = el('input', { type: 'text', value: value || '' });
        const submit = () => {
            const v = input.value.trim();
            if (!v) {
                toast('不能为空', 'err');
                return;
            }
            finish(v);
        };
        const form = el('form', { onsubmit: (ev) => { ev.preventDefault(); submit(); } }, [
            el('label', { text: label }, [input]),
            hint ? el('p', { class: 'note-box', style: 'margin:8px 0 0', text: hint }) : null,
        ]);
        const foot = el('div', { style: 'display:flex;gap:8px' }, [
            el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => finish(null) }),
            el('button', { class: 'btn primary', type: 'submit', text: okLabel || '确定', onclick: submit }),
        ]);
        const m = modal({ title, body: form, footer: foot, onClose: () => finish(null) });
    });
}

/* ------------------------------------------------------------------- auth */

function bindAuth() {
    const setupForm = $('#form-setup');
    setupForm.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const errEl = $('#setup-error');
        errEl.textContent = '';
        const fd = new FormData(setupForm);
        const username = String(fd.get('username') || '').trim();
        const password = String(fd.get('password') || '');
        const password2 = String(fd.get('password2') || '');
        if (password !== password2) {
            errEl.textContent = '两次输入的密码不一致';
            return;
        }
        const btn = setupForm.querySelector('button[type="submit"]');
        btn.disabled = true;
        try {
            await api('/api/setup', { method: 'POST', body: { username, password } });
            state.setup = true;
            state.authed = true;
            state.user = username;
            enterApp();
        } catch (e) {
            errEl.textContent = e.message;
        } finally {
            btn.disabled = false;
        }
    });

    const loginForm = $('#form-login');
    loginForm.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const errEl = $('#login-error');
        errEl.textContent = '';
        const fd = new FormData(loginForm);
        const btn = loginForm.querySelector('button[type="submit"]');
        btn.disabled = true;
        try {
            const res = await api('/api/login', {
                method: 'POST',
                body: { username: String(fd.get('username') || '').trim(), password: String(fd.get('password') || '') },
            });
            state.authed = true;
            state.user = (res && res.user) || '';
            enterApp();
        } catch (e) {
            errEl.textContent = e.message;
        } finally {
            btn.disabled = false;
        }
    });
}

/* -------------------------------------------------------------- dashboard */

function setNav(name) {
    state.nav = name;
    $$('.rail-item[data-nav]').forEach((b) => b.classList.toggle('on', b.dataset.nav === name));
}

function renderDash() {
    renderFilters();
    renderHosts();
    renderDashFoot();
    updateGlobePoints();
}

function visibleHosts() {
    if (state.filter === 'all') return state.hosts;
    return state.hosts.filter((h) => (h.country || '') === state.filter);
}

function renderFilters() {
    const box = $('#filters');
    box.textContent = '';
    const counts = new Map();
    for (const h of state.hosts) {
        const cc = h.country || '';
        if (!cc) continue;
        counts.set(cc, (counts.get(cc) || 0) + 1);
    }
    const add = (key, label, count, flag) => {
        const btn = el('button', { class: 'filter' + (state.filter === key ? ' on' : ''), type: 'button' });
        btn.innerHTML = (flag ? '<span class="flag">' + flag + '</span>' : '') + '<span>' + esc(label) + '</span><b>' + count + '</b>';
        btn.addEventListener('click', () => {
            state.filter = key;
            renderFilters();
            renderHosts();
        });
        box.appendChild(btn);
    };
    add('all', '全部', state.hosts.length, '');
    const ordered = Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    for (const [cc, n] of ordered) {
        const co = countryOf(cc);
        add(cc, co ? co.n : cc, n, co ? co.f : '');
    }
}

function groupOf(host) {
    const g = String(host.group || '').trim();
    return g || '未分组';
}

// stable colour for hosts that never picked one
function autoColor(host) {
    const s = String((host && (host.name || host.host)) || '');
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0xffff;
    return PALETTE[h % PALETTE.length];
}

const COLLAPSE_KEY = 'webssh.collapsedGroups';

function collapsedGroups() {
    try {
        const raw = JSON.parse(localStorage.getItem(COLLAPSE_KEY) || '[]');
        return new Set(Array.isArray(raw) ? raw : []);
    } catch (_) {
        return new Set();
    }
}

function persistCollapsed(set) {
    try {
        localStorage.setItem(COLLAPSE_KEY, JSON.stringify(Array.from(set)));
    } catch (_) {}
}

function renderHosts() {
    const box = $('#host-groups');
    box.textContent = '';
    const list = visibleHosts();

    if (!list.length) {
        const empty = el('div', { class: 'empty' });
        if (!state.hosts.length) {
            empty.innerHTML =
                '<div style="color:#c9c0b0">' + icon('server', 30) + '</div>' +
                '<h3>还没有添加任何主机</h3>' +
                '<p>把常用的服务器存进来，之后一键就能连上。<br>凭据会用 AES-GCM 加密后保存在你自己的 R2 存储中。</p>';
            empty.appendChild(
                el('button', { class: 'btn primary', type: 'button', html: icon('plus', 15) + ' 添加第一台主机', onclick: () => openHostEditor(null) })
            );
        } else {
            empty.innerHTML = '<h3>这个地区还没有主机</h3><p>换个筛选条件试试。</p>';
        }
        box.appendChild(empty);
        return;
    }

    const groups = new Map();
    for (const h of list) {
        const g = groupOf(h);
        if (!groups.has(g)) groups.set(g, []);
        groups.get(g).push(h);
    }
    const names = Array.from(groups.keys()).sort((a, b) => {
        if (a === '未分组') return 1;
        if (b === '未分组') return -1;
        return a.localeCompare(b, 'zh-CN');
    });

    let idx = 0;
    const collapsed = collapsedGroups();
    for (const name of names) {
        const items = groups.get(name);
        const group = el('div', { class: 'group' + (collapsed.has(name) ? ' collapsed' : '') });
        const head = el('button', { class: 'group-head', type: 'button', title: '收起 / 展开' }, [
            el('span', { class: 'chev', html: icon('chevron', 13) }),
            el('b', { text: name }),
            el('span', { class: 'count', text: items.length + ' 台' }),
        ]);
        head.setAttribute('aria-expanded', collapsed.has(name) ? 'false' : 'true');
        head.addEventListener('click', () => {
            const set = collapsedGroups();
            const nowCollapsed = !set.has(name);
            if (nowCollapsed) set.add(name);
            else set.delete(name);
            persistCollapsed(set);
            group.classList.toggle('collapsed', nowCollapsed);
            head.setAttribute('aria-expanded', nowCollapsed ? 'false' : 'true');
        });
        const body = el('div', { class: 'group-body' });
        for (const h of items) body.appendChild(hostRow(h, idx++));
        group.appendChild(head);
        group.appendChild(body);
        box.appendChild(group);
    }
}

function hostRow(host, index) {
    const color = host.color || autoColor(host);
    const row = el('div', { class: 'host-row' });

    row.appendChild(el('div', { class: 'tile', style: 'background:' + color, text: host.icon || initials(host.name) }));
    row.appendChild(
        el('div', { class: 'host-main' }, [
            el('div', { class: 'host-name', text: host.name || host.host }),
            el('div', { class: 'host-sub', text: (host.username || '') + '@' + host.host + ':' + (host.port || 22) }),
        ])
    );
    row.appendChild(
        el('div', { class: 'host-loc' }, [
            el('span', { class: 'flag', text: flagOf(host.country) }),
            el('span', { text: regionLabel(host) }),
        ])
    );

    const acts = el('div', { class: 'host-acts' });
    const go = el('button', { class: 'act go', type: 'button', text: '连接' });
    go.addEventListener('click', (ev) => {
        ev.stopPropagation();
        connectHost(host);
    });
    const edit = el('button', { class: 'act icon-only', type: 'button', title: '编辑', html: icon('edit', 14) });
    edit.addEventListener('click', (ev) => {
        ev.stopPropagation();
        openHostEditor(host);
    });
    const logs = el('button', { class: 'act icon-only', type: 'button', title: '连接记录', html: icon('log', 14) });
    logs.addEventListener('click', (ev) => {
        ev.stopPropagation();
        openLogs(host);
    });
    const del = el('button', { class: 'act icon-only', type: 'button', title: '删除', html: icon('trash', 14) });
    del.addEventListener('click', (ev) => {
        ev.stopPropagation();
        removeHost(host);
    });
    acts.appendChild(go);
    acts.appendChild(edit);
    acts.appendChild(logs);
    acts.appendChild(del);
    row.appendChild(acts);

    row.addEventListener('click', () => connectHost(host));
    return row;
}

function renderDashFoot() {
    const regions = new Set();
    for (const h of state.hosts) if (h.country) regions.add(h.country);
    $('#dash-count').textContent = state.hosts.length
        ? state.hosts.length + ' 台主机 · ' + regions.size + ' 个地区'
        : '还没有主机';
    const gc = $('#globe-count');
    if (gc) {
        const n = state.hosts.length;
        gc.textContent = n
            ? n + (n > 1 ? ' hosts' : ' host') + ' across ' + regions.size + (regions.size > 1 ? ' regions' : ' region')
            : 'no host yet';
    }
}

/* ------------------------------------------------------------------ globe */

function ensureGlobe() {
    if (state.globe) {
        updateGlobePoints();
        return;
    }
    const canvas = $('#globe');
    const labels = $('#globe-labels');
    if (!canvas) return;
    state.globe = createGlobe(canvas, labels, {
        autoRotate: true,
        onPick: (p) => {
            const host = state.hosts.find((h) => h.id === p.id);
            if (host) connectHost(host);
        },
    });
    const btn = $('#btn-rotate');
    if (btn) {
        btn.textContent = '暂停旋转';
        btn.addEventListener('click', () => {
            const on = !state.globe.isAutoRotate();
            state.globe.setAutoRotate(on);
            btn.textContent = on ? '暂停旋转' : '继续旋转';
        });
    }
    updateGlobePoints();
}

function updateGlobePoints() {
    if (!state.globe) return;
    const pts = [];
    for (const h of state.hosts) {
        const loc = locate(h);
        if (!loc) continue;
        pts.push({
            id: h.id,
            lat: loc.lat,
            lon: loc.lon,
            name: h.name || h.host,
            city: loc.city || regionLabel(h),
            flag: flagOf(h.country),
        });
    }
    state.globe.setPoints(pts);
}

/* ------------------------------------------------------------- connecting */

function connectHost(host) {
    if (!state.term) return;
    showTerm();
    const base = {
        hostId: host.id,
        name: host.name || host.host,
        host: host.host,
        port: host.port || 22,
        username: host.username,
    };
    if (host.hasSecret) {
        state.term.open(base);
        return;
    }
    askCredentials(host).then((creds) => {
        if (!creds) {
            if (!state.term.sessions().length) showDash();
            return;
        }
        state.term.open(Object.assign(base, creds));
    });
}

function askCredentials(host) {
    return new Promise((resolve) => {
        let done = false;
        const finish = (v) => {
            if (done) return;
            done = true;
            m.close();
            resolve(v);
        };
        const isKey = host.authType === 'key';
        const secretInput = isKey
            ? el('textarea', { placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----', spellcheck: 'false' })
            : el('input', { type: 'password', autocomplete: 'off', placeholder: '登录密码' });
        const passphrase = isKey ? el('input', { type: 'password', autocomplete: 'off', placeholder: '私钥没有口令可留空' }) : null;
        const body = el('div', { style: 'display:flex;flex-direction:column;gap:12px' }, [
            el('p', {
                class: 'note-box',
                style: 'margin:0',
                html:
                    '这台主机没有保存凭据，请输入 <b>' + esc(host.username) + '@' + esc(host.host) + '</b> 的' +
                    (isKey ? '私钥。' : '密码。') +
                    '本次输入只在内存中使用。',
            }),
            el('label', { text: isKey ? '私钥（PEM）' : '密码' }, [secretInput]),
            passphrase ? el('label', { text: '私钥口令' }, [passphrase]) : null,
        ]);
        const foot = el('div', { style: 'display:flex;gap:8px' }, [
            el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => finish(null) }),
            el('button', {
                class: 'btn primary',
                type: 'button',
                text: '连接',
                onclick: () => {
                    const value = secretInput.value;
                    if (!value) {
                        toast('请先填入凭据', 'err');
                        return;
                    }
                    finish(isKey ? { privateKey: value, passphrase: passphrase ? passphrase.value : '' } : { password: value });
                },
            }),
        ]);
        const m = modal({ title: '需要凭据', body, footer: foot, onClose: () => finish(null) });
    });
}

/* ------------------------------------------------------------ host editor */

function field(label, input, hint) {
    const wrap = el('label', { text: label }, [input]);
    if (hint) wrap.appendChild(el('span', { class: 'muted-sm', style: 'font-weight:400', text: hint }));
    return wrap;
}

function openHostEditor(host) {
    const h = host || {};
    const isNew = !host;

    const nameIn = el('input', { type: 'text', value: h.name || '', placeholder: '例如 香港生产机' });
    if (h.group && !state.groups.includes(h.group)) state.groups.push(h.group);
    const groupSel = el('select', { name: 'group' });
    const fillGroups = (selected) => {
        groupSel.textContent = '';
        groupSel.appendChild(el('option', { value: '', text: '未分组' }));
        for (const g of state.groups) groupSel.appendChild(el('option', { value: g, text: g }));
        groupSel.appendChild(el('option', { value: '__new', text: '＋ 新建分组…' }));
        groupSel.value = selected && state.groups.includes(selected) ? selected : '';
    };
    fillGroups(h.group || '');
    groupSel.addEventListener('change', async () => {
        if (groupSel.value !== '__new') return;
        groupSel.value = h.group && state.groups.includes(h.group) ? h.group : '';
        const name = await promptText('新建分组', '分组名称', '', '创建', '创建后可在「分组」面板里管理，所有主机下拉框都会同步。');
        if (!name) return;
        const res = await safe(() => api('/api/groups', { method: 'POST', body: { op: 'add', name } }));
        if (!res) return;
        state.groups = res.groups || state.groups;
        fillGroups(name);
        toast('分组已创建');
    });

    const userIn = el('input', { type: 'text', value: h.username || 'root', placeholder: 'root', autocomplete: 'off' });
    const hostIn = el('input', { type: 'text', name: 'host', value: h.host || '', placeholder: '192.0.2.10、example.com 或 2001:db8::1', spellcheck: 'false' });
    const portIn = el('input', { type: 'number', value: h.port || 22, min: '1', max: '65535' });

    const pwIn = el('input', { type: 'password', autocomplete: 'new-password', placeholder: h.hasSecret ? '已保存，留空则不修改' : '登录密码' });
    const keyIn = el('textarea', { placeholder: h.hasSecret ? '已保存私钥，留空则不修改' : '-----BEGIN OPENSSH PRIVATE KEY-----', spellcheck: 'false' });
    const passIn = el('input', { type: 'password', autocomplete: 'off', placeholder: '私钥没有口令可留空' });

    let keyId = h.keyId && state.keys.some((k) => k.id === h.keyId) ? h.keyId : '';
    const keySel = el('select', { name: 'keyId' });
    const keyMeta = el('div', { class: 'fp', style: 'font-size:11px;padding:8px 10px' });
    const keyField = field('私钥（PEM）', keyIn);
    const passField = field('私钥口令', passIn);
    const keyNote = el('p', { class: 'muted-sm', style: 'margin:0', text: '在「凭据库」里可以复用同一把私钥，主机只需要引用。' });
    const applyKey = () => {
        const entry = state.keys.find((k) => k.id === keyId);
        keyMeta.hidden = !entry;
        if (entry) keyMeta.textContent = (entry.algo || '') + ' · ' + (entry.fingerprint || '');
        keyField.hidden = !!entry;
        passField.hidden = !!entry;
        keyNote.textContent = entry ? '这把私钥在「凭据库」中统一管理。' : '在「凭据库」里可以复用同一把私钥，主机只需要引用。';
    };
    const fillKeys = (selected) => {
        keySel.textContent = '';
        keySel.appendChild(el('option', { value: '', text: '手动填写私钥' }));
        for (const k of state.keys) keySel.appendChild(el('option', { value: k.id, text: k.name + (k.algo ? ' · ' + k.algo : '') }));
        keySel.appendChild(el('option', { value: '__new', text: '＋ 新建密钥…' }));
        keyId = selected && state.keys.some((k) => k.id === selected) ? selected : '';
        keySel.value = keyId;
        applyKey();
    };
    keySel.addEventListener('change', async () => {
        if (keySel.value === '__new') {
            keySel.value = keyId;
            keyEditor(null, (meta) => fillKeys(meta.id));
            return;
        }
        keyId = keySel.value;
        applyKey();
    });
    fillKeys(h.keyId || '');

    let credId = h.credId && state.creds.some((c) => c.id === h.credId) ? h.credId : '';
    const credSel = el('select', { name: 'credId' });
    const credField = field('常用账号', credSel);
    const pwField = field('密码', pwIn);
    const credNote = el('p', {
        class: 'muted-sm',
        style: 'margin:0',
        text: '把用户名和密码存进「凭据库」，多台主机可以共用同一份登录信息。',
    });
    const applyCred = (fillUser) => {
        const entry = state.creds.find((c) => c.id === credId);
        pwField.hidden = !!entry;
        if (entry) {
            userIn.readOnly = true;
            if (fillUser) userIn.value = entry.username;
            credNote.textContent = '用户名和密码由凭据库「' + entry.name + '」提供。';
        } else {
            userIn.readOnly = false;
            credNote.textContent = '把用户名和密码存进「凭据库」，多台主机可以共用同一份登录信息。';
        }
    };
    const fillCreds = (selected, fillUser) => {
        credSel.textContent = '';
        credSel.appendChild(el('option', { value: '', text: '手动输入密码' }));
        for (const c of state.creds) credSel.appendChild(el('option', { value: c.id, text: c.name + ' · ' + c.username }));
        credSel.appendChild(el('option', { value: '__new', text: '＋ 新建常用账号…' }));
        credId = selected && state.creds.some((c) => c.id === selected) ? selected : '';
        credSel.value = credId;
        applyCred(fillUser);
    };
    credSel.addEventListener('change', () => {
        if (credSel.value === '__new') {
            credSel.value = credId;
            credEditor(null, (meta) => fillCreds(meta.id, true));
            return;
        }
        credId = credSel.value;
        applyCred(true);
    });
    fillCreds(h.credId || '', false);

    let authType = h.authType === 'key' ? 'key' : 'password';
    const segPw = el('button', { type: 'button', text: '密码' });
    const segKey = el('button', { type: 'button', text: '私钥' });
    const seg = el('div', { class: 'seg' }, [segPw, segKey]);
    const pwBox = el('div', { style: 'display:flex;flex-direction:column;gap:10px' }, [credField, pwField, credNote]);
    const keyBox = el('div', { style: 'display:flex;flex-direction:column;gap:10px' }, [
        field('私钥来源', keySel),
        keyMeta,
        keyField,
        passField,
        keyNote,
    ]);

    const applyAuth = () => {
        segPw.classList.toggle('on', authType === 'password');
        segKey.classList.toggle('on', authType === 'key');
        pwBox.hidden = authType !== 'password';
        keyBox.hidden = authType !== 'key';
    };
    segPw.addEventListener('click', () => {
        authType = 'password';
        applyAuth();
    });
    segKey.addEventListener('click', () => {
        authType = 'key';
        applyAuth();
    });
    applyAuth();

    /* country + city picker */
    let country = h.country || '';

    // 自己画城市建议，原生 <datalist> 弹层会吃掉紧跟着的那次点击（选地区时点不动）。
    const cityIn = el('input', { type: 'text', value: h.city || '', placeholder: '例如 香港 / 东京', autocomplete: 'off' });
    const citySug = el('div', { class: 'city-sug', hidden: true });
    const cityWrap = el('div', { class: 'city-pick' }, [cityIn, citySug]);
    const renderCitySug = () => {
        const q = cityIn.value.trim().toLowerCase();
        const hits = q
            ? CITIES.filter((c) => c.n.toLowerCase().includes(q) || c.c.toLowerCase() === q)
                  .sort((a, b) => (b.c === country) - (a.c === country))
                  .slice(0, 8)
            : [];
        citySug.textContent = '';
        if (!hits.length) {
            citySug.hidden = true;
            return;
        }
        for (const c of hits) {
            const co = countryOf(c.c);
            const opt = el('button', { type: 'button', class: 'city-opt' }, [
                el('span', { class: 'flag', text: co ? co.f : '' }),
                el('span', { text: c.n }),
                el('span', { class: 'city-cc', text: co ? co.n : c.c }),
            ]);
            opt.addEventListener('mousedown', (ev) => {
                ev.preventDefault();
                cityIn.value = c.n;
                citySug.hidden = true;
            });
            citySug.appendChild(opt);
        }
        citySug.hidden = false;
    };
    cityIn.addEventListener('input', renderCitySug);
    cityIn.addEventListener('focus', renderCitySug);
    const hideCitySug = (ev) => {
        if (!cityWrap.contains(ev.target)) citySug.hidden = true;
    };
    document.addEventListener('pointerdown', hideCitySug, true);

    const countryGrid = el('div', { class: 'country-pick' });
    const countrySearch = el('input', { type: 'text', placeholder: '搜索国家 / 地区', style: 'margin-bottom:8px' });
    const countryButtons = [];
    const selectCountry = (code) => {
        const prev = countryOf(country);
        country = code;
        for (const b of countryButtons) {
            const on = b.dataset.code === code;
            b.classList.toggle('on', on);
            b.setAttribute('aria-pressed', on ? 'true' : 'false');
        }
        citySug.hidden = true;
        const co = countryOf(code);
        const typed = cityIn.value.trim();
        if (co && (!typed || (prev && typed === prev.city))) cityIn.value = co.city;
    };
    const mkCountry = (code, label, flag) => {
        const btn = el('button', { type: 'button', class: code === country ? 'on' : '', 'aria-pressed': code === country ? 'true' : 'false' }, [
            el('span', { class: 'flag', text: flag }),
            el('span', { text: label }),
        ]);
        btn.dataset.code = code;
        btn.dataset.search = (label + ' ' + code).toLowerCase();
        btn.addEventListener('click', () => selectCountry(code));
        countryButtons.push(btn);
        countryGrid.appendChild(btn);
    };
    const noneBtn = el(
        'button',
        { type: 'button', class: country ? '' : 'on', 'aria-pressed': country ? 'false' : 'true' },
        [el('span', { class: 'flag', text: '🌐' }), el('span', { text: '不标注' })]
    );
    noneBtn.dataset.code = '';
    noneBtn.dataset.search = '不标注 none';
    noneBtn.addEventListener('click', () => selectCountry(''));
    countryButtons.push(noneBtn);
    countryGrid.appendChild(noneBtn);
    COUNTRIES.forEach((c) => mkCountry(c.c, c.n, c.f));
    countrySearch.addEventListener('input', () => {
        const q = countrySearch.value.trim().toLowerCase();
        for (const b of countryButtons) b.style.display = !q || b.dataset.search.indexOf(q) >= 0 ? '' : 'none';
    });

    let color = h.color || (isNew ? '' : autoColor(h));
    const swatches = el('div', { class: 'swatches' });
    const swatchNodes = PALETTE.map((c) => {
        const b = el('button', { type: 'button', class: 'swatch' + (c === color ? ' on' : ''), style: 'background:' + c, title: c });
        b.addEventListener('click', () => {
            color = c;
            swatchNodes.forEach((n) => n.classList.toggle('on', n.title === c));
        });
        swatches.appendChild(b);
        return b;
    });

    const noteIn = el('textarea', { placeholder: '备注（选填）', style: 'min-height:64px' });
    noteIn.value = h.note || '';

    const saveSecret = el('input', { type: 'checkbox', checked: h.hasSecret !== false });
    const saveSecretLabel = el('label', { class: 'check' }, [saveSecret, el('span', { text: '把凭据加密保存到 R2（方便一键连接）' })]);

    const body = el('div', { style: 'display:flex;flex-direction:column;gap:12px' }, [
        field('名称', nameIn),
        el('div', { class: 'grid-2' }, [field('分组', groupSel), field('认证方式', seg)]),
        el('div', { class: 'grid-2' }, [field('用户名', userIn), field('端口', portIn)]),
        field('主机地址', hostIn),
        pwBox,
        keyBox,
        el('div', { class: 'grid-2' }, [field('地区', countrySearch), field('城市', cityWrap)]),
        countryGrid,
        el('div', {}, [el('div', { class: 'muted-sm', style: 'margin-bottom:6px', text: '标签颜色' }), swatches]),
        field('备注', noteIn),
        saveSecretLabel,
    ]);

    const submit = async () => {
        const payload = {
            name: nameIn.value.trim(),
            group: groupSel.value === '__new' ? '' : groupSel.value,
            username: userIn.value.trim(),
            host: hostIn.value.trim(),
            port: parseInt(portIn.value, 10) || 22,
            authType,
            country,
            city: cityIn.value.trim(),
            color,
            note: noteIn.value.trim(),
            saveSecret: saveSecret.checked,
        };
        if (!payload.host) {
            toast('主机地址不能为空', 'err');
            return;
        }
        if (!payload.username) {
            toast('用户名不能为空', 'err');
            return;
        }
        if (authType === 'password') {
            if (credId) payload.credId = credId;
            else if (pwIn.value) payload.password = pwIn.value;
        } else if (keyId) {
            payload.keyId = keyId;
        } else {
            if (keyIn.value.trim()) payload.privateKey = keyIn.value.trim();
            if (passIn.value) payload.passphrase = passIn.value;
        }
        if (host) payload.id = host.id;
        const res = await safe(() => api('/api/hosts', { method: 'POST', body: payload }));
        if (!res) return;
        m.close();
        toast(host ? '主机已更新' : '主机已添加');
        await loadHosts();
    };

    const foot = el('div', { style: 'display:flex;gap:8px' }, [
        el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => m.close() }),
        el('button', { class: 'btn primary', type: 'button', text: isNew ? '添加主机' : '保存修改', onclick: submit }),
    ]);

    const m = modal({
        title: isNew ? '添加主机' : '编辑主机',
        body,
        footer: foot,
        width: '620px',
        onClose: () => document.removeEventListener('pointerdown', hideCitySug, true),
    });
}

async function removeHost(host) {
    const ok = await confirmModal('删除主机', '确定删除 <b>' + esc(host.name || host.host) + '</b> 吗？保存的凭据会一并删除，此操作不可撤销。', '删除', true);
    if (!ok) return;
    const res = await safe(() => api('/api/hosts/' + encodeURIComponent(host.id), { method: 'DELETE' }));
    if (!res) return;
    toast('已删除');
    await loadHosts();
}

/* ------------------------------------------------------------------ data */

async function loadHosts() {
    const res = await safe(() => api('/api/hosts'));
    if (!res) return;
    state.hosts = res.hosts || [];
    if (state.filter !== 'all' && !state.hosts.some((h) => h.country === state.filter)) state.filter = 'all';
    renderDash();
    loadGroups();
}

async function loadSnippets() {
    const res = await safe(() => api('/api/snippets'));
    if (!res) return;
    state.snippets = res.snippets || [];
    return state.snippets;
}

async function loadGroups() {
    const res = await safe(() => api('/api/groups'));
    if (!res) return;
    state.groups = res.groups || [];
    return state.groups;
}

async function loadKeys() {
    const res = await safe(() => api('/api/keys'));
    if (!res) return;
    state.keys = res.keys || [];
    return state.keys;
}

async function loadCreds() {
    const res = await safe(() => api('/api/creds'));
    if (!res) return;
    state.creds = res.creds || [];
    return state.creds;
}

/* ---------------------------------------------------------------- groups */

function openGroups() {
    setNav('groups');
    const box = el('div', { class: 'list' });
    const render = () => {
        box.textContent = '';
        const counts = new Map();
        for (const h of state.hosts) {
            const g = String(h.group || '').trim();
            counts.set(g, (counts.get(g) || 0) + 1);
        }
        if (!state.groups.length) {
            box.appendChild(el('div', { class: 'empty-hint', html: '还没有分组。<br>把主机按环境或项目归类，列表会更清爽。' }));
            return;
        }
        for (const g of state.groups) {
            const n = counts.get(g) || 0;
            const edit = el('button', { class: 'act icon-only', type: 'button', title: '重命名', html: icon('edit', 14) });
            edit.addEventListener('click', async () => {
                const name = await promptText('重命名分组', '新的名称', g, '保存');
                if (!name || name === g) return;
                const res = await safe(() => api('/api/groups', { method: 'POST', body: { op: 'rename', from: g, to: name } }));
                if (!res) return;
                state.groups = res.groups || state.groups;
                await loadHosts();
                render();
                toast(res.updated ? '已重命名，' + res.updated + ' 台主机已同步' : '已重命名');
            });
            const del = el('button', { class: 'act icon-only', type: 'button', title: '删除', html: icon('trash', 14) });
            del.addEventListener('click', async () => {
                const ok = await confirmModal(
                    '删除分组',
                    '确定删除 <b>' + esc(g) + '</b> 吗？' + (n ? '组内 ' + n + ' 台主机会移到「未分组」。' : ''),
                    '删除',
                    true
                );
                if (!ok) return;
                const res = await safe(() => api('/api/groups', { method: 'POST', body: { op: 'remove', name: g } }));
                if (!res) return;
                state.groups = res.groups || state.groups;
                await loadHosts();
                render();
                toast(res.moved ? '已删除，' + res.moved + ' 台主机移到未分组' : '已删除');
            });
            box.appendChild(
                el('div', { class: 'list-row' }, [
                    el('span', { class: 'flag', text: '📁' }),
                    el('div', { class: 'grow' }, [el('div', { class: 'ttl', text: g }), el('div', { class: 'mono', text: n + ' 台主机' })]),
                    edit,
                    del,
                ])
            );
        }
    };
    const addBtn = el('button', {
        class: 'btn',
        type: 'button',
        html: icon('plus', 14) + ' 新建分组',
        onclick: async () => {
            const name = await promptText('新建分组', '分组名称', '', '创建');
            if (!name) return;
            const res = await safe(() => api('/api/groups', { method: 'POST', body: { op: 'add', name } }));
            if (!res) return;
            state.groups = res.groups || state.groups;
            render();
            toast('分组已创建');
        },
    });
    modal({
        title: '分组',
        body: el('div', {}, [
            el('p', {
                class: 'note-box',
                style: 'margin:0 0 10px',
                text: '分组用来归类主机；重命名会同步更新组内主机，删除后主机会回到「未分组」。',
            }),
            box,
        ]),
        footer: el('div', { style: 'display:flex;gap:8px;align-items:center;width:100%' }, [addBtn]),
        onClose: () => setNav('overview'),
    });
    render();
    loadGroups().then(render);
}

/* --------------------------------------------------------------- vault */

function openVault() {
    setNav('keys');
    const credBox = el('div', { class: 'list' });
    const keyBox = el('div', { class: 'list' });

    const renderCreds = () => {
        credBox.textContent = '';
        const used = new Map();
        for (const h of state.hosts) {
            if (!h.credId) continue;
            used.set(h.credId, (used.get(h.credId) || 0) + 1);
        }
        if (!state.creds.length) {
            credBox.appendChild(el('div', { class: 'empty-hint', html: '还没有常用账号。<br>把常用的 SSH 用户名和密码存进来，多台主机共用一份。' }));
            return;
        }
        for (const c of state.creds) {
            const n = used.get(c.id) || 0;
            const edit = el('button', { class: 'act icon-only', type: 'button', title: '编辑', html: icon('edit', 14) });
            edit.addEventListener('click', () => credEditor(c, render));
            const del = el('button', { class: 'act icon-only', type: 'button', title: '删除', html: icon('trash', 14) });
            del.addEventListener('click', async () => {
                const ok = await confirmModal(
                    '删除常用账号',
                    '确定删除 <b>' + esc(c.name) + '</b> 吗？' + (n ? '<br>它正被 ' + n + ' 台主机使用，删除后这些主机会连不上。' : ''),
                    '删除',
                    true
                );
                if (!ok) return;
                const res = await safe(() => api('/api/creds/' + encodeURIComponent(c.id), { method: 'DELETE' }));
                if (!res) return;
                state.creds = state.creds.filter((x) => x.id !== c.id);
                render();
                toast('已删除');
            });
            credBox.appendChild(
                el('div', { class: 'list-row' }, [
                    el('span', { class: 'flag', html: icon('user', 18) }),
                    el('div', { class: 'grow' }, [
                        el('div', { class: 'ttl', text: c.name + (n ? '  ·  ' + n + ' 台主机' : '') }),
                        el('div', { class: 'mono', text: c.username }),
                    ]),
                    edit,
                    del,
                ])
            );
        }
    };

    const renderKeys = () => {
        keyBox.textContent = '';
        const used = new Map();
        for (const h of state.hosts) {
            if (!h.keyId) continue;
            used.set(h.keyId, (used.get(h.keyId) || 0) + 1);
        }
        if (!state.keys.length) {
            keyBox.appendChild(el('div', { class: 'empty-hint', html: '还没有私钥。<br>把常用的 SSH 私钥存进来，多台主机可以共用同一把。' }));
            return;
        }
        for (const k of state.keys) {
            const n = used.get(k.id) || 0;
            const edit = el('button', { class: 'act icon-only', type: 'button', title: '编辑', html: icon('edit', 14) });
            edit.addEventListener('click', () => keyEditor(k, render));
            const del = el('button', { class: 'act icon-only', type: 'button', title: '删除', html: icon('trash', 14) });
            del.addEventListener('click', async () => {
                const ok = await confirmModal(
                    '删除密钥',
                    '确定删除 <b>' + esc(k.name) + '</b> 吗？' + (n ? '<br>它正被 ' + n + ' 台主机使用，删除后这些主机会连不上。' : ''),
                    '删除',
                    true
                );
                if (!ok) return;
                const res = await safe(() => api('/api/keys/' + encodeURIComponent(k.id), { method: 'DELETE' }));
                if (!res) return;
                state.keys = state.keys.filter((x) => x.id !== k.id);
                render();
                toast('已删除');
            });
            keyBox.appendChild(
                el('div', { class: 'list-row' }, [
                    el('span', { class: 'flag', text: '🔑' }),
                    el('div', { class: 'grow' }, [
                        el('div', { class: 'ttl', text: k.name + (n ? '  ·  ' + n + ' 台主机' : '') }),
                        el('div', { class: 'mono', text: (k.algo || '') + ' · ' + (k.fingerprint || '') }),
                    ]),
                    edit,
                    del,
                ])
            );
        }
    };

    const render = () => {
        renderCreds();
        renderKeys();
        credCount.textContent = state.creds.length + ' 个';
        keyCount.textContent = state.keys.length + ' 把';
    };

    const credCount = el('span', { class: 'count' });
    const keyCount = el('span', { class: 'count' });

    const addCred = el('button', {
        class: 'btn primary',
        type: 'button',
        html: icon('plus', 14) + ' 常用账号',
        onclick: () => credEditor(null, render),
    });
    const addKey = el('button', {
        class: 'btn',
        type: 'button',
        html: icon('plus', 14) + ' 私钥',
        onclick: () => keyEditor(null, render),
    });

    modal({
        title: '凭据库',
        body: el('div', {}, [
            el('p', {
                class: 'note-box',
                style: 'margin:0 0 14px',
                text: '常用账号和私钥都用 AES-GCM 加密后保存在你的 R2；主机引用后连接时自动解密，无需重复填写。',
            }),
            el('div', { class: 'vault-sec', 'data-sec': 'creds' }, [
                el('div', { class: 'vault-sec-head' }, [el('b', { text: '常用账号' }), credCount]),
                credBox,
            ]),
            el('div', { class: 'vault-sec', 'data-sec': 'keys' }, [
                el('div', { class: 'vault-sec-head' }, [el('b', { text: '私钥' }), keyCount]),
                keyBox,
            ]),
        ]),
        footer: el('div', { style: 'display:flex;gap:8px;align-items:center;width:100%' }, [addCred, addKey]),
        onClose: () => setNav('overview'),
    });
    render();
    Promise.all([loadCreds(), loadKeys()]).then(render);
}

function credEditor(cred, after) {
    const nameIn = el('input', { type: 'text', value: cred ? cred.name : '', placeholder: '例如 生产服务器账号' });
    const userIn = el('input', { type: 'text', value: cred ? cred.username : '', placeholder: 'root', autocomplete: 'off' });
    const pwIn = el('input', {
        type: 'password',
        autocomplete: 'new-password',
        placeholder: cred ? '已保存，留空则不修改' : '登录密码',
    });
    const body = el('div', { style: 'display:flex;flex-direction:column;gap:12px' }, [
        field('名称', nameIn, '在主机设置里用这个名字识别账号'),
        field('用户名', userIn),
        field('密码', pwIn),
        el('p', {
            class: 'note-box',
            style: 'margin:0',
            text: '密码加密保存在你的 R2；引用该账号的主机会使用这里的用户名和密码登录。',
        }),
    ]);
    const foot = el('div', { style: 'display:flex;gap:8px' }, [
        el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => m.close() }),
        el('button', {
            class: 'btn primary',
            type: 'button',
            text: '保存',
            onclick: async () => {
                const name = nameIn.value.trim();
                const username = userIn.value.trim();
                if (!name) {
                    toast('账号名称不能为空', 'err');
                    return;
                }
                if (!username) {
                    toast('用户名不能为空', 'err');
                    return;
                }
                if (!cred && !pwIn.value) {
                    toast('请填写登录密码', 'err');
                    return;
                }
                const payload = { name, username };
                if (cred) payload.id = cred.id;
                if (pwIn.value) payload.password = pwIn.value;
                const res = await safe(() => api('/api/creds', { method: 'POST', body: payload }));
                if (!res) return;
                m.close();
                toast(cred ? '账号已更新' : '账号已添加');
                await loadCreds();
                if (after) after(res.cred);
            },
        }),
    ]);
    const m = modal({ title: cred ? '编辑常用账号' : '新建常用账号', body, footer: foot, width: '520px' });
}

function keyEditor(key, after) {
    const nameIn = el('input', { type: 'text', value: key ? key.name : '', placeholder: '例如 生产服务器密钥' });
    const keyIn = el('textarea', { placeholder: key ? '已保存，留空则不修改' : '-----BEGIN OPENSSH PRIVATE KEY-----', spellcheck: 'false' });
    const passIn = el('input', { type: 'password', autocomplete: 'off', placeholder: '私钥没有口令可留空' });
    const body = el('div', { style: 'display:flex;flex-direction:column;gap:12px' }, [
        field('名称', nameIn),
        key
            ? el('div', { class: 'fp', style: 'font-size:11px;padding:8px 10px', text: (key.algo || '') + ' · ' + (key.fingerprint || '') })
            : null,
        field('私钥（PEM）', keyIn),
        field('私钥口令', passIn),
        el('p', {
            class: 'note-box',
            style: 'margin:0',
            text: '支持 ed25519、RSA（OpenSSH / PEM）；暂不支持带口令的 OpenSSH 私钥和 ECDSA。',
        }),
    ]);
    const foot = el('div', { style: 'display:flex;gap:8px' }, [
        el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => m.close() }),
        el('button', {
            class: 'btn primary',
            type: 'button',
            text: '保存',
            onclick: async () => {
                const name = nameIn.value.trim();
                if (!name) {
                    toast('密钥名称不能为空', 'err');
                    return;
                }
                if (!key && !keyIn.value.trim()) {
                    toast('请粘贴私钥内容', 'err');
                    return;
                }
                const payload = { name };
                if (key) payload.id = key.id;
                if (keyIn.value.trim()) payload.privateKey = keyIn.value.trim();
                if (passIn.value) payload.passphrase = passIn.value;
                const res = await safe(() => api('/api/keys', { method: 'POST', body: payload }));
                if (!res) return;
                m.close();
                toast(key ? '私钥已更新' : '私钥已添加');
                await loadKeys();
                if (after) after(res.key);
            },
        }),
    ]);
    const m = modal({ title: key ? '编辑密钥' : '新建密钥', body, footer: foot, width: '620px' });
}

/* -------------------------------------------------------------- snippets */

function openSnippets(onUse) {
    setNav('snippets');
    const listBox = el('div', { class: 'snip-list' });
    const render = () => {
        listBox.textContent = '';
        if (!state.snippets.length) {
            listBox.appendChild(el('div', { class: 'empty-hint', html: '还没有代码片段。<br>把常用的命令存成片段，之后在终端里一键发送。' }));
            return;
        }
        for (const s of state.snippets) {
            const cmd = el('div', { class: 'cmd', text: s.command });
            const nm = el('div', { class: 'nm', text: s.name });
            const edit = el('button', { class: 'act icon-only', type: 'button', title: '编辑', html: icon('edit', 14) });
            const del = el('button', { class: 'act icon-only', type: 'button', title: '删除', html: icon('trash', 14) });
            const copy = el('button', { class: 'act icon-only', type: 'button', title: '复制', html: icon('copy', 14) });
            copy.addEventListener('click', (ev) => {
                ev.stopPropagation();
                copyText(s.command);
                toast('已复制');
            });
            const row = el('div', { class: 'snip', title: s.command }, [el('div', { class: 'grow', style: 'flex:1;min-width:0' }, [nm, cmd]), copy, edit, del]);
            row.addEventListener('click', (ev) => {
                if (ev.target.closest('button')) return;
                if (onUse) {
                    if (onUse(s.command)) {
                        m.close();
                        toast('已发送：' + s.name);
                    }
                } else {
                    copyText(s.command);
                    toast('已复制到剪贴板');
                }
            });
            edit.addEventListener('click', (ev) => {
                ev.stopPropagation();
                snippetEditor(s, render);
            });
            del.addEventListener('click', async (ev) => {
                ev.stopPropagation();
                state.snippets = state.snippets.filter((x) => x.id !== s.id);
                await persistSnippets();
                render();
            });
            listBox.appendChild(row);
        }
    };
    const addBtn = el('button', { class: 'btn', type: 'button', html: icon('plus', 14) + ' 新建片段', onclick: () => snippetEditor(null, render) });
    const foot = el('div', { style: 'display:flex;gap:8px;align-items:center;width:100%' }, [addBtn]);
    const hint = el('p', {
        class: 'note-box',
        style: 'margin:0 0 10px',
        text: onUse ? '点击片段即可发送到当前会话。' : '点击片段即可复制命令。',
    });
    const m = modal({
        title: '代码片段',
        body: el('div', {}, [hint, listBox]),
        footer: foot,
        onClose: () => setNav(state.nav === 'snippets' ? 'overview' : state.nav),
    });
    render();
    loadSnippets().then(render);
}

function snippetEditor(snippet, after) {
    const nameIn = el('input', { type: 'text', value: snippet ? snippet.name : '', placeholder: '例如 查看磁盘占用' });
    const cmdIn = el('textarea', { placeholder: 'df -h', style: 'min-height:110px' });
    cmdIn.value = snippet ? snippet.command : '';
    const body = el('div', { style: 'display:flex;flex-direction:column;gap:12px' }, [field('名称', nameIn), field('命令', cmdIn)]);
    const foot = el('div', { style: 'display:flex;gap:8px' }, [
        el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => m.close() }),
        el('button', {
            class: 'btn primary',
            type: 'button',
            text: '保存',
            onclick: async () => {
                const command = cmdIn.value.trim();
                if (!command) {
                    toast('命令不能为空', 'err');
                    return;
                }
                const name = nameIn.value.trim() || command.slice(0, 24);
                if (snippet) {
                    snippet.name = name;
                    snippet.command = command;
                } else {
                    state.snippets.push({ id: 's' + Date.now().toString(36), name, command });
                }
                const ok = await persistSnippets();
                if (!ok) return;
                m.close();
                if (after) after();
            },
        }),
    ]);
    const m = modal({ title: snippet ? '编辑片段' : '新建片段', body, footer: foot });
}

async function persistSnippets() {
    const res = await safe(() => api('/api/snippets', { method: 'POST', body: { snippets: state.snippets } }));
    if (!res) return false;
    state.snippets = res.snippets || state.snippets;
    return true;
}

/* ------------------------------------------------------------- known keys */

function openKnown() {
    setNav('known');
    const box = el('div', { class: 'list' });
    const render = (items) => {
        box.textContent = '';
        if (!items.length) {
            box.appendChild(el('div', { class: 'empty-hint', html: '还没有记录。<br>第一次连接某台主机时会询问你是否信任它的主机密钥。' }));
            return;
        }
        for (const k of items) {
            const del = el('button', { class: 'act icon-only', type: 'button', title: '忘记这台主机', html: icon('trash', 14) });
            del.addEventListener('click', async () => {
                const ok = await safe(() => api('/api/known?key=' + encodeURIComponent(k.key), { method: 'DELETE' }));
                if (!ok) return;
                toast('已移除');
                openKnownRefresh();
            });
            box.appendChild(
                el('div', { class: 'list-row' }, [
                    el('span', { class: 'flag', text: '🔑' }),
                    el('div', { class: 'grow' }, [
                        el('div', { class: 'ttl', text: k.host + ':' + k.port + '  ·  ' + (k.type || '') }),
                        el('div', { class: 'mono', text: k.fingerprint || '' }),
                    ]),
                    del,
                ])
            );
        }
    };
    let m;
    const openKnownRefresh = async () => {
        const res = await safe(() => api('/api/known'));
        if (!res) return;
        render(res.known || []);
    };
    m = modal({ title: '主机密钥', body: box, onClose: () => setNav('overview') });
    openKnownRefresh();
}

/* ------------------------------------------------------------------- logs */

function openLogs(host) {
    const box = el('div', { class: 'list' });
    const body = el('div', { style: 'display:flex;flex-direction:column;gap:10px' }, [
        el('p', { class: 'note-box', style: 'margin:0', text: '开启「会话录制」后，每次连接的终端输出都会存到 R2。' }),
        box,
    ]);
    const m = modal({ title: host ? '连接记录 · ' + (host.name || host.host) : '会话日志', body, width: '640px' });

    const show = async (entry) => {
        const text = await safe(async () => {
            const res = await fetch('/api/logs/' + encodeURIComponent(entry.key), { credentials: 'same-origin' });
            if (!res.ok) throw new Error('读取失败 (' + res.status + ')');
            return res.text();
        });
        if (text == null) return;
        const pre = el('pre', { class: 'fp', style: 'margin:0;max-height:58vh', text: text });
        body.textContent = '';
        body.appendChild(
            el('div', { style: 'display:flex;align-items:center;gap:8px;flex-wrap:wrap' }, [
                el('span', { class: 'muted-sm', text: (entry.user || '') + '@' + entry.host + ':' + entry.port + ' · ' + fmtDate(entry.started || entry.uploaded) }),
                el('span', { style: 'flex:1' }),
                el('button', {
                    class: 'btn',
                    type: 'button',
                    html: icon('copy', 14) + ' 复制',
                    onclick: () => {
                        copyText(text);
                        toast('已复制');
                    },
                }),
                el('button', { class: 'btn', type: 'button', text: '返回列表', onclick: () => m.close() }),
            ])
        );
        body.appendChild(pre);
    };

    (async () => {
        const res = await safe(() => api('/api/logs'));
        if (!res) return;
        let items = res.logs || [];
        if (host) items = items.filter((l) => l.host === host.host && String(l.port || 22) === String(host.port || 22));
        box.textContent = '';
        if (!items.length) {
            box.appendChild(el('div', { class: 'empty-hint', text: '还没有会话记录。' }));
            return;
        }
        for (const it of items) {
            const row = el('div', { class: 'list-row', style: 'cursor:pointer' }, [
                el('span', { class: 'flag', text: '📄' }),
                el('div', { class: 'grow' }, [
                    el('div', { class: 'ttl', text: (it.user || '') + '@' + it.host + ':' + it.port }),
                    el('div', { class: 'mono', text: fmtDate(it.started || it.uploaded) + ' · ' + fmtBytes(it.size) }),
                ]),
                el('span', { class: 'muted-sm', text: timeAgo(it.uploaded) }),
            ]);
            row.addEventListener('click', () => show(it));
            box.appendChild(row);
        }
    })();
}

/* --------------------------------------------------------------- settings */

function openSettings() {
    setNav('settings');
    const sizeIn = el('input', { type: 'range', min: '11', max: '20', step: '1', value: String(state.settings.fontSize), style: 'flex:1' });
    const sizeVal = el('span', { class: 'muted-sm', style: 'white-space:nowrap;min-width:44px;text-align:right', text: state.settings.fontSize + ' px' });
    sizeIn.addEventListener('input', () => {
        sizeVal.textContent = sizeIn.value + ' px';
    });
    const recordIn = el('input', { type: 'checkbox', checked: !!state.settings.record });

    const curIn = el('input', { type: 'password', autocomplete: 'current-password' });
    const nextIn = el('input', { type: 'password', autocomplete: 'new-password', placeholder: '至少 8 位' });
    const pwMsg = el('p', { class: 'form-error', style: 'margin:0' });

    const body = el('div', { style: 'display:flex;flex-direction:column;gap:16px' }, [
        el('div', { style: 'display:flex;flex-direction:column;gap:8px' }, [
            el('div', { class: 'muted-sm', text: '终端字号' }),
            el('div', { style: 'display:flex;align-items:center;gap:10px' }, [sizeIn, sizeVal]),
        ]),
        el('label', { class: 'check' }, [recordIn, el('span', { text: '默认录制会话输出（保存在 R2，可随时回看）' })]),
        el('hr', { style: 'border:0;border-top:1px solid #f0ebe2;margin:2px 0' }),
        el('div', { class: 'eyebrow', style: 'margin:0', text: 'CHANGE PASSWORD' }),
        field('当前密码', curIn),
        field('新密码', nextIn),
        pwMsg,
        el('div', { class: 'muted-sm', text: '账号：' + (state.user || 'admin') + ' · WebSSH v1.0.0 · 数据保存在你自己的 R2' }),
    ]);

    const foot = el('div', { style: 'display:flex;gap:8px;width:100%;justify-content:space-between' }, [
        el('button', {
            class: 'btn',
            type: 'button',
            text: '修改密码',
            onclick: async () => {
                pwMsg.textContent = '';
                if (!nextIn.value || nextIn.value.length < 8) {
                    pwMsg.textContent = '新密码至少 8 位';
                    return;
                }
                const res = await safe(() => api('/api/password', { method: 'POST', body: { current: curIn.value, next: nextIn.value } }));
                if (!res) return;
                curIn.value = '';
                nextIn.value = '';
                toast('密码已更新');
            },
        }),
        el('button', {
            class: 'btn primary',
            type: 'button',
            text: '保存设置',
            onclick: () => {
                state.settings.fontSize = Number(sizeIn.value) || 13;
                state.settings.record = recordIn.checked;
                saveSettings();
                if (state.term) state.term.setFontSize(state.settings.fontSize);
                m.close();
                toast('设置已保存');
            },
        }),
    ]);

    const m = modal({ title: '设置', body, footer: foot, onClose: () => setNav(state.nav === 'settings' ? 'overview' : state.nav) });
}

/* ----------------------------------------------------------- quick connect */

function openQuickConnect() {
    setNav('quick');
    const userIn = el('input', { type: 'text', value: 'root', autocomplete: 'off' });
    const hostIn = el('input', { type: 'text', name: 'host', placeholder: 'example.com、192.0.2.10 或 2001:db8::1', spellcheck: 'false' });
    const portIn = el('input', { type: 'number', value: '22', min: '1', max: '65535' });
    const pwIn = el('input', { type: 'password', autocomplete: 'off', placeholder: '登录密码' });
    const keyIn = el('textarea', { placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----', spellcheck: 'false' });
    const passIn = el('input', { type: 'password', placeholder: '私钥没有口令可留空' });

    let authType = 'password';
    const segPw = el('button', { type: 'button', class: 'on', text: '密码' });
    const segKey = el('button', { type: 'button', text: '私钥' });
    const seg = el('div', { class: 'seg' }, [segPw, segKey]);
    const pwBox = el('div', {}, [field('密码', pwIn)]);
    const keyBox = el('div', { hidden: true }, [field('私钥（PEM）', keyIn), field('私钥口令', passIn)]);
    segPw.addEventListener('click', () => {
        authType = 'password';
        segPw.classList.add('on');
        segKey.classList.remove('on');
        pwBox.hidden = false;
        keyBox.hidden = true;
    });
    segKey.addEventListener('click', () => {
        authType = 'key';
        segKey.classList.add('on');
        segPw.classList.remove('on');
        pwBox.hidden = true;
        keyBox.hidden = false;
    });

    const saveIn = el('input', { type: 'checkbox' });
    const body = el('div', { style: 'display:flex;flex-direction:column;gap:12px' }, [
        el('div', { class: 'grid-2' }, [field('用户名', userIn), field('端口', portIn)]),
        field('主机地址', hostIn),
        el('div', { class: 'grid-2' }, [field('认证方式', seg), el('div')]),
        pwBox,
        keyBox,
        el('label', { class: 'check' }, [saveIn, el('span', { text: '同时保存到「我的主机」' })]),
    ]);

    const submit = async () => {
        const host = hostIn.value.trim();
        const username = userIn.value.trim();
        const port = parseInt(portIn.value, 10) || 22;
        if (!host || !username) {
            toast('主机和用户名都不能为空', 'err');
            return;
        }
        const secret = authType === 'password' ? { password: pwIn.value } : { privateKey: keyIn.value.trim(), passphrase: passIn.value };
        if (authType === 'password' && !pwIn.value) {
            toast('请输入密码', 'err');
            return;
        }
        if (authType === 'key' && !secret.privateKey) {
            toast('请粘贴私钥', 'err');
            return;
        }
        m.close();
        showTerm();
        if (saveIn.checked) {
            const res = await safe(() =>
                api('/api/hosts', {
                    method: 'POST',
                    body: { name: username + '@' + host, host, port, username, authType, saveSecret: true, ...secret },
                })
            );
            if (res && res.host) {
                await loadHosts();
                state.term.open({ hostId: res.host.id, name: res.host.name, host, port, username });
                return;
            }
        }
        state.term.open(Object.assign({ name: username + '@' + host, host, port, username }, secret));
    };

    const foot = el('div', { style: 'display:flex;gap:8px' }, [
        el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => m.close() }),
        el('button', { class: 'btn primary', type: 'button', text: '连接', onclick: submit }),
    ]);

    const m = modal({ title: '快速连接', body, footer: foot, onClose: () => setNav(state.nav === 'quick' ? 'overview' : state.nav) });
}

/* -------------------------------------------------------------- bootstrap */

function enterApp() {
    state.authed = true;
    if (!state.term) {
        state.term = createTerminalView({
            getSettings: () => state.settings,
            onBack: showDash,
            onSettings: openSettings,
            onLogout: logout,
            onSnippets: (useFn) => openSnippets(useFn),
            onFiles: (session) =>
                openFiles({
                    title: '文件管理 · ' + (session.name || session.host || '会话'),
                    request: (payload, timeout) => state.term.sftpRequest(session, payload, timeout),
                }),
            onLogs: (session) => {
                const host = session && session.hostId ? state.hosts.find((h) => h.id === session.hostId) : null;
                openLogs(host || null);
            },
            onEmpty: showDash,
        });
        state.term.init();
    }
    showDash();
    loadHosts();
    loadSnippets();
    loadKeys();
    loadCreds();
}

async function logout() {
    await safe(() => api('/api/logout', { method: 'POST' }));
    state.authed = false;
    if (state.term) {
        for (const s of state.term.sessions().slice()) state.term.close(s.id);
    }
    showAuth('login');
}

function bindStatic() {
    bindAuth();

    const addBtn = $('#btn-add-host');
    if (addBtn) addBtn.addEventListener('click', () => openHostEditor(null));
    const refresh = $('#btn-refresh');
    if (refresh) refresh.addEventListener('click', () => loadHosts());

    $$('.rail-item[data-nav]').forEach((btn) => {
        btn.addEventListener('click', () => {
            const nav = btn.dataset.nav;
            if (nav === 'overview') {
                setNav('overview');
                showDash();
            } else if (nav === 'groups') openGroups();
            else if (nav === 'snippets') openSnippets(state.term && !$('#view-term').hidden ? (cmd) => state.term.sendToActive(cmd) : null);
            else if (nav === 'quick') openQuickConnect();
            else if (nav === 'known') openKnown();
            else if (nav === 'keys') openVault();
            else if (nav === 'settings') openSettings();
            else if (nav === 'logout') logout();
        });
    });

    window.addEventListener('resize', () => {
        if (!$('#view-dash').hidden && state.globe) state.globe.nudge();
    });
}

async function boot() {
    loadSettings();
    bindStatic();
    let info = null;
    try {
        info = await api('/api/state');
    } catch (e) {
        toast('无法连接服务器：' + e.message, 'err');
    }
    hideBoot();
    if (!info) {
        showAuth('login');
        return;
    }
    state.setup = !!info.setup;
    state.authed = !!info.authed;
    state.user = info.user || info.username || '';
    if (!state.setup) showAuth('setup');
    else if (!state.authed) showAuth('login');
    else enterApp();
}

boot();
