/* Terminal view: tabs, panes, websocket sessions, live host metrics, key bar. */

import { $, el, icon, toast, modal, confirmModal, fmtBytes, fmtRate, fmtUptime, copyText } from './ui.js';
import { LONG_PRESS_MS, LONG_PRESS_JITTER, MOVE_TOLERANCE, gestureIntent, shouldBlockPullToRefresh, isTapLike, cellAt, selectionRows, joinLines } from './touch-select.js';

const THEME = {
    background: '#070910',
    foreground: '#d6dbe4',
    cursor: '#ff7a4d',
    cursorAccent: '#070910',
    selectionBackground: 'rgba(255, 122, 77, 0.26)',
    black: '#171b22',
    red: '#ff7a70',
    green: '#5ddb8b',
    yellow: '#e8c07d',
    blue: '#7fb2ff',
    magenta: '#c9a0f0',
    cyan: '#5fd8e0',
    white: '#c8cfdb',
    brightBlack: '#5c6679',
    brightRed: '#ffa39a',
    brightGreen: '#8df0b3',
    brightYellow: '#f6d79c',
    brightBlue: '#a9caff',
    brightMagenta: '#dfc2f8',
    brightCyan: '#96eaf0',
    brightWhite: '#f4f7fb',
};

const FONT_STACK = 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace';

// 单条输入上限：服务端 handleMessage 只收 1MB 以内的 data，超过就整条丢弃
const INPUT_CHUNK = 64 * 1024;

const KEYS = [
    { label: 'Ctrl', mod: 'ctrl' },
    { label: 'Alt', mod: 'alt' },
    { label: 'Tab', send: '\t' },
    { label: 'Esc', send: '\x1b' },
    { label: '↑', arrow: 'A' },
    { label: '↓', arrow: 'B' },
    { label: '←', arrow: 'D' },
    { label: '→', arrow: 'C' },
    { label: 'Ctrl+C', send: '\x03' },
    { label: 'Ctrl+D', send: '\x04' },
    { label: 'PgUp', send: '\x1b[5~' },
    { label: 'PgDn', send: '\x1b[6~' },
    { label: 'Home', send: '\x1b[H' },
    { label: 'End', send: '\x1b[F' },
    { label: 'Del', send: '\x1b[3~' },
];

const SHORTCUTS = [
    ['Ctrl + Shift + C', '复制选中内容'],
    ['Ctrl + Shift + V', '粘贴剪贴板'],
    ['右键', '粘贴剪贴板'],
    ['Ctrl + Shift + F', '全屏切换'],
    ['Ctrl + Shift + R', '重新连接当前会话'],
    ['Alt + 数字', '切换到第 N 个标签'],
    ['Ctrl + Shift + W', '关闭当前会话'],
    ['触屏长按 + 拖动', '选择文本并复制'],
];

export function createTerminalView(cfg) {
    const c = cfg || {};
    const state = {
        sessions: [],
        activeId: null,
        seq: 0,
        ctrl: false,
        alt: false,
    };
    let bound = false;
    // 当前挂在 #hb-stats 里的是哪个会话的监控 DOM
    let statsMountedFor = null;

    const panesEl = $('#panes');
    const tabsEl = $('#tabs');

    /* ------------------------------------------------------------ helpers */

    function active() {
        return state.sessions.find((s) => s.id === state.activeId) || null;
    }

    function send(s, obj) {
        if (!s || !s.ws || s.ws.readyState !== 1) return false;
        try {
            s.ws.send(JSON.stringify(obj));
            return true;
        } catch (_) {
            return false;
        }
    }

    function sendInput(s, data) {
        if (!data) return;
        if (data.length <= INPUT_CHUNK) {
            send(s, { t: 'input', data });
            return;
        }
        // 一次粘贴好几 MB 时，服务端按单条 1MB 上限整条丢弃（表现是「什么都没发生」）。
        // 这里分片发送：顺序不变，也不丢内容；边界避开代理对，免得 emoji 变成 U+FFFD。
        let i = 0;
        while (i < data.length) {
            let end = Math.min(data.length, i + INPUT_CHUNK);
            if (end < data.length) {
                const code = data.charCodeAt(end - 1);
                if (code >= 0xd800 && code <= 0xdbff) end--;
            }
            send(s, { t: 'input', data: data.slice(i, end) });
            i = end;
        }
    }

    /* ------------------------------------------------------------- paste */

    // 粘两行以上要先确认。
    //
    // 从文档/聊天窗口复制命令时，剪贴板里常常顺带带上换行，粘进去就等于
    // 直接回车执行 —— 粘错窗口（比如粘到 root 的会话里）就是一条 rm -rf。
    // 单行粘贴（复制一个路径、一个 token）不打扰。
    async function pasteInto(s, text) {
        const raw = String(text || '');
        if (!raw) return;
        const lines = raw.replace(/\r\n?/g, '\n').split('\n');
        // 末尾的空串只表示「最后一行以换行结尾」，不算多出来的一行
        const count = lines[lines.length - 1] === '' ? lines.length - 1 : lines.length;
        if (count >= 2) {
            // 这里只放数字，不把剪贴板内容塞进弹窗（confirmModal 的 text 是 innerHTML）
            const ok = await confirmModal(
                '粘贴多行内容',
                `剪贴板里有 <b>${count}</b> 行文本，粘进去会逐行执行。确认当前窗口和主机没错再继续。`,
                '粘贴执行',
                true
            );
            if (!ok) return;
        }
        sendInput(s, raw.replace(/\r?\n/g, '\r'));
    }

    /* ------------------------------------------------------------- sftp */

    function sftpRequest(s, payload, timeoutMs) {
        return new Promise((resolve, reject) => {
            if (!s || !s.ws || s.ws.readyState !== 1) {
                reject(new Error('会话尚未就绪'));
                return;
            }
            const id = 'q' + ++s.sftpSeq;
            const timer = setTimeout(() => {
                s.sftpPending.delete(id);
                reject(new Error('文件操作超时'));
            }, timeoutMs || 30000);
            s.sftpPending.set(id, {
                resolve: (v) => {
                    clearTimeout(timer);
                    s.sftpPending.delete(id);
                    resolve(v);
                },
                reject: (e) => {
                    clearTimeout(timer);
                    s.sftpPending.delete(id);
                    reject(e);
                },
            });
            try {
                s.ws.send(JSON.stringify(Object.assign({ t: 'sftp', id }, payload)));
            } catch (e) {
                clearTimeout(timer);
                s.sftpPending.delete(id);
                reject(e);
            }
        });
    }

    function failSftp(s, reason) {
        if (!s || !s.sftpPending) return;
        for (const p of s.sftpPending.values()) p.reject(new Error(reason));
        s.sftpPending.clear();
    }

    function sysLine(s, text, color) {
        const col = color || '38;5;245';
        // 服务端的多行错误用 \n 分隔，而 xterm 只认 \r\n：不转换的话后几行会阶梯状错位
        const body = String(text == null ? '' : text).replace(/\r?\n/g, '\r\n');
        s.term.write('\r\n\x1b[' + col + 'm· ' + body + '\x1b[0m\r\n');
    }

    function fontSize() {
        return (c.getSettings && c.getSettings().fontSize) || 13;
    }

    /* -------------------------------------------------------------- tabs */

    function renderTabs() {
        tabsEl.textContent = '';
        for (const s of state.sessions) {
            const dot = el('span', { class: 'd ' + (s.status === 'ready' ? '' : s.status === 'err' ? 'err' : 'wait') });
            const lbl = el('span', { class: 'lbl', text: s.name || s.host || '会话' });
            const x = el('button', { class: 'x', type: 'button', html: '&times;', title: '关闭' });
            const tab = el('div', { class: 'ttab' + (s.id === state.activeId ? ' on' : ''), title: s.name }, [dot, lbl, x]);
            tab.addEventListener('click', () => setActive(s.id));
            x.addEventListener('click', (ev) => {
                ev.stopPropagation();
                closeSession(s.id);
            });
            s.tabEl = tab;
            tabsEl.appendChild(tab);
        }
        const count = $('#pane-count');
        if (count) count.textContent = state.sessions.length ? state.sessions.length + ' 个会话' : '';
    }

    function updateTab(s) {
        if (!s.tabEl) return;
        const dot = s.tabEl.querySelector('.d');
        if (dot) dot.className = 'd ' + (s.status === 'ready' ? '' : s.status === 'err' ? 'err' : 'wait');
    }

    /* --------------------------------------------------------- host bar */

    function renderHostbar() {
        const s = active();
        const dot = $('#hb-dot');
        const title = $('#hb-title');
        const osEl = $('#hb-os');
        const statsEl = $('#hb-stats');
        if (!s) {
            if (dot) dot.className = 'hb-dot';
            if (title) title.textContent = '—';
            if (osEl) osEl.textContent = '';
            if (statsEl) statsEl.textContent = '';
            statsMountedFor = null;
            return;
        }
        if (dot) dot.className = 'hb-dot' + (s.status === 'ready' ? '' : s.status === 'err' ? ' err' : ' wait');
        if (title) {
            title.textContent = s.name || s.host || '会话';
            title.title = (s.username ? s.username + '@' : '') + (s.host || '') + (s.port ? ':' + s.port : '');
        }
        if (osEl) {
            const bits = [];
            if (s.os) {
                bits.push(s.os.pretty || [s.os.system, s.os.release].filter(Boolean).join(' ') || '');
                if (s.os.arch) bits.push(s.os.arch);
            } else if (s.status === 'wait') {
                bits.push('正在建立连接 …');
            }
            if (s.stats && s.stats.uptime) bits.push('已运行 ' + fmtUptime(s.stats.uptime));
            osEl.textContent = bits.filter(Boolean).join(' · ');
        }
        if (statsEl) buildStats(s);
    }

    function buildStats(s) {
        const box = $('#hb-stats');
        if (!box) return;
        // 判断「这块 DOM 现在挂的是哪个会话」，而不是「这个会话以前建过 DOM」。
        // 后者在切换标签时会踩坑：A 的 _statsFor 仍是 A，但盒子里已经是 B 的节点，
        // 于是 updateStats(A) 往一堆已经脱离文档的节点里写，界面上永远是 B 的旧数字。
        if (statsMountedFor === s.id && box.firstChild) {
            updateStats(s);
            return;
        }
        statsMountedFor = s.id;
        box.textContent = '';
        const mk = (label, optional) => {
            const wrap = el('div', { class: 'stat' + (optional ? ' optional' : '') }, [el('span', { class: 'k', text: label })]);
            const v = el('span', { class: 'v' });
            wrap.appendChild(v);
            box.appendChild(wrap);
            return v;
        };
        s._ui = {
            cpu: mk('CPU'),
            mem: mk('MEM', true),
            net: mk('NET', true),
            rtt: mk('RTT', true),
        };
        updateStats(s);
    }

    function bar(pct) {
        const p = Math.max(0, Math.min(100, Number(pct) || 0));
        const cls = p >= 90 ? 'crit' : p >= 70 ? 'warn' : '';
        return '<span class="bar"><i class="' + cls + '" style="width:' + p.toFixed(0) + '%"></i></span>';
    }

    function spark(hist) {
        const w = 54;
        const h = 16;
        if (!hist || hist.length < 2) return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '"></svg>';
        const step = w / Math.max(1, hist.length - 1);
        const pts = hist
            .map((v, i) => (i * step).toFixed(1) + ',' + (h - 1 - (Math.max(0, Math.min(100, v)) / 100) * (h - 2)).toFixed(1))
            .join(' ');
        const last = hist[hist.length - 1];
        const color = last >= 90 ? '#f85149' : last >= 70 ? '#d29922' : '#3fb950';
        return (
            '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
            '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="1.2" ' +
            'stroke-linejoin="round" stroke-linecap="round" opacity="0.9"/></svg>'
        );
    }

    function updateStats(s) {
        const ui = s._ui;
        if (!ui) return;
        const st = s.stats;
        if (s.statsOff) {
            ui.cpu.innerHTML = '<span class="dim">不可用</span>';
            ui.mem.textContent = '';
            ui.net.textContent = '';
            ui.rtt.textContent = '';
            return;
        }
        if (!st) {
            ui.cpu.innerHTML = '<span class="dim">等待采样…</span>';
            ui.mem.textContent = '';
            ui.net.textContent = '';
            ui.rtt.textContent = '';
        } else {
            if (typeof st.cpu === 'number') {
                ui.cpu.innerHTML = bar(st.cpu) + ' ' + st.cpu + '%' + spark(s.hist);
            } else {
                ui.cpu.innerHTML = bar(0) + ' <span class="dim">—</span>';
            }
            if (st.mem) {
                ui.mem.innerHTML = bar(st.mem.pct) + ' ' + st.mem.pct + '% <span class="dim">' + fmtBytes(st.mem.used) + '/' + fmtBytes(st.mem.total) + '</span>';
            }
            if (st.net) {
                ui.net.innerHTML = '↓' + fmtRate(st.net.rx) + ' <span class="dim">↑' + fmtRate(st.net.tx) + '</span>';
            } else {
                ui.net.innerHTML = '<span class="dim">—</span>';
            }
            if (st.load && st.load.length) {
                ui.net.title = 'load ' + st.load.map((n) => n.toFixed(2)).join(' / ');
            }
        }
        ui.rtt.innerHTML = s.rtt == null ? '<span class="dim">—</span>' : s.rtt + ' ms';
    }

    /* ------------------------------------------------- touch selection */

    // xterm 是 canvas 渲染，没有原生文本选择；它公开的 select() 又会被自己的
    // SelectionService 中途清掉（触屏上表现为「一拖选区就没了」）。
    // 所以这里干脆不依赖 xterm 的选区：
    //   · 高亮自己画（.tsel-layer 里的 .tsel-row）
    //   · 文字自己从 buffer 取（translateToString(trim, fromCol, endCol)）
    // 这样无论 xterm 在触摸事件里做什么，选区和复制都不受影响。
    let touchSel = null;        // { s, id, x0, y0, x, y, t0, start, end, active, timer, all }
    let suppressUntil = 0;      // 长按期间抑制 contextmenu（移动端长按会派发它）
    let suppressMouseUntil = 0; // 抑制浏览器合成的鼠标事件，免得 xterm 重开鼠标选择
    let lastTouchAt = 0;        // 兜底：系统 contextmenu 可能早于长按阈值派发
    let selBar = null;          // 「复制 / 全选 / 取消」浮动条，挂在 .term-body 上

    function ensureSelLayer(s) {
        if (s.selLayer && s.selLayer.parentNode === s.pane) return s.selLayer;
        const layer = el('div', { class: 'tsel-layer' });
        s.pane.appendChild(layer);
        s.selLayer = layer;
        return layer;
    }

    function ensureSelBar() {
        if (selBar) return selBar;
        const body = $('.term-body');
        if (!body) return null;
        const mk = (label, cls, fn) => {
            const b = el('button', { type: 'button', class: cls || '', text: label });
            b.addEventListener('click', (ev) => {
                ev.stopPropagation();
                fn();
            });
            return b;
        };
        selBar = el('div', { class: 'sel-bar' }, [
            mk('复制', 'primary', copySelection),
            mk('全选', '', () => {
                const sel = touchSel;
                if (!sel) return;
                // 全选交给 xterm 自己（一次性操作，不怕被清），复制时走 getSelection()
                sel.all = true;
                renderSel(sel);
                try {
                    sel.s.term.selectAll();
                } catch (_) {}
                toast('已全选当前缓冲区，点「复制」即可');
            }),
            mk('取消', '', clearTouchSelection),
        ]);
        body.appendChild(selBar);
        return selBar;
    }

    function showSelBar(clientX, clientY) {
        const bar = ensureSelBar();
        const body = $('.term-body');
        if (!bar || !body) return;
        const box = body.getBoundingClientRect();
        bar.classList.add('on');
        const w = bar.offsetWidth || 210;
        const h = bar.offsetHeight || 40;
        const left = Math.max(8, Math.min(box.width - w - 8, clientX - box.left - w / 2));
        const top = Math.max(8, Math.min(box.height - h - 8, clientY - box.top - h - 14));
        bar.style.left = left + 'px';
        bar.style.top = top + 'px';
    }

    function hideSelBar() {
        if (selBar) selBar.classList.remove('on');
    }

    async function copySelection() {
        const sel = touchSel;
        if (!sel) return;
        const text = sel.all ? sel.s.term.getSelection() : selText(sel);
        if (!text) {
            toast('没有选中内容', 'err');
            return;
        }
        try {
            await copyText(text);
            toast('已复制 ' + text.length + ' 个字符');
            clearTouchSelection();
        } catch (e) {
            toast('复制失败：' + String((e && e.message) || e), 'err');
        }
    }

    function clearTouchSelection() {
        if (touchSel && touchSel.s) {
            if (touchSel.timer) clearTimeout(touchSel.timer);
            const s = touchSel.s;
            try {
                s.term.clearSelection();
            } catch (_) {}
            if (s.selLayer) s.selLayer.textContent = '';
        }
        touchSel = null;
        // 长按中途取消时别让两个抑制窗口残留太久
        if (suppressUntil > Date.now() + 1000) suppressUntil = Date.now() + 500;
        if (suppressMouseUntil > Date.now() + 1000) suppressMouseUntil = Date.now() + 500;
        hideSelBar();
    }

    function screenRect(s) {
        const node = s.term.element && s.term.element.querySelector('.xterm-screen');
        return (node || s.pane).getBoundingClientRect();
    }

    function cellSize(s) {
        const rect = screenRect(s);
        const cols = s.term.cols || 0;
        const rows = s.term.rows || 0;
        const w = cols > 0 ? rect.width / cols : 0;
        const h = rows > 0 ? rect.height / rows : 0;
        return w > 0 && h > 0 ? { w, h, rect } : null;
    }

    // 自己画高亮：一行一个矩形，坐标全部换算成相对 .pane 的像素
    function renderSel(sel) {
        const s = sel && sel.s;
        if (!s || !s.term) return;
        const layer = ensureSelLayer(s);
        layer.textContent = '';
        if (sel.all || !sel.start || !sel.end) return;
        const size = cellSize(s);
        if (!size) return;
        const box = s.pane.getBoundingClientRect();
        const ox = size.rect.left - box.left;
        const oy = size.rect.top - box.top;
        const frag = document.createDocumentFragment();
        for (const sp of selectionRows(s.term.cols, sel.start, sel.end)) {
            const d = el('div', { class: 'tsel-row' });
            d.style.left = ox + sp.from * size.w + 'px';
            d.style.top = oy + sp.row * size.h + 'px';
            d.style.width = (sp.to - sp.from + 1) * size.w + 'px';
            d.style.height = size.h + 'px';
            frag.appendChild(d);
        }
        layer.appendChild(frag);
    }

    // 自己取文字：视口第 N 行 = 缓冲区第 viewportY + N 行
    function selText(sel) {
        const s = sel && sel.s;
        if (!s || sel.all || !sel.start || !sel.end) return '';
        const buf = s.term.buffer && s.term.buffer.active;
        if (!buf) return '';
        const parts = [];
        const spans = selectionRows(s.term.cols, sel.start, sel.end);
        for (let i = 0; i < spans.length && i < 800; i++) {
            const sp = spans[i];
            const line = buf.getLine(buf.viewportY + sp.row);
            const text = line ? line.translateToString(true, sp.from, sp.to + 1) : '';
            parts.push({ text, wrapped: !!(line && line.isWrapped) });
        }
        return joinLines(parts);
    }

    function beginTouchSelection(sel) {
        const s = sel.s;
        if (!s || !s.term || touchSel !== sel) return;
        sel.active = true;
        sel.all = false;
        // 覆盖整个选择过程；松开后由 endTouchSelection 收窄到 900ms
        suppressUntil = Date.now() + 10000;
        // 这里刻意不 blur()：收起软键盘会触发 resize，行列重排会让刚算好的坐标失效
        const rect = screenRect(s);
        sel.start = cellAt(rect, s.term.cols, s.term.rows, sel.x0, sel.y0);
        sel.end = sel.start;
        renderSel(sel);
    }

    function updateTouchSelection(sel, x, y) {
        if (!sel.start) return;
        sel.end = cellAt(screenRect(sel.s), sel.s.term.cols, sel.s.term.rows, x, y);
        renderSel(sel);
    }

    function endTouchSelection(sel) {
        if (sel.timer) clearTimeout(sel.timer);
        sel.timer = null;
        if (!sel.active) {
            if (touchSel === sel) touchSel = null;
            return;
        }
        sel.active = false;
        suppressUntil = Date.now() + 900;
        // 先按当前几何把文字取出来，再收软键盘：blur 会触发 resize，
        // 行列一重排，之前算好的坐标就作废了。
        const text = sel.all ? sel.s.term.getSelection() : selText(sel);
        try {
            sel.s.term.blur();
        } catch (_) {}
        if (text) {
            showSelBar(sel.x, sel.y);
            // 键盘收起后视口变大，高亮按新几何再画一次
            requestAnimationFrame(() => {
                if (touchSel === sel) renderSel(sel);
            });
        } else {
            clearTouchSelection();
        }
    }

    function bindTouchSelection() {
        const view = $('#view-term');
        if (!view) return;

        const pointInPane = (x, y) => {
            const s = active();
            if (!s || !s.pane || view.hidden) return null;
            const r = s.pane.getBoundingClientRect();
            if (x < r.left || x > r.right || y < r.top || y > r.bottom) return null;
            return s;
        };

        const evPoint = (ev) => {
            const t = ev.touches && ev.touches[0];
            return t ? { x: t.clientX, y: t.clientY } : { x: ev.clientX || 0, y: ev.clientY || 0 };
        };

        const hitSession = (ev) => {
            // 浮动条自己的点击不参与选择手势
            if (selBar && ev.target && selBar.contains(ev.target)) return null;
            // 手势进行中不要再按坐标判定：手指可能已经拖出终端区域
            if (touchSel && touchSel.s && touchSel.active) return touchSel.s;
            const p = evPoint(ev);
            return pointInPane(p.x, p.y);
        };

        // 全部挂在 document 的捕获阶段：比 xterm 绑在 canvas / viewport / textarea 上的
        // 任何监听都早，它 cancel(e) / stopPropagation 也掐不到我们。
        const DOC = { capture: true, passive: false };

        // 移动端长按会派发 contextmenu：拦掉，否则会触发「右键粘贴」与多行确认弹窗
        document.addEventListener(
            'contextmenu',
            (ev) => {
                if (!hitSession(ev)) return;
                if (Date.now() < suppressUntil || Date.now() - lastTouchAt < 1500) {
                    ev.preventDefault();
                    ev.stopPropagation();
                }
            },
            DOC
        );

        // 选择期间浏览器会合成 mousedown / mouseup：xterm 的 mousedown 会 focus() 并让
        // SelectionService 重开一次鼠标选择。不拦 click，避免影响按钮与正常聚焦。
        const blockMouse = (ev) => {
            if (Date.now() >= suppressMouseUntil) return;
            if (selBar && ev.target && selBar.contains(ev.target)) return;
            if (!hitSession(ev)) return;
            ev.preventDefault();
            ev.stopPropagation();
        };
        document.addEventListener('mousedown', blockMouse, true);
        document.addEventListener('mouseup', blockMouse, true);

        document.addEventListener(
            'touchstart',
            (ev) => {
                const s = hitSession(ev);
                if (!s) return;
                lastTouchAt = Date.now();
                if (ev.touches.length !== 1) {
                    clearTouchSelection();
                    return;
                }
                const t = ev.touches[0];
                // 关键：从 touchstart 就把浏览器原生手势挡在门外（长按菜单、放大镜、
                // 合成鼠标事件），这样按在「字」上和按在「空白」上走的是同一条路。
                // 只 preventDefault，不 stopPropagation：xterm 用 JS 改 scrollTop 照常滚动。
                if (ev.cancelable) ev.preventDefault();
                clearTouchSelection();
                const sel = {
                    s,
                    id: t.identifier,
                    x0: t.clientX,
                    y0: t.clientY,
                    x: t.clientX,
                    y: t.clientY,
                    t0: Date.now(),
                    start: null,
                    end: null,
                    active: false,
                    all: false,
                    mode: '',
                    timer: null,
                };
                touchSel = sel;
                suppressMouseUntil = 0;
                sel.timer = setTimeout(() => {
                    if (touchSel !== sel || sel.active) return;
                    beginTouchSelection(sel);
                    suppressMouseUntil = Date.now() + 10000;
                }, LONG_PRESS_MS);
            },
            DOC
        );

        document.addEventListener(
            'touchmove',
            (ev) => {
                const sel = touchSel;
                if (!sel) return;
                const t = Array.from(ev.touches).find((p) => p.identifier === sel.id);
                if (!t) return;
                sel.x = t.clientX;
                sel.y = t.clientY;

                if (sel.active) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    updateTouchSelection(sel, t.clientX, t.clientY);
                    return;
                }

                const dx = t.clientX - sel.x0;
                const dy = t.clientY - sel.y0;
                // 手指一动就撤掉长按计时器：只有「真的停住」才算长按，
                // 否则慢慢滑出去想滚历史，会被误判成选字。
                if (sel.timer && (Math.abs(dx) > LONG_PRESS_JITTER || Math.abs(dy) > LONG_PRESS_JITTER)) {
                    clearTimeout(sel.timer);
                    sel.timer = null;
                }
                // 'wait' 是中间态，不能锁存，否则手指先动一点再滑就永远滚不动
                if (!sel.mode) {
                    const intent = gestureIntent(dx, dy, Date.now() - sel.t0, MOVE_TOLERANCE);
                    if (intent !== 'wait') sel.mode = intent;
                }

                if (sel.mode === 'scroll') {
                    if (sel.timer) clearTimeout(sel.timer);
                    sel.timer = null;
                    // 滚动是 xterm 的活儿，别抢手势
                    touchSel = null;
                    return;
                }

                if (sel.mode === 'select') {
                    // 「按在字 A 上 → 拖到字 B」：不用等长按，立刻开始选字，
                    // 起点就是按下那个字，终点是手指下的字。
                    ev.preventDefault();
                    ev.stopPropagation();
                    if (sel.timer) clearTimeout(sel.timer);
                    sel.timer = null;
                    beginTouchSelection(sel);
                    suppressMouseUntil = Date.now() + 10000;
                    updateTouchSelection(sel, t.clientX, t.clientY);
                }
            },
            DOC
        );

        const finish = (ev) => {
            const sel = touchSel;
            if (!sel) return;
            if (sel.active) {
                ev.preventDefault();
                ev.stopPropagation();
                // 只有真正进入过选区才开抑制窗口，普通点击/滚动不受影响
                suppressMouseUntil = Date.now() + 400;
            } else if (sel.mode !== 'scroll' && isTapLike(sel.x - sel.x0, sel.y - sel.y0, Date.now() - sel.t0, MOVE_TOLERANCE)) {
                // touchstart 被 preventDefault 后浏览器不会合成 mousedown / 自动聚焦，
                // 纯点击要手动补一次，否则触屏点终端弹不出软键盘。
                try {
                    sel.s.term.focus();
                } catch (_) {}
            }
            // 系统手势（放大镜 / callout）可能派发 touchcancel：选区已经画出来了，
            // 别把它丢掉，照样给复制条。
            endTouchSelection(sel);
        };
        document.addEventListener('touchend', finish, DOC);
        document.addEventListener('touchcancel', finish, DOC);
    }

    /* ------------------------------------------------- overscroll guard */

    // 终端里上下滑看历史时，旧版 iOS Safari 会把「滚到顶后继续下拉」解释成
    // 浏览器下拉刷新 —— 页面一刷新，WebSocket 断开，SSH 会话彻底没了。
    // 现代浏览器靠 CSS overscroll-behavior 解决，这里是给不认它的浏览器兜底。
    function bindOverscrollGuard() {
        const view = $('#view-term');
        if (!view) return;
        let y0 = null;
        view.addEventListener(
            'touchstart',
            (ev) => {
                y0 = ev.touches.length === 1 ? ev.touches[0].clientY : null;
            },
            { passive: true, capture: true }
        );
        view.addEventListener(
            'touchmove',
            (ev) => {
                if (y0 == null || !ev.touches.length) return;
                // 正在选字，别插手
                if (touchSel && touchSel.active) return;
                const t = ev.touches[0];
                const s = active();
                if (!s || !s.pane) return;
                // 只管终端内容区，按键条 / 标签栏的横向滑动照旧
                const r = s.pane.getBoundingClientRect();
                if (t.clientX < r.left || t.clientX > r.right || t.clientY < r.top || t.clientY > r.bottom) return;
                const vp = s.term.element && s.term.element.querySelector('.xterm-viewport');
                const top = vp ? vp.scrollTop : 0;
                if (shouldBlockPullToRefresh(t.clientY - y0, top)) ev.preventDefault();
                // 只挡浏览器默认行为，不 stopPropagation：xterm 用 JS 改 scrollTop 照常滚
            },
            { passive: false, capture: true }
        );
        const end = () => {
            y0 = null;
        };
        view.addEventListener('touchend', end, { passive: true, capture: true });
        view.addEventListener('touchcancel', end, { passive: true, capture: true });
    }

    /* ------------------------------------------------------------ session */

    function wsUrl(opts) {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const q = new URLSearchParams();
        if (opts.hostId) q.set('hostId', opts.hostId);
        else {
            q.set('host', opts.host || '');
            q.set('port', String(opts.port || 22));
        }
        return proto + '//' + location.host + '/ws?' + q.toString();
    }

    function connect(s) {
        const ws = new WebSocket(wsUrl(s.opts));
        ws.binaryType = 'arraybuffer';
        s.ws = ws;

        ws.onopen = () => {
            send(s, {
                t: 'init',
                hostId: s.opts.hostId || undefined,
                host: s.opts.host || undefined,
                port: s.opts.port || undefined,
                username: s.opts.username || undefined,
                password: s.opts.password || undefined,
                privateKey: s.opts.privateKey || undefined,
                cols: s.term.cols,
                rows: s.term.rows,
                record: !!(c.getSettings && c.getSettings().record),
            });
            // first round trip right away so the RTT cell fills in immediately
            send(s, { t: 'ping', ts: Date.now() });
            s.pingTimer = setInterval(() => {
                if (s.ws && s.ws.readyState === 1) send(s, { t: 'ping', ts: Date.now() });
            }, 5000);
        };

        ws.onmessage = (ev) => {
            if (typeof ev.data === 'string') {
                let msg;
                try {
                    msg = JSON.parse(ev.data);
                } catch (_) {
                    return;
                }
                onMessage(s, msg);
            } else if (ev.data instanceof ArrayBuffer) {
                s.term.write(new Uint8Array(ev.data));
            } else if (ev.data && ev.data.arrayBuffer) {
                ev.data.arrayBuffer().then((buf) => s.term.write(new Uint8Array(buf)));
            }
        };

        ws.onerror = () => {
            s.status = 'err';
            updateTab(s);
            if (s.id === state.activeId) renderHostbar();
        };

        ws.onclose = () => {
            if (s.pingTimer) clearInterval(s.pingTimer);
            s.pingTimer = null;
            failSftp(s, '会话已断开');
            // 只有「还没连上就断了」才算异常。已经 ready 或正常退出的会话保持原状态，
            // 否则用户敲完 exit 之后标签会莫名其妙变红。
            if (s.status === 'ready') s.status = 'closed';
            else if (s.status === 'wait') s.status = 'err';
            updateTab(s);
            if (s.id === state.activeId) renderHostbar();
        };
    }

    function onMessage(s, msg) {
        switch (msg.t) {
            case 'status':
                if (msg.phase === 'tcp') {
                    sysLine(s, msg.message, '38;5;245');
                } else if (msg.phase === 'auth') {
                    sysLine(s, msg.message + (msg.hostKeyType ? ' [' + msg.hostKeyType + ']' : ''), '38;5;245');
                } else if (msg.phase === 'closed') {
                    s.status = 'err';
                    updateTab(s);
                    sysLine(s, msg.message, '38;5;203');
                }
                break;

            case 'ready':
                s.status = 'ready';
                updateTab(s);
                if (s.id === state.activeId) {
                    renderHostbar();
                    // 用户点「连接」之后就该能直接打字，不该再点一次终端
                    if (!$('#view-term').hidden) s.term.focus();
                }
                break;

            case 'banner':
                if (msg.message) s.term.write(msg.message.replace(/\r?\n/g, '\r\n'));
                break;

            case 'os':
                s.os = msg;
                if (s.id === state.activeId) renderHostbar();
                break;

            case 'stats':
                s.stats = msg.stats;
                s.statsOff = false;
                if (typeof msg.stats.cpu === 'number') {
                    s.hist.push(msg.stats.cpu);
                    if (s.hist.length > 40) s.hist.shift();
                }
                if (s.id === state.activeId) {
                    updateStats(s);
                    const osEl = $('#hb-os');
                    if (osEl && s.stats.uptime) {
                        const bits = [];
                        if (s.os) {
                            bits.push(s.os.pretty || [s.os.system, s.os.release].filter(Boolean).join(' ') || '');
                            if (s.os.arch) bits.push(s.os.arch);
                        }
                        bits.push('已运行 ' + fmtUptime(s.stats.uptime));
                        osEl.textContent = bits.filter(Boolean).join(' · ');
                    }
                }
                break;

            case 'stats-off':
                s.statsOff = true;
                s.stats = null;
                if (s.id === state.activeId) updateStats(s);
                break;

            case 'pong':
                if (msg.ts) s.rtt = Math.max(0, Date.now() - msg.ts);
                if (s.id === state.activeId) updateStats(s);
                break;

            case 'toast':
                toast(msg.message);
                break;

            case 'exit':
                s.status = 'closed';
                updateTab(s);
                sysLine(s, '会话已结束' + (msg.code != null ? '（退出码 ' + msg.code + '）' : ''), '38;5;245');
                if (s.id === state.activeId) renderHostbar();
                break;

            case 'eof':
                break;

            case 'error':
                s.status = 'err';
                updateTab(s);
                // 指纹变了：除了在终端留一行说明，再给一个「删除旧记录并重连」的出口，
                // 省掉「切到主机密钥页 → 找到这条 → 删掉 → 回来重连」的四步操作。
                if (msg.hostKeyMismatch) askReplaceHostKey(s, msg.hostKeyMismatch);
                else sysLine(s, msg.message || '发生未知错误', '38;5;203');
                if (s.id === state.activeId) renderHostbar();
                break;

            case 'hostkey':
                askHostKey(s, msg);
                break;

            case 'kbd':
                askKbd(s, msg);
                break;

            case 'sftp': {
                const pending = s.sftpPending.get(msg.id);
                if (!pending) break;
                if (msg.ok) pending.resolve(msg);
                else pending.reject(new Error(msg.error || '文件操作失败'));
                break;
            }

            default:
                break;
        }
    }

    /* ------------------------------------------------------- auth dialogs */

    function askHostKey(s, msg) {
        const body = el('div', { style: 'display:flex;flex-direction:column;gap:12px' }, [
            el('p', {
                class: 'note-box',
                style: 'margin:0',
                text:
                    '首次连接到 ' + msg.host + ':' + msg.port + '，请确认下面这台主机的身份。' +
                    '接受后会记入「主机密钥」，之后指纹变化将自动拒绝连接。',
            }),
            el('div', { class: 'fp', text: (msg.type || '') + '\n' + (msg.fingerprint || '') }),
        ]);
        const foot = el('div', { style: 'display:flex;gap:8px' }, [
            el('button', {
                class: 'btn',
                type: 'button',
                text: '取消',
                onclick: () => {
                    send(s, { t: 'hostkey', id: msg.id, accept: false });
                    m.close();
                },
            }),
            el('button', {
                class: 'btn primary',
                type: 'button',
                text: '信任并保存',
                onclick: () => {
                    send(s, { t: 'hostkey', id: msg.id, accept: true });
                    m.close();
                },
            }),
        ]);
        const m = modal({ title: '验证主机密钥', body, footer: foot, onClose: () => send(s, { t: 'hostkey', id: msg.id, accept: false }) });
    }

    /**
     * 指纹和本地记录不一致（典型场景：机器重装系统后 sshd 重新生成了主机密钥）。
     * 服务端已经把 key / 新旧指纹一起带过来了，这里直接给「删除并重连」，
     * 但删除动作仍然要用户自己点，绝不自动放行新指纹。
     */
    function askReplaceHostKey(s, info) {
        const addr = (info.host || s.host || '') + ':' + (info.port || s.port || 22);
        sysLine(s, addr + ' 的主机密钥已变更，连接已在认证前中止', '38;5;203');

        const body = el('div', { style: 'display:flex;flex-direction:column;gap:12px' }, [
            el('p', {
                class: 'note-box',
                style: 'margin:0',
                text:
                    addr +
                    ' 的主机密钥和本地记录不一致，连接在认证之前就被中止了。' +
                    '机器重装系统、重装 sshd、或换过主机密钥都会出现这种情况；' +
                    '如果不是你做的，请直接取消 —— 那可能是中间人在冒充这台服务器。',
            }),
            el('div', {
                class: 'fp',
                text:
                    '已保存  ' + (info.saved || '(空)') +
                    '\n服务器  ' + (info.current || '(空)') +
                    (info.type ? '\n算法    ' + info.type : ''),
            }),
            el('p', {
                class: 'note-box',
                style: 'margin:0',
                text: '删除后会立即重连，并重新弹出「验证主机密钥」——那一步仍然需要你自己核对指纹，不会自动信任。',
            }),
        ]);

        let busy = false;
        async function forget() {
            if (busy) return;
            if (!c.onForgetHostKey) {
                toast('请到「主机密钥」页手动删除该记录后重连', 'err');
                return;
            }
            busy = true;
            try {
                await c.onForgetHostKey(info.key);
            } catch (e) {
                busy = false;
                toast(String((e && e.message) || e), 'err');
                return;
            }
            m.close();
            toast('已删除旧的主机密钥记录，正在重连 …');
            // 弹窗开着的时候标签可能已经被关掉了，这时只删记录、不重连
            if (state.sessions.indexOf(s) >= 0) restartSession(s);
        }

        const foot = el('div', { style: 'display:flex;gap:8px' }, [
            el('button', { class: 'btn', type: 'button', text: '取消', onclick: () => m.close() }),
            el('button', { class: 'btn danger', type: 'button', text: '删除旧记录并重连', onclick: forget }),
        ]);
        const m = modal({ title: '主机密钥已变更', body, footer: foot, width: '540px' });
    }

    function askKbd(s, msg) {
        const prompts = msg.prompts || [];
        const inputs = [];
        const body = el('div', { style: 'display:flex;flex-direction:column;gap:10px' });
        if (msg.instruction) body.appendChild(el('p', { class: 'note-box', style: 'margin:0', text: msg.instruction }));
        prompts.forEach((p, i) => {
            const input = el('input', { type: p.echo ? 'text' : 'password', autocomplete: 'off' });
            inputs.push(input);
            body.appendChild(el('label', { text: p.prompt || '输入 ' + (i + 1) }, [input]));
        });
        const submit = () => {
            send(s, { t: 'kbd', id: msg.id, answers: inputs.map((i) => i.value) });
            m.close();
        };
        const form = el('form', { onsubmit: (ev) => { ev.preventDefault(); submit(); } }, [body]);
        const foot = el('div', { style: 'display:flex;gap:8px' }, [
            el('button', {
                class: 'btn',
                type: 'button',
                text: '取消',
                onclick: () => {
                    send(s, { t: 'kbd', id: msg.id, answers: null });
                    m.close();
                },
            }),
            el('button', { class: 'btn primary', type: 'submit', text: '提交', onclick: submit }),
        ]);
        const m = modal({ title: msg.name || '键盘交互认证', body: form, footer: foot, onClose: () => send(s, { t: 'kbd', id: msg.id, answers: null }) });
    }

    /* ------------------------------------------------------------- create */

    function openSession(opts) {
        const id = 's' + ++state.seq;
        const pane = el('div', { class: 'pane' });
        const holder = el('div', { style: 'height:100%;width:100%' });
        pane.appendChild(holder);
        panesEl.appendChild(pane);

        const term = new window.Terminal({
            theme: THEME,
            fontFamily: FONT_STACK,
            fontSize: fontSize(),
            lineHeight: 1.25,
            cursorBlink: true,
            cursorStyle: 'bar',
            scrollback: 8000,
            allowTransparency: true,
            macOptionIsMeta: true,
            rightClickSelectsWord: false,
        });
        const fit = new window.FitAddon.FitAddon();
        term.loadAddon(fit);
        term.open(holder);

        const s = {
            id,
            opts,
            hostId: opts.hostId || null,
            host: opts.host || '',
            port: opts.port || 22,
            username: opts.username || '',
            name: opts.name || opts.host || '会话',
            term,
            fit,
            pane,
            ws: null,
            status: 'wait',
            stats: null,
            statsOff: false,
            hist: [],
            rtt: null,
            os: null,
            pingTimer: null,
            tabEl: null,
            _ui: null,
            sftpPending: new Map(),
            sftpSeq: 0,
        };
        state.sessions.push(s);
        renderTabs();

        term.onData((data) => sendInput(s, data));
        term.onResize(({ cols, rows }) => send(s, { t: 'resize', cols, rows }));

        // right click pastes (keeps the muscle memory of desktop terminals)
        pane.addEventListener('contextmenu', async (ev) => {
            ev.preventDefault();
            // 触屏长按派发的 contextmenu 是「选择」手势，不是桌面右键粘贴；
            // 捕获阶段的抑制没盖住时，这里再兜一次底。
            if (Date.now() - lastTouchAt < 1500 || Date.now() < suppressUntil) return;
            try {
                const text = await navigator.clipboard.readText();
                await pasteInto(s, text);
            } catch (_) {
                toast('浏览器拒绝了剪贴板读取，请用 Ctrl+Shift+V', 'err');
            }
        });

        setActive(id, true);
        connect(s);
        return s;
    }

    function setActive(id, silent) {
        const s = state.sessions.find((x) => x.id === id);
        if (!s) return;
        // 切到别的标签时收起上一个会话的选区与浮动条
        if (touchSel && touchSel.s && touchSel.s.id !== id) clearTouchSelection();
        state.activeId = id;
        for (const other of state.sessions) {
            other.pane.classList.toggle('on', other.id === id);
            if (other.tabEl) other.tabEl.classList.toggle('on', other.id === id);
        }
        renderHostbar();
        requestAnimationFrame(() => {
            fitSession(s);
            if (!silent) s.term.focus();
        });
    }

    function fitSession(s) {
        try {
            s.fit.fit();
        } catch (_) {}
    }

    function closeSession(id) {
        const idx = state.sessions.findIndex((s) => s.id === id);
        if (idx < 0) return;
        const s = state.sessions[idx];
        if (touchSel && touchSel.s === s) clearTouchSelection();
        failSftp(s, '会话已关闭');
        try {
            if (s.ws && s.ws.readyState === 1) s.ws.send(JSON.stringify({ t: 'close' }));
            if (s.ws) s.ws.close();
        } catch (_) {}
        if (s.pingTimer) clearInterval(s.pingTimer);
        try {
            s.term.dispose();
        } catch (_) {}
        s.pane.remove();
        state.sessions.splice(idx, 1);
        if (state.activeId === id) {
            const next = state.sessions[Math.min(idx, state.sessions.length - 1)];
            state.activeId = next ? next.id : null;
            if (next) setActive(next.id, true);
        }
        renderTabs();
        renderHostbar();
        if (!state.sessions.length && c.onEmpty) c.onEmpty();
    }

    function restart() {
        restartSession(active());
    }

    function restartSession(s) {
        if (!s) return;
        failSftp(s, '会话已重连');
        try {
            if (s.ws) {
                s.ws.onclose = null;
                s.ws.send(JSON.stringify({ t: 'close' }));
                s.ws.close();
            }
        } catch (_) {}
        if (s.pingTimer) clearInterval(s.pingTimer);
        s.status = 'wait';
        s.stats = null;
        s.statsOff = false;
        s.hist = [];
        s.rtt = null;
        s.os = null;
        s.term.reset();
        updateTab(s);
        renderHostbar();
        sysLine(s, '正在重新连接 …', '38;5;245');
        connect(s);
    }

    function duplicate() {
        const s = active();
        if (!s) return;
        openSession(Object.assign({}, s.opts));
    }

    /* ---------------------------------------------------------- key bar */

    function arrowSeq(final) {
        const m = 1 + (state.alt ? 2 : 0) + (state.ctrl ? 4 : 0);
        return m === 1 ? '\x1b[' + final : '\x1b[1;' + m + final;
    }

    function buildKeys() {
        const box = $('#keys');
        if (!box) return;
        box.textContent = '';
        for (const k of KEYS) {
            const btn = el('button', { class: 'key', type: 'button', text: k.label });
            if (k.mod) {
                btn.dataset.mod = k.mod;
                btn.addEventListener('click', () => {
                    state[k.mod] = !state[k.mod];
                    btn.classList.toggle('on', state[k.mod]);
                });
            } else {
                btn.addEventListener('click', () => {
                    const s = active();
                    if (!s) return;
                    sendInput(s, k.arrow ? arrowSeq(k.arrow) : k.send);
                    s.term.focus();
                });
            }
            box.appendChild(btn);
        }
    }

    /* ------------------------------------------------------------- bindings */

    function bind() {
        if (bound) return;
        bound = true;

        buildKeys();
        renderTabs();
        renderHostbar();
        // 只绑一次，挂在 #view-term 捕获阶段，覆盖所有会话的 pane
        bindTouchSelection();
        // 防止上下翻历史时带出浏览器的下拉刷新
        bindOverscrollGuard();

        const on = (sel, ev, fn) => {
            const node = $(sel);
            if (node) node.addEventListener(ev, fn);
        };

        on('.term-top-actions [data-act="back"]', 'click', () => c.onBack && c.onBack());
        on('.term-top-actions [data-act="settings"]', 'click', () => c.onSettings && c.onSettings());
        on('.term-top-actions [data-act="logout"]', 'click', () => c.onLogout && c.onLogout());
        on('#btn-snippets', 'click', () => c.onSnippets && c.onSnippets(sendToActive));
        on('#btn-files', 'click', () => {
            const s = active();
            if (!s) {
                toast('当前没有打开的会话', 'err');
                return;
            }
            if (s.status !== 'ready') {
                toast('会话还没连接就绪，请稍后再试', 'err');
                return;
            }
            if (c.onFiles) c.onFiles(s);
        });
        on('#btn-dup', 'click', duplicate);
        on('#btn-reconnect', 'click', restart);
        on('#btn-disconnect', 'click', () => {
            const s = active();
            if (s) closeSession(s.id);
        });
        on('#btn-fullscreen', 'click', toggleFullscreen);
        on('#btn-logs', 'click', () => c.onLogs && c.onLogs(active()));
        on('#btn-help', 'click', showHelp);

        window.addEventListener('resize', () => {
            const s = active();
            if (s) fitSession(s);
        });
        document.addEventListener('fullscreenchange', () => {
            const s = active();
            if (s) setTimeout(() => fitSession(s), 60);
        });

        document.addEventListener('keydown', (ev) => {
            if ($('#view-term').hidden) return;
            const mod = ev.ctrlKey || ev.metaKey;
            if (mod && ev.shiftKey && ev.key.toLowerCase() === 'c') {
                const s = active();
                if (s && s.term.hasSelection()) {
                    copyText(s.term.getSelection());
                    ev.preventDefault();
                }
                return;
            }
            if (mod && ev.shiftKey && ev.key.toLowerCase() === 'v') {
                navigator.clipboard
                    .readText()
                    .then((text) => {
                        const s = active();
                        if (s && text) return pasteInto(s, text);
                    })
                    .catch(() => toast('浏览器拒绝了剪贴板读取', 'err'));
                ev.preventDefault();
                return;
            }
            if (mod && ev.shiftKey && ev.key.toLowerCase() === 'f') {
                toggleFullscreen();
                ev.preventDefault();
                return;
            }
            if (mod && ev.shiftKey && ev.key.toLowerCase() === 'r') {
                restart();
                ev.preventDefault();
                return;
            }
            if (mod && ev.shiftKey && ev.key.toLowerCase() === 'w') {
                const s = active();
                if (s) closeSession(s.id);
                ev.preventDefault();
                return;
            }
            if (ev.altKey && /^[1-9]$/.test(ev.key)) {
                const s = state.sessions[Number(ev.key) - 1];
                if (s) {
                    setActive(s.id);
                    ev.preventDefault();
                }
            }
        });
    }

    function sendToActive(command) {
        const s = active();
        if (!s) {
            toast('当前没有打开的会话', 'err');
            return false;
        }
        sendInput(s, command.replace(/\r?\n/g, '\r') + '\r');
        s.term.focus();
        return true;
    }

    function toggleFullscreen() {
        const node = $('#view-term');
        if (!document.fullscreenElement) {
            (node.requestFullscreen || node.webkitRequestFullscreen || function () {}).call(node);
        } else {
            (document.exitFullscreen || document.webkitExitFullscreen || function () {}).call(document);
        }
    }

    function showHelp() {
        const rows = SHORTCUTS.map((r) =>
            el('div', { class: 'list-row' }, [
                el('span', { class: 'grow mono', text: r[0] }),
                el('span', { style: 'color:#8b857a;font-size:12px', text: r[1] }),
            ])
        );
        modal({
            title: '快捷键',
            body: el('div', { class: 'list' }, rows),
        });
    }

    /* -------------------------------------------------------------- public */

    return {
        init: bind,
        open: openSession,
        setActive,
        close: closeSession,
        restart,
        duplicate,
        sendToActive,
        active,
        sftpRequest(session, payload, timeoutMs) {
            return sftpRequest(session || active(), payload, timeoutMs);
        },
        sessions: () => state.sessions,
        setFontSize(size) {
            for (const s of state.sessions) {
                s.term.options.fontSize = size;
                fitSession(s);
            }
        },
        fitActive() {
            const s = active();
            if (s) fitSession(s);
        },
    };
}
