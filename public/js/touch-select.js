/* Touch long-press selection: pure geometry helpers (no DOM, unit-testable in Node). */

export const LONG_PRESS_MS = 420;
export const MOVE_TOLERANCE = 16;
/**
 * 手指的抖动容差：超过它可以认定「用户开始动了」，就该取消长按计时器。
 * 比 MOVE_TOLERANCE 小 —— 手指慢慢滑出去时，绝不能还被判成长按，
 * 否则想滚历史的手势会变成选字。
 */
export const LONG_PRESS_JITTER = 6;

/**
 * 旧版 iOS Safari 不认 overscroll-behavior 时的兜底判定。
 * dy > 0 表示手指往下拉；xterm 的 viewport 已经到顶（scrollTop<=0）时，
 * 浏览器会把继续下拉解释成「刷新页面」—— 一刷新 SSH 会话就全没了。
 */
export function shouldBlockPullToRefresh(dy, scrollTop) {
    return dy > 0 && (Number(scrollTop) || 0) <= 0;
}

/**
 * touchstart 被 preventDefault 后浏览器不会合成 mousedown / 自动聚焦，
 * 纯点击（几乎没位移、时间很短）需要手动补一次 term.focus() 才能弹出软键盘。
 */
export function isTapLike(dx, dy, elapsedMs, tolerance) {
    const tol = Number(tolerance) || MOVE_TOLERANCE;
    return Math.abs(dx) <= tol && Math.abs(dy) <= tol && elapsedMs < LONG_PRESS_MS;
}

/**
 * 判定一次触摸是「滚动」还是「选字」。纯函数，方便单测。
 *
 * 终端只有垂直滚动（xterm 的 handleTouchMove 只看 pageY 差值），所以：
 *  - 垂直位移为主且超容差 → 滚 scrollback，别抢手势；
 *  - 水平位移为主且已有明显位移 → 用户正从一个字拖到另一个字，立刻进选择模式，
 *    不必等长按阈值（这正是触屏上最自然的选字动作）；
 *  - 位移都在容差内 → 静止够久就开始长按选择，否则继续等。
 */
export function gestureIntent(dx, dy, elapsedMs, tolerance) {
    const tol = Number(tolerance) || MOVE_TOLERANCE;
    const ax = Math.abs(dx);
    const ay = Math.abs(dy);
    // 垂直明显占主导 → 滚 scrollback
    if (ay > tol && ay > ax * 1.2) return 'scroll';
    // 水平占主导（含跨行的斜向拖动，最多约三行）→ 从字 A 选到字 B
    if (ax > 8 && ax >= ay * 0.8 && ay <= tol * 3) return 'select';
    if (ax > tol || ay > tol) return 'scroll';
    return elapsedMs >= LONG_PRESS_MS ? 'select' : 'wait';
}

/** 把触点换算成终端字符坐标。rect 取 .xterm-screen 的 getBoundingClientRect()。 */
export function cellAt(rect, cols, rows, clientX, clientY) {
    const w = Number(rect && rect.width) || 0;
    const h = Number(rect && rect.height) || 0;
    const cw = w / Math.max(1, cols);
    const ch = h / Math.max(1, rows);
    // 视图隐藏时 rect 可能是 0×0，别把 NaN 喂给 term.select()
    if (!(cw > 0) || !(ch > 0)) return { col: 0, row: 0 };
    const left = Number(rect.left) || 0;
    const top = Number(rect.top) || 0;
    const col = Math.max(0, Math.min(cols - 1, Math.floor((clientX - left) / cw)));
    const row = Math.max(0, Math.min(rows - 1, Math.floor((clientY - top) / ch)));
    return { col, row };
}

/**
 * 把两个字符坐标归一成「起点在前、终点在后」的区间。
 * 反向拖动（从字 B 拖回字 A）也能得到同一段选区。
 */
export function normalizeSel(cols, a, b) {
    const n = Math.max(1, cols);
    const i1 = a.row * n + a.col;
    const i2 = b.row * n + b.col;
    const from = Math.min(i1, i2);
    const to = Math.max(i1, i2);
    return {
        from: { row: Math.floor(from / n), col: from % n },
        to: { row: Math.floor(to / n), col: to % n },
        forward: i2 >= i1,
        cells: to - from + 1,
    };
}

/**
 * 逐行的列跨度（闭区间），用来自己画高亮：
 * 首行从起点列开始，末行到终点列结束，中间整行全选。
 */
export function selectionRows(cols, a, b) {
    const { from, to } = normalizeSel(cols, a, b);
    const n = Math.max(1, cols);
    const rows = [];
    for (let row = from.row; row <= to.row; row++) {
        const c1 = row === from.row ? from.col : 0;
        const c2 = row === to.row ? to.col : n - 1;
        if (c2 >= c1) rows.push({ row, from: c1, to: c2 });
    }
    return rows;
}

/**
 * 终端里「一个词」由哪些字符组成。路径、URL、命令行参数、文件名都算整体，
 * 长按一下就能整段复制，比逐字拖要顺手得多。
 */
const WORD_CHARS = /[A-Za-z0-9_\-./~:@%+=?&#$!*(){}[\]'"<>|\\]/;

/**
 * 行内某个列所在的「词」区间（闭区间）。落在空白上就只返回那一格，
 * 返回 null 表示列号越界（终端行尾的填充空格）。
 */
export function wordRange(text, col) {
    const s = text == null ? '' : String(text);
    const n = s.length;
    if (!n) return null;
    const i = Math.floor(Number(col) || 0);
    // 列号落在行尾填充区（终端每行都补到 cols）：这不是「某个字」，返回 null
    if (i < 0 || i >= n) return null;
    if (!WORD_CHARS.test(s[i])) return { from: i, to: i };
    let a = i;
    let b = i;
    while (a > 0 && WORD_CHARS.test(s[a - 1])) a--;
    while (b < n - 1 && WORD_CHARS.test(s[b + 1])) b++;
    return { from: a, to: b };
}

/**
 * 只保留与视口相交的行。选区可以跨几千行缓冲区，
 * 但屏幕上最多只画得下 `rows` 行 —— 先裁掉，避免生成大量 DOM。
 */
export function clipRows(spans, firstRow, lastRow) {
    const out = [];
    for (const sp of spans || []) {
        if (!sp) continue;
        if (sp.row < firstRow || sp.row > lastRow) continue;
        out.push(sp);
    }
    return out;
}

/**
 * 把逐行取到的文字拼回一段文本：xterm 里软换行的续行（isWrapped）不能插换行，
 * 否则复制出来的命令会被截断。
 */
export function joinLines(parts) {
    let out = '';
    let first = true;
    for (const p of parts || []) {
        const text = p && p.text != null ? String(p.text) : '';
        if (!first && !(p && p.wrapped)) out += '\n';
        out += text;
        first = false;
    }
    return out;
}

/**
 * 两个字符坐标之间的选区，转成 xterm 的 select(column, row, length)。
 * length 是「从起点开始的字符数」，xterm 自己会沿 buffer 跨行展开，
 * 所以这里把视口坐标拉平成一维索引再算差值，反向拖动也能正确工作。
 *
 * 注：触屏选择现在由 term.js 自绘高亮 + 自己取文字，不再依赖 xterm 的选区，
 * 这个函数保留给需要调用 term.select() 的场景。
 */
export function selectionRange(cols, a, b, rowOffset) {
    const n = Math.max(1, cols);
    const i1 = a.row * n + a.col;
    const i2 = b.row * n + b.col;
    const from = Math.min(i1, i2);
    // xterm.select() 的行号是「绝对缓冲区行」：鼠标选择内部会叠加 buffer.ydisp，
    // 公开 API 不会，所以滚动过 scrollback 后要把 viewportY 补上去。
    const off = Number(rowOffset) || 0;
    return { col: from % n, row: Math.floor(from / n) + off, length: Math.abs(i2 - i1) + 1 };
}
