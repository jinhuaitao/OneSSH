/* Touch long-press selection: pure geometry helpers (no DOM, unit-testable in Node). */

export const LONG_PRESS_MS = 480;
export const MOVE_TOLERANCE = 10;

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
 * 两个字符坐标之间的选区，转成 xterm 的 select(column, row, length)。
 * length 是「从起点开始的字符数」，xterm 自己会沿 buffer 跨行展开，
 * 所以这里把视口坐标拉平成一维索引再算差值，反向拖动也能正确工作。
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
