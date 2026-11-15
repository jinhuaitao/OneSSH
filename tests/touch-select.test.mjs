import test from 'node:test';
import assert from 'node:assert/strict';
import { LONG_PRESS_MS, LONG_PRESS_JITTER, MOVE_TOLERANCE, gestureIntent, shouldBlockPullToRefresh, isTapLike, cellAt, selectionRange, normalizeSel, selectionRows, clipRows, wordRange, joinLines } from '../public/js/touch-select.js';

const rect = { left: 12, top: 8, width: 800, height: 400 };

test('cellAt：按 .xterm-screen 的尺寸把触点换算成列/行', () => {
    // 80 列 × 25 行 → 每格 10×16
    assert.deepEqual(cellAt(rect, 80, 25, 12 + 35, 8 + 50), { col: 3, row: 3 });
    assert.deepEqual(cellAt(rect, 80, 25, 12, 8), { col: 0, row: 0 });
    assert.deepEqual(cellAt(rect, 80, 25, 12 + 799, 8 + 399), { col: 79, row: 24 });
});

test('cellAt：触点超出渲染区时钳在边界内', () => {
    assert.deepEqual(cellAt(rect, 80, 25, 0, 0), { col: 0, row: 0 });
    assert.deepEqual(cellAt(rect, 80, 25, 9999, 9999), { col: 79, row: 24 });
});

test('cellAt：视图隐藏 / 零尺寸时不产生 NaN', () => {
    assert.deepEqual(cellAt({ left: 0, top: 0, width: 0, height: 0 }, 80, 25, 0, 0), { col: 0, row: 0 });
    assert.deepEqual(cellAt(null, 80, 25, 100, 100), { col: 0, row: 0 });
});

test('selectionRange：同行选择', () => {
    assert.deepEqual(selectionRange(80, { col: 2, row: 3 }, { col: 7, row: 3 }), { col: 2, row: 3, length: 6 });
});

test('selectionRange：跨行选择从较靠前的坐标开始', () => {
    // 2 行第 70 列 → 3 行第 5 列，共 16 个字符
    assert.deepEqual(selectionRange(80, { col: 70, row: 2 }, { col: 5, row: 3 }), { col: 70, row: 2, length: 16 });
});

test('selectionRange：反向拖动与单点', () => {
    assert.deepEqual(selectionRange(80, { col: 10, row: 5 }, { col: 2, row: 1 }), { col: 2, row: 1, length: 329 });
    assert.deepEqual(selectionRange(80, { col: 4, row: 2 }, { col: 4, row: 2 }), { col: 4, row: 2, length: 1 });
});

test('selectionRange：滚动过 scrollback 时叠加 viewportY', () => {
    // 视口第 3 行 = 缓冲区第 123 行（viewportY=120）
    assert.deepEqual(selectionRange(80, { col: 2, row: 3 }, { col: 7, row: 3 }, 120), { col: 2, row: 123, length: 6 });
    assert.deepEqual(selectionRange(80, { col: 70, row: 2 }, { col: 5, row: 3 }, 120), { col: 70, row: 122, length: 16 });
});

test('shouldBlockPullToRefresh：只有滚到顶后继续下拉才拦', () => {
    assert.equal(shouldBlockPullToRefresh(30, 0), true);
    assert.equal(shouldBlockPullToRefresh(30, 120), false); // 还在翻历史，正常滚
    assert.equal(shouldBlockPullToRefresh(-30, 0), false); // 上滑看最新输出，不拦
    assert.equal(shouldBlockPullToRefresh(0, 0), false);
    assert.equal(shouldBlockPullToRefresh(8, undefined), true);
});

test('isTapLike：只有短按且几乎不移动才补聚焦', () => {
    assert.equal(isTapLike(2, 3, 120, MOVE_TOLERANCE), true);
    assert.equal(isTapLike(30, 0, 120, MOVE_TOLERANCE), false); // 拖动选字
    assert.equal(isTapLike(0, 40, 120, MOVE_TOLERANCE), false); // 滚历史
    assert.equal(isTapLike(0, 0, LONG_PRESS_MS, MOVE_TOLERANCE), false); // 长按
});

test('gestureIntent：按在一个字上横向拖到另一个字，立即进入选择', () => {
    // 不必等 420ms 的长按阈值，起点是按下那个字、终点是手指下的字
    assert.equal(gestureIntent(30, 0, 120, MOVE_TOLERANCE), 'select');
    assert.equal(gestureIntent(-40, 2, 90, MOVE_TOLERANCE), 'select');
    assert.equal(gestureIntent(120, 6, 80, MOVE_TOLERANCE), 'select');
});

test('gestureIntent：垂直滑动让给 xterm 滚 scrollback', () => {
    assert.equal(gestureIntent(2, 40, 100, MOVE_TOLERANCE), 'scroll');
    assert.equal(gestureIntent(0, 25, 100, MOVE_TOLERANCE), 'scroll');
    assert.equal(gestureIntent(100, 100, 100, MOVE_TOLERANCE), 'scroll');
});

test('gestureIntent：斜向跨行拖动仍算选字，不算滚动', () => {
    assert.equal(gestureIntent(30, 30, 100, MOVE_TOLERANCE), 'select');
    assert.equal(gestureIntent(60, 30, 100, MOVE_TOLERANCE), 'select');
});

test('gestureIntent：静止够久才长按，轻微抖动继续等', () => {
    assert.equal(gestureIntent(0, 0, 100, MOVE_TOLERANCE), 'wait');
    assert.equal(gestureIntent(4, 3, 100, MOVE_TOLERANCE), 'wait');
    assert.equal(gestureIntent(0, 0, LONG_PRESS_MS, MOVE_TOLERANCE), 'select');
});

test('长按阈值与移动容差在可用区间', () => {
    assert.ok(LONG_PRESS_MS >= 300 && LONG_PRESS_MS <= 800);
    assert.ok(MOVE_TOLERANCE > 0 && MOVE_TOLERANCE <= 20);
});

test('抖动容差小于移动容差：一动手就不再算长按', () => {
    assert.ok(LONG_PRESS_JITTER > 0);
    assert.ok(LONG_PRESS_JITTER < MOVE_TOLERANCE);
});

test('normalizeSel：正向与反向拖动得到同一段区间', () => {
    const fwd = normalizeSel(80, { col: 2, row: 1 }, { col: 5, row: 1 });
    assert.deepEqual(fwd, { from: { row: 1, col: 2 }, to: { row: 1, col: 5 }, forward: true, cells: 4 });
    const back = normalizeSel(80, { col: 5, row: 3 }, { col: 2, row: 1 });
    assert.deepEqual(back, { from: { row: 1, col: 2 }, to: { row: 3, col: 5 }, forward: false, cells: 164 });
});

test('selectionRows：单行 / 跨行 / 反向的逐行跨度', () => {
    // 同一行：只覆盖起止列之间
    assert.deepEqual(selectionRows(80, { col: 2, row: 1 }, { col: 5, row: 1 }), [{ row: 1, from: 2, to: 5 }]);
    // 跨行：首行到尾列、中间整行、末行从 0 开始
    const spans = selectionRows(80, { col: 78, row: 0 }, { col: 1, row: 2 });
    assert.deepEqual(spans, [
        { row: 0, from: 78, to: 79 },
        { row: 1, from: 0, to: 79 },
        { row: 2, from: 0, to: 1 },
    ]);
    // 反向拖动（从下面的字拖回上面的字）结果一致
    assert.deepEqual(selectionRows(80, { col: 1, row: 2 }, { col: 78, row: 0 }), spans);
});

test('selectionRows：单点选择覆盖一个字符', () => {
    assert.deepEqual(selectionRows(80, { col: 4, row: 2 }, { col: 4, row: 2 }), [{ row: 2, from: 4, to: 4 }]);
});

test('joinLines：软换行的续行不插换行符', () => {
    assert.equal(joinLines([{ text: 'abc' }, { text: 'def', wrapped: true }]), 'abcdef');
    assert.equal(joinLines([{ text: 'abc' }, { text: 'def' }]), 'abc\ndef');
    assert.equal(joinLines([{ text: '' }, { text: 'x' }]), '\nx');
    assert.equal(joinLines([]), '');
    assert.equal(joinLines(null), '');
});

test('wordRange：长按 / 双击选中整个 token', () => {
    const line = 'cd /usr/local/lib/node_modules';
    // 点在路径中间 → 整段路径
    assert.deepEqual(wordRange(line, 8), { from: 3, to: 29 });
    // 点在 cd 上
    assert.deepEqual(wordRange(line, 1), { from: 0, to: 1 });
    // 命令参数算一个词（-m 是一个整体，空格是边界）
    assert.deepEqual(wordRange('git commit -m "fix: x"', 12), { from: 11, to: 12 });
    assert.deepEqual(wordRange('git commit -m "fix: x"', 18), { from: 14, to: 18 });
    // 点在空白上 → 只选那一格，不做扩展
    assert.deepEqual(wordRange(line, 2), { from: 2, to: 2 });
    // 空行 / 越界列
    assert.equal(wordRange('', 0), null);
    assert.equal(wordRange(null, 3), null);
    assert.equal(wordRange('abc', 99), null); // 行尾填充区不算字
    assert.deepEqual(wordRange('a b', 1), { from: 1, to: 1 });
});

test('clipRows：跨几千行的选区只保留视口内的行', () => {
    const spans = selectionRows(80, { col: 0, row: 0 }, { col: 5, row: 500 });
    assert.equal(spans.length, 501);
    const vis = clipRows(spans, 480, 503);
    assert.equal(vis.length, 21);
    assert.equal(vis[0].row, 480);
    assert.equal(vis[vis.length - 1].row, 500);
    // 视口完全在选区之外
    assert.deepEqual(clipRows(spans, 600, 620), []);
    assert.deepEqual(clipRows(null, 0, 10), []);
});
