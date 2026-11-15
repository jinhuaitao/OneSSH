import test from 'node:test';
import assert from 'node:assert/strict';
import { LONG_PRESS_MS, MOVE_TOLERANCE, cellAt, selectionRange } from '../public/js/touch-select.js';

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

test('长按阈值与移动容差在可用区间', () => {
    assert.ok(LONG_PRESS_MS >= 300 && LONG_PRESS_MS <= 800);
    assert.ok(MOVE_TOLERANCE > 0 && MOVE_TOLERANCE <= 20);
});
