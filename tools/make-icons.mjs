// 生成 PWA 图标：纯 Node（zlib 手写 PNG 编码 + SDF 光栅化），零第三方依赖。
// 图形与 public/favicon.svg 完全同源（同一套 64 单位坐标），改图标只需改这里再跑一次：
//   node tools/make-icons.mjs
import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const OUT_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'icons');

/* ------------------------------------------------------------------ 几何 */
// 全部坐标沿用 favicon.svg 的 64×64 视口
const GLYPH = [
    // 折线箭头：M17 23.5 L26.5 32 L17 40.5
    [17, 23.5, 26.5, 32],
    [26.5, 32, 17, 40.5],
    // 下划线：M33.5 41 H47.5
    [33.5, 41, 47.5, 41],
];
const STROKE = 5; // 与 favicon 的 stroke-width 一致
const RADIUS = 15; // 与 favicon 的 rx 一致
const TOP = [0xff, 0x6a, 0x3d];
const BOTTOM = [0xf0, 0x3d, 0x08];

function sdRoundRect(x, y, cx, cy, hw, hh, r) {
    const qx = Math.abs(x - cx) - (hw - r);
    const qy = Math.abs(y - cy) - (hh - r);
    return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - r;
}

function sdSegment(x, y, x1, y1, x2, y2) {
    const dx = x2 - x1;
    const dy = y2 - y1;
    const t = Math.max(0, Math.min(1, ((x - x1) * dx + (y - y1) * dy) / (dx * dx + dy * dy)));
    return Math.hypot(x - (x1 + t * dx), y - (y1 + t * dy));
}

/* ------------------------------------------------------------- 光栅化 */
/**
 * @param {number} size      输出边长（像素）
 * @param {object} opt
 * @param {boolean} opt.maskable 可遮罩图标：满幅方底（由系统裁形状），图形放大留安全区
 * @param {boolean} opt.bleed    满幅不裁角（iOS 图标用，圆角交给系统）
 */
function render(size, { maskable = false, bleed = false } = {}) {
    const scale = size / 64; // 单位 → 像素
    const px = Buffer.alloc(size * size * 4);
    const glyphScale = maskable ? 1.12 : 1; // 可遮罩版图形放大，仍在 80% 安全圆内
    const round = bleed || maskable ? 0 : RADIUS;

    for (let y = 0; y < size; y++) {
        // 渐变按行取值（与 favicon 的竖直渐变一致）
        const t = (y + 0.5) / size;
        const r = TOP[0] + (BOTTOM[0] - TOP[0]) * t;
        const g = TOP[1] + (BOTTOM[1] - TOP[1]) * t;
        const b = TOP[2] + (BOTTOM[2] - TOP[2]) * t;

        for (let x = 0; x < size; x++) {
            const ux = (x + 0.5) / scale;
            const uy = (y + 0.5) / scale;

            // 底：圆角矩形（maskable / bleed 用满幅方底）
            const dBase = round
                ? sdRoundRect(ux, uy, 32, 32, 32, 32, round)
                : Math.max(Math.abs(ux - 32) - 32, Math.abs(uy - 32) - 32);
            const baseA = Math.min(1, Math.max(0, 0.5 - dBase * scale));

            // 图形：胶囊并集（圆头圆角），按中心缩放
            const gx = (ux - 32) / glyphScale + 32;
            const gy = (uy - 32) / glyphScale + 32;
            let dGlyph = Infinity;
            for (const [x1, y1, x2, y2] of GLYPH) {
                dGlyph = Math.min(dGlyph, sdSegment(gx, gy, x1, y1, x2, y2));
            }
            dGlyph = (dGlyph - STROKE / 2) * glyphScale; // 缩放回屏幕单位
            const glyphA = Math.min(1, Math.max(0, 0.5 - dGlyph * scale));

            const i = (y * size + x) * 4;
            if (glyphA <= 0) {
                px[i] = Math.round(r);
                px[i + 1] = Math.round(g);
                px[i + 2] = Math.round(b);
                px[i + 3] = Math.round(baseA * 255);
            } else {
                // 白色图形叠在渐变底上（预乘前先做简单混合）
                const k = glyphA;
                px[i] = Math.round(r + (255 - r) * k);
                px[i + 1] = Math.round(g + (255 - g) * k);
                px[i + 2] = Math.round(b + (255 - b) * k);
                px[i + 3] = Math.round(baseA * 255);
            }
        }
    }
    return px;
}

/* ------------------------------------------------------------- PNG 编码 */
const CRC_TABLE = (() => {
    const table = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        table[n] = c;
    }
    return table;
})();

function crc32(buf) {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
}

function encodePNG(size, rgba) {
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(size, 0);
    ihdr.writeUInt32BE(size, 4);
    ihdr[8] = 8; // bit depth
    ihdr[9] = 6; // RGBA
    // 10..12 = compression / filter / interlace，均为 0

    const stride = size * 4;
    const raw = Buffer.alloc((stride + 1) * size);
    for (let y = 0; y < size; y++) {
        raw[y * (stride + 1)] = 0; // filter: none
        rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
    }

    return Buffer.concat([
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        chunk('IHDR', ihdr),
        chunk('IDAT', deflateSync(raw, { level: 9 })),
        chunk('IEND', Buffer.alloc(0)),
    ]);
}

/* ------------------------------------------------------------------ 输出 */
const TARGETS = [
    ['icon-192.png', 192, {}],
    ['icon-512.png', 512, {}],
    ['icon-maskable-192.png', 192, { maskable: true }],
    ['icon-maskable-512.png', 512, { maskable: true }],
    ['apple-touch-icon.png', 180, { bleed: true }],
    ['favicon-32.png', 32, {}],
];

mkdirSync(OUT_DIR, { recursive: true });
for (const [name, size, opt] of TARGETS) {
    const png = encodePNG(size, render(size, opt));
    writeFileSync(join(OUT_DIR, name), png);
    console.log(`  ${name.padEnd(24)} ${size}×${size}  ${(png.length / 1024).toFixed(1)} KB`);
}
console.log(`\n写入 ${OUT_DIR}`);
