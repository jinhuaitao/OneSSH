/* Dotted orthographic globe: land mask + host markers + DOM label cards. */

import { LAND_META, LAND_ROWS } from './land.js';

const TAU = Math.PI * 2;
const RAD = Math.PI / 180;

/* ------------------------------------------------------------ land dots */

const LAND = (() => {
    const out = [];
    const { cols, rows, lat0, step } = LAND_META;
    for (let r = 0; r < rows; r++) {
        const line = LAND_ROWS[r] || '';
        const lat = (lat0 + (r + 0.5) * step) * RAD;
        const cosLat = Math.cos(lat);
        const sinLat = Math.sin(lat);
        for (let c = 0; c < cols; c++) {
            const ch = line[Math.floor(c / 4)];
            if (!ch) continue;
            const nibble = parseInt(ch, 16);
            if (!Number.isFinite(nibble)) continue;
            if (!((nibble >> (3 - (c % 4))) & 1)) continue;
            const lon = (-180 + (c + 0.5) * step) * RAD;
            out.push({
                cl: cosLat,
                sl: sinLat,
                cn: Math.cos(lon),
                sn: Math.sin(lon),
            });
        }
    }
    return out;
})();

export function landDotCount() {
    return LAND.length;
}

/* ---------------------------------------------------------------- globe */

export function createGlobe(canvas, labelLayer, opts) {
    const options = opts || {};
    const ctx = canvas.getContext('2d', { alpha: true });
    let dpr = Math.min(2.5, window.devicePixelRatio || 1);
    let W = 0;
    let H = 0;
    let cx = 0;
    let cy = 0;
    let R = 100;

    let yaw = -1.92; // centres the disk on ~110°E
    let pitch = 0.28; // and tilts it up to ~16°N
    let auto = options.autoRotate !== false;
    let dragging = false;
    let lastX = 0;
    let lastY = 0;
    let raf = 0;
    let points = [];
    let labels = [];
    let alive = true;

    /* ------------------------------------------------------------ sizing */

    function resize() {
        const rect = canvas.getBoundingClientRect();
        const w = Math.max(80, Math.round(rect.width));
        const h = Math.max(80, Math.round(rect.height));
        dpr = Math.min(2.5, window.devicePixelRatio || 1);
        canvas.width = Math.round(w * dpr);
        canvas.height = Math.round(h * dpr);
        W = w;
        H = h;
        cx = w / 2;
        cy = h / 2;
        R = Math.min(w, h) * 0.43;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    /* -------------------------------------------------------- projection */

    let cosYaw = Math.cos(yaw);
    let sinYaw = Math.sin(yaw);

    function project(latDeg, lonDeg) {
        const la = latDeg * RAD;
        const lo = lonDeg * RAD;
        const cl = Math.cos(la);
        const y0 = Math.sin(la);
        const x0 = cl * Math.sin(lo);
        const z0 = cl * Math.cos(lo);
        // yaw
        const x1 = x0 * cosYaw + z0 * sinYaw;
        const z1 = z0 * cosYaw - x0 * sinYaw;
        // pitch (rotate around X)
        const cp = Math.cos(pitch);
        const sp = Math.sin(pitch);
        const y2 = y0 * cp - z1 * sp;
        const z2 = y0 * sp + z1 * cp;
        return { x: cx + x1 * R, y: cy - y2 * R, z: z2 };
    }

    /* ------------------------------------------------------------ drawing */

    function drawSphere() {
        const g = ctx.createRadialGradient(cx - R * 0.34, cy - R * 0.4, R * 0.08, cx, cy, R * 1.02);
        g.addColorStop(0, '#ffffff');
        g.addColorStop(0.62, '#fdfbf7');
        g.addColorStop(1, '#f3ede3');
        ctx.beginPath();
        ctx.arc(cx, cy, R, 0, TAU);
        ctx.fillStyle = g;
        ctx.fill();
        ctx.lineWidth = 1;
        ctx.strokeStyle = 'rgba(170, 158, 138, 0.5)';
        ctx.stroke();
    }

    const BUCKETS = 6;

    function drawLand() {
        const cosP = Math.cos(pitch);
        const sinP = Math.sin(pitch);
        const buckets = [];
        for (let i = 0; i < BUCKETS; i++) buckets.push([]);

        for (let i = 0; i < LAND.length; i++) {
            const d = LAND[i];
            const x0 = d.cl * (d.sn * cosYaw + d.cn * sinYaw);
            const z1 = d.cl * (d.cn * cosYaw - d.sn * sinYaw);
            const y2 = d.sl * cosP - z1 * sinP;
            const z2 = d.sl * sinP + z1 * cosP;
            if (z2 <= 0.015) continue;
            const x = cx + x0 * R;
            const y = cy - y2 * R;
            const b = Math.min(BUCKETS - 1, Math.floor(z2 * BUCKETS));
            buckets[b].push(x, y, z2);
        }

        const base = Math.max(0.85, R / 132);
        for (let b = 0; b < BUCKETS; b++) {
            const arr = buckets[b];
            if (!arr.length) continue;
            const depth = (b + 0.5) / BUCKETS;
            ctx.beginPath();
            const rad = base * (0.62 + depth * 0.5);
            for (let i = 0; i < arr.length; i += 3) {
                ctx.moveTo(arr[i] + rad, arr[i + 1]);
                ctx.arc(arr[i], arr[i + 1], rad, 0, TAU);
            }
            ctx.fillStyle = 'rgba(38, 33, 26, ' + (0.09 + depth * 0.44).toFixed(3) + ')';
            ctx.fill();
        }
    }

    function drawMarkers(t) {
        for (const p of points) {
            const s = project(p.lat, p.lon);
            p._x = s.x;
            p._y = s.y;
            p._z = s.z;
            if (s.z <= 0.03) continue;
            const fade = Math.min(1, (s.z - 0.03) / 0.32);
            const pulse = (Math.sin(t / 620 + (p.phase || 0)) + 1) / 2;
            // halo
            ctx.beginPath();
            ctx.arc(s.x, s.y, 6 + pulse * 6, 0, TAU);
            ctx.fillStyle = 'rgba(255, 74, 23, ' + (0.14 * fade * (1 - pulse * 0.7)).toFixed(3) + ')';
            ctx.fill();
            // ring
            ctx.beginPath();
            ctx.arc(s.x, s.y, 4.6, 0, TAU);
            ctx.strokeStyle = 'rgba(255, 74, 23, ' + (0.55 * fade).toFixed(3) + ')';
            ctx.lineWidth = 1.2;
            ctx.stroke();
            // core
            ctx.beginPath();
            ctx.arc(s.x, s.y, 2.5, 0, TAU);
            ctx.fillStyle = 'rgba(255, 74, 23, ' + fade.toFixed(3) + ')';
            ctx.fill();
        }
    }

    /* ------------------------------------------------------------- labels */

    function syncLabels() {
        if (labels.length !== points.length) {
            labelLayer.textContent = '';
            labels = points.map((p) => {
                const node = document.createElement('div');
                node.className = 'glabel';
                const flag = document.createElement('span');
                flag.className = 'gl-flag';
                flag.textContent = p.flag || '🌐';
                const txt = document.createElement('span');
                txt.className = 'gl-txt';
                const nm = document.createElement('span');
                nm.className = 'gl-name';
                nm.textContent = p.name || '';
                const ct = document.createElement('span');
                ct.className = 'gl-city';
                ct.textContent = p.city || '';
                txt.appendChild(nm);
                txt.appendChild(ct);
                node.appendChild(flag);
                node.appendChild(txt);
                node.addEventListener('click', (ev) => {
                    ev.stopPropagation();
                    if (options.onPick) options.onPick(p);
                });
                labelLayer.appendChild(node);
                return { node, p, h: 34, w: 132 };
            });
        }
    }

    function layoutLabels() {
        const placed = [];
        // 前面的先放，后面的避让
        const order = labels.slice().sort((a, b) => (b.p._z || -1) - (a.p._z || -1));
        for (const item of order) {
            const p = item.p;
            const visible = p._z > 0.08;
            if (!visible) {
                item.node.style.opacity = '0';
                item.node.style.pointerEvents = 'none';
                continue;
            }
            const w = item.node.offsetWidth || 132;
            const h = item.node.offsetHeight || 34;
            let x = p._x + 12;
            let y = p._y;
            if (x + w > W - 4) x = p._x - w - 12;
            const tries = [0, -h - 6, h + 6, -2 * (h + 6), 2 * (h + 6)];
            let ok = false;
            for (const dy of tries) {
                const yy = y + dy;
                const box = { x, y: yy - h / 2, w, h };
                if (box.y < 2 || box.y + h > H - 2) continue;
                let hit = false;
                for (const other of placed) {
                    if (box.x < other.x + other.w + 4 && box.x + w + 4 > other.x && box.y < other.y + other.h + 4 && box.y + h + 4 > other.y) {
                        hit = true;
                        break;
                    }
                }
                if (!hit) {
                    y = yy;
                    ok = true;
                    break;
                }
            }
            placed.push({ x, y: y - h / 2, w, h });
            item.node.style.opacity = String(Math.min(1, (p._z - 0.08) / 0.3).toFixed(2));
            item.node.style.pointerEvents = 'auto';
            item.node.style.left = Math.round(x) + 'px';
            item.node.style.top = Math.round(y) + 'px';
            item.node.style.zIndex = String(10 + Math.round(p._z * 40));
            if (!ok) item.node.style.opacity = '0.55';
        }
    }

    /* --------------------------------------------------------------- loop */

    let last = 0;

    function frame(t) {
        if (!alive) return;
        const dt = last ? Math.min(60, t - last) : 16;
        last = t;
        if (auto && !dragging) {
            yaw += dt * 0.00011;
            cosYaw = Math.cos(yaw);
            sinYaw = Math.sin(yaw);
        }
        ctx.clearRect(0, 0, W, H);
        drawSphere();
        drawLand();
        drawMarkers(t);
        layoutLabels();
        raf = requestAnimationFrame(frame);
    }

    /* ---------------------------------------------------------- interact */

    function onDown(ev) {
        dragging = true;
        lastX = ev.clientX;
        lastY = ev.clientY;
        canvas.setPointerCapture(ev.pointerId);
    }
    function onMove(ev) {
        if (!dragging) return;
        const dx = ev.clientX - lastX;
        const dy = ev.clientY - lastY;
        lastX = ev.clientX;
        lastY = ev.clientY;
        yaw += dx * 0.0062;
        pitch = Math.max(-1.15, Math.min(1.15, pitch - dy * 0.005));
        cosYaw = Math.cos(yaw);
        sinYaw = Math.sin(yaw);
    }
    function onUp(ev) {
        dragging = false;
        try {
            canvas.releasePointerCapture(ev.pointerId);
        } catch (_) {}
    }

    canvas.addEventListener('pointerdown', onDown);
    canvas.addEventListener('pointermove', onMove);
    canvas.addEventListener('pointerup', onUp);
    canvas.addEventListener('pointercancel', onUp);

    const ro = new ResizeObserver(() => resize());
    ro.observe(canvas.parentElement || canvas);

    resize();
    raf = requestAnimationFrame(frame);

    return {
        setPoints(list) {
            points = (list || []).map((p, i) => Object.assign({ phase: i * 1.3 }, p));
            labels = [];
            syncLabels();
        },
        setAutoRotate(on) {
            auto = !!on;
        },
        isAutoRotate() {
            return auto;
        },
        nudge() {
            yaw += 0.12;
            cosYaw = Math.cos(yaw);
            sinYaw = Math.sin(yaw);
        },
        destroy() {
            alive = false;
            cancelAnimationFrame(raf);
            ro.disconnect();
            canvas.removeEventListener('pointerdown', onDown);
            canvas.removeEventListener('pointermove', onMove);
            canvas.removeEventListener('pointerup', onUp);
            canvas.removeEventListener('pointercancel', onUp);
        },
    };
}
