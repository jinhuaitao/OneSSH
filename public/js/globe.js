/* Orthographic globe: NASA Blue Marble on a WebGL sphere, markers on canvas 2D. */

const TAU = Math.PI * 2;
const RAD = Math.PI / 180;

const QUAD_VERT = `
attribute vec2 aPos;
void main() { gl_Position = vec4(aPos, 0.0, 1.0); }
`;

// atmosphere bloom and the page shadow, outside the disk
const BG_FRAG = `
precision highp float;
uniform vec2 uCenter;
uniform float uRadius;
void main() {
    vec2 p = (gl_FragCoord.xy - uCenter) / uRadius;
    float r = length(p);
    if (r <= 1.0) discard;
    float ga = 1.0 - smoothstep(1.0, 1.075, r);
    ga = ga * ga * 0.45;
    vec3 gc = vec3(0.42, 0.64, 0.92);
    vec2 s = (p - vec2(0.06, -1.03)) / vec2(0.78, 0.14);
    float sa = (1.0 - smoothstep(0.15, 1.0, length(s))) * 0.16;
    vec3 sc = vec3(0.45, 0.39, 0.31);
    gl_FragColor = vec4(gc * ga + sc * sa, ga + sa);
}
`;

const SPHERE_VERT = `
attribute vec3 aPos;
attribute vec2 aUv;
uniform vec2 uView;   // globe radius in clip space, per axis
uniform float uYaw;
uniform float uPitch;
varying vec2 vUv;
varying vec3 vN;
void main() {
    float cy = cos(uYaw);
    float sy = sin(uYaw);
    vec3 p = vec3(aPos.x * cy + aPos.z * sy, aPos.y, -aPos.x * sy + aPos.z * cy);
    float cp = cos(uPitch);
    float sp = sin(uPitch);
    vN = vec3(p.x, p.y * cp - p.z * sp, p.y * sp + p.z * cp);
    vUv = aUv;
    gl_Position = vec4(vN.x * uView.x, vN.y * uView.y, 0.0, 1.0);
}
`;

const SPHERE_FRAG = `
precision highp float;
uniform sampler2D uTex;
varying vec2 vUv;
varying vec3 vN;
void main() {
    vec3 n = normalize(vN);
    // lifted and slightly washed out so the globe sits on the light dashboard
    vec3 tex = pow(texture2D(uTex, vUv).rgb, vec3(0.66));
    tex = mix(tex, vec3(0.90, 0.94, 0.98), 0.18);
    vec3 L = normalize(vec3(-0.5, 0.58, 0.64));
    float diff = max(dot(n, L), 0.0);
    float lit = 0.88 + 0.26 * pow(diff, 0.9);
    vec3 H = normalize(L + vec3(0.0, 0.0, 1.0));
    float water = smoothstep(0.02, 0.14, tex.b - tex.r);
    float glint = pow(max(dot(n, H), 0.0), 110.0) * water * 0.55;
    float graze = pow(1.0 - max(n.z, 0.0), 3.0);
    float haze = graze * 0.42 + graze * diff * 0.18;
    vec3 col = tex * lit + vec3(glint) + vec3(0.62, 0.76, 0.92) * haze;
    gl_FragColor = vec4(col, 1.0);
}
`;

/* ------------------------------------------------------------------- globe */

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
    let downX = 0;
    let downY = 0;
    let tapMoved = 0;
    let raf = 0;
    let points = [];
    let selected = null;
    let alive = true;

    /* --------------------------------------------------------- gl layer */

    const glCanvas = document.createElement('canvas');
    glCanvas.setAttribute('aria-hidden', 'true');
    glCanvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;pointer-events:none';
    canvas.parentNode.insertBefore(glCanvas, canvas);

    const gl = glCanvas.getContext('webgl', { alpha: true, antialias: true });
    let bgProg = null;
    let bgUni = null;
    let bgPos = -1;
    let sphereProg = null;
    let sphereUni = null;
    let sphereCount = 0;
    let quadBuf = null;
    let posBuf = null;
    let uvBuf = null;
    let idxBuf = null;
    let texture = null;
    let texWanted = false;
    let texReady = false;
    let glOk = !!gl;

    function makeProgram(frag, vert) {
        const compile = (type, src) => {
            const sh = gl.createShader(type);
            gl.shaderSource(sh, src);
            gl.compileShader(sh);
            if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(sh));
            return sh;
        };
        const prog = gl.createProgram();
        gl.attachShader(prog, compile(gl.VERTEX_SHADER, vert));
        gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, frag));
        gl.linkProgram(prog);
        if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog));
        return prog;
    }

    // UV sphere: texture coordinates interpolate across the mesh, so the
    // equirectangular seam and the polar singularity never reach the shader
    function buildSphere() {
        const SEG = 128;
        const RING = 64;
        const verts = [];
        const uvs = [];
        for (let y = 0; y <= RING; y++) {
            const v = y / RING;
            const lat = (0.5 - v) * Math.PI;
            const cl = Math.cos(lat);
            const sl = Math.sin(lat);
            for (let x = 0; x <= SEG; x++) {
                const u = x / SEG;
                const lon = (u - 0.5) * TAU;
                verts.push(cl * Math.sin(lon), sl, cl * Math.cos(lon));
                uvs.push(u, 1 - v);
            }
        }
        const idx = [];
        for (let y = 0; y < RING; y++) {
            for (let x = 0; x < SEG; x++) {
                const a = y * (SEG + 1) + x;
                const b = a + 1;
                const c = a + SEG + 1;
                const d = c + 1;
                idx.push(a, c, b, b, c, d);
            }
        }
        sphereCount = idx.length;

        posBuf = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, posBuf);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(verts), gl.STATIC_DRAW);

        uvBuf = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, uvBuf);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(uvs), gl.STATIC_DRAW);

        idxBuf = gl.createBuffer();
        gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, idxBuf);
        gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, new Uint16Array(idx), gl.STATIC_DRAW);
    }

    function initGL() {
        if (!gl) return;
        bgProg = makeProgram(BG_FRAG, QUAD_VERT);
        sphereProg = makeProgram(SPHERE_FRAG, SPHERE_VERT);

        bgUni = {
            center: gl.getUniformLocation(bgProg, 'uCenter'),
            radius: gl.getUniformLocation(bgProg, 'uRadius'),
        };
        bgPos = gl.getAttribLocation(bgProg, 'aPos');
        sphereUni = {
            view: gl.getUniformLocation(sphereProg, 'uView'),
            yaw: gl.getUniformLocation(sphereProg, 'uYaw'),
            pitch: gl.getUniformLocation(sphereProg, 'uPitch'),
            tex: gl.getUniformLocation(sphereProg, 'uTex'),
            aPos: gl.getAttribLocation(sphereProg, 'aPos'),
            aUv: gl.getAttribLocation(sphereProg, 'aUv'),
        };

        quadBuf = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, quadBuf);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);

        buildSphere();

        gl.disable(gl.BLEND);
        gl.disable(gl.DEPTH_TEST);

        texture = gl.createTexture();
        gl.bindTexture(gl.TEXTURE_2D, texture);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 1, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE, new Uint8Array([12, 40, 66, 255]));
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.REPEAT);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    }

    // the pane is hidden below 1180px; only pay for the 1MB texture once it shows
    function wantTexture() {
        if (texWanted || !gl || !glOk) return;
        texWanted = true;
        loadTexture();
    }

    function loadTexture() {
        const img = new Image();
        img.decoding = 'async';
        img.onload = () => {
            if (!alive || !gl || gl.isContextLost()) return;
            gl.bindTexture(gl.TEXTURE_2D, texture);
            gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, true);
            gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, img);
            gl.generateMipmap(gl.TEXTURE_2D);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
            const aniso = gl.getExtension('EXT_texture_filter_anisotropic');
            if (aniso) {
                const max = gl.getParameter(aniso.MAX_TEXTURE_MAX_ANISOTROPY_EXT);
                gl.texParameterf(gl.TEXTURE_2D, aniso.TEXTURE_MAX_ANISOTROPY_EXT, Math.min(8, max));
            }
            texReady = true;
        };
        img.src = 'img/earth.jpg';
    }

    if (gl) {
        try {
            initGL();
        } catch (e) {
            glOk = false;
        }
        glCanvas.addEventListener('webglcontextlost', (ev) => {
            ev.preventDefault();
            texReady = false;
            glOk = false;
        });
        glCanvas.addEventListener('webglcontextrestored', () => {
            glOk = true;
            try {
                initGL();
                if (texWanted) loadTexture();
            } catch (e) {
                glOk = false;
            }
        });
    }

    function drawGL() {
        if (!gl || !bgProg || gl.isContextLost()) return;
        gl.viewport(0, 0, glCanvas.width, glCanvas.height);
        gl.clearColor(0, 0, 0, 0);
        gl.clear(gl.COLOR_BUFFER_BIT);

        // sky: atmosphere and shadow behind the disk
        gl.disable(gl.CULL_FACE);
        gl.useProgram(bgProg);
        gl.bindBuffer(gl.ARRAY_BUFFER, quadBuf);
        gl.enableVertexAttribArray(bgPos);
        gl.vertexAttribPointer(bgPos, 2, gl.FLOAT, false, 0, 0);
        gl.uniform2f(bgUni.center, cx * dpr, (H - cy) * dpr);
        gl.uniform1f(bgUni.radius, R * dpr);
        gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);

        // globe
        gl.enable(gl.CULL_FACE);
        gl.cullFace(gl.BACK);
        gl.useProgram(sphereProg);
        gl.bindBuffer(gl.ARRAY_BUFFER, posBuf);
        gl.enableVertexAttribArray(sphereUni.aPos);
        gl.vertexAttribPointer(sphereUni.aPos, 3, gl.FLOAT, false, 0, 0);
        gl.bindBuffer(gl.ARRAY_BUFFER, uvBuf);
        gl.enableVertexAttribArray(sphereUni.aUv);
        gl.vertexAttribPointer(sphereUni.aUv, 2, gl.FLOAT, false, 0, 0);
        gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, idxBuf);
        gl.activeTexture(gl.TEXTURE0);
        gl.bindTexture(gl.TEXTURE_2D, texture);
        gl.uniform1i(sphereUni.tex, 0);
        gl.uniform2f(sphereUni.view, (2 * R) / Math.max(1, W), (2 * R) / Math.max(1, H));
        gl.uniform1f(sphereUni.yaw, ((yaw % TAU) + TAU) % TAU);
        gl.uniform1f(sphereUni.pitch, pitch);
        gl.drawElements(gl.TRIANGLES, sphereCount, gl.UNSIGNED_SHORT, 0);
        gl.disable(gl.CULL_FACE);
    }

    /* --------------------------------------------------------- projection */

    let cosYaw = Math.cos(yaw);
    let sinYaw = Math.sin(yaw);

    function project(latDeg, lonDeg) {
        const la = latDeg * RAD;
        const lo = lonDeg * RAD;
        const cl = Math.cos(la);
        const y0 = Math.sin(la);
        const x0 = cl * Math.sin(lo);
        const z0 = cl * Math.cos(lo);
        const x1 = x0 * cosYaw + z0 * sinYaw;
        const z1 = z0 * cosYaw - x0 * sinYaw;
        const cp = Math.cos(pitch);
        const sp = Math.sin(pitch);
        const ny = y0 * cp - z1 * sp;
        const z = y0 * sp + z1 * cp;
        return { x: cx + x1 * R, y: cy - ny * R, z };
    }

    /* ------------------------------------------------------ 2d fallback */

    function drawFallback() {
        const g = ctx.createRadialGradient(cx - R * 0.42, cy - R * 0.46, R * 0.04, cx + R * 0.1, cy + R * 0.14, R * 1.12);
        g.addColorStop(0, '#5d95bb');
        g.addColorStop(0.55, '#2f668f');
        g.addColorStop(1, '#123a5c');
        ctx.beginPath();
        ctx.arc(cx, cy, R, 0, TAU);
        ctx.fillStyle = g;
        ctx.fill();
        ctx.beginPath();
        ctx.arc(cx, cy, R - 0.5, 0, TAU);
        ctx.lineWidth = 1;
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.4)';
        ctx.stroke();
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
            ctx.fillStyle = 'rgba(255, 74, 23, ' + (0.16 * fade * (1 - pulse * 0.7)).toFixed(3) + ')';
            ctx.fill();
            // white collar keeps the pin readable over land and sea
            ctx.beginPath();
            ctx.arc(s.x, s.y, 5.2, 0, TAU);
            ctx.strokeStyle = 'rgba(255, 255, 255, ' + (0.9 * fade).toFixed(3) + ')';
            ctx.lineWidth = 1.8;
            ctx.stroke();
            // core
            ctx.beginPath();
            ctx.arc(s.x, s.y, 2.7, 0, TAU);
            ctx.fillStyle = 'rgba(255, 74, 23, ' + fade.toFixed(3) + ')';
            ctx.fill();
            if (p === selected) {
                ctx.beginPath();
                ctx.arc(s.x, s.y, 9, 0, TAU);
                ctx.strokeStyle = 'rgba(255, 74, 23, ' + (0.5 * fade).toFixed(3) + ')';
                ctx.lineWidth = 1.4;
                ctx.stroke();
            }
        }
    }

    /* ------------------------------------------------------- name card */

    const card = document.createElement('div');
    card.className = 'glabel';
    card.style.display = 'none';
    const cardFlag = document.createElement('span');
    cardFlag.className = 'gl-flag';
    const cardTxt = document.createElement('span');
    cardTxt.className = 'gl-txt';
    const cardName = document.createElement('span');
    cardName.className = 'gl-name';
    const cardCity = document.createElement('span');
    cardCity.className = 'gl-city';
    cardTxt.appendChild(cardName);
    cardTxt.appendChild(cardCity);
    card.appendChild(cardFlag);
    card.appendChild(cardTxt);
    labelLayer.appendChild(card);
    card.addEventListener('click', (ev) => {
        ev.stopPropagation();
        if (selected && options.onPick) options.onPick(selected);
    });

    function selectPoint(p) {
        selected = p;
        if (!p) {
            card.style.display = 'none';
            return;
        }
        cardFlag.textContent = p.flag || '🌐';
        cardName.textContent = p.name || '';
        cardCity.textContent = p.city || '';
        card.style.display = '';
        card.style.opacity = '0';
    }

    function placeCard() {
        const p = selected;
        if (!p || !p._z || p._z <= 0.08) {
            card.style.display = 'none';
            return;
        }
        if (card.style.display === 'none') card.style.display = '';
        const w = card.offsetWidth || 132;
        const h = card.offsetHeight || 34;
        let x = p._x + 14;
        if (x + w > W - 6) x = p._x - w - 14;
        x = Math.max(4, x);
        const y = Math.max(2 + h / 2, Math.min(H - 2 - h / 2, p._y));
        card.style.left = Math.round(x) + 'px';
        card.style.top = Math.round(y) + 'px';
        card.style.opacity = String(Math.min(1, (p._z - 0.08) / 0.3).toFixed(2));
    }

    function pickAt(x, y) {
        let best = null;
        let bestD = 15 * 15;
        for (const p of points) {
            if (!p._z || p._z <= 0.08) continue;
            const dx = p._x - x;
            const dy = p._y - y;
            const d = dx * dx + dy * dy;
            if (d < bestD) {
                bestD = d;
                best = p;
            }
        }
        return best;
    }

    /* --------------------------------------------------------------- loop */

    let last = 0;

    function frame(t) {
        if (!alive) return;
        const dt = last ? Math.min(60, t - last) : 16;
        last = t;
        if (auto && !dragging && !selected) {
            yaw += dt * 0.00011;
            cosYaw = Math.cos(yaw);
            sinYaw = Math.sin(yaw);
        }
        if (glOk && texReady) drawGL();
        ctx.clearRect(0, 0, W, H);
        if (!glOk || !texReady) drawFallback();
        drawMarkers(t);
        placeCard();
        raf = requestAnimationFrame(frame);
    }

    /* ---------------------------------------------------------- interact */

    function resize() {
        const rect = canvas.getBoundingClientRect();
        const w = Math.max(80, Math.round(rect.width));
        const h = Math.max(80, Math.round(rect.height));
        dpr = Math.min(2.5, window.devicePixelRatio || 1);
        canvas.width = Math.round(w * dpr);
        canvas.height = Math.round(h * dpr);
        glCanvas.width = Math.round(w * dpr);
        glCanvas.height = Math.round(h * dpr);
        W = w;
        H = h;
        cx = w / 2;
        cy = h / 2;
        R = Math.min(w, h) * 0.43;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        if (w >= 200) wantTexture();
    }

    function onDown(ev) {
        dragging = true;
        lastX = ev.clientX;
        lastY = ev.clientY;
        downX = ev.clientX;
        downY = ev.clientY;
        tapMoved = 0;
        canvas.setPointerCapture(ev.pointerId);
    }
    function onMove(ev) {
        if (!dragging) {
            const rect = canvas.getBoundingClientRect();
            canvas.style.cursor = pickAt(ev.clientX - rect.left, ev.clientY - rect.top) ? 'pointer' : 'grab';
            return;
        }
        const dx = ev.clientX - lastX;
        const dy = ev.clientY - lastY;
        lastX = ev.clientX;
        lastY = ev.clientY;
        tapMoved = Math.max(tapMoved, Math.abs(ev.clientX - downX) + Math.abs(ev.clientY - downY));
        yaw += dx * 0.0062;
        pitch = Math.max(-1.15, Math.min(1.15, pitch + dy * 0.005));
        cosYaw = Math.cos(yaw);
        sinYaw = Math.sin(yaw);
    }
    function onUp(ev) {
        if (!dragging) return;
        dragging = false;
        try {
            canvas.releasePointerCapture(ev.pointerId);
        } catch (_) {}
        if (tapMoved < 6) {
            const rect = canvas.getBoundingClientRect();
            selectPoint(pickAt(ev.clientX - rect.left, ev.clientY - rect.top));
        }
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
            selectPoint(null);
            points = (list || []).map((p, i) => Object.assign({ phase: i * 1.3 }, p));
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
            card.remove();
            glCanvas.remove();
        },
    };
}
