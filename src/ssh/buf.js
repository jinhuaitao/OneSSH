// SSH binary buffer helpers (RFC 4251 §5)
const TE = new TextEncoder();
const TD = new TextDecoder();

export class Reader {
    constructor(bytes, pos = 0) {
        this.b = bytes;
        this.p = pos;
    }
    get left() {
        return this.b.length - this.p;
    }
    eof() {
        return this.p >= this.b.length;
    }
    byte() {
        return this.b[this.p++];
    }
    bool() {
        return this.b[this.p++] !== 0;
    }
    u32() {
        const b = this.b,
            p = this.p;
        const v = ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
        this.p = p + 4;
        return v;
    }
    /** length-prefixed byte string */
    str() {
        const n = this.u32();
        if (this.p + n > this.b.length) throw new Error('ssh: truncated string');
        const s = this.b.subarray(this.p, this.p + n);
        this.p += n;
        return s;
    }
    text() {
        return TD.decode(this.str());
    }
    /** mpint as raw big-endian magnitude (leading 0x00 stripped) */
    mpint() {
        const raw = this.str();
        if (raw.length && raw[0] === 0) return raw.subarray(1);
        return raw;
    }
    nameList() {
        const t = this.text();
        return t.length ? t.split(',') : [];
    }
    rest() {
        const s = this.b.subarray(this.p);
        this.p = this.b.length;
        return s;
    }
}

export class Writer {
    constructor() {
        this.parts = [];
        this.len = 0;
    }
    _push(u8) {
        this.parts.push(u8);
        this.len += u8.length;
        return this;
    }
    byte(v) {
        return this._push(new Uint8Array([v & 0xff]));
    }
    bool(v) {
        return this.byte(v ? 1 : 0);
    }
    u32(v) {
        const a = new Uint8Array(4);
        new DataView(a.buffer).setUint32(0, v >>> 0);
        return this._push(a);
    }
    raw(u8) {
        return this._push(u8 instanceof Uint8Array ? u8 : new Uint8Array(u8));
    }
    str(v) {
        const u8 = typeof v === 'string' ? TE.encode(v) : v;
        this.u32(u8.length);
        return this._push(u8);
    }
    nameList(list) {
        return this.str(list.join(','));
    }
    /** mpint: raw magnitude bytes, prepend 0x00 when the high bit is set */
    mpint(raw) {
        let v = raw;
        while (v.length > 1 && v[0] === 0 && !(v[1] & 0x80)) v = v.subarray(1);
        if (v.length && v[0] & 0x80) {
            const t = new Uint8Array(v.length + 1);
            t.set(v, 1);
            v = t;
        }
        return this.str(v);
    }
    bytes() {
        const out = new Uint8Array(this.len);
        let o = 0;
        for (const p of this.parts) {
            out.set(p, o);
            o += p.length;
        }
        return out;
    }
}

export function concat(...arrs) {
    let n = 0;
    for (const a of arrs) n += a.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const a of arrs) {
        out.set(a, o);
        o += a.length;
    }
    return out;
}

export function bytesToHex(u8) {
    let s = '';
    for (const b of u8) s += b.toString(16).padStart(2, '0');
    return s;
}

export function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

export function toBase64(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
}

export function fromBase64(b64) {
    const s = atob(b64.replace(/\s+/g, ''));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
}

export function randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
}

export function utf8(s) {
    return TE.encode(s);
}

export function fromUtf8(u8) {
    return TD.decode(u8);
}

export function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
}
