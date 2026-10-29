/**
 * 测试基础设施：一个内存版 R2 桶 + 一个能直接调用 Worker fetch 的客户端。
 *
 * 目标是把「路由 / 鉴权 / 加密 / 限流 / CRUD」这条链路放进 `node --test` 里跑，
 * 既不依赖 wrangler，也不依赖真实的 Cloudflare 账号。
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

function toBytes(value) {
    if (value == null) return new Uint8Array(0);
    if (typeof value === 'string') return enc.encode(value);
    if (value instanceof Uint8Array) return value.slice();
    if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    return enc.encode(String(value));
}

class StoredObject {
    constructor(key, bytes, opts) {
        this.key = key;
        this.bytes = bytes;
        this.size = bytes.length;
        this.uploaded = new Date();
        this.httpMetadata = (opts && opts.httpMetadata) || {};
        this.customMetadata = (opts && opts.customMetadata) || {};
    }
    async json() {
        return JSON.parse(dec.decode(this.bytes));
    }
    async text() {
        return dec.decode(this.bytes);
    }
    async arrayBuffer() {
        return this.bytes.buffer.slice(this.bytes.byteOffset, this.bytes.byteOffset + this.bytes.length);
    }
}

/** 只实现 Worker 代码真正用到的那部分 R2 API。 */
export class MemoryBucket {
    constructor() {
        this.map = new Map();
        this.puts = 0;
    }
    async get(key) {
        return this.map.get(key) || null;
    }
    async put(key, value, opts) {
        this.puts++;
        const onlyIf = opts && opts.onlyIf;
        if (onlyIf && onlyIf.get && onlyIf.get('if-none-match') === '*' && this.map.has(key)) {
            // R2 语义：条件不满足时返回 null，而不是抛错
            return null;
        }
        const obj = new StoredObject(key, toBytes(value), opts);
        this.map.set(key, obj);
        return obj;
    }
    async delete(key) {
        this.map.delete(key);
    }
    async list(query) {
        const q = query || {};
        const prefix = q.prefix || '';
        const limit = Math.min(1000, q.limit || 1000);
        const keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
        const start = q.cursor ? Number(q.cursor) || 0 : 0;
        const slice = keys.slice(start, start + limit);
        const objects = slice.map((k) => {
            const o = this.map.get(k);
            return {
                key: k,
                size: o.size,
                uploaded: o.uploaded,
                customMetadata: q.include && q.include.includes('customMetadata') ? o.customMetadata : undefined,
                httpMetadata: q.include && q.include.includes('httpMetadata') ? o.httpMetadata : undefined,
            };
        });
        const truncated = start + slice.length < keys.length;
        return { objects, truncated, cursor: truncated ? String(start + slice.length) : undefined };
    }
    keys(prefix) {
        return [...this.map.keys()].filter((k) => k.startsWith(prefix || '')).sort();
    }
}

export const ORIGIN = 'https://webssh.test';

export function makeEnv(extra) {
    return Object.assign({ BUCKET: new MemoryBucket() }, extra || {});
}

/** 调一次 Worker；返回 { status, headers, text, json } 方便断言。 */
export async function call(env, path, opts) {
    const o = opts || {};
    const headers = new Headers(o.headers || {});
    let body;
    if (o.body !== undefined) {
        if (typeof o.body === 'string') {
            body = o.body;
        } else {
            body = JSON.stringify(o.body);
            if (!headers.has('content-type')) headers.set('content-type', 'application/json');
        }
    }
    if (o.method && o.method !== 'GET' && !headers.has('origin') && o.origin !== false) {
        headers.set('origin', ORIGIN);
    }
    if (o.cookie) headers.set('cookie', o.cookie);
    if (o.ip) headers.set('cf-connecting-ip', o.ip);

    const req = new Request(ORIGIN + path, { method: o.method || 'GET', headers, body });
    const res = await env.__worker.fetch(req, env, {});
    const text = await res.text();
    let parsed = null;
    if (text) {
        try {
            parsed = JSON.parse(text);
        } catch (_) {
            parsed = null;
        }
    }
    return { status: res.status, headers: res.headers, text, json: parsed, res };
}

export function cookieFrom(res) {
    const raw = res.headers.get('set-cookie') || '';
    return raw.split(';')[0];
}

/** 直接读桶里的 JSON 记录（用来断言「落盘的是密文」这类事实）。 */
export function stored(env, key) {
    const obj = env.BUCKET.map.get(key);
    if (!obj) return null;
    return JSON.parse(dec.decode(obj.bytes));
}

/** 从 Worker 响应里取出会话 token（用于断言 / 复用）。 */
export function tokenFrom(res) {
    const raw = res.headers.get('set-cookie') || '';
    const m = raw.match(/wssh_session=([a-f0-9]{64})/);
    return m ? m[1] : '';
}

export const ADMIN = { username: 'admin', password: 'correct-horse-battery' };
