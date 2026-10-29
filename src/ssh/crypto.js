// SSH crypto primitives built on WebCrypto (works in Workers + Node 22+)
import { Reader, Writer, concat, toBase64 } from './buf.js';

const subtle = () => globalThis.crypto.subtle;

/* ------------------------------------------------------------------ hashes */

export async function sha256(data) {
    return new Uint8Array(await subtle().digest('SHA-256', data));
}

export async function sha512(data) {
    return new Uint8Array(await subtle().digest('SHA-512', data));
}

export async function sha1(data) {
    return new Uint8Array(await subtle().digest('SHA-1', data));
}

/* -------------------------------------------------------------------- hmac */

const HMAC_HASH = {
    'hmac-sha2-256': { hash: 'SHA-256', len: 32 },
    'hmac-sha2-512': { hash: 'SHA-512', len: 64 },
};

export class Mac {
    constructor(alg, keyBytes) {
        const spec = HMAC_HASH[alg];
        if (!spec) throw new Error('unsupported mac: ' + alg);
        this.alg = alg;
        this.len = spec.len;
        this.hash = spec.hash;
        this.keyBytes = keyBytes;
        this.key = null;
    }
    async ready() {
        this.key = await subtle().importKey('raw', this.keyBytes, { name: 'HMAC', hash: this.hash }, false, ['sign']);
        return this;
    }
    async sign(seq, packet) {
        const head = new Uint8Array(4);
        new DataView(head.buffer).setUint32(0, seq >>> 0);
        const mac = new Uint8Array(await subtle().sign('HMAC', this.key, concat(head, packet)));
        return mac.subarray(0, this.len);
    }
}

/* ------------------------------------------------------------ aes-ctr mode */

function addCounter(iv, blocks) {
    const out = new Uint8Array(iv);
    let add = BigInt(blocks);
    for (let i = 15; i >= 0 && add > 0n; i--) {
        const sum = BigInt(out[i]) + (add & 0xffn);
        out[i] = Number(sum & 0xffn);
        add = (add >> 8n) + (sum >> 8n);
    }
    return out;
}

/**
 * Continuous CTR keystream with byte-granular offsets: SSH encrypts packet by
 * packet but the counter never resets, so we recompute the counter block for
 * each call and slice into the generated keystream.
 */
export class CtrCipher {
    constructor(keyBytes, iv) {
        this.keyBytes = keyBytes;
        this.iv = iv;
        this.offset = 0;
        this.key = null;
    }
    async ready() {
        this.key = await subtle().importKey('raw', this.keyBytes, { name: 'AES-CTR' }, false, ['encrypt']);
        return this;
    }
    async _keystream(len) {
        const startBlock = Math.floor(this.offset / 16);
        const intra = this.offset % 16;
        const blocks = Math.ceil((intra + len) / 16);
        const counter = addCounter(this.iv, startBlock);
        const zeros = new Uint8Array(blocks * 16);
        const ks = new Uint8Array(
            await subtle().encrypt({ name: 'AES-CTR', counter, length: 128 }, this.key, zeros)
        );
        return ks.subarray(intra, intra + len);
    }
    async crypt(data) {
        if (!data.length) return data;
        const ks = await this._keystream(data.length);
        const out = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) out[i] = data[i] ^ ks[i];
        this.offset += data.length;
        return out;
    }
    /** decrypt without advancing the keystream (used to peek at the packet length) */
    async peek(data) {
        const ks = await this._keystream(data.length);
        const out = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) out[i] = data[i] ^ ks[i];
        return out;
    }
}

/* --------------------------------------------------------- key derivation */

/**
 * RFC 4253 §7.2: HASH(K || H || X || session_id), extended when longer keys
 * are needed. K is the mpint-encoded shared secret.
 */
export async function deriveKey(hash, kMpint, H, letter, sessionId, needed) {
    let out = await hash(concat(kMpint, H, new Uint8Array([letter.charCodeAt(0)]), sessionId));
    while (out.length < needed) {
        const next = await hash(concat(kMpint, H, out));
        out = concat(out, next);
    }
    return out.subarray(0, needed);
}

/* ------------------------------------------------------------ curve25519 */

export const CURVE25519 = 'curve25519-sha256';

export async function curve25519Keypair() {
    const kp = await subtle().generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pub = new Uint8Array(await subtle().exportKey('raw', kp.publicKey));
    return { privateKey: kp.privateKey, publicKey: pub };
}

export async function curve25519Shared(privateKey, serverPubRaw) {
    const peer = await subtle().importKey('raw', serverPubRaw, { name: 'X25519' }, false, []);
    const bits = await subtle().deriveBits({ name: 'X25519', public: peer }, privateKey, 256);
    return new Uint8Array(bits);
}

/* --------------------------------------------------------------- der/x509 */

function derTLV(tag, content) {
    const len = content.length;
    let hdr;
    if (len < 0x80) hdr = new Uint8Array([tag, len]);
    else if (len < 0x100) hdr = new Uint8Array([tag, 0x81, len]);
    else if (len < 0x10000) hdr = new Uint8Array([tag, 0x82, len >> 8, len & 0xff]);
    else hdr = new Uint8Array([tag, 0x83, len >> 16, (len >> 8) & 0xff, len & 0xff]);
    return concat(hdr, content);
}

function derInt(raw) {
    let v = raw;
    while (v.length > 1 && v[0] === 0) v = v.subarray(1);
    if (v.length === 0) v = new Uint8Array([0]);
    if (v[0] & 0x80) v = concat(new Uint8Array([0]), v);
    return derTLV(0x02, v);
}

const OID_RSA = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
const OID_EC = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
const OID_P256 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

function rsaSpki(n, e) {
    const alg = derTLV(0x30, concat(derTLV(0x06, OID_RSA), derTLV(0x05, new Uint8Array(0))));
    const bits = derTLV(0x03, concat(new Uint8Array([0]), derTLV(0x30, concat(derInt(n), derInt(e)))));
    return derTLV(0x30, concat(alg, bits));
}

function ecP256Spki(point) {
    const alg = derTLV(0x30, concat(derTLV(0x06, OID_EC), derTLV(0x06, OID_P256)));
    const bits = derTLV(0x03, concat(new Uint8Array([0]), point));
    return derTLV(0x30, concat(alg, bits));
}

/* ----------------------------------------------------------- host key api */

// 不包含 'ssh-rsa'：那意味着用 SHA-1 验证主机签名，2026 年没有任何理由接受。
// （RSA 主机密钥仍然支持，只是强制走 rsa-sha2-256/512）
export const HOST_KEY_ALGS = ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256'];

/** SHA256 fingerprint in the same shape `ssh-keygen -lf` prints. */
export async function fingerprint(keyBlob) {
    const h = await sha256(keyBlob);
    return 'SHA256:' + toBase64(h).replace(/=+$/, '');
}

export function hostKeyType(keyBlob) {
    const r = new Reader(keyBlob);
    return r.text();
}

async function importHostKey(keyBlob) {
    const r = new Reader(keyBlob);
    const type = r.text();
    if (type === 'ssh-ed25519') {
        const pub = r.str();
        return {
            type,
            key: await subtle().importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']),
            params: { name: 'Ed25519' },
        };
    }
    if (type === 'ssh-rsa') {
        const e = r.mpint();
        const n = r.mpint();
        const spki = rsaSpki(n, e);
        const key = await subtle().importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
            'verify',
        ]);
        return { type, key, params: { name: 'RSASSA-PKCS1-v1_5' }, rsa: true };
    }
    if (type.startsWith('ecdsa-sha2-')) {
        const curve = r.text();
        const q = r.str();
        if (curve !== 'nistp256') throw new Error('unsupported ecdsa curve: ' + curve);
        const key = await subtle().importKey('spki', ecP256Spki(q), { name: 'ECDSA', namedCurve: 'P-256' }, false, [
            'verify',
        ]);
        return { type, key, params: { name: 'ECDSA', hash: 'SHA-256' }, ecdsa: true };
    }
    throw new Error('unsupported host key type: ' + type);
}

/**
 * Verify the server signature over the exchange hash.
 * Returns { type, verified, reason }.
 */
export async function verifyHostKeySignature(keyBlob, sigBlob, exchangeHash) {
    const type = hostKeyType(keyBlob);
    const sr = new Reader(sigBlob);
    const sigAlg = sr.text();
    const sig = sr.str();
    const fail = (reason) => ({ type, sigAlg, verified: false, reason });

    // SHA-1 签名一律拒绝：这是最容易被降级命中的一环（rsa-sha2-* 协商成功却被回退到 ssh-rsa）
    if (sigAlg === 'ssh-rsa') return fail('拒绝 SHA-1 主机签名（ssh-rsa），请让服务器改用 rsa-sha2-256/512');

    let imported;
    try {
        imported = await importHostKey(keyBlob);
    } catch (e) {
        return fail(e.message);
    }
    try {
        if (imported.type === 'ssh-ed25519') {
            if (sigAlg !== 'ssh-ed25519') return fail('签名算法（' + sigAlg + '）与主机密钥类型（' + type + '）不符');
            const ok = await subtle().verify({ name: 'Ed25519' }, imported.key, sig, exchangeHash);
            return ok ? { type, sigAlg, verified: true, reason: null } : fail('signature mismatch');
        }
        if (imported.rsa) {
            if (sigAlg !== 'rsa-sha2-256' && sigAlg !== 'rsa-sha2-512') {
                return fail('不支持的 RSA 签名算法：' + sigAlg);
            }
            const hash = sigAlg === 'rsa-sha2-512' ? 'SHA-512' : 'SHA-256';
            const key = await subtle().importKey(
                'spki',
                rsaSpkiFromBlob(keyBlob),
                { name: 'RSASSA-PKCS1-v1_5', hash },
                false,
                ['verify']
            );
            const ok = await subtle().verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sig, exchangeHash);
            return ok ? { type, sigAlg, verified: true, reason: null } : fail('signature mismatch');
        }
        if (imported.ecdsa) {
            if (sigAlg !== 'ecdsa-sha2-nistp256') return fail('签名算法（' + sigAlg + '）与主机密钥类型（' + type + '）不符');
            // SSH packs ECDSA signatures as (mpint r, mpint s); WebCrypto wants r||s
            const ir = new Reader(sig);
            const rr = ir.mpint();
            const ss = ir.mpint();
            const raw = concat(leftPad(rr, 32), leftPad(ss, 32));
            const ok = await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, imported.key, raw, exchangeHash);
            return ok ? { type, sigAlg, verified: true, reason: null } : fail('signature mismatch');
        }
    } catch (e) {
        return fail(String(e && e.message ? e.message : e));
    }
    return fail('unsupported signature algorithm: ' + sigAlg);
}

function rsaSpkiFromBlob(keyBlob) {
    const r = new Reader(keyBlob);
    r.text();
    const e = r.mpint();
    const n = r.mpint();
    return rsaSpki(n, e);
}

function leftPad(u8, len) {
    if (u8.length >= len) return u8.subarray(u8.length - len);
    const out = new Uint8Array(len);
    out.set(u8, len - u8.length);
    return out;
}

export { Writer, Reader };
