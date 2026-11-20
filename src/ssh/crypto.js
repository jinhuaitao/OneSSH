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
        // 4 字节序号头复用：sign() 里 concat() 会同步把它拷进新缓冲（见 sign 注释），
        // 拷完之后再无任何 await 接触它；而且 sign 的调用方（send/_readPacket）
        // 都是串行 await，不存在两个 sign 交错写同一块 head 的情况。
        this._head = new Uint8Array(4);
        this._headView = new DataView(this._head.buffer);
    }
    async ready() {
        this.key = await subtle().importKey('raw', this.keyBytes, { name: 'HMAC', hash: this.hash }, false, ['sign']);
        return this;
    }
    async sign(seq, packet) {
        this._headView.setUint32(0, seq >>> 0);
        // concat() 是同步拷贝：head 的 4 个字节在这一行就进了新缓冲，
        // 之后的 await（subtle.sign）再也不会读到 this._head，所以复用安全。
        // packet 本身那份拷贝省不掉：WebCrypto sign 只接受一段连续缓冲，
        // 没有流式 HMAC 接口，seq 头 + 包体必须先拼成一段。
        const mac = new Uint8Array(await subtle().sign('HMAC', this.key, concat(this._head, packet)));
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

// keystream 按 16KB 块生成：足够覆盖一次 peek(16B 头) + 绝大多数整包，
// 又不至于一次分配过大；大于 16KB 的包分块生成。
const KS_CHUNK = 16 * 1024;
// 全零输入复用同一块只读缓冲：subtle().encrypt 不改写输入，
// 两个方向的 CtrCipher 并发调用也安全。
const ZEROS = new Uint8Array(KS_CHUNK);

/** out[i] = data[i] ^ ks[i]：能对齐时按 Uint32 批量异或，尾部逐字节。 */
function xorInto(out, data, ks) {
    const n = data.length;
    let i = 0;
    // 先逐字节走到 data 4 字节对齐（最多 3 字节）；此时 ks/out 若也对齐，
    // 字边界就一致，批量异或才与逐字节等价。
    const lead = (4 - (data.byteOffset & 3)) & 3;
    for (; i < lead && i < n; i++) out[i] = data[i] ^ ks[i];
    if (i < n && ((ks.byteOffset + i) & 3) === 0 && ((out.byteOffset + i) & 3) === 0) {
        const words = (n - i) >> 2;
        const d32 = new Uint32Array(data.buffer, data.byteOffset + i, words);
        const k32 = new Uint32Array(ks.buffer, ks.byteOffset + i, words);
        const o32 = new Uint32Array(out.buffer, out.byteOffset + i, words);
        for (let j = 0; j < words; j++) o32[j] = d32[j] ^ k32[j];
        i += words << 2;
    }
    for (; i < n; i++) out[i] = data[i] ^ ks[i];
}

/**
 * Continuous CTR keystream with byte-granular offsets: SSH encrypts packet by
 * packet but the counter never resets, so we recompute the counter block for
 * each call and slice into the generated keystream.
 *
 * 缓存：最近一次生成的 16KB keystream 块留在 this._ks 里（[_ksStart, _ksStart
 * + _ks.length)）。_readPacket 里 peek(16B 包头) 紧接着 crypt(整包)，
 * 原来同一包头要算两次 keystream，现在第二次命中缓存、不调 WebCrypto；
 * 大包分块生成时，未用完的块尾也留在缓存里给下一次调用。
 * offset 只向前走，缓存的区间永远是“已生成且对应当前 key/iv 的真 keystream”，
 * 不存在过期问题；peek 不推进 offset，所以 peek 后的 crypt 仍命中同一区间。
 */
export class CtrCipher {
    constructor(keyBytes, iv) {
        this.keyBytes = keyBytes;
        this.iv = iv;
        this.offset = 0;
        this.key = null;
        this._ks = null;
        this._ksStart = 0;
    }
    async ready() {
        this.key = await subtle().importKey('raw', this.keyBytes, { name: 'AES-CTR' }, false, ['encrypt']);
        return this;
    }
    async _keystream(len) {
        const start = this.offset;
        const end = start + len;
        // 全部命中缓存：直接切片，不调 WebCrypto
        if (this._ks && start >= this._ksStart && end <= this._ksStart + this._ks.length) {
            return this._ks.subarray(start - this._ksStart, end - this._ksStart);
        }
        const parts = [];
        let covered = start;
        // 缓存的前缀能覆盖一部分：先取走，避免重算
        if (this._ks && start >= this._ksStart && start < this._ksStart + this._ks.length) {
            const take = Math.min(this._ksStart + this._ks.length, end) - start;
            parts.push(this._ks.subarray(start - this._ksStart, start - this._ksStart + take));
            covered = start + take;
        }
        let lastChunk = null;
        let lastChunkStart = 0;
        while (covered < end) {
            const startBlock = Math.floor(covered / 16);
            const intra = covered % 16;
            // 本轮从块边界起算，最多生成一个 16KB 块
            const want = Math.min(KS_CHUNK, end - covered + intra);
            const blocks = Math.ceil(want / 16);
            const counter = addCounter(this.iv, startBlock);
            const ks = new Uint8Array(
                await subtle().encrypt({ name: 'AES-CTR', counter, length: 128 }, this.key, ZEROS.subarray(0, blocks * 16))
            );
            const take = Math.min(ks.length - intra, end - covered);
            parts.push(ks.subarray(intra, intra + take));
            lastChunk = ks;
            lastChunkStart = startBlock * 16;
            covered += take;
        }
        // 只缓存最后生成的整块：它的尾部可能正好是下一次 peek/crypt 的起点
        // （例如 peek 生成 16KB 后 crypt 只消耗了包头部分，剩余仍在缓存里）。
        if (lastChunk) {
            this._ks = lastChunk;
            this._ksStart = lastChunkStart;
        }
        if (parts.length === 1) return parts[0];
        const out = new Uint8Array(len);
        let o = 0;
        for (const p of parts) {
            out.set(p, o);
            o += p.length;
        }
        return out;
    }
    async crypt(data) {
        if (!data.length) return data;
        const ks = await this._keystream(data.length);
        const out = new Uint8Array(data.length);
        xorInto(out, data, ks);
        this.offset += data.length;
        return out;
    }
    /** decrypt without advancing the keystream (used to peek at the packet length) */
    async peek(data) {
        const ks = await this._keystream(data.length);
        const out = new Uint8Array(data.length);
        xorInto(out, data, ks);
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

/* ------------------------------------------- diffie-hellman group14-sha256 */

// RFC 3526 §3：2048-bit MODP 群（group 14），生成元 g = 2。
// 素数 p 的 16 进制值即 RFC 3526 给出的 group 14 素数（与 Node
// crypto.createDiffieHellman('modp14') 的素数一致，见测试）。
export const DH_GROUP14_PRIME_HEX =
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AACAA68FFFFFFFFFFFFFFFF';
export const DH_GROUP14_PRIME = BigInt('0x' + DH_GROUP14_PRIME_HEX);
const DH_GROUP14_G = 2n;

function modPow(base, exp, mod) {
    let result = 1n;
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
        if (e & 1n) result = (result * b) % mod;
        e >>= 1n;
        if (e) b = (b * b) % mod;
    }
    return result;
}

function bigIntToBytes(v) {
    if (v === 0n) return new Uint8Array([0]);
    let hex = v.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

function bytesToBigInt(u8) {
    if (!u8.length) return 0n;
    let hex = '';
    for (const b of u8) hex += b.toString(16).padStart(2, '0');
    return BigInt('0x' + hex);
}

/**
 * mpint 的值字节：最小大端表示，最高位为 1 时前补一个 0x00（RFC 4251 §5）。
 * 按此规范化后，Writer().mpint() 不会再改动它，包里发的 e 与交换哈希里的 e
 * 就是同一串字节。
 */
function mpintValueBytes(v) {
    const b = bigIntToBytes(v);
    if (b[0] & 0x80) {
        const out = new Uint8Array(b.length + 1);
        out.set(b, 1);
        return out;
    }
    return b;
}

/**
 * 生成 group14 密钥对。私钥 x 为 256-bit 随机数（范围 2..p-2），公钥为
 * g^x mod p（mpint 值字节形式）。
 * @returns {{ privateKey: bigint, publicKey: Uint8Array }}
 */
export function dhGroup14Keypair() {
    const p = DH_GROUP14_PRIME;
    let x;
    do {
        x = bytesToBigInt(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    } while (x < 2n || x > p - 2n);
    return { privateKey: x, publicKey: mpintValueBytes(modPow(DH_GROUP14_G, x, p)) };
}

/**
 * 计算 group14 共享密钥。serverPubBytes 为对端公钥 f 的 mpint 值字节
 * （KEXDH_REPLY 里 str() 读出的内容）；返回原始大端字节，调用方再按
 * 现有用法包一层 Writer().mpint()（与 curve25519Shared 的约定一致）。
 * f 不在 (1, p-1) 范围内直接拒绝：那是无效/恶意的 DH 公钥。
 */
export function dhGroup14Shared(privateKey, serverPubBytes) {
    const p = DH_GROUP14_PRIME;
    const f = bytesToBigInt(serverPubBytes);
    if (f <= 1n || f >= p - 1n) {
        throw new Error('DH group14: 对端公钥不在有效范围 (1 < f < p-1)，已中止连接');
    }
    return bigIntToBytes(modPow(f, privateKey, p));
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

async function importHostKey(keyBlob, sigAlg) {
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
        // RSA 的 hash 由签名算法定（rsa-sha2-256 → SHA-256，rsa-sha2-512 → SHA-512）：
        // WebCrypto 的 key 绑定 hash，SHA-256 的 key 验不了 SHA-512 的签名，
        // 所以必须按 sigAlg 导入——但只导入一次。旧代码在这里按 SHA-256
        // 导入一次，验签分支又按 hash 再导入一次，第二次导入才是真正用的那把。
        const hash = sigAlg === 'rsa-sha2-512' ? 'SHA-512' : 'SHA-256';
        const key = await subtle().importKey('spki', rsaSpki(n, e), { name: 'RSASSA-PKCS1-v1_5', hash }, false, [
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

    // RSA 的签名算法必须在导入前定下来：hash 绑在 key 上，算法不对连导入
    // 都没意义；提前拒绝也避免给一个非法算法白白导入一次。
    if (type === 'ssh-rsa' && sigAlg !== 'rsa-sha2-256' && sigAlg !== 'rsa-sha2-512') {
        return fail('不支持的 RSA 签名算法：' + sigAlg);
    }

    let imported;
    try {
        imported = await importHostKey(keyBlob, sigAlg);
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
            // hash 已在 importHostKey 里按 sigAlg 选好，这把 key 就是验签用的那把，不再导入
            const ok = await subtle().verify({ name: 'RSASSA-PKCS1-v1_5' }, imported.key, sig, exchangeHash);
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

function leftPad(u8, len) {
    if (u8.length >= len) return u8.subarray(u8.length - len);
    const out = new Uint8Array(len);
    out.set(u8, len - u8.length);
    return out;
}

export { Writer, Reader };
