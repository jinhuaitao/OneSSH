// Private key parsing (OpenSSH / PKCS#1 / PKCS#8 / SEC1) + userauth signing.
import { Reader, Writer, concat, fromBase64, bytesToHex } from './buf.js';

const subtle = () => globalThis.crypto.subtle;
const OID_ED25519 = new Uint8Array([0x2b, 0x65, 0x70]);
const OID_RSA = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
const OID_EC = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
const OID_P256 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

/* ------------------------------------------------------------------- der */

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
    if (!v.length) v = new Uint8Array([0]);
    if (v[0] & 0x80) v = concat(new Uint8Array([0]), v);
    return derTLV(0x02, v);
}

function derSeq(...items) {
    return derTLV(0x30, concat(...items));
}

function derOctet(u8) {
    return derTLV(0x04, u8);
}

function derOid(o) {
    return derTLV(0x06, o);
}

function derNull() {
    return derTLV(0x05, new Uint8Array(0));
}

function parseDer(bytes) {
    let p = 0;
    function node() {
        const tag = bytes[p++];
        let len = bytes[p++];
        if (len & 0x80) {
            const n = len & 0x7f;
            len = 0;
            for (let i = 0; i < n; i++) len = (len << 8) | bytes[p++];
        }
        const from = p;
        const to = from + len;
        const value = bytes.subarray(from, to);
        p = to;
        const out = { tag, value, from, to, children: [] };
        // constructed（SEQUENCE/SET）：递归解析子节点。
        // 偏移必须从内容区绝对起点算，不能从 0 重新开始，否则会读回自己的 tag。
        if (tag & 0x20) {
            let q = from;
            while (q < to) {
                const save = p;
                p = q;
                out.children.push(node());
                q = p;
                p = save;
            }
        }
        return out;
    }
    return node();
}

function bigFromBytes(u8) {
    const hex = bytesToHex(u8);
    return hex ? BigInt('0x' + hex) : 0n;
}

function bytesFromBig(v) {
    let hex = v.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

/* ------------------------------------------------------------------ pem */

function pemBody(text) {
    return text.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '').replace(/\s+/g, '');
}

function pkcs8Wrap(innerDer, algOid, curveOid) {
    const algId = curveOid ? derSeq(derOid(algOid), derOid(curveOid)) : derSeq(derOid(algOid), derNull());
    return derSeq(derInt(new Uint8Array([0])), algId, derOctet(innerDer));
}

function rsaPkcs1ToPkcs8(pkcs1) {
    return pkcs8Wrap(pkcs1, OID_RSA);
}

/* --------------------------------------------------------- openssh format */

function parseOpenSSH(text) {
    const raw = fromBase64(pemBody(text));
    const magic = 'openssh-key-v1\0';
    const head = new TextDecoder().decode(raw.subarray(0, magic.length));
    if (head !== magic) throw new Error('不是有效的 OpenSSH 私钥');
    const r = new Reader(raw, magic.length);
    const cipher = r.text();
    const kdf = r.text();
    r.str(); // kdf options
    const nkeys = r.u32();
    for (let i = 0; i < nkeys; i++) r.str(); // public keys
    const priv = r.str();
    if (cipher !== 'none' || kdf !== 'none') {
        throw new Error(ENCRYPTED_HINT);
    }
    const pr = new Reader(priv);
    const c1 = pr.u32();
    const c2 = pr.u32();
    if (c1 !== c2) throw new Error('私钥校验失败（可能口令错误）');
    const type = pr.text();
    if (type === 'ssh-ed25519') {
        const pub = pr.str();
        const priv64 = pr.str();
        return { kind: 'ed25519', seed: priv64.subarray(0, 32), publicRaw: pub };
    }
    if (type === 'ssh-rsa') {
        const n = pr.mpint();
        const e = pr.mpint();
        const d = pr.mpint();
        const iqmp = pr.mpint();
        const p = pr.mpint();
        const q = pr.mpint();
        return { kind: 'rsa', n, e, d, p, q, iqmp };
    }
    if (type.startsWith('ecdsa-sha2-')) {
        const curve = pr.text();
        const pub = pr.str();
        const d = pr.mpint();
        if (curve !== 'nistp256') throw new Error('暂不支持 ' + curve + ' 私钥');
        return { kind: 'ecdsa', d, publicRaw: pub };
    }
    throw new Error('不支持的私钥类型: ' + type);
}

/* ------------------------------------------------------------------ main */

/**
 * @returns {Promise<{alg:string, publicBlob:Uint8Array, sign:(d:Uint8Array)=>Promise<Uint8Array>}>}
 *
 * 注意：不支持带口令（已加密）的私钥 —— 解密它们需要 bcrypt_pbkdf（Blowfish）或 MD5 派生，
 * WebCrypto 两者都没有。所以这里明确报错，而不是收一个用不上的 passphrase 假装支持。
 */
export async function loadPrivateKey(text) {
    if (!text || !text.trim()) throw new Error('私钥内容为空');
    const pem = text.trim();
    if (/BEGIN OPENSSH PRIVATE KEY/.test(pem)) {
        const k = parseOpenSSH(pem);
        if (k.kind === 'ed25519') return ed25519FromSeed(k.seed);
        if (k.kind === 'rsa') return rsaFromComponents(k.n, k.e, k.d, k.p, k.q, k.iqmp);
        if (k.kind === 'ecdsa') throw new Error('暂不支持 ECDSA 私钥，请改用 ed25519 或密码登录');
    }
    if (/BEGIN RSA PRIVATE KEY/.test(pem)) {
        assertNotEncrypted(pem);
        const der = fromBase64(pemBody(pem));
        const root = parseDer(der);
        const ints = root.children.map((c) => c.value);
        // version, n, e, d, p, q, dP, dQ, qInv
        if (ints.length < 3) throw new Error('私钥结构异常（RSAPrivateKey 字段不足）');
        return rsaFromPkcs1(der, ints[1], ints[2]);
    }
    if (/BEGIN ENCRYPTED PRIVATE KEY/.test(pem)) throw new Error(ENCRYPTED_HINT);
    if (/BEGIN PRIVATE KEY/.test(pem)) {
        const der = fromBase64(pemBody(pem));
        const root = parseDer(der);
        const algSeq = root.children[1];
        const inner = root.children[2];
        if (!algSeq || !algSeq.children.length || !inner) throw new Error('私钥结构异常（PKCS#8 字段缺失）');
        const oid = algSeq.children[0].value;
        if (bytesToHex(oid) === bytesToHex(OID_ED25519)) {
            const seed = parseDer(inner.value).value;
            return ed25519FromSeed(seed);
        }
        if (bytesToHex(oid) === bytesToHex(OID_RSA)) {
            const k = parseDer(inner.value);
            const ints = k.children.map((c) => c.value);
            if (ints.length < 3) throw new Error('私钥结构异常（RSAPrivateKey 字段不足）');
            return rsaFromPkcs1(inner.value, ints[1], ints[2]);
        }
        throw new Error('不支持的 PKCS#8 密钥类型');
    }
    if (/BEGIN EC PRIVATE KEY/.test(pem)) {
        assertNotEncrypted(pem);
        throw new Error('暂不支持 EC 私钥，请改用 ed25519 或密码登录');
    }
    throw new Error('无法识别的私钥格式（支持 OpenSSH / PEM PKCS#1 / PKCS#8）');
}

const ENCRYPTED_HINT =
    '这个私钥带口令（已加密），本工具不支持口令私钥。请先在本机去掉口令再粘贴：\n' +
    'ssh-keygen -p -N "" -f <你的私钥文件>（会覆盖原文件，先备份）';

/** 传统 PEM 加密：头部带 "Proc-Type: 4,ENCRYPTED" 与 "DEK-Info" */
function assertNotEncrypted(pem) {
    if (/Proc-Type:\s*4\s*,\s*ENCRYPTED/i.test(pem) || /DEK-Info:/i.test(pem)) throw new Error(ENCRYPTED_HINT);
}

async function ed25519FromSeed(seed) {
    const pkcs8 = derSeq(
        derInt(new Uint8Array([0])),
        derSeq(derOid(OID_ED25519)),
        derOctet(derOctet(seed))
    );
    // extractable so we can read the public half back out of the JWK
    const key = await subtle().importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
    const jwk = await subtle().exportKey('jwk', key).catch(() => null);
    let pubRaw = null;
    if (jwk && jwk.x) {
        const b = jwk.x.replace(/-/g, '+').replace(/_/g, '/');
        pubRaw = fromBase64(b + '='.repeat((4 - (b.length % 4)) % 4));
    }
    if (!pubRaw) throw new Error('无法导出 ed25519 公钥，请检查运行环境是否支持 WebCrypto Ed25519');
    const publicBlob = new Writer().str('ssh-ed25519').str(pubRaw).bytes();
    return {
        alg: 'ssh-ed25519',
        publicBlob,
        async sign(data) {
            return new Uint8Array(await subtle().sign({ name: 'Ed25519' }, key, data));
        },
    };
}

async function rsaFromPkcs1(pkcs1Der, n, e) {
    const pkcs8 = rsaPkcs1ToPkcs8(pkcs1Der);
    const key = await subtle().importKey(
        'pkcs8',
        pkcs8,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const publicBlob = new Writer().str('ssh-rsa').mpint(e).mpint(n).bytes();
    return {
        alg: 'rsa-sha2-256',
        publicBlob,
        async sign(data) {
            return new Uint8Array(await subtle().sign({ name: 'RSASSA-PKCS1-v1_5' }, key, data));
        },
    };
}

async function rsaFromComponents(n, e, d, p, q, iqmp) {
    const N = bigFromBytes(n),
        E = bigFromBytes(e),
        D = bigFromBytes(d),
        P = bigFromBytes(p),
        Q = bigFromBytes(q);
    const dP = D % (P - 1n);
    const dQ = D % (Q - 1n);
    const pkcs1 = derSeq(
        derInt(new Uint8Array([0])),
        derInt(bytesFromBig(N)),
        derInt(bytesFromBig(E)),
        derInt(bytesFromBig(D)),
        derInt(bytesFromBig(P)),
        derInt(bytesFromBig(Q)),
        derInt(bytesFromBig(dP)),
        derInt(bytesFromBig(dQ)),
        derInt(iqmp)
    );
    return rsaFromPkcs1(pkcs1, n, e);
}

export async function signUserauth(key, data) {
    return key.sign(data);
}
