// Cloudflare's connect() requires IPv6 literals in brackets; the UI and the
// stored records keep that form too so displays read as user@[addr]:port.

function isIPv6(s) {
    if (!s.includes(':') || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
    try {
        new URL('http://[' + s + ']/');
        return true;
    } catch (_) {
        return false;
    }
}

/**
 * 逐段校验域名。
 *
 * 原来只用一条 `/^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/` 卡整体，
 * 于是 `bad-.example`、`a..b`（后者靠 includes('..') 兜住）这类以连字符结尾的
 * 段也能通过 —— 存进库没问题，等真正 connect() 时才在 DNS 层失败，
 * 错误信息还是一句「无法建立 TCP 连接」，很难定位。这里按 label 检查：
 * 每段 1-63 字符、首尾不能是连字符、总长不超过 253。
 */
function isHostname(raw) {
    if (raw.length > 253) return false;
    for (const label of raw.split('.')) {
        if (!label || label.length > 63) return false;
        if (!/^[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?$/.test(label)) return false;
    }
    return true;
}

export function normalizeHost(input) {
    const raw = String(input == null ? '' : input).trim();
    if (!raw) return '';
    if (raw.startsWith('[')) {
        const inner = raw.endsWith(']') ? raw.slice(1, -1) : '';
        return inner && isIPv6(inner) ? '[' + inner.toLowerCase() + ']' : '';
    }
    if (raw.includes(':')) return isIPv6(raw) ? '[' + raw.toLowerCase() + ']' : '';
    if (!isHostname(raw)) return '';
    return raw;
}

/* ------------------------------------------------------- 私网 / 保留地址 */

// 把字面 IP 解析成 { v: 4|6, parts: number[] }；域名或解析失败返回 null。
// 与 src/auth.js 的 parseIp 同源逻辑，但 hostaddr 不能 import auth
//（auth 不依赖 hostaddr，反向依赖会形成循环）。
function parseLiteralIp(raw) {
    let s = String(raw == null ? '' : raw).trim().toLowerCase();
    if (!s) return null;
    if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
    if (s.includes(':')) {
        // IPv4 内嵌（::ffff:10.0.0.1）：先按 IPv4 尾部解析
        if (s.includes('.')) {
            const i = s.lastIndexOf(':');
            const v4 = s.slice(i + 1).split('.');
            if (v4.length === 4) {
                const n = v4.map((x) => (/^\d{1,3}$/.test(x) ? Number(x) : NaN));
                if (n.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
                    // 只有 ::ffff:a.b.c.d 这种映射形才算 IPv4；其他带点的写法非法
                    const head = s.slice(0, i).toLowerCase();
                    if (head === '::ffff' || head === '::') return { v: 4, parts: n };
                }
            }
            return null;
        }
        const halves = s.split('::');
        if (halves.length > 2) return null;
        const head = halves[0] ? halves[0].split(':') : [];
        const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : null;
        let groups;
        if (tail === null) groups = head;
        else {
            const fill = 8 - head.length - tail.length;
            if (fill < 1) return null;
            groups = head.concat(new Array(fill).fill('0'), tail);
        }
        if (groups.length !== 8) return null;
        const out = [];
        for (const g of groups) {
            if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
            out.push(parseInt(g, 16));
        }
        return { v: 6, parts: out };
    }
    const p = s.split('.');
    if (p.length !== 4) return null;
    const n = p.map((x) => (/^\d{1,3}$/.test(x) ? Number(x) : NaN));
    if (n.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
    return { v: 4, parts: n };
}

function isPrivateV4(parts) {
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8（本机 / 未指定）
    if (a === 10) return true; // 10/8
    if (a === 127) return true; // 127/8（环回）
    if (a === 169 && b === 254) return true; // 169.254/16（链路本地）
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
    if (a === 192 && b === 168) return true; // 192.168/16
    return false;
}

function isPrivateV6(parts) {
    // ::1（环回）与 ::（未指定）
    if (parts.every((x) => x === 0)) return true;
    if (parts.slice(0, 7).every((x) => x === 0) && parts[7] === 1) return true;
    if ((parts[0] & 0xfe00) === 0xfc00) return true; // fc00::/7（ULA）
    if ((parts[0] & 0xffc0) === 0xfe80) return true; // fe80::/10（链路本地）
    return false;
}

/**
 * 字面 IP 是否为私网 / 保留地址。域名返回 false（不是字面 IP，无法在
 * 不解析 DNS 的情况下判断）；解析失败返回 false（调用方另有格式校验）。
 * 2001:db8::/32 是文档段（TEST-NET），故意不拦：测试与示例都用它，
 * 且它在公网 DNS 里不会指向真实主机。
 */
export function isPrivateIP(input) {
    const parsed = parseLiteralIp(input);
    if (!parsed) return false;
    if (parsed.v === 4) return isPrivateV4(parsed.parts);
    return isPrivateV6(parsed.parts);
}

/**
 * 该地址是否允许作为 SSH 目标。域名一律放行（解析后的地址 Workers 的
 * connect() 还会再拦一次私网，见 README「DNS 重绑定」说明）；字面
 * 私网 / 保留 IP 拒绝；格式非法的也拒绝。
 */
export function isPublicHost(input) {
    const norm = normalizeHost(input);
    if (!norm) return false;
    if (parseLiteralIp(norm)) return !isPrivateIP(norm);
    return true;
}
