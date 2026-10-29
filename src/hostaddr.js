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
