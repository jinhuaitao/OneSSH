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

export function normalizeHost(input) {
    const raw = String(input == null ? '' : input).trim();
    if (!raw) return '';
    if (raw.startsWith('[')) {
        const inner = raw.endsWith(']') ? raw.slice(1, -1) : '';
        return inner && isIPv6(inner) ? '[' + inner.toLowerCase() + ']' : '';
    }
    if (raw.includes(':')) return isIPv6(raw) ? '[' + raw.toLowerCase() + ']' : '';
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/.test(raw)) return '';
    if (raw.includes('..') || raw.length > 253) return '';
    return raw;
}
