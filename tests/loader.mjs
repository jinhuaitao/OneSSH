/**
 * 让 Node 能加载 src/ 下的 Worker 代码。
 *
 * worker.js / session.js 都 `import { connect } from 'cloudflare:sockets'`，
 * 这是 Workers 运行时专有的模块，Node 无法解析。测试里用 --import 注册这个
 * resolve hook，把它指向一个只在测试中存在的桩，于是整条链路（路由 → 存储 →
 * 加密 → 鉴权）都能在本地跑起来，不需要 wrangler、不需要网络、不需要真 sshd。
 */
export async function resolve(specifier, context, next) {
    if (specifier === 'cloudflare:sockets') {
        return { url: new URL('./stub-sockets.mjs', import.meta.url).href, shortCircuit: true };
    }
    return next(specifier, context);
}
