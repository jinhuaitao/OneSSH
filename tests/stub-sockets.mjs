/** `cloudflare:sockets` 的测试桩：不真的建连，只把参数记下来方便断言。 */
export const attempts = [];

export function connect(target) {
    attempts.push(target);
    const err = new Error('测试环境不建立真实 TCP 连接');
    err.code = 'ENOT_TEST';
    return {
        opened: Promise.reject(err),
        readable: { getReader: () => ({ read: () => Promise.resolve({ done: true }) }) },
        writable: { getWriter: () => ({ write: () => Promise.resolve(), close: () => Promise.resolve() }) },
        close: () => Promise.resolve(),
    };
}
