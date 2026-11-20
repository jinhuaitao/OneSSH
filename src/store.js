// Thin helpers over the R2 bucket binding (auto-provisioned at deploy time).
const enc = new TextEncoder();
const dec = new TextDecoder();

export function bucket(env) {
    if (!env.BUCKET) {
        throw new Error('缺少 R2 绑定 BUCKET：请检查 wrangler.jsonc 中的 r2_buckets 配置并重新部署');
    }
    return env.BUCKET;
}

export async function getJSON(env, key) {
    const obj = await bucket(env).get(key);
    if (!obj) return null;
    try {
        return await obj.json();
    } catch (_) {
        return null;
    }
}

export async function putJSON(env, key, value, meta) {
    await bucket(env).put(key, JSON.stringify(value), {
        httpMetadata: { contentType: 'application/json' },
        customMetadata: meta,
    });
}

/**
 * 只在 key 不存在时写入（R2 的 If-None-Match: *，条件不满足时 put 返回 null）。
 * 返回 true 表示确实是本次写入的赢家。
 */
export async function putJSONIfAbsent(env, key, value, meta) {
    const obj = await bucket(env).put(key, JSON.stringify(value), {
        httpMetadata: { contentType: 'application/json' },
        customMetadata: meta,
        onlyIf: new Headers({ 'If-None-Match': '*' }),
    });
    return obj !== null;
}

export async function getBytes(env, key) {
    const obj = await bucket(env).get(key);
    if (!obj) return null;
    return { bytes: new Uint8Array(await obj.arrayBuffer()), meta: obj.customMetadata || {} };
}

export async function putBytes(env, key, bytes, meta) {
    await bucket(env).put(key, bytes, {
        httpMetadata: { contentType: 'application/octet-stream' },
        customMetadata: meta,
    });
}

export async function del(env, key) {
    await bucket(env).delete(key);
}

export async function list(env, prefix, includeMeta) {
    const out = [];
    let cursor;
    // 必须翻完所有分页：原来只翻 10 页（5000 个对象），超出的部分静默丢失 ——
    // 会话数超量时「改密踢掉所有设备」会失效，主机/日志列表也会被截断。
    for (let i = 0; i < 200; i++) {
        const page = await bucket(env).list({
            prefix,
            cursor,
            limit: 500,
            include: includeMeta ? ['customMetadata', 'httpMetadata'] : undefined,
        });
        for (const o of page.objects) out.push(o);
        if (!page.truncated) return out;
        cursor = page.cursor;
    }
    return out;
}

/**
 * 带上限的 list：拿到 limit 条就停，不翻完所有页。
 * 只适用于「够数就能下结论」的场景（连接预算：limit+1 条就知道超没超；
 * 主机数量上限：MAX_HOSTS 条就知道满没满）。需要「一个都不能漏」的场景
 * （destroyAllSessions、pruneSessions、列表展示）继续用全量 list()。
 */
export async function listLimited(env, prefix, limit, includeMeta) {
    const out = [];
    let cursor;
    for (let i = 0; i < 200 && out.length < limit; i++) {
        const page = await bucket(env).list({
            prefix,
            cursor,
            limit: Math.min(500, limit - out.length),
            include: includeMeta ? ['customMetadata', 'httpMetadata'] : undefined,
        });
        for (const o of page.objects) out.push(o);
        if (!page.truncated) return out;
        cursor = page.cursor;
    }
    return out;
}

/* ----------------------------------------------------- 并发批量读写 */

// R2 单次读的延迟在 10-50ms 量级，串行回读 100 个对象就是「首页打不开」。
// 分批并发把总耗时压到原来的约 1/24，且不改变总请求数（免费计划 50 子请求
// 的上限由对象数量决定，并发方式不影响它）。
const BATCH = 24;

export async function getJSONAll(env, keys, batchSize = BATCH) {
    const out = new Array(keys.length).fill(null);
    for (let i = 0; i < keys.length; i += batchSize) {
        const chunk = keys.slice(i, i + batchSize);
        const parts = await Promise.all(chunk.map((k) => getJSON(env, k)));
        for (let j = 0; j < chunk.length; j++) out[i + j] = parts[j];
    }
    return out;
}

/** 列出前缀下所有对象并并发回读内容：[ { key, rec } ]，读取失败/为空的条目跳过 */
export async function listJSON(env, prefix, batchSize = BATCH) {
    const objs = await list(env, prefix);
    const recs = await getJSONAll(env, objs.map((o) => o.key), batchSize);
    const out = [];
    for (let i = 0; i < objs.length; i++) {
        if (recs[i]) out.push({ key: objs[i].key, rec: recs[i] });
    }
    return out;
}

export async function putJSONAll(env, pairs, batchSize = BATCH) {
    for (let i = 0; i < pairs.length; i += batchSize) {
        const chunk = pairs.slice(i, i + batchSize);
        await Promise.all(chunk.map((p) => putJSON(env, p.key, p.rec, p.meta)));
    }
}

export async function delAll(env, keys, batchSize = BATCH) {
    for (let i = 0; i < keys.length; i += batchSize) {
        const chunk = keys.slice(i, i + batchSize);
        await Promise.all(chunk.map((k) => del(env, k)));
    }
}

export { enc, dec };
