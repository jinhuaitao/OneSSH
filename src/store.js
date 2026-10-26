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

export { enc, dec };
