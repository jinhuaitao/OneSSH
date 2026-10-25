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

export async function getText(env, key) {
    const obj = await bucket(env).get(key);
    return obj ? await obj.text() : null;
}

export async function putText(env, key, text, meta) {
    await bucket(env).put(key, text, {
        httpMetadata: { contentType: 'text/plain; charset=utf-8' },
        customMetadata: meta,
    });
}

export async function del(env, key) {
    await bucket(env).delete(key);
}

export async function list(env, prefix, includeMeta) {
    const out = [];
    let cursor;
    for (let i = 0; i < 10; i++) {
        const page = await bucket(env).list({
            prefix,
            cursor,
            limit: 500,
            include: includeMeta ? ['customMetadata', 'httpMetadata'] : undefined,
        });
        for (const o of page.objects) out.push(o);
        if (!page.truncated) break;
        cursor = page.cursor;
    }
    return out;
}

export { enc, dec };
