/**
 * L0 限流：滑窗计数器，按 (tenantId, userId) 维度。
 * 单进程内存版仅用于本地演示；多副本部署必须换 Redis / DB（否则每副本各算各的，等于没限）。
 * 面试点：Agent 限流要限「每轮对话的图执行次数」，而不只是 HTTP QPS —— 一次请求可能内部跑 20 步。
 */
export function createRateLimiter({ limit = 20, windowMs = 60_000 } = {}) {
  const buckets = new Map();

  return {
    check(key, now = Date.now()) {
      const cutoff = now - windowMs;
      const hits = (buckets.get(key) ?? []).filter((t) => t > cutoff);
      if (hits.length >= limit) {
        buckets.set(key, hits);
        return { ok: false, remaining: 0, retryAfterMs: Math.max(1, hits[0] + windowMs - now) };
      }
      hits.push(now);
      buckets.set(key, hits);
      return { ok: true, remaining: limit - hits.length };
    },
    reset(key) {
      buckets.delete(key);
    },
    size() {
      return buckets.size;
    },
  };
}
