import { createHash } from "node:crypto";
import { withTenant } from "../db/pool.js";
import { config } from "../config.js";
import { scanInjection, scanSecrets, sanitizeRetrieved } from "../security/injection.js";
import { redact } from "../security/pii.js";
import { T } from "../db/tables.js";

const hash = (s) => createHash("sha256").update(s).digest("hex");
const vectorLiteral = (vec) => `[${vec.join(",")}]`;

/**
 * L2 记忆层：RAG 是间接 Prompt Injection 的头号入口。
 * 三层防护：
 *   1. 写入前扫描 → 含注入/凭据的内容标 quarantined，永不参与检索
 *   2. 读取时 RLS 租户隔离 + trust 过滤（DB 层兜底，不靠应用层记得加 WHERE）
 *   3. 结果逐条 sanitize 后再包 untrusted 信封交给模型（见 inputGuard.buildContext）
 */
export function createPgVectorStore({ pool, embedder }) {
  return {
    kind: "pgvector",

    async add({ tenantId, ownerId, source, content }) {
      const clean = redact(String(content ?? ""));
      const hits = [...scanInjection(clean).flags, ...scanSecrets(clean)];
      const trust = hits.length
        ? "quarantined"
        : source.startsWith("kb:") ? "trusted" : "untrusted";
      const [vec] = await embedder.embed([clean]);
      const row = await withTenant(pool, tenantId, (client) =>
        client.query(
          `INSERT INTO ${T.memoryChunks} (tenant_id, owner_id, source, trust, content, content_hash, embedding)
           VALUES ($1,$2,$3,$4,$5,$6,$7::vector)
           ON CONFLICT (content_hash) DO NOTHING
           RETURNING id, trust`,
          [tenantId, ownerId, source, trust, clean, hash(`${tenantId}:${clean}`), vectorLiteral(vec)]
        )
      );
      return { id: row.rows[0]?.id ?? null, trust, flags: hits };
    },

    async search({ tenantId, query, k = 4 }) {
      const [vec] = await embedder.embed([query]);
      const safeK = Math.min(Math.max(1, Number(k) || 4), 20);
      const { result, excludedRes } = await withTenant(pool, tenantId, async (client) => ({
        result: await client.query(
          `SELECT id::text, source, trust, content,
                  1 - (embedding <=> $1::vector) AS similarity
             FROM ${T.memoryChunks}
            WHERE trust <> 'quarantined'
              AND embedding IS NOT NULL
            ORDER BY embedding <=> $1::vector
            LIMIT $2`,
          [vectorLiteral(vec), safeK]
        ),
        excludedRes: await client.query(
          `SELECT count(*)::int AS n FROM ${T.memoryChunks} WHERE trust = 'quarantined'`
        ),
      }));
      const chunks = result.rows.map((r) => ({
        id: r.id, source: r.source, trust: r.trust, content: r.content,
        similarity: Number(r.similarity),
      }));
      const sanitized = sanitizeRetrieved(chunks);
      return {
        ...sanitized,
        accepted: sanitized.accepted.map((c) => ({ ...c, content: redact(c.content) })),
        excluded: excludedRes.rows[0]?.n ?? 0, // 写入时就被隔离的条数
      };
    },
  };
}

/** 内存实现：接口与 pgvector 版完全一致。离线演示与「真实 LLM + 内存存储」组合都用它 */
export function createMemoryVectorStore({ embedder }) {
  const rows = [];
  return {
    kind: "memory",
    rows,
    async add({ tenantId, ownerId, source, content }) {
      const clean = redact(String(content ?? ""));
      const hits = [...scanInjection(clean).flags, ...scanSecrets(clean)];
      const trust = hits.length ? "quarantined" : source.startsWith("kb:") ? "trusted" : "untrusted";
      const [vec] = await embedder.embed([clean]);
      const existing = rows.find((r) => r.contentHash === hash(`${tenantId}:${clean}`));
      if (existing) return { id: existing.id, trust, flags: hits };
      const id = `mem-${rows.length + 1}`;
      rows.push({ id, tenantId, ownerId, source, trust, content: clean, contentHash: hash(`${tenantId}:${clean}`), vec });
      return { id, trust, flags: hits };
    },
    async search({ tenantId, query, k = 4 }) {
      const [qv] = await embedder.embed([query]);
      const chunks = rows
        .filter((r) => r.tenantId === tenantId && r.trust !== "quarantined")
        .map((r) => ({
          id: r.id, source: r.source, trust: r.trust, content: r.content,
          similarity: r.vec.reduce((s, v, i) => s + v * (qv[i] ?? 0), 0),
        }))
        .sort((a, b) => b.similarity - a.similarity)
        .slice(0, Math.min(k, config.EMBED_DIM));
      const sanitized = sanitizeRetrieved(chunks);
      return {
        ...sanitized,
        accepted: sanitized.accepted.map((c) => ({ ...c, content: redact(c.content) })),
        excluded: rows.filter((r) => r.tenantId === tenantId && r.trust === "quarantined").length,
      };
    },
  };
}
