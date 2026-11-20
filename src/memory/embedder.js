import { createHash } from "node:crypto";
import { OpenAIEmbeddings } from "@langchain/openai";
import { config, getSecret } from "../config.js";

/** 本地确定性伪向量：只为让 demo 无需 embedding 服务也能跑通检索链路。
 *  它没有任何语义能力，仅保证「相同文本 → 相同向量」，不可用于生产。 */
function localEmbed(texts, dim) {
  return texts.map((text) => {
    const vec = new Array(dim).fill(0);
    const tokens = String(text).toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
    for (const token of tokens) {
      const h = createHash("sha256").update(token).digest();
      vec[h.readUInt32BE(0) % dim] += 1;
      vec[h.readUInt32BE(4) % dim] += 0.5;
    }
    const norm = Math.hypot(...vec) || 1;
    return vec.map((v) => Number((v / norm).toFixed(6)));
  });
}

/**
 * 关键取舍：LLM 与 Embedding 是两把独立的凭据、两个独立端点。
 *
 * DeepSeek / 硅基流动的 OpenAI 兼容端点只实现 /chat/completions，
 * 实测 /embeddings 返回 404。若沿用一个 baseURL + 一个 key，检索链路会直接崩，
 * 而且会把 chat 密钥误发给第二个服务（凭据超范围使用）。
 * 因此：没显式配 EMBEDDING_API_KEY 就一律降级为 local-hash，链路可跑但语义退化，
 * 并在启动日志里明确标注；要真语义检索，单独配一个 embedding 供应商即可。
 */
export function createEmbedder() {
  if (config.embeddingMode === "remote") {
    const client = new OpenAIEmbeddings({
      model: config.EMBEDDING_MODEL,
      apiKey: getSecret("embedding"),
      ...(/^text-embedding-3/.test(config.EMBEDDING_MODEL) ? { dimensions: config.EMBED_DIM } : {}),
      ...(config.EMBEDDING_BASE_URL ? { configuration: { baseURL: config.EMBEDDING_BASE_URL } } : {}),
    });
    return {
      kind: "remote",
      model: config.EMBEDDING_MODEL,
      async embed(texts) {
        const vecs = await client.embedDocuments(texts);
        // 维度不符时 fail-closed：pgvector 列是 vector(1536)，写错维度会污染整张表
        for (const v of vecs) {
          if (!Array.isArray(v) || v.length !== config.EMBED_DIM) {
            throw new Error(`[embedder] 维度 ${v?.length} ≠ schema vector(${config.EMBED_DIM})，请换模型或改 sql/001_init.sql`);
          }
        }
        return vecs;
      },
    };
  }
  return {
    kind: "local-hash",
    model: "sha256-token-hash",
    embed: async (texts) => localEmbed(texts, config.EMBED_DIM),
  };
}
