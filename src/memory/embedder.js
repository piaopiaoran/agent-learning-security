import { createHash } from "node:crypto";
import { OpenAIEmbeddings } from "@langchain/openai";
import { config, getSecret } from "../config.js";

/** 本地确定性伪向量：只为让 offline demo 无需 API key 也能跑通检索链路。
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

export function createEmbedder({ offline = false } = {}) {
  if (!offline && config.hasLLM) {
    const client = new OpenAIEmbeddings({
      model: config.EMBEDDING_MODEL,
      apiKey: getSecret("openai"),
      dimensions: config.EMBED_DIM,
    });
    return {
      kind: "openai",
      embed: (texts) => client.embedDocuments(texts),
    };
  }
  return {
    kind: "local-hash",
    embed: async (texts) => localEmbed(texts, config.EMBED_DIM),
  };
}
