import test from "node:test";
import assert from "node:assert/strict";
import { HumanMessage } from "@langchain/core/messages";
import { config, getSecret, assertSafeEndpoint } from "../src/config.js";
import { createModel } from "../src/graph/model.js";
import { createEmbedder } from "../src/memory/embedder.js";
import { createRuntime } from "../src/runtime.js";
import { traceConfig } from "../src/observability.js";
import { SECRET_RULES } from "../src/security/patterns.js";

const identity = {
  traceId: "trace-1", sessionId: "session-1",
  tenantId: "tenant-a", userId: "u-1", role: "user",
};

test("LLM 配置 / config 对象不含任何密钥，端点只保留 origin", () => {
  const dump = JSON.stringify(config);
  assert.ok(!dump.includes("sk-"), "不得包含 LLM key 前缀");
  assert.ok(!dump.includes("lsv2"), "不得包含 LangSmith key 前缀");
  assert.equal(config.LLM_API_KEY, undefined);
  assert.equal(config.EMBEDDING_API_KEY, undefined);
  assert.equal(config.LANGSMITH_API_KEY, undefined);
  assert.ok(!String(config.llmEndpoint).includes("/v1"), "日志里的端点不应带路径/查询串");
});

test("LLM 配置 / 密钥只能通过白名单 getter 取用", () => {
  for (const n of ["llm", "openai", "embedding", "langsmith"]) {
    assert.equal(typeof getSecret(n), "string");
  }
  assert.throws(() => getSecret("anything_else"));
});

test("LLM 配置 / 端点必须 HTTPS，禁止 URL 内嵌凭据或查询串", () => {
  assert.equal(assertSafeEndpoint("https://api.deepseek.com/v1"), "https://api.deepseek.com");
  assert.equal(assertSafeEndpoint("http://localhost:11434/v1"), "http://localhost:11434");
  assert.throws(() => assertSafeEndpoint("http://api.example.com/v1"), /HTTPS/);
  assert.throws(() => assertSafeEndpoint("https://user:pass@api.example.com/v1"), /凭据/);
  assert.throws(() => assertSafeEndpoint("https://api.example.com/v1?key=abc"), /凭据/);
  assert.throws(() => assertSafeEndpoint("not-a-url"), /合法 URL/);
});

test("LLM 配置 / 凭据泄漏规则覆盖新的环境变量名", () => {
  const rule = SECRET_RULES.find((r) => r.id === "env_secret");
  assert.ok(rule);
  for (const line of [
    "LLM_API_KEY=sk-abcdefgh12345678",
    "EMBEDDING_API_KEY=sk-abcdefgh12345678",
    "LANGSMITH_API_KEY=lsv2_pt_abcdefgh1234",
  ]) {
    assert.ok(rule.re.test(line), `应识别 ${line.split("=")[0]}`);
  }
});

test("模型 / fake 模式返回确定性 tool_calls，且不发起外部请求", async () => {
  const model = createModel({ offline: true });
  const res = await model.invoke([new HumanMessage("帮我查一下 ORD-1001 的订单状态")]);
  assert.equal(res.tool_calls[0].name, "get_order_status");
  assert.deepEqual(res.tool_calls[0].args, { orderId: "ORD-1001" });
  assert.ok(res.usage_metadata.total_tokens > 0, "L7 预算依赖 usage_metadata");
});

test("Embedding / 无专用凭据时降级为 1536 维本地确定性向量", async (t) => {
  const embedder = createEmbedder();
  if (embedder.kind !== "local-hash") {
    return t.skip("已配置远程 embedding，跳过降级路径");
  }
  const [a, b] = await embedder.embed(["退款政策", "退款政策"]);
  assert.equal(a.length, config.EMBED_DIM);
  assert.deepEqual(a, b, "相同文本必须得到相同向量");
  assert.ok(Math.abs(Math.hypot(...a) - 1) < 1e-3, "向量应归一化");
});

test("Runtime / 模型模式与存储模式正交，真实模型不必依赖数据库", async () => {
  const rt = await createRuntime({ model: "fake", store: "memory" });
  assert.equal(rt.modelMode, "fake");
  assert.equal(rt.storeMode, "memory");
  assert.equal(rt.pool, null, "memory 模式不应创建连接池");
  assert.equal(rt.vectorStore.kind, "memory");
  await rt.close();
});

test("Runtime / --offline 强制 fake + memory", async () => {
  const rt = await createRuntime({ offline: true });
  assert.equal(rt.modelMode, "fake");
  assert.equal(rt.storeMode, "memory");
  assert.equal(rt.offline, true);
  await rt.close();
});

test("可观测性 / trace metadata 标注模型与存储模式，但不含任何密钥", () => {
  const t = traceConfig(identity, { metadata: { modelMode: "openai", storeMode: "memory" } });
  assert.equal(t.metadata.modelMode, "openai");
  assert.equal(t.metadata.storeMode, "memory");
  assert.ok(!("userId" in t.metadata));
  const dump = JSON.stringify(t);
  assert.ok(!dump.includes("sk-"));
  assert.ok(!dump.includes("lsv2"));
});
