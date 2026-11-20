import test from "node:test";
import assert from "node:assert/strict";
import { config, getSecret } from "../src/config.js";
import { traceConfig, tracingStatus } from "../src/observability.js";

const identity = {
  traceId: "trace-1", sessionId: "session-1",
  tenantId: "tenant-a", userId: "u-1", role: "user",
};

test("可观测性 / 启动状态自检不泄漏任何密钥", () => {
  const dump = JSON.stringify(tracingStatus());
  assert.ok(!dump.includes("lsv2"), "不得包含 LangSmith key 前缀");
  assert.ok(!dump.includes("sk-"), "不得包含 OpenAI key 前缀");
  assert.equal(typeof tracingStatus().enabled, "boolean");
});

test("可观测性 / config 对象里不含 API key", () => {
  const dump = JSON.stringify(config);
  assert.ok(!dump.includes("lsv2"));
  assert.ok(!dump.includes("sk-"));
  assert.equal(config.OPENAI_API_KEY, undefined);
  assert.equal(config.LANGSMITH_API_KEY, undefined);
  assert.equal(typeof config.langsmith.enabled, "boolean");
});

test("可观测性 / 密钥只能通过白名单 getter 取用", () => {
  assert.equal(typeof getSecret("openai"), "string");
  assert.equal(typeof getSecret("langsmith"), "string");
  assert.throws(() => getSecret("anything_else"));
});

test("可观测性 / trace metadata 只放非敏感标识", () => {
  const t = traceConfig(identity);
  const dump = JSON.stringify(t);
  assert.equal(t.metadata.traceId, "trace-1");
  assert.equal(t.metadata.tenantId, "tenant-a");
  assert.ok(t.tags.includes("agent-security-lab"));
  assert.ok(!dump.includes("lsv2"));
  assert.ok(!dump.includes("13812345678"));
  assert.ok(!dump.includes("SYSTEM_PROMPT"));
  assert.ok(!("userId" in t.metadata), "用户标识不进第三方 trace metadata");
});
