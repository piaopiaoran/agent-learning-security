import { randomUUID } from "node:crypto";
import { Command, MemorySaver } from "@langchain/langgraph";
import { PostgresSaver } from "@langchain/langgraph-checkpoint-postgres";
import { config } from "./config.js";
import { createPool } from "./db/pool.js";
import { createEmbedder } from "./memory/embedder.js";
import { createMemoryVectorStore, createPgVectorStore } from "./memory/vectorStore.js";
import { createRegistry } from "./tools/registry.js";
import { builtinTools } from "./tools/builtins.js";
import { createModel } from "./graph/model.js";
import { buildGraph } from "./graph/buildGraph.js";
import { createAuditor, createBudget, createRateLimiter } from "./security/index.js";
import { traceConfig } from "./observability.js";

function createApprovalStore({ pool }) {
  const records = [];
  return {
    records,
    async record(r) {
      records.push(r);
      if (!pool) return;
      await pool.query(
        `INSERT INTO approval_records
           (trace_id, session_id, tenant_id, approver_id, tool_name, tool_args, decision, reason)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [r.traceId, r.sessionId, r.tenantId, r.approverId, r.toolName,
          JSON.stringify(r.toolArgs ?? {}), r.decision, r.reason ?? null]
      ).catch((err) => console.error("[approval] persist failed:", err.message));
    },
  };
}

/**
 * 全局共享资源：连接池、模型、注册表、checkpointer、限流器。
 *
 * 两个正交维度（旧版误把它们绑成一个 offline）：
 *   modelMode: fake | openai   —— 用不用第三方 LLM
 *   storeMode: memory|postgres —— 用不用 PostgreSQL / pgvector / DB 审计
 *
 * 因此支持四种组合，最实用的是「openai + memory」：
 * 有真实模型、有完整安全链路，但不需要 Docker，适合面试现场演示与调试。
 * --offline 仍等价于强制 fake + memory（零密钥、零外部网络）。
 */
export async function createRuntime({ offline, model, store } = {}) {
  const modelMode = offline ? "fake" : (model ?? config.modelMode);
  const storeMode = offline ? "memory" : (store ?? config.storeMode);
  const usePg = storeMode === "postgres";

  const pool = usePg ? createPool() : null;
  const embedder = createEmbedder();
  const registry = createRegistry(builtinTools);
  const vectorStore = usePg
    ? createPgVectorStore({ pool, embedder })
    : createMemoryVectorStore({ embedder });
  const approvalStore = createApprovalStore({ pool });

  let checkpointer;
  if (usePg) {
    checkpointer = new PostgresSaver(pool);
    await checkpointer.setup();
  } else {
    checkpointer = new MemorySaver();
  }

  const llm = createModel({ offline: modelMode === "fake", registry });

  return {
    // 兼容字段：完全无外部依赖时才算 offline
    offline: modelMode === "fake" && !usePg,
    modelMode,
    storeMode,
    pool, registry, vectorStore, embedder, approvalStore, checkpointer,
    model: llm,
    cfg: config,
    rateLimiter: createRateLimiter({ limit: config.RATE_LIMIT_PER_MIN }),
    async close() {
      if (pool) await pool.end();
    },
  };
}

/**
 * 每个会话独立编译一次 graph（图编译是纯内存操作，成本可忽略）。
 * 这样 auditor / identity 这类 per-trace 依赖可以用闭包注入，不必塞进 checkpoint。
 * 生产可缓存 graph，并用 AsyncLocalStorage 注入 per-request 的 auditor。
 */
export function createSession(runtime, { tenantId, userId, role = "user", sessionId = randomUUID() } = {}) {
  if (!tenantId || !userId) throw new Error("tenantId and userId are required (来自可信会话，不可由模型提供)");
  const traceId = randomUUID();
  const identity = { traceId, sessionId, tenantId, userId, role };
  const auditor = createAuditor({
    pool: runtime.pool,
    base: { traceId, sessionId, tenantId, userId },
    mode: runtime.storeMode === "postgres" ? "db" : "memory",
    strict: false,
  });

  const graph = buildGraph({ ...runtime, auditor, identity });
  const runConfig = {
    configurable: { thread_id: sessionId },
    recursionLimit: runtime.cfg.MAX_STEPS * 3,
    // tags / metadata / runName 会被 LangSmith 自动采集；只含非敏感标识
    ...traceConfig(identity, {
      metadata: { modelMode: runtime.modelMode, storeMode: runtime.storeMode },
    }),
  };

  return {
    identity, auditor, graph, runConfig, traceId, sessionId,
    start(raw) {
      return graph.invoke(
        { input: { raw }, identity, budget: createBudget(runtime.cfg) },
        runConfig
      );
    },
    resume(reply) {
      return graph.invoke(new Command({ resume: reply }), runConfig);
    },
  };
}

/** 兼容不同 LangGraph 版本的中断返回形态 */
export function extractInterrupt(result) {
  const list = result?.__interrupt__;
  if (Array.isArray(list) && list.length) return list;
  return null;
}
