import { awaitAllCallbacks } from "@langchain/core/callbacks/promises";
import { config } from "./config.js";

/**
 * LangSmith 可观测性接入。
 *
 * 工作方式：LangChain.js / LangGraph 的 Runnable 会自动读取
 *   LANGSMITH_TRACING / LANGSMITH_API_KEY / LANGSMITH_PROJECT / LANGSMITH_ENDPOINT
 * 无需在业务代码里手动创建 tracer；这里只负责三件事：
 *   1. 启动状态自检（绝不打印 key）
 *   2. 把「非敏感标识」挂到 trace 上，让 LangSmith run 能和 L9 审计日志对上
 *   3. CLI 退出前 flush，避免后台提交的 trace 被进程结束截断
 *
 * ⚠️ 安全立场：开启 tracing 等于新增一个数据出口 —— prompt、工具参数、模型输出
 *    会被发送到第三方。本项目已在入模前做 PII 脱敏，但生产环境仍需评估数据合规，
 *    金融/医疗等场景应改自托管 LangSmith 或关闭内容采集。
 */
export function tracingStatus() {
  return {
    enabled: config.langsmith.enabled,
    project: config.langsmith.project,
    endpoint: config.langsmith.endpoint,
    hasModel: config.hasLLM,
  };
}

export function logTracingStatus() {
  const s = tracingStatus();
  // 只输出开关与项目名，不输出 key / endpoint 中的任何凭据
  console.log(`[tracing] LangSmith ${s.enabled ? "ON" : "OFF"} · project=${s.project}`);
  if (s.enabled) {
    if (!s.hasModel) {
      console.log("[tracing] 当前为 offline 假模型，仅会记录图级 run；填入 OPENAI_API_KEY 后可看到完整 LLM / 工具 span。");
    }
    console.log("[tracing] 注意：trace 会把 prompt / 工具参数 / 输出发送到 LangSmith；生产环境请先评估数据合规。");
  }
}

/**
 * trace metadata 的最小披露原则：
 * 只放可用于关联排查的 ID 和枚举，绝不放用户输入、密钥、工具参数、系统提示。
 * traceId 与 audit_events.trace_id 一致，可以在 LangSmith 与审计表之间双向定位。
 */
export function traceConfig(identity, extra = {}) {
  return {
    runName: extra.runName ?? "agent-security-lab",
    tags: [
      "agent-security-lab",
      `project:${config.langsmith.project}`,
      `stage:${extra.stage ?? "chat"}`,
    ],
    metadata: {
      traceId: identity.traceId,
      sessionId: identity.sessionId,
      tenantId: identity.tenantId,
      role: identity.role,
      offline: !config.hasLLM,
      ...(extra.metadata ?? {}),
    },
  };
}

/** LangSmith 的 trace 是后台异步提交的，短命 CLI 进程必须显式等待 */
export async function flushTraces() {
  if (!config.langsmith.enabled) return;
  try {
    await awaitAllCallbacks();
  } catch (err) {
    // 追踪失败不应影响主流程，但要留痕
    console.error("[tracing] flush failed:", err.message);
  }
}
