import { redact } from "./pii.js";

const MAX_DEPTH = 5;
const MAX_STR = 1000;

/** 审计内容也可能含敏感信息：落库前统一脱敏 + 截断，防止「安全日志变成新的泄漏源」 */
function scrub(value, depth = 0) {
  if (depth > MAX_DEPTH) return "[depth_truncated]";
  if (typeof value === "string") return redact(value).slice(0, MAX_STR);
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => scrub(v, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).slice(0, 50).map(([k, v]) => [k, scrub(v, depth + 1)]));
  }
  return value ?? null;
}

/**
 * L9 审计：每次「决策」都留痕，而不是只记最终答案。
 * mode: "db" → 写 audit_events（append-only 表）；"memory" → 内存，供单测断言；"noop"
 * strict: true → 写库失败时中断请求（金融/合规场景的 fail-closed）；默认 false（可用性优先 + 告警）
 */
export function createAuditor({ pool = null, base = {}, mode = null, strict = false } = {}) {
  const resolvedMode = mode ?? (pool ? "db" : "memory");
  const events = [];

  async function emit({ node, event, decision, flags = [], detail = {} }) {
    const row = {
      traceId: base.traceId,
      sessionId: base.sessionId,
      tenantId: base.tenantId,
      userId: base.userId,
      node: String(node),
      event: String(event),
      decision: String(decision),
      flags: [...new Set(flags)],
      detail: scrub(detail),
      at: new Date().toISOString(),
    };
    events.push(row);

    if (resolvedMode !== "db") return row;
    try {
      await pool.query(
        `INSERT INTO audit_events
           (trace_id, session_id, tenant_id, user_id, node, event, decision, risk_flags, detail)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          row.traceId, row.sessionId, row.tenantId, row.userId,
          row.node, row.event, row.decision, row.flags, JSON.stringify(row.detail),
        ]
      );
    } catch (err) {
      console.error("[audit] write failed:", err.message);
      if (strict) throw new Error("audit_unavailable");
    }
    return row;
  }

  return { emit, events, mode: resolvedMode };
}
