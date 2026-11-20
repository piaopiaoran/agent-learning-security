import { config } from "../config.js";
import { DECISION, RISK } from "./constants.js";
import { scanInjection, scanSecrets } from "./injection.js";
import { PATH_TRAVERSAL_RE, PRIVATE_HOST_RE } from "./patterns.js";

/**
 * L4 工具网关：模型产生的 tool_call 只是「请求」，不是「授权」。
 * 这是 Agent 安全和传统 Web 安全最大的区别 —— LLM 输出不可信，必须重新鉴权。
 * 检查链：注册白名单 → RBAC → Zod 参数校验 → 参数值深度扫描 → 风险分级 → 降权态检查
 */

function checkUrl(value, cfg) {
  let u;
  try {
    u = new URL(value);
  } catch {
    return ["invalid_url"];
  }
  const flags = [];
  if (!["http:", "https:"].includes(u.protocol)) flags.push("blocked_scheme");
  const host = u.hostname.toLowerCase();
  if (PRIVATE_HOST_RE.test(host)) flags.push("ssrf_private_host");
  // 白名单为空 = 默认全禁（fail-closed）；生产还要处理 DNS rebinding / 重定向跳板
  if (!cfg.allowedHosts.has(host)) flags.push("host_not_allowlisted");
  return flags;
}

/** 递归扫描参数值：拼接进 prompt / SQL / shell / URL 的每一个字符串都是攻击面 */
function deepScan(value, cfg, flags = [], depth = 0) {
  if (depth > 6 || value === null || value === undefined) return flags;
  if (typeof value === "string") {
    const hit = scanInjection(value);
    flags.push(...hit.flags.map((f) => `arg_injection:${f}`));
    flags.push(...scanSecrets(value).map((f) => `arg_secret:${f}`));
    if (PATH_TRAVERSAL_RE.test(value)) flags.push("path_traversal");
    if (/^https?:\/\//i.test(value)) flags.push(...checkUrl(value, cfg));
    if (value.includes("\u0000")) flags.push("null_byte");
    return flags;
  }
  if (Array.isArray(value)) {
    for (const v of value.slice(0, 50)) deepScan(v, cfg, flags, depth + 1);
  } else if (typeof value === "object") {
    for (const v of Object.values(value).slice(0, 50)) deepScan(v, cfg, flags, depth + 1);
  }
  return flags;
}

export function authorizeTool(tool, call, ctx = {}) {
  const cfg = ctx.cfg ?? config;
  const role = ctx.role ?? "user";
  const flags = [];

  if (!tool) {
    return { decision: DECISION.DENY, reason: "unregistered_tool", flags: ["hallucinated_tool"] };
  }

  // 1) RBAC：工具自带角色白名单，不依赖模型自觉
  if (tool.roles && !tool.roles.includes(role)) {
    return { decision: DECISION.DENY, reason: "role_not_permitted", flags: ["rbac_denied"] };
  }

  // 2) 结构化校验：Zod 在边界处收窄类型，挡掉参数注入 / 类型混淆 / 多余字段
  const parsed = tool.schema.safeParse(call.args ?? {});
  if (!parsed.success) {
    return {
      decision: DECISION.DENY,
      reason: "invalid_tool_args",
      flags: ["schema_violation"],
      detail: parsed.error.issues.map((i) => ({ path: i.path.join("."), code: i.code })),
    };
  }
  const args = parsed.data;

  // 3) 参数值深度扫描（间接注入经常藏在这里，而不是用户原始消息里）
  flags.push(...deepScan(args, cfg));
  if (flags.some((f) => f.startsWith("arg_injection:") || f.startsWith("arg_secret:") || f === "ssrf_private_host" || f === "path_traversal" || f === "blocked_scheme" || f === "host_not_allowlisted" || f === "null_byte")) {
    return { decision: DECISION.DENY, reason: "unsafe_tool_args", flags: [...new Set(flags)] };
  }

  // 4) 降权态：可疑输入下禁止任何副作用工具（escalate 不等于放行）
  if (ctx.degraded && (tool.sideEffect || tool.risk === RISK.HIGH)) {
    return { decision: DECISION.DENY, reason: "degraded_mode_blocks_side_effect", flags: ["degraded"] };
  }

  // 5) 高危动作强制人工审批
  if (tool.risk === RISK.HIGH || tool.risk === RISK.CRITICAL) {
    return { decision: DECISION.ESCALATE, reason: "requires_human_approval", flags, args, tool };
  }

  return { decision: DECISION.ALLOW, reason: "ok", flags, args, tool };
}
