import { config, SYSTEM_PROMPT } from "../config.js";
import { scanSecrets } from "./injection.js";
import { detectPII, redact } from "./pii.js";
import { UNAUTHORIZED_CLAIM_RE } from "./patterns.js";

/**
 * L8 出口守卫：模型输出同样是不可信数据。
 * 拦三件事：凭据/PII 泄漏、系统提示泄漏、无工具执行记录的「已完成」幻觉。
 */
export function guardOutput(raw, opts = {}) {
  const cfg = opts.cfg ?? config;
  const toolsExecuted = opts.toolsExecuted ?? 0;
  const text = String(raw ?? "");
  const flags = [];

  const secrets = scanSecrets(text);
  if (secrets.length) {
    return {
      ok: false,
      text: "抱歉，本次回答包含疑似凭据信息，已被安全策略拦截。",
      flags: secrets.map((f) => `secret:${f}`),
      reason: "credential_leak",
    };
  }

  // 系统提示泄漏：用特征片段匹配，比整串相等更抗改写
  const leakProbe = /受控的企业助手|不得包含任何凭据|等待人工批准/;
  if (leakProbe.test(text) && text.includes("规则") && text.length < SYSTEM_PROMPT.length * 2) {
    return { ok: false, text: "抱歉，我不能复述内部配置。", flags: ["system_prompt_leak"], reason: "system_prompt_leak" };
  }

  if (UNAUTHORIZED_CLAIM_RE.test(text) && toolsExecuted === 0) {
    return {
      ok: false,
      text: "该操作尚未执行。涉及资金或对外发送的动作必须由工具发起并经过审批，我不能代替系统确认结果。",
      flags: ["unauthorized_completion_claim"],
      reason: "hallucinated_completion",
    };
  }

  const pii = detectPII(text);
  if (pii.length) flags.push(...pii.map((f) => `pii_redacted:${f}`));

  let out = redact(text);
  if (out.length > cfg.MAX_OUTPUT_CHARS) {
    out = out.slice(0, cfg.MAX_OUTPUT_CHARS) + "\n[输出过长已截断]";
    flags.push("output_truncated");
  }
  return { ok: true, text: out, flags, reason: "ok" };
}
