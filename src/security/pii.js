import { PII_RULES } from "./patterns.js";

/** 返回命中类型，不返回原文 —— 审计日志只记「有 PII」，不记 PII 内容 */
export function detectPII(text) {
  const value = String(text ?? "");
  const flags = [];
  for (const rule of PII_RULES) {
    rule.re.lastIndex = 0;
    if (rule.re.test(value)) flags.push(rule.id);
  }
  return flags;
}

/**
 * 脱敏后再进模型上下文 / 审计日志。
 * 面试取舍：完全拦截含 PII 的输入体验差；脱敏能保住可用性，但要确保
 * 原始 PII 不落 checkpoint（checkpoint 会长期存在 Postgres 里）。
 */
export function redact(text) {
  let out = String(text ?? "");
  for (const rule of PII_RULES) {
    out = out.replace(rule.re, rule.mask);
  }
  return out;
}
