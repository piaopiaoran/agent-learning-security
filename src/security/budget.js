import { config } from "../config.js";

/**
 * L7 资源与循环预算：Agent 的 DoS 不是流量型，而是「自我循环烧钱型」。
 * 三重限制：步数 / token / 墙钟时间，外加重复调用检测（同一 tool+args 连打 3 次即熔断）。
 * 所有字段都是可 JSON 序列化的纯数据 —— 因为要写进 Postgres checkpoint。
 */
export function createBudget(cfg = config, now = Date.now()) {
  return {
    steps: 0,
    tokens: 0,
    startedAt: now,
    deadline: now + cfg.MAX_WALL_MS,
    lastSignature: "",
    repeatCount: 0,
    toolsExecuted: 0,
  };
}

export function checkBudget(budget, cfg = config, now = Date.now()) {
  if (!budget) return { ok: false, reason: "budget_missing" };
  if (now > budget.deadline) return { ok: false, reason: "wall_time_exceeded" };
  if (budget.steps >= cfg.MAX_STEPS) return { ok: false, reason: "step_limit_exceeded" };
  if (budget.tokens >= cfg.MAX_TOTAL_TOKENS) return { ok: false, reason: "token_budget_exceeded" };
  if (budget.repeatCount >= 3) return { ok: false, reason: "repeated_tool_loop" };
  return { ok: true, reason: "ok" };
}

/** 返回新对象，避免就地修改 LangGraph state */
export function charge(budget, { tokens = 0, signature = "", toolExecuted = false } = {}) {
  const repeated = signature !== "" && signature === budget.lastSignature;
  return {
    ...budget,
    steps: budget.steps + 1,
    tokens: budget.tokens + Math.max(0, Math.round(tokens)),
    lastSignature: signature || budget.lastSignature,
    repeatCount: repeated ? budget.repeatCount + 1 : 0,
    toolsExecuted: budget.toolsExecuted + (toolExecuted ? 1 : 0),
  };
}

export function toolSignature(name, args) {
  try {
    return `${name}:${JSON.stringify(args ?? {})}`;
  } catch {
    return `${name}:[unserializable]`;
  }
}
