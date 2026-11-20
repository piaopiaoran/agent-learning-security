export const DECISION = Object.freeze({
  ALLOW: "allow",
  DENY: "deny",
  ESCALATE: "escalate",   // 不直接拒绝，但降权（禁高危工具 / 加人工复核）
  APPROVE: "approved",
  REJECT: "rejected",
});

export const RISK = Object.freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
});

/** 命中阈值：>= DENY_AT 直接拒，>= ESCALATE_AT 降权 */
export const THRESHOLD = Object.freeze({ ESCALATE_AT: 25, DENY_AT: 55 });

export const TOOL_META = Object.freeze({
  SIDE_EFFECT: "sideEffect",
  NETWORK: "network",
  READ_ONLY: "readOnly",
});
