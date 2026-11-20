import { Annotation, MessagesAnnotation } from "@langchain/langgraph";

/** 单值字段统一用「后写覆盖」reducer；不要用数组/对象 reducer 累积不可信内容 */
const last = (initial) =>
  Annotation({
    reducer: (prev, next) => (next === undefined ? prev : next),
    default: () => initial,
  });

/**
 * State 设计原则：
 *  - 所有内容都必须是可 JSON 序列化的纯数据（要写进 Postgres checkpoint）
 *  - 身份来自可信会话，不来自模型输出；checkpoint 中不含原始 PII / 凭据
 *  - toolPlan 是「已鉴权的调用计划」，不是模型原始的 tool_calls
 */
export const AgentState = Annotation.Root({
  ...MessagesAnnotation.spec,

  identity: last({ traceId: "", sessionId: "", tenantId: "", userId: "", role: "user" }),
  input: last({ raw: "", text: "", decision: "", reason: "", flags: [] }),
  degraded: last(false),
  memory: last([]),
  toolPlan: last([]),
  approval: last(null),
  budget: last(null),
  verdict: last(""),
  refusalReason: last(""),
  finalAnswer: last(""),
});
