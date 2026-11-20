import { randomUUID } from "node:crypto";
import { AIMessage, HumanMessage, SystemMessage, ToolMessage } from "@langchain/core/messages";
import { interrupt } from "@langchain/langgraph";
import { config, SYSTEM_PROMPT } from "../config.js";
import {
  DECISION, authorizeTool, buildContext, checkBudget, charge,
  guardInput, guardOutput, toolSignature,
} from "../security/index.js";
import { redact } from "../security/pii.js";

const msgKind = (m) =>
  m?.getType?.() ?? m?._getType?.() ?? (m?.tool_call_id !== undefined ? "tool" : "generic");

const lastAIMessage = (messages) =>
  [...messages].reverse().find((m) => msgKind(m) === "ai") ?? null;

const lastToolCallMessage = (messages) =>
  [...messages].reverse().find((m) => Array.isArray(m.tool_calls) && m.tool_calls.length > 0) ?? null;

/**
 * 所有节点都由 createNodes(deps) 闭包注入依赖 —— 安全测试可以替换成 fake，
 * 不需要真的连 LLM / 数据库。
 */
export function createNodes(deps) {
  const {
    model, registry, vectorStore, auditor, approvalStore,
    pool = null, cfg = config, identity,
  } = deps;

  const emit = (node, event, decision, flags = [], detail = {}) =>
    auditor.emit({ node, event, decision, flags, detail });

  const toolCtx = () => ({
    pool,
    vectorStore,
    tenantId: identity.tenantId,
    userId: identity.userId,
    role: identity.role,
    traceId: identity.traceId,
    maxToolOutputChars: cfg.MAX_TOOL_OUTPUT_CHARS,
  });

  return {
    // ---------------- L1 入口守卫 ----------------
    async guardInput(state) {
      const raw = state.input?.raw ?? "";
      const g = guardInput(raw, cfg);
      await emit("guardInput", "input_scan", g.decision, g.flags, {
        reason: g.reason, score: g.score ?? 0, preview: redact(raw).slice(0, 120),
      });
      const blocked = g.decision === DECISION.DENY;
      return {
        // 只把脱敏、规范化后的文本写进 messages / checkpoint
        input: { raw: redact(raw).slice(0, 200), text: g.text, decision: g.decision, reason: g.reason, flags: g.flags },
        messages: blocked ? [] : [new HumanMessage({ content: g.text, id: `human-${randomUUID()}` })],
        degraded: g.decision === DECISION.ESCALATE,
        verdict: blocked ? "rejected" : "continue",
        refusalReason: blocked ? g.reason : "",
      };
    },

    // ---------------- 统一拒绝出口 ----------------
    async reject(state) {
      // 只回 reason code，不回具体命中了哪条规则 —— 避免把检测规则当 oracle 喂给攻击者
      const text = `请求未通过安全策略（${state.refusalReason || "policy_violation"}）。如需继续，请简化请求或联系管理员。`;
      await emit("reject", "request_rejected", DECISION.DENY, [], { reason: state.refusalReason });
      return {
        messages: [new AIMessage({ content: text, id: `reject-${randomUUID()}` })],
        finalAnswer: text,
        verdict: "rejected",
      };
    },

    // ---------------- L2 记忆检索 ----------------
    async retrieve(state) {
      try {
        const r = await vectorStore.search({
          tenantId: identity.tenantId,
          query: state.input.text,
          k: 3,
        });
        await emit("retrieve", "memory_retrieval", DECISION.ALLOW, r.flags, {
          accepted: r.accepted.length,
          quarantined: r.quarantined.length,   // 读取时二次扫描新发现的
          excluded: r.excluded ?? 0,           // 写入时就被隔离的
        });
        return {
          memory: r.accepted.map((c) => ({ content: c.content, source: c.source, trust: c.trust })),
          verdict: "retrieved",
        };
      } catch (err) {
        // 检索失败降级为空上下文（可用性优先），但必须留痕告警
        await emit("retrieve", "retrieval_failed", DECISION.ESCALATE, ["retrieval_error"], { error: err.message });
        return { memory: [], verdict: "retrieved_degraded" };
      }
    },

    // ---------------- L3 模型推理 ----------------
    async agent(state) {
      const b = checkBudget(state.budget, cfg);
      if (!b.ok) {
        await emit("agent", "budget_block", DECISION.DENY, [b.reason], { budget: state.budget });
        return { verdict: "budget_exceeded", refusalReason: b.reason };
      }

      const prompt = buildContext({
        systemPrompt: SYSTEM_PROMPT,
        trusted: [`当前会话角色：${identity.role}；租户：${identity.tenantId}。此信息来自可信会话上下文。`],
        untrusted: state.memory,
        degraded: state.degraded,
      });

      let res;
      try {
        res = await model.invoke([new SystemMessage(prompt), ...state.messages]);
      } catch (err) {
        await emit("agent", "model_error", DECISION.DENY, ["model_error"], { error: err.message });
        return { verdict: "model_error", refusalReason: "model_unavailable" };
      }

      const calls = Array.isArray(res.tool_calls) ? res.tool_calls : [];
      const tokens = res.usage_metadata?.total_tokens
        ?? Math.ceil((String(res.content ?? "").length + prompt.length) / 4);
      const signature = calls.map((c) => toolSignature(c.name, c.args)).join("|");

      await emit("agent", "llm_response", DECISION.ALLOW, [], {
        toolCalls: calls.map((c) => c.name), tokens, degraded: state.degraded,
      });

      return {
        messages: [res],
        budget: charge(state.budget, { tokens, signature }),
        verdict: calls.length ? "tool_calls" : "answer",
      };
    },

    // ---------------- L4 工具网关 ----------------
    async toolGate(state) {
      const ai = lastToolCallMessage(state.messages);
      if (!ai) return { toolPlan: [], verdict: "gated" };

      const plan = ai.tool_calls.map((c) => {
        const auth = authorizeTool(
          registry.get(c.name),
          { args: c.args },
          { role: identity.role, degraded: state.degraded, cfg }
        );
        return {
          id: c.id,
          name: c.name,
          args: c.args,
          safeArgs: auth.args,
          decision: auth.decision,
          reason: auth.reason,
          flags: auth.flags,
        };
      });

      for (const p of plan) {
        await emit("toolGate", "tool_authorization", p.decision, p.flags, {
          tool: p.name, reason: p.reason, args: p.safeArgs ?? p.args,
        });
      }
      return {
        toolPlan: plan,
        verdict: plan.some((p) => p.decision === DECISION.ESCALATE) ? "needs_approval" : "gated",
      };
    },

    // ---------------- L5 人工审批（HITL） ----------------
    async approval(state) {
      const pending = state.toolPlan.filter((p) => p.decision === DECISION.ESCALATE);

      // ⚠️ interrupt 恢复时本节点会从头重放。interrupt() 之前不能有任何副作用，
      //    否则审批人点一次，退款登记可能写两遍。这是 LangGraph HITL 最常见的坑。
      const reply = interrupt({
        type: "human_approval_required",
        traceId: identity.traceId,
        sessionId: identity.sessionId,
        items: pending.map((p) => ({ tool: p.name, args: p.safeArgs, reason: p.reason })),
        expected: "{ decision: 'approved' | 'rejected', approverId, reason }",
      });

      // ↓ 以下只在 resume 之后执行
      const approved = reply?.decision === "approved";
      const approverId = String(reply?.approverId ?? "unknown");
      for (const p of pending) {
        await approvalStore.record({
          traceId: identity.traceId,
          sessionId: identity.sessionId,
          tenantId: identity.tenantId,
          approverId,
          toolName: p.name,
          toolArgs: p.safeArgs ?? p.args ?? {},
          decision: approved ? "approved" : "rejected",
          reason: String(reply?.reason ?? ""),
        });
      }
      await emit("humanApproval", "human_decision", approved ? DECISION.APPROVE : DECISION.REJECT, [], {
        approverId, items: pending.map((p) => p.name), reason: reply?.reason,
      });

      return {
        toolPlan: state.toolPlan.map((p) =>
          p.decision === DECISION.ESCALATE
            ? {
                ...p,
                decision: approved ? DECISION.ALLOW : DECISION.DENY,
                reason: approved ? "approved_by_human" : "rejected_by_human",
              }
            : p
        ),
        approval: { decision: approved ? "approved" : "rejected", approverId, at: Date.now() },
        verdict: "approval_resolved",
      };
    },

    // ---------------- L6 受控执行 ----------------
    async executeTools(state) {
      const ai = lastToolCallMessage(state.messages);
      if (!ai) return { verdict: "tools_done" };
      const planById = new Map(state.toolPlan.map((p) => [p.id, p]));
      const replies = [];
      let budget = state.budget;

      // 为一个 AIMessage 的每一条 tool_call 都生成恰好一条 ToolMessage，顺序一致，
      // 否则 OpenAI 协议会报 "tool_call has no response"，也容易被当成注入缝隙。
      for (const c of ai.tool_calls) {
        const p = planById.get(c.id) ?? { decision: DECISION.DENY, reason: "missing_authorization" };
        let content;
        if (p.decision === DECISION.ALLOW) {
          content = await registry.execute(p.name, p.safeArgs ?? p.args ?? {}, toolCtx());
          budget = charge(budget, {
            signature: toolSignature(p.name, p.safeArgs),
            toolExecuted: true,
          });
        } else {
          content = `[安全网关拒绝] 工具 ${p.name} 未获授权：${p.reason}`;
        }
        replies.push(new ToolMessage({ content, tool_call_id: c.id, name: c.name, id: `tool-${randomUUID()}` }));
        await emit("executeTools", "tool_result", p.decision, p.flags, {
          tool: p.name, authorized: p.decision === DECISION.ALLOW, preview: content.slice(0, 160),
        });
      }
      return { messages: replies, budget, verdict: "tools_done" };
    },

    // ---------------- L7 预算复核 ----------------
    async budgetGate(state) {
      const b = checkBudget(state.budget, cfg);
      if (!b.ok) {
        await emit("budgetGate", "budget_exceeded", DECISION.DENY, [b.reason], { budget: state.budget });
        return { verdict: "budget_exceeded", refusalReason: b.reason };
      }
      return { verdict: "continue" };
    },

    // ---------------- L8 出口守卫 ----------------
    async guardOutput(state) {
      const ai = lastAIMessage(state.messages);
      const raw = String(ai?.content ?? "");
      const g = guardOutput(raw, { cfg, toolsExecuted: state.budget?.toolsExecuted ?? 0 });
      await emit("guardOutput", "output_scan", g.ok ? DECISION.ALLOW : DECISION.DENY, g.flags, {
        reason: g.reason, length: raw.length,
      });
      return {
        // 用相同 id 覆盖原消息（messagesStateReducer 按 id 去重替换），不产生重复回答
        messages: [new AIMessage({ content: g.text, id: ai?.id ?? `ai-${randomUUID()}` })],
        finalAnswer: g.text,
        verdict: g.ok ? "done" : "blocked_output",
        refusalReason: g.ok ? "" : g.reason,
      };
    },
  };
}
