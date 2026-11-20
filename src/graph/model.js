import { randomUUID } from "node:crypto";
import { ChatOpenAI } from "@langchain/openai";
import { AIMessage } from "@langchain/core/messages";
import { config, getSecret } from "../config.js";

/**
 * offline 假模型：规则驱动，用来在没有 API key / 没起数据库时跑通整条安全链路。
 * 它故意「不遵守」安全规则（会尝试调高危工具），这样才能验证是网关而不是模型自觉在拦截。
 */
export function createFakeModel() {
  const model = {
    bindTools() {
      return model;
    },
    async invoke(messages) {
      const tail = messages[messages.length - 1];
      const kind = (m) => m?.getType?.() ?? m?._getType?.() ?? (m?.tool_call_id ? "tool" : "generic");

      if (kind(tail) === "tool") {
        const summary = String(tail.content ?? "").split("\n")[0].slice(0, 160).replace(/[。.\s]+$/, "");
        const denied = summary.startsWith("[安全网关拒绝]");
        return new AIMessage({
          id: `ai-${randomUUID()}`,
          content: denied
            ? `安全网关拦截：${summary.replace("[安全网关拒绝] ", "")}。如需继续请联系管理员。`
            : `根据已授权的工具结果：${summary}。如需进一步操作请说明。`,
          usage_metadata: { total_tokens: 40 },
        });
      }

      const human = [...messages].reverse().find((m) => kind(m) === "human");
      const text = String(human?.content ?? "");
      const call = (name, args) => ({ name, args, id: `call-${randomUUID()}`, type: "tool_call" });

      let tool_calls = [];
      // 「问政策」优先于「包含退款二字」，避免把咨询误判成退款动作
      if (/政策|知识|规定|手册/.test(text)) {
        tool_calls = [call("search_knowledge", { query: text.slice(0, 100) })];
      } else if (/退款|refund/i.test(text)) {
        tool_calls = [call("refund_order", { orderId: "ORD-1001", reason: "用户申请退款" })];
      } else if (/邮件|email|发送/i.test(text)) {
        tool_calls = [call("send_email", { to: "ops@example.com", subject: "报告", body: "请查看附件" })];
      } else if (/导出|全部订单/i.test(text)) {
        tool_calls = [call("export_all_orders", { format: "csv" })];
      } else if (/ORD-\d{4}|订单/.test(text)) {
        const id = text.match(/ORD-\d{4}/)?.[0] ?? "ORD-1001";
        tool_calls = [call("get_order_status", { orderId: id })];
      }

      return new AIMessage({
        id: `ai-${randomUUID()}`,
        content: tool_calls.length ? "" : "我已收到你的问题，会在授权范围内协助你。",
        tool_calls,
        usage_metadata: { total_tokens: 60 },
      });
    },
  };
  return model;
}

/** 真实模型：bindTools 只暴露注册表里的能力，工具执行权不在模型手上 */
export function createModel({ offline = false, registry } = {}) {
  if (offline || !config.hasLLM) return createFakeModel();
  const llm = new ChatOpenAI({
    model: config.OPENAI_MODEL,
    apiKey: getSecret("openai"),
    temperature: 0,
  });
  return llm.bindTools(registry.langchainTools());
}
