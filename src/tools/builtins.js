import { z } from "zod";
import { RISK } from "../security/constants.js";

/**
 * 示例工具集。关键安全约定：
 *  - tenantId / userId 一律从 session ctx 取，绝不接受模型传参（否则就是越权查询）
 *  - 所有 SQL 参数化；写操作这里只做「登记」，不真的改业务数据
 *  - 副作用工具标 risk=HIGH，由 LangGraph 强制走人工审批
 */
export const builtinTools = [
  {
    name: "search_knowledge",
    description: "检索企业内部知识库中的政策与说明（只读）。",
    schema: z.object({ query: z.string().min(1).max(200) }),
    risk: RISK.LOW,
    roles: ["user", "admin"],
    sideEffect: false,
    network: false,
    timeoutMs: 3000,
    async execute({ query }, ctx) {
      const r = await ctx.vectorStore.search({ tenantId: ctx.tenantId, query, k: 3 });
      if (!r.accepted.length) return "未检索到相关资料。";
      return r.accepted.map((c) => `[${c.source}] ${c.content}`).join("\n");
    },
  },
  {
    name: "get_order_status",
    description: "查询当前登录用户自己的订单状态（只读）。",
    schema: z.object({ orderId: z.string().regex(/^ORD-\d{4}$/, "订单号格式不合法") }),
    risk: RISK.LOW,
    roles: ["user", "admin"],
    sideEffect: false,
    network: false,
    timeoutMs: 3000,
    async execute({ orderId }, ctx) {
      if (!ctx.pool) return "[offline demo] 订单 ORD-1001: 已支付 ¥129.00";
      const r = await ctx.pool.query(
        "SELECT id, amount_cents, status FROM orders WHERE id=$1 AND tenant_id=$2 AND user_id=$3",
        [orderId, ctx.tenantId, ctx.userId]
      );
      if (!r.rows.length) return "未找到该订单（或不属于当前用户）。";
      const o = r.rows[0];
      return `订单 ${o.id}: 状态 ${o.status}, 金额 ¥${(o.amount_cents / 100).toFixed(2)}`;
    },
  },
  {
    name: "refund_order",
    description: "为订单发起退款（有副作用，需人工审批）。",
    schema: z.object({
      orderId: z.string().regex(/^ORD-\d{4}$/),
      reason: z.string().min(2).max(200),
    }),
    risk: RISK.HIGH,
    roles: ["user", "admin"],
    sideEffect: true,
    network: false,
    timeoutMs: 3000,
    async execute({ orderId, reason }, ctx) {
      // 真实系统这里应调用财务服务；本项目只返回意图已登记，避免 demo 产生真实副作用。
      // 「已批准」这件事由 approval_records + audit_events 记录，不靠工具自己声明。
      return `已登记退款申请（订单 ${orderId}，原因：${reason}，trace=${ctx.traceId}）；实际资金动作需财务系统执行。`;
    },
  },
  {
    name: "send_email",
    description: "向指定收件人发送邮件（对外副作用，需人工审批）。",
    schema: z.object({
      to: z.string().min(3).max(200),
      subject: z.string().min(1).max(200),
      body: z.string().min(1).max(2000),
    }),
    risk: RISK.HIGH,
    roles: ["user", "admin"],
    sideEffect: true,
    network: true,
    timeoutMs: 3000,
    async execute({ to, subject }, ctx) {
      return `已登记邮件发送请求（收件人 ${to}，主题 ${subject}，trace=${ctx.traceId}）；demo 不实际外发。`;
    },
  },
  {
    name: "export_all_orders",
    description: "导出全部租户订单数据（仅管理员）。",
    schema: z.object({ format: z.enum(["csv", "json"]) }),
    risk: RISK.CRITICAL,
    roles: ["admin"],
    sideEffect: false,
    network: false,
    timeoutMs: 3000,
    async execute() {
      return "导出结果（脱敏）";
    },
  },
];
