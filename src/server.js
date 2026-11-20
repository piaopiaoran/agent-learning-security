import { randomUUID } from "node:crypto";
import express from "express";
import { config } from "./config.js";
import { createRuntime, createSession, extractInterrupt } from "./runtime.js";

const runtime = await createRuntime();
const app = express();
app.use(express.json({ limit: "16kb" })); // body 体积限制也是一层入口防护
const sessions = new Map();

app.get("/health", (_req, res) => {
  res.json({ ok: true, offline: runtime.offline, tools: runtime.registry.names() });
});

app.post("/chat", async (req, res) => {
  // ⚠️ 演示用：真实系统必须从已验证的 JWT / OIDC session 取身份，
  //    绝不能信任客户端自报的 x-tenant-id / x-role（否则一行 header 就完成越权）。
  const tenantId = String(req.get("x-tenant-id") ?? "tenant-a");
  const userId = String(req.get("x-user-id") ?? "u-1");
  const role = req.get("x-role") === "admin" ? "admin" : "user";

  const rl = runtime.rateLimiter.check(`${tenantId}:${userId}`);
  if (!rl.ok) {
    return res.status(429).json({ error: "rate_limited", retryAfterMs: rl.retryAfterMs });
  }

  const sessionId = String(req.body.sessionId ?? randomUUID());
  const sess = createSession(runtime, { tenantId, userId, role, sessionId });
  sessions.set(sessionId, sess);

  try {
    const result = await sess.start(String(req.body.message ?? ""));
    const pending = extractInterrupt(result);
    return res.json({
      traceId: sess.traceId,
      sessionId,
      status: pending ? "awaiting_approval" : "done",
      answer: result.finalAnswer ?? "",
      verdict: result.verdict ?? "",
      interrupt: pending ?? undefined,
      ...(runtime.offline ? { audit: sess.auditor.events } : {}),
    });
  } catch (err) {
    console.error("[chat] failed", err);
    return res.status(500).json({ error: "internal_error", traceId: sess.traceId });
  }
});

app.post("/approve", async (req, res) => {
  const sess = sessions.get(String(req.body.sessionId ?? ""));
  if (!sess) return res.status(404).json({ error: "session_not_found" });

  const approverId = String(req.get("x-approver-id") ?? "unknown");
  // 职责分离（SoD）：审批人必须是 admin，且不能是发起请求的人
  if (req.get("x-role") !== "admin" || approverId === sess.identity.userId) {
    return res.status(403).json({ error: "approval_requires_independent_admin" });
  }

  try {
    const result = await sess.resume({
      decision: req.body.decision === "approved" ? "approved" : "rejected",
      approverId,
      reason: String(req.body.reason ?? ""),
    });
    return res.json({
      traceId: sess.traceId,
      status: "done",
      answer: result.finalAnswer ?? "",
      approval: result.approval ?? null,
      ...(runtime.offline ? { audit: sess.auditor.events } : {}),
    });
  } catch (err) {
    console.error("[approve] failed", err);
    return res.status(500).json({ error: "internal_error" });
  }
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  console.log(`[server] http://localhost:${port}  offline=${runtime.offline}`);
});
