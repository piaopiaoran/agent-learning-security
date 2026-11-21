import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { config } from "./config.js";
import { createRuntime, createSession, extractInterrupt } from "./runtime.js";
import { flushTraces, logDataEgress, logTracingStatus } from "./observability.js";

const publicDir = fileURLToPath(new URL("../public/", import.meta.url));
const MAX_SESSIONS = 200; // 演示用内存会话表必须有上限，否则是可被刷爆的内存泄漏

/**
 * 把 app 的构造与「启动监听」分开，测试才能用随机端口 import 后直接跑，
 * 不必占用 3000、也不必真的连 LLM / 数据库。
 */
export function buildApp(runtime) {
  const app = express();
  const sessions = new Map();

  // 前端渲染的每一段文本（模型输出、审计 detail、工具参数）都是不可信数据。
  // 除了在浏览器侧坚持 textContent 渲染，服务端再加一层 CSP：
  // 禁内联脚本、禁外域资源、禁 object/base。生产还应加 frame-ancestors 与
  // X-Frame-Options 防点击劫持；此处为兼容内嵌预览面板暂不设置（README 有说明）。
  app.use((_req, res, next) => {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; " +
      "connect-src 'self'; img-src 'self' data:; object-src 'none'; " +
      "base-uri 'none'; form-action 'self'"
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    next();
  });

  app.use(express.json({ limit: "16kb" })); // body 体积限制也是一层入口防护
  app.use(express.static(publicDir, { index: "index.html" }));

  app.get("/health", (_req, res) => {
    res.json({
      ok: true,
      modelMode: runtime.modelMode,
      storeMode: runtime.storeMode,
      model: config.modelLabel,
      llmEndpoint: config.llmEndpoint,
      embeddingMode: config.embeddingMode,
      tracing: { enabled: config.langsmith.enabled, project: config.langsmith.project },
      budgets: {
        maxSteps: config.MAX_STEPS,
        maxTotalTokens: config.MAX_TOTAL_TOKENS,
        maxWallMs: config.MAX_WALL_MS,
      },
      tools: runtime.registry.names(),
    });
  });

  app.post("/chat", async (req, res) => {
    // ⚠️ 演示用：真实系统必须从已验证的 JWT / OIDC session 取身份，
    //    绝不能信任客户端自报的 x-tenant-id / x-role（否则一行 header 就完成越权）。
    //    前端把这个「可切换身份」做成显眼的演示控件，正是为了让这条风险看得见。
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
    if (sessions.size > MAX_SESSIONS) sessions.delete(sessions.keys().next().value);

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
        role,
        // auditor.events 在 db / memory 两种模式下都保留内存副本，
        // 所以前端始终能拿到本轮完整决策链（内容已统一脱敏）。
        audit: sess.auditor.events,
        budget: result.budget ?? null,
      });
    } catch (err) {
      // 不打印完整堆栈：SDK 错误对象可能携带请求配置 / 凭据
      console.error("[chat] failed:", String(err.message ?? "").slice(0, 200));
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
        verdict: result.verdict ?? "",
        approval: result.approval ?? null,
        // 同一个 sess，返回的是含 chat 阶段的完整链，前端直接替换而非追加
        audit: sess.auditor.events,
        budget: result.budget ?? null,
      });
    } catch (err) {
      console.error("[approve] failed:", String(err.message ?? "").slice(0, 200));
      return res.status(500).json({ error: "internal_error" });
    }
  });

  return app;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const runtime = await createRuntime();
  const app = buildApp(runtime);
  const port = Number(process.env.PORT ?? 3000);
  const server = app.listen(port, () => {
    console.log(`[server] http://localhost:${port}  model=${runtime.modelMode}  store=${runtime.storeMode}`);
    console.log(`[web] 安全控制台: http://localhost:${port}/`);
    logTracingStatus();
    logDataEgress();
  });

  async function shutdown() {
    // 长驻服务退出前也要等后台 trace 提交完
    await flushTraces();
    await runtime.close();
    server.close(() => process.exit(0));
  }
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
