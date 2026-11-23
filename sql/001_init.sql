-- ============================================================================
-- agent-security-lab / schema
--
-- 运行环境：与其他项目共用的 PGlite（PostgreSQL 18.7 + pgvector 0.8.7），
--           连接串 postgresql://postgres@127.0.0.1:5432/postgres。
-- 命名约定：本项目所有数据库对象统一前缀 `agent-security-lab_`，与
--           src/db/tables.js 的 T 常量逐字对应（含双引号，前缀里有连字符）。
--           LangGraph 官方 checkpointer 的表名硬编码，改不了前缀，因此放进
--           独立 schema "agent-security-lab"（由 migrate.js 创建）。
-- 设计要点：
--   1. 审计日志 append-only（RULE 拦截 UPDATE/DELETE），用于取证与抗抵赖
--   2. pgvector 记忆表开 RLS + FORCE RLS，租户隔离下沉到数据库层
--   3. 向量内容带 trust / source，区分「可信知识」与「用户输入」，防记忆投毒
-- ============================================================================

-- pgvector 由共享服务预装；IF NOT EXISTS 在已装时不会触发任何权限操作。
CREATE EXTENSION IF NOT EXISTS vector;
-- gen_random_uuid() 在 PG 13+ 是内置函数，不需要 pgcrypto，避免对共享库提权。

-- ---------------------------------------------------------------------------
-- 审计事件（只增不改）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "agent-security-lab_audit_events" (
  id            BIGSERIAL PRIMARY KEY,
  trace_id      UUID NOT NULL,
  session_id    TEXT NOT NULL,
  tenant_id     TEXT NOT NULL,
  user_id       TEXT NOT NULL,
  node          TEXT NOT NULL,
  event         TEXT NOT NULL,
  decision      TEXT NOT NULL,          -- allow | deny | escalate | approve | reject
  risk_flags    TEXT[] NOT NULL DEFAULT '{}',
  detail        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS "agent-security-lab_audit_trace_idx"
  ON "agent-security-lab_audit_events" (trace_id, id);
CREATE INDEX IF NOT EXISTS "agent-security-lab_audit_tenant_time_idx"
  ON "agent-security-lab_audit_events" (tenant_id, created_at DESC);

CREATE OR REPLACE RULE "agent-security-lab_audit_no_update"
  AS ON UPDATE TO "agent-security-lab_audit_events" DO INSTEAD NOTHING;
CREATE OR REPLACE RULE "agent-security-lab_audit_no_delete"
  AS ON DELETE TO "agent-security-lab_audit_events" DO INSTEAD NOTHING;

-- ---------------------------------------------------------------------------
-- 长期记忆 / RAG 语料
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "agent-security-lab_memory_chunks" (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     TEXT NOT NULL,
  owner_id      TEXT NOT NULL,
  source        TEXT NOT NULL,          -- 例: kb:handbook / user:upload / agent:summary
  trust         TEXT NOT NULL DEFAULT 'untrusted'
                CHECK (trust IN ('trusted', 'untrusted', 'quarantined')),
  content       TEXT NOT NULL,
  content_hash  TEXT NOT NULL,
  embedding     vector(1536),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS "agent-security-lab_memory_hash_unique"
  ON "agent-security-lab_memory_chunks" (content_hash);
CREATE INDEX IF NOT EXISTS "agent-security-lab_memory_tenant_idx"
  ON "agent-security-lab_memory_chunks" (tenant_id);

-- HNSW 是可选加速：某些 PGlite / 托管 PG 构建未编译 hnsw，索引创建失败不应
-- 阻塞整条链路（小数据量下顺序扫描完全够用），因此单独容错执行。
DO $$
BEGIN
  EXECUTE 'CREATE INDEX IF NOT EXISTS "agent-security-lab_memory_embedding_idx" ON "agent-security-lab_memory_chunks" USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)';
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE '[agent-security-lab] HNSW 索引不可用，已跳过: %', SQLERRM;
END
$$;

-- RLS：连接未设置 app.tenant_id 时返回 0 行（fail-closed，而不是放行）。
-- FORCE：让表拥有者也受策略约束；但 postgres 超级用户自带 BYPASSRLS 仍会绕过，
--        所以应用层的 withTenant() + 显式 tenant 条件是必需的第二道兜底，
--        生产环境应改用最小权限的专用角色连接。
ALTER TABLE "agent-security-lab_memory_chunks" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "agent-security-lab_memory_chunks" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "agent-security-lab_memory_tenant_isolation"
  ON "agent-security-lab_memory_chunks";
CREATE POLICY "agent-security-lab_memory_tenant_isolation"
  ON "agent-security-lab_memory_chunks"
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- ---------------------------------------------------------------------------
-- 人工审批记录（与 LangGraph checkpoint 互补：checkpoint 存状态，此表存「谁批的」）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "agent-security-lab_approval_records" (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  trace_id      UUID NOT NULL,
  session_id    TEXT NOT NULL,
  tenant_id     TEXT NOT NULL,
  approver_id   TEXT NOT NULL,
  tool_name     TEXT NOT NULL,
  tool_args     JSONB NOT NULL,
  decision      TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
  reason        TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS "agent-security-lab_approval_trace_idx"
  ON "agent-security-lab_approval_records" (trace_id);

-- ---------------------------------------------------------------------------
-- 示例业务表（只读工具会用到；参数化查询，禁止拼接 SQL）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "agent-security-lab_orders" (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  user_id       TEXT NOT NULL,
  amount_cents  INTEGER NOT NULL,
  status        TEXT NOT NULL
);
INSERT INTO "agent-security-lab_orders" (id, tenant_id, user_id, amount_cents, status)
VALUES ('ORD-1001', 'tenant-a', 'u-1', 12900, 'paid'),
       ('ORD-1002', 'tenant-a', 'u-1', 4900, 'shipped'),
       ('ORD-9001', 'tenant-b', 'u-2', 99900, 'paid')
ON CONFLICT (id) DO NOTHING;
