-- ============================================================================
-- agent-security-lab / schema
-- 设计要点：
--   1. 审计日志 append-only（RULE 拦截 UPDATE/DELETE），用于取证与抗抵赖
--   2. pgvector 记忆表开 RLS，租户隔离下沉到数据库层（防线不止在应用代码）
--   3. 向量内容带 trust / source，用于区分「可信知识」与「用户输入」，防记忆投毒
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- 审计事件（只增不改）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
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
CREATE INDEX IF NOT EXISTS audit_trace_idx ON audit_events (trace_id, id);
CREATE INDEX IF NOT EXISTS audit_tenant_time_idx ON audit_events (tenant_id, created_at DESC);

CREATE OR REPLACE RULE audit_no_update AS ON UPDATE TO audit_events DO INSTEAD NOTHING;
CREATE OR REPLACE RULE audit_no_delete AS ON DELETE TO audit_events DO INSTEAD NOTHING;

-- ---------------------------------------------------------------------------
-- 长期记忆 / RAG 语料
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memory_chunks (
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
CREATE UNIQUE INDEX IF NOT EXISTS memory_hash_unique ON memory_chunks (content_hash);
CREATE INDEX IF NOT EXISTS memory_tenant_idx ON memory_chunks (tenant_id);
CREATE INDEX IF NOT EXISTS memory_embedding_idx
  ON memory_chunks USING hnsw (embedding vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);

-- RLS：连接未设置 app.tenant_id 时返回 0 行（fail-closed，而不是放行）
ALTER TABLE memory_chunks ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS memory_tenant_isolation ON memory_chunks;
CREATE POLICY memory_tenant_isolation ON memory_chunks
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- ---------------------------------------------------------------------------
-- 人工审批记录（与 LangGraph checkpoint 互补：checkpoint 存状态，此表存「谁批的」）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approval_records (
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
CREATE INDEX IF NOT EXISTS approval_trace_idx ON approval_records (trace_id);

-- ---------------------------------------------------------------------------
-- 示例业务表（只读工具会用到；参数化查询，禁止拼接 SQL）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS orders (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  user_id       TEXT NOT NULL,
  amount_cents  INTEGER NOT NULL,
  status        TEXT NOT NULL
);
INSERT INTO orders (id, tenant_id, user_id, amount_cents, status)
VALUES ('ORD-1001', 'tenant-a', 'u-1', 12900, 'paid'),
       ('ORD-1002', 'tenant-a', 'u-1', 4900, 'shipped'),
       ('ORD-9001', 'tenant-b', 'u-2', 99900, 'paid')
ON CONFLICT (id) DO NOTHING;
