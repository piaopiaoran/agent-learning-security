/**
 * 共享 PostgreSQL 实例的命名空间约定。
 *
 * 背景：本项目和其他项目共用同一个 PGlite / PostgreSQL 服务（127.0.0.1:5432 的
 * postgres 库），因此所有数据库对象名必须带统一前缀，否则 CREATE TABLE / 索引 /
 * RULE / RLS 策略都可能与别的项目撞名，甚至误读别人的业务数据。
 *
 * 前缀含连字符（-），在 PostgreSQL 里是非法裸标识符，必须双引号引用：
 *   SELECT * FROM "agent-security-lab_orders";   -- 正确
 *   SELECT * FROM agent-security-lab_orders;     -- 语法错误（被当成减法）
 * 所以下面导出的每个名字都是「已加引号」的完整标识符，直接拼进 SQL 即可。
 *
 * 面试点：命名前缀是「约定式隔离」，RLS 才是「强制式隔离」；两者都要有，
 * 但只有后者能防住应用代码里漏写 WHERE 的情况。
 */
export const TABLE_PREFIX = "agent-security-lab_";

/**
 * LangGraph 官方 PostgresSaver 的四张表名（checkpoints / checkpoint_blobs /
 * checkpoint_writes / checkpoint_migrations）在 dist/sql.js 里硬编码，无法通过
 * 参数改前缀；它只支持自定义 schema。因此把 checkpoint 放进专属 schema，
 * 完整限定名为 "agent-security-lab".checkpoints —— 同样以本项目命名空间开头，
 * 且与共享库里其他项目（包括它们自己的 checkpointer）完全隔离。
 */
export const CHECKPOINT_SCHEMA = "agent-security-lab";

const qualified = (suffix) => `"${TABLE_PREFIX}${suffix}"`;

/** sql/001_init.sql 中的表名必须与这里逐字一致；test/schema.test.js 会守着 */
export const T = Object.freeze({
  auditEvents: qualified("audit_events"),
  memoryChunks: qualified("memory_chunks"),
  approvalRecords: qualified("approval_records"),
  orders: qualified("orders"),
});

/** new PostgresSaver(pool, undefined, checkpointOptions) */
export const checkpointOptions = Object.freeze({ schema: CHECKPOINT_SCHEMA });
