import "dotenv/config";
import { config, assertSharedDatabase } from "./config.js";
import { createPool } from "./db/pool.js";
import { TABLE_PREFIX, CHECKPOINT_SCHEMA } from "./db/tables.js";

/**
 * 只读诊断：确认共享 PGlite 服务可达、pgvector 可用、本项目对象是否已建。
 * 刻意不做任何写操作 —— 它不启动/重启数据库、不建库、不新开端口。
 * 真正建表请用 npm run migrate。
 */
const pool = createPool();
try {
  console.log(`[check:db] ${assertSharedDatabase(config.DATABASE_URL)}（共享端口 5432）`);

  const { rows: [v] } = await pool.query("SELECT version() AS v");
  console.log("[check:db] server:", v.v.split(",")[0]);

  const ext = await pool.query(
    "SELECT extname, extversion FROM pg_extension WHERE extname = 'vector'"
  );
  console.log("[check:db] pgvector:", ext.rows.length
    ? ext.rows.map((r) => `${r.extname} ${r.extversion}`).join(", ")
    : "NOT INSTALLED（迁移会尝试 CREATE EXTENSION）");

  const tables = await pool.query(
    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE $1 ORDER BY 1",
    [`${TABLE_PREFIX}%`]
  );
  console.log(`[check:db] ${tables.rows.length} 张业务表:`,
    tables.rows.length ? tables.rows.map((r) => r.tablename).join(", ") : "尚未创建 → 运行 npm run migrate");

  const cp = await pool.query(
    "SELECT tablename FROM pg_tables WHERE schemaname = $1 ORDER BY 1",
    [CHECKPOINT_SCHEMA]
  );
  console.log(`[check:db] schema "${CHECKPOINT_SCHEMA}" 下 checkpoint 表:`,
    cp.rows.length ? cp.rows.map((r) => r.tablename).join(", ") : "尚未创建 → 运行 npm run migrate");
} catch (err) {
  console.error("[check:db] 连接失败:", err.message);
  console.error("[check:db] 只检查已有服务；不会启动/重启数据库，也不会新开端口。");
  process.exitCode = 1;
} finally {
  await pool.end().catch(() => {});
}
