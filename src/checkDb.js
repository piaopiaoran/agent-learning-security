import "dotenv/config";
import { config, assertSharedDatabase } from "./config.js";
import { createPool } from "./db/pool.js";
import { TABLE_PREFIX, CHECKPOINT_SCHEMA } from "./db/tables.js";

/**
 * 只读诊断：确认共享 PGlite 服务可达、pgvector 可用、本项目对象是否已建。
 * 刻意不做任何写操作 —— 它不启动/重启数据库、不建库、不新开端口。
 * 真正建表请用 npm run migrate。
 *
 * 为什么要显式打印 schema：共享服务的 search_path 只有 public，而官方
 * PostgresSaver 的四张表被放在专属 schema "agent-security-lab" 里。
 * 大多数数据库 GUI 默认只展开 public，直接在表树里找是看不到的。
 */
const pool = createPool();

/** 表名来自系统目录，仍做白名单校验：不给「拼接 SQL 标识符」开坏头。
 *  允许连字符 —— 本项目前缀带 `-`，但已用双引号包裹；禁用引号与空格。 */
async function countRows(schema, table) {
  if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(table)) return "?";
  const { rows: [{ n }] } = await pool.query(
    `SELECT count(*)::int AS n FROM "${schema}"."${table}"`
  );
  return n;
}

try {
  console.log(`[check:db] ${assertSharedDatabase(config.DATABASE_URL)}（共享端口 5432）`);

  const { rows: [v] } = await pool.query("SELECT version() AS v");
  console.log("[check:db] server:", v.v.split(",")[0]);

  const { rows: [sp] } = await pool.query(
    "SELECT current_database() AS db, current_setting('search_path') AS sp"
  );
  console.log(`[check:db] database: ${sp.db} | search_path: ${sp.sp}（裸表名只会解析到 public）`);

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
  if (tables.rows.length) {
    const list = [];
    for (const { tablename } of tables.rows) {
      list.push(`${tablename}(${await countRows("public", tablename)})`);
    }
    console.log(`[check:db] public 下 ${tables.rows.length} 张业务表: ${list.join(", ")}`);
  } else {
    console.log("[check:db] public 下业务表: 尚未创建 → 运行 npm run migrate");
  }

  const cp = await pool.query(
    "SELECT tablename FROM pg_tables WHERE schemaname = $1 ORDER BY 1",
    [CHECKPOINT_SCHEMA]
  );
  if (cp.rows.length) {
    const list = [];
    for (const { tablename } of cp.rows) {
      list.push(`${tablename}(${await countRows(CHECKPOINT_SCHEMA, tablename)})`);
    }
    console.log(`[check:db] 另有 ${cp.rows.length} 张 checkpoint 表，不在 public，位于 schema "${CHECKPOINT_SCHEMA}":`);
    console.log(`           ${list.join(", ")}`);
    console.log(`           访问需双引号: SELECT * FROM "${CHECKPOINT_SCHEMA}".checkpoints;`);
    console.log("           GUI 里请展开该 schema 节点（不是 public 下的表）。");
  } else {
    console.log(`[check:db] schema "${CHECKPOINT_SCHEMA}" 下 checkpoint 表: 尚未创建 → 运行 npm run migrate`);
  }
} catch (err) {
  console.error("[check:db] 连接失败:", err.message);
  console.error("[check:db] 只检查已有服务；不会启动/重启数据库，也不会新开端口。");
  process.exitCode = 1;
} finally {
  await pool.end().catch(() => {});
}
