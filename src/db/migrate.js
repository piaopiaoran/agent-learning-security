import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { PostgresSaver } from "@langchain/langgraph-checkpoint-postgres";
import { createPool } from "./pool.js";
import { CHECKPOINT_SCHEMA, checkpointOptions } from "./tables.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const sqlPath = path.resolve(here, "../../sql/001_init.sql");

const pool = createPool();
try {
  // 共享数据库约束：只在已有 postgres 库里创建本项目自己的对象，
  // 不建库、不装扩展之外的服务、不启容器、不监听新端口。
  // 所有表带 agent-security-lab_ 前缀；checkpoint 放独立 schema 隔离。
  await pool.query(`CREATE SCHEMA IF NOT EXISTS "${CHECKPOINT_SCHEMA}"`);

  const sql = await readFile(sqlPath, "utf8");
  await pool.query(sql);
  console.log("[migrate] agent-security-lab_ tables / RLS / audit rules ready");

  // 官方 checkpointer 的四张表名硬编码，只能靠 schema 隔离（见 tables.js）
  const saver = new PostgresSaver(pool, undefined, checkpointOptions);
  await saver.setup();
  console.log(`[migrate] langgraph checkpoint tables ready in schema "${CHECKPOINT_SCHEMA}"`);
} catch (err) {
  console.error("[migrate] failed:", err.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
