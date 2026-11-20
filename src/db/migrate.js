import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { PostgresSaver } from "@langchain/langgraph-checkpoint-postgres";
import { createPool } from "./pool.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const sqlPath = path.resolve(here, "../../sql/001_init.sql");

const pool = createPool();
try {
  const sql = await readFile(sqlPath, "utf8");
  await pool.query(sql);
  console.log("[migrate] schema / RLS / audit rules ready");

  // LangGraph 官方 checkpointer 自建 checkpoint 系列表，用于 HITL 中断后可恢复
  const saver = new PostgresSaver(pool);
  await saver.setup();
  console.log("[migrate] langgraph checkpoint tables ready");
} catch (err) {
  console.error("[migrate] failed:", err.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
