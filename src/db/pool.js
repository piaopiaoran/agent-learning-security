import pg from "pg";
import { config } from "../config.js";

const { Pool } = pg;

export function createPool(connectionString = config.DATABASE_URL) {
  const pool = new Pool({
    connectionString,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });
  pool.on("error", (err) => console.error("[pg] idle client error", err));
  return pool;
}

/**
 * 租户上下文：用 SET LOCAL 把 tenant_id 绑在事务里，配合 memory_chunks 的 RLS。
 * 面试点：
 *  - 为什么不用字符串拼 WHERE tenant_id？→ 一处漏写就是横向越权；RLS 是 DB 层兜底。
 *  - 为什么 SET LOCAL 而不是 SET？→ 连接归还池后不会残留上一个租户的身份。
 *  - 为什么用 set_config($1, true)？→ 参数化，tenant_id 本身来自不可信输入时也不会注入。
 */
export async function withTenant(pool, tenantId, fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
