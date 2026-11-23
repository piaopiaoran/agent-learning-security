import test from "node:test";
import assert from "node:assert/strict";
import { readFile, access } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { T, TABLE_PREFIX, CHECKPOINT_SCHEMA, checkpointOptions } from "../src/db/tables.js";
import { config, assertSharedDatabase } from "../src/config.js";

const root = new URL("../", import.meta.url);
const read = async (p) => readFile(new URL(p, root), "utf8");

test("Schema / 所有表名与对象名都带 agent-security-lab_ 前缀且用双引号引用", async () => {
  const sql = await read("sql/001_init.sql");
  const created = [...sql.matchAll(/CREATE TABLE IF NOT EXISTS\s+(\S+)/g)].map((m) => m[1]);
  assert.equal(created.length, 4, "应有 4 张自建表");
  for (const name of created) {
    assert.match(name, /^"agent-security-lab_[\w]+"$/, `${name} 必须带前缀并加双引号`);
  }
  // 索引 / RULE / POLICY 也都在共享库里，必须同样带前缀
  for (const m of sql.matchAll(/CREATE (?:UNIQUE )?INDEX IF NOT EXISTS\s+(\S+)/g)) {
    assert.match(m[1], /^"agent-security-lab_/);
  }
  for (const m of sql.matchAll(/CREATE OR REPLACE RULE\s+(\S+)/g)) {
    assert.match(m[1], /^"agent-security-lab_/);
  }
  assert.match(sql, /CREATE POLICY\s+"agent-security-lab_/);
});

test("Schema / JS 的 T 常量与 SQL 文件逐字一致，且 SQL 中不留裸表名", async () => {
  const sql = await read("sql/001_init.sql");
  for (const [key, qualified] of Object.entries(T)) {
    assert.ok(qualified.startsWith(`"${TABLE_PREFIX}`), `${key} 必须带前缀`);
    assert.ok(sql.includes(qualified), `SQL 缺少 ${key}: ${qualified}`);
  }
  // 前缀含连字符，裸写会被 PG 当成减法表达式；这些旧写法一律不许出现
  for (const bad of [
    "CREATE TABLE IF NOT EXISTS audit_events",
    "INSERT INTO memory_chunks",
    "FROM orders ",
    "INSERT INTO approval_records",
  ]) {
    assert.ok(!sql.includes(bad), `SQL 仍含裸表名: ${bad}`);
  }
});

test("Schema / 所有运行时 SQL 都从 T 常量取表名，不再硬编码", async () => {
  const files = [
    "src/security/audit.js", "src/memory/vectorStore.js",
    "src/tools/builtins.js", "src/runtime.js",
  ];
  for (const f of files) {
    const js = await read(f);
    assert.ok(js.includes("tables.js"), `${f} 必须 import 集中表名常量`);
    for (const bad of [
      "INSERT INTO audit_events", "INSERT INTO memory_chunks",
      "FROM memory_chunks", "FROM orders ", "INSERT INTO approval_records",
    ]) {
      assert.ok(!js.includes(bad), `${f} 仍硬编码表名: ${bad}`);
    }
  }
});

test("Schema / 官方 checkpoint 表用独立 schema 隔离，不污染 public", async () => {
  assert.equal(CHECKPOINT_SCHEMA, "agent-security-lab");
  assert.deepEqual(checkpointOptions, { schema: CHECKPOINT_SCHEMA });
  for (const f of ["src/runtime.js", "src/db/migrate.js"]) {
    const js = await read(f);
    assert.match(js, /checkpointOptions/, `${f} 必须传 schema 给 PostgresSaver`);
  }
  const migrate = await read("src/db/migrate.js");
  assert.match(migrate, /CREATE SCHEMA IF NOT EXISTS/);
});

test("Schema / 连接串固定为共享本地 5432，禁止另开端口或改库", () => {
  const expected = "postgresql://postgres@127.0.0.1:5432/postgres";
  assert.equal(config.DATABASE_URL, expected);
  assert.match(assertSharedDatabase(expected), /127\.0\.0\.1:5432\/postgres/);
  assert.throws(() => assertSharedDatabase("postgresql://postgres@127.0.0.1:5433/postgres"), /5432/);
  assert.throws(() => assertSharedDatabase("postgresql://postgres@db.internal:5432/postgres"), /5432/);
  assert.throws(() => assertSharedDatabase("postgresql://postgres@127.0.0.1:5432/agent_sec"), /postgres 库/);
  assert.throws(() => assertSharedDatabase("postgresql://postgres:secret@127.0.0.1:5432/postgres"), /密码/);
});

test("Schema / 不再依赖 Docker：无 compose 文件，setup 只跑迁移", async () => {
  const pkg = JSON.parse(await read("package.json"));
  assert.equal(pkg.scripts.setup, "node src/db/migrate.js");
  assert.ok(!JSON.stringify(pkg.scripts).includes("docker"), "scripts 不得再引用 docker");
  assert.equal(pkg.scripts["check:db"], "node src/checkDb.js");
  await assert.rejects(
    () => access(fileURLToPath(new URL("docker-compose.yml", root))),
    "docker-compose.yml 应已删除"
  );
});

test("Schema / .env.example 同步为共享 PGlite 连接串", async () => {
  const example = await read(".env.example");
  assert.match(example, /DATABASE_URL=postgresql:\/\/postgres@127\.0\.0\.1:5432\/postgres/);
  assert.match(example, /STORE=memory/);
});
