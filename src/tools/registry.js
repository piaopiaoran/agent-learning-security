import { tool } from "@langchain/core/tools";
import { redact } from "../security/pii.js";

/**
 * 工具注册表 = 唯一的能力清单（allowlist）。
 * 模型只能看见注册表里存在的工具；注册表之外的名字一律判为幻觉工具并拒绝。
 * 每个工具都带：Zod schema、风险等级、角色白名单、是否有副作用、是否出网、超时。
 */
export function createRegistry(defs = []) {
  const map = new Map(defs.map((d) => [d.name, d]));

  // 只用于向 LLM 描述能力；真实执行永远走下面的 execute()，不会让模型直接调用 func
  const lcTools = defs.map((d) =>
    tool(async () => "mediated by security gateway", {
      name: d.name,
      description: d.description,
      schema: d.schema,
    })
  );

  async function execute(name, args, ctx) {
    const def = map.get(name);
    if (!def) throw new Error(`unregistered tool: ${name}`);
    let timer;
    try {
      const result = await Promise.race([
        Promise.resolve().then(() => def.execute(args, ctx)),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("tool_timeout")), def.timeoutMs ?? 3000);
        }),
      ]);
      // 工具输出也是不可信数据：脱敏、限长，之后还会被包进 untrusted 信封
      return redact(String(result ?? "")).slice(0, ctx.maxToolOutputChars ?? 6000);
    } catch (err) {
      return `[工具执行失败/被拒绝] ${redact(err.message)}`;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    defs,
    get: (name) => map.get(name),
    names: () => [...map.keys()],
    langchainTools: () => lcTools,
    execute,
  };
}
