import { HumanMessage, SystemMessage } from "@langchain/core/messages";
import { config } from "./config.js";
import { createModel } from "./graph/model.js";
import { createRegistry } from "./tools/registry.js";
import { builtinTools } from "./tools/builtins.js";
import { flushTraces, logDataEgress, logTracingStatus } from "./observability.js";

/**
 * 供应商接入自检：只发一次最小请求，验证三件事
 *   1. baseURL / key / model 是否能打通
 *   2. 该模型的 function calling 是否返回标准 tool_calls（安全网关的上游依赖）
 *   3. usage_metadata 是否可读（L7 token 预算依赖它）
 * 切到 DeepSeek / 硅基流动 / OpenAI 后先跑这个，再跑 npm run demo。
 */
console.log("=== LLM 连通性检查 ===");
console.log(`provider    : ${config.LLM_PROVIDER}`);
console.log(`endpoint    : ${config.llmEndpoint}`);
console.log(`model       : ${config.LLM_MODEL}`);
console.log(`temperature : ${config.LLM_TEMPERATURE}  timeout=${config.LLM_TIMEOUT_MS}ms  retries=${config.LLM_MAX_RETRIES}`);
logTracingStatus();
logDataEgress();

if (!config.hasLLM) {
  console.error("\n[x] 未启用真实模型（LLM_PROVIDER=fake 或缺少 LLM_API_KEY），没有发起任何外部请求。");
  console.error("    在 .env 设置 LLM_PROVIDER=openai 与 LLM_API_KEY 后重试。");
  process.exitCode = 1;
} else {
  const registry = createRegistry(builtinTools);
  const model = createModel({ registry });
  const started = Date.now();
  try {
    const res = await model.invoke([
      new SystemMessage("你是企业助手。需要查询信息时必须使用给定工具，不要编造结果。"),
      new HumanMessage("帮我查一下 ORD-1001 的订单状态"),
    ]);
    const calls = res.tool_calls ?? [];
    console.log(`\n[ok] 响应耗时 ${Date.now() - started}ms`);
    console.log(`     tool_calls : ${JSON.stringify(calls.map((c) => ({ name: c.name, args: c.args })))}`);
    console.log(`     usage      : ${JSON.stringify(res.usage_metadata ?? {})}`);
    console.log(`     content    : ${JSON.stringify(String(res.content ?? "").slice(0, 160))}`);

    if (!calls.length) {
      console.error("\n[!] 模型没有发起 tool_call —— 该模型/端点可能不支持 function calling，请更换模型。");
      process.exitCode = 1;
    } else if (!res.usage_metadata?.total_tokens) {
      console.error("\n[!] 响应缺少 usage_metadata.total_tokens —— L7 token 预算会退化为字符数估算。");
      process.exitCode = 1;
    } else {
      console.log("\n[✓] 连通性、工具调用、用量统计均正常；后续授权仍由 L4 工具网关接管。");
    }
  } catch (err) {
    // 不打印完整堆栈：OpenAI SDK 的错误对象可能携带请求配置
    console.error("\n[x] 调用失败:", err.name, String(err.message ?? "").slice(0, 300));
    process.exitCode = 1;
  }
  await flushTraces();
}
