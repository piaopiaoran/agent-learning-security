/**
 * 规则库：启发式检测，不追求「识别所有攻击」，而是提供可解释、可灰度、零成本的第一层。
 * 面试点：正则/关键词只能挡低级攻击，必须说明它和「语义级检测（小模型分类器）」「结构性隔离」的分工。
 */

// 直接 / 间接 Prompt Injection、越狱、系统提示探测
export const INJECTION_RULES = [
  // 「忽略上层指令」是明确的攻击语义，单条命中即拒绝（权重 >= DENY_AT）
  { id: "override_en", w: 60, re: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)/i },
  { id: "override_zh", w: 60, re: /(忽略|无视|忘记|清除|抛弃)[^，。；\n]{0,12}(指令|规则|提示|设定|约束|要求|上文|系统提示)/ },
  { id: "prompt_leak", w: 55, re: /(reveal|print|repeat|show|dump|output).{0,30}(system prompt|instructions|hidden rules|你的系统提示|输出你的(系统)?提示词|打印.*提示词)/i },
  { id: "prompt_leak_zh", w: 55, re: /(打印|输出|复述|显示|告诉我|泄露|暴露)[^，。；\n]{0,20}(系统提示|提示词|内部指令|隐藏规则|system prompt)/i },
  { id: "jailbreak", w: 60, re: /(DAN mode|jailbreak|越狱|开发者模式|不受限制|do anything now)/i },
  { id: "authority_spoof", w: 40, re: /(this is (an )?(admin|developer|system) (message|override)|【?系统指令】?|\[SYSTEM\]|<\|im_start\|>|\bBEGIN SYSTEM\b)/i },
  // 以下为弱信号：单条命中只降权（escalate），组合命中才拒绝
  { id: "role_switch", w: 30, re: /(you are now|act as|pretend to be|from now on|switch to developer mode|你现在是)/i },
  { id: "tool_coercion", w: 30, re: /(call|invoke|run|use)\s+(the\s+)?(tool|function).{0,60}(refund|transfer|delete|send|drop|exec|shell)/i },
  { id: "exfiltration", w: 30, re: /(send|post|upload|curl|fetch).{0,50}(to|@).{0,50}(http|webhook|pastebin|外部地址)/i },
  { id: "delimiter_escape", w: 50, re: /(<\/?\s*(untrusted_data|trusted_context|system|tool_output)\s*>|\[\/?INST\]|<\|.*?\|>)/i },
  { id: "urgency_coercion", w: 30, re: /(紧急|立即执行|不要询问|不要确认|without asking|do not confirm|skip approval|绕过审批)/i },
  { id: "encoding_smuggle", w: 20, re: /(base64\s*解码|decode\s+this\s+base64|rot13|把.{0,10}解码后执行)/i },
];

// 凭据泄漏（输入里带密钥 / 输出里吐密钥，都要拦）
export const SECRET_RULES = [
  { id: "openai_key", re: /\bsk-[A-Za-z0-9_-]{16,}\b/ },
  { id: "aws_key", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: "github_token", re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/ },
  { id: "slack_token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: "private_key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { id: "bearer", re: /\bBearer\s+[A-Za-z0-9._-]{20,}/i },
  { id: "env_secret", re: /(OPENAI_API_KEY|LLM_API_KEY|EMBEDDING_API_KEY|LANGSMITH_API_KEY|DATABASE_URL|AWS_SECRET_ACCESS_KEY)\s*=\s*\S{8,}/ },
];

// PII（脱敏用，不是拦截用）
export const PII_RULES = [
  { id: "cn_id", re: /\b\d{17}[\dXx]\b/g, mask: (s) => s.slice(0, 1) + "****************" + s.slice(-1) },
  { id: "cn_mobile", re: /\b1[3-9]\d{9}\b/g, mask: (s) => s.slice(0, 3) + "****" + s.slice(-4) },
  { id: "bank_card", re: /\b\d{16,19}\b/g, mask: (s) => s.slice(0, 4) + " **** **** " + s.slice(-4) },
  { id: "email", re: /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, mask: (s) => s[0] + "***@" + s.split("@")[1] },
];

// 模型自作主张的「已完成」话术：没有真实工具执行记录时属于高危幻觉
export const UNAUTHORIZED_CLAIM_RE =
  /(已(经)?(为你|替你)?(完成|退款|转账|发送|删除|下单|批准)|(退款|邮件|转账)(已|已经)(成功|完成|发出)|successfully (refunded|transferred|sent|deleted))/i;

// 出站 / 文件系统攻击面
export const SSRF_RE = /^(https?:\/\/)([^/@]+)/i;
export const PRIVATE_HOST_RE = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|\[::1\]|metadata\.google\.internal)/i;
export const PATH_TRAVERSAL_RE = /(\.\.[\/\\]|^\/|^[A-Za-z]:[\\\/]|file:\/\/|%2e%2e|~[\/\\])/i;
