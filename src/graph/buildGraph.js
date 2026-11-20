import { END, START, StateGraph } from "@langchain/langgraph";
import { AgentState } from "./state.js";
import { createNodes } from "./nodes.js";

export const routeAfterInput = (s) => (s.verdict === "rejected" ? "reject" : "retrieve");
export const routeAfterAgent = (s) => {
  if (s.verdict === "budget_exceeded" || s.verdict === "model_error") return "reject";
  return s.verdict === "tool_calls" ? "toolGate" : "guardOutput";
};
export const routeAfterGate = (s) => (s.verdict === "needs_approval" ? "approval" : "executeTools");
export const routeAfterBudget = (s) => (s.verdict === "budget_exceeded" ? "reject" : "agent");

/**
 * 图结构（每一条边都是一次「重新鉴权」的机会）：
 *
 *  START → guardInput ─deny→ reject → END
 *                     └pass→ retrieve → agent ─answer→ guardOutput → END
 *                                             └tool_calls→ toolGate
 *                                                            ├需审批→ humanApproval(interrupt) ┐
 *                                                            └──────→ executeTools ←──────┘
 *                                                                       ↓
 *                                                              budgetGate ─超预算→ reject
 *                                                                       └ok→ agent（回到循环）
 */
export function buildGraph(deps) {
  const n = createNodes(deps);
  return new StateGraph(AgentState)
    .addNode("guardInput", n.guardInput)
    .addNode("reject", n.reject)
    .addNode("retrieve", n.retrieve)
    .addNode("agent", n.agent)
    .addNode("toolGate", n.toolGate)
    .addNode("humanApproval", n.approval)
    .addNode("executeTools", n.executeTools)
    .addNode("budgetGate", n.budgetGate)
    .addNode("guardOutput", n.guardOutput)

    .addEdge(START, "guardInput")
    .addConditionalEdges("guardInput", routeAfterInput, { reject: "reject", retrieve: "retrieve" })
    .addEdge("retrieve", "agent")
    .addConditionalEdges("agent", routeAfterAgent, {
      reject: "reject", toolGate: "toolGate", guardOutput: "guardOutput",
    })
    .addConditionalEdges("toolGate", routeAfterGate, {
      approval: "humanApproval", executeTools: "executeTools",
    })
    .addEdge("humanApproval", "executeTools")
    .addEdge("executeTools", "budgetGate")
    .addConditionalEdges("budgetGate", routeAfterBudget, { reject: "reject", agent: "agent" })
    .addEdge("guardOutput", END)
    .addEdge("reject", END)
    .compile({ checkpointer: deps.checkpointer });
}
