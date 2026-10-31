/**
 * Fixed notices sent back to the model. They contain only values we control (known tool
 * names, rule IDs, error codes). Never interpolate model output or retrieved content here.
 */
import type { ToolErrorCode, ToolName } from "@contracts";

const RULE_ID = /^[A-Z0-9-]{1,64}$/;

function safeRuleIds(ruleIds: string[]): string {
  const ids = ruleIds.filter((id) => RULE_ID.test(id));
  return ids.length ? ids.join(", ") : "policy";
}

export const notices = {
  denied(tool: ToolName | null, ruleIds: string[]): string {
    return `Tool call ${tool ?? "(unknown tool)"} was denied by security policy (${safeRuleIds(ruleIds)}). Do not retry it. Continue with the user's task if possible, or explain what you could not do.`;
  },
  rejected(tool: ToolName): string {
    return `The operator rejected the ${tool} call. Do not retry it. Continue or explain.`;
  },
  approvalUnavailable(tool: ToolName): string {
    return `The ${tool} call was not approved in time and did not run. Do not retry it.`;
  },
  dropped(): string {
    return "Other tool calls from that step were discarded while waiting for approval. Re-plan if needed.";
  },
  toolFailed(tool: ToolName, code: ToolErrorCode): string {
    return `Tool ${tool} failed with error ${code}.`;
  },
  correction(): string {
    return 'Your previous reply was not valid. Reply with exactly one JSON object: {"action":"final","text":"..."} or {"action":"tool_calls","calls":[{"tool":"<name>","args":{...}}]}. No other text.';
  },
};
