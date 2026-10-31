/**
 * src/lib/security/policy.ts
 *
 * Policy loading and defaults.
 */
import { readFileSync } from "node:fs";
import type { Policy, ToolName } from "@contracts";
import { TOOL_NAMES } from "@contracts";

/** Default MVP policy — all tools enabled, sensitive actions require approval. */
export function defaultPolicy(): Policy {
  return {
    version: "default-v1",
    tools: Object.fromEntries(
      TOOL_NAMES.map((name) => {
        const isSensitive = (name === "email.send" || name === "file.write") as boolean;
        return [name, { enabled: true, approval: isSensitive ? ("always" as const) : ("never" as const) }];
      }),
    ) as Policy["tools"],
    email: {
      recipientAllowlist: [],
      contacts: [],
    },
    web: {
      domainAllowlist: [],
      allowUnlistedWhenUntainted: true,
    },
    file: {
      readExtensions: [".txt", ".md", ".json", ".csv", ".pdf"],
      writeExtensions: [".txt", ".md", ".json"],
      maxBytes: 1_048_576, // 1 MB
    },
    limits: {
      maxSteps: 10,
      maxToolCalls: 20,
      maxProposalsPerStep: 5,
    },
  };
}

/**
 * Loads a policy from a JSON file. Falls back to defaultPolicy() if the
 * file does not exist or is malformed.
 */
export function loadPolicy(filePath: string): Policy {
  try {
    const raw = readFileSync(filePath, "utf8");
    return JSON.parse(raw) as Policy;
  } catch {
    return defaultPolicy();
  }
}
