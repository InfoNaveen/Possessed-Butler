/**
 * src/lib/security/rules/index.ts
 *
 * Deterministic policy rules. Each rule is a pure function that receives a
 * ToolCallProposal (with already-parsed canonical args), the session state, and
 * the tool registry, and returns a RuleResult.
 *
 * Rules are evaluated in the order declared in RULES. The policy engine collects
 * all non-abstain results and picks the most restrictive kind.
 *
 * Rule IDs follow the pattern R-<CATEGORY>-<CONCERN> and are stable identifiers
 * used in audit logs and tests.
 */
import { createHash } from "node:crypto";
import path from "node:path";
import type {
  ContentSource,
  DecisionKind,
  PolicyEngine,
  RuleResult,
  SessionSecurityState,
  ToolCallProposal,
  ToolMetadata,
  ToolName,
  ToolRegistry,
} from "@contracts";
import { TOOL_NAMES } from "@contracts";
import { containsEmbeddedToolCall } from "../detectors/index";

// ---------------------------------------------------------------------------
// Sensitive tools — always require explicit approval
// ---------------------------------------------------------------------------

const ALWAYS_APPROVE: ReadonlySet<ToolName> = new Set<ToolName>(["email.send", "file.write"]);

// ---------------------------------------------------------------------------
// Credential file patterns (applies to file.read)
// ---------------------------------------------------------------------------

const SECRET_FILE_PATTERNS: RegExp[] = [
  /^\.env(?:\.|$)/i,
  /\.(pem|key|p12|pfx|crt|cer)$/i,
  /^id_(rsa|ecdsa|ed25519|dsa)$/i,
  /credentials?(\.json)?$/i,
  /secrets?(\.json|\.yaml|\.yml)?$/i,
  /^\.npmrc$/i,
  /^\.netrc$/i,
  /keystore\.(jks|p12)$/i,
  /^api[-_]?key/i,
];

function isSecretFile(filePath: string): boolean {
  const base = path.basename(filePath);
  return SECRET_FILE_PATTERNS.some((p) => p.test(base));
}

// ---------------------------------------------------------------------------
// Sandbox helper (mirrors src/tools sandbox validation)
// ---------------------------------------------------------------------------

const SANDBOX_DIR = process.env["SANDBOX_DIR"] ?? "./sandbox";

function isInsideSandbox(rawPath: string): boolean {
  const sandbox = path.resolve(SANDBOX_DIR);
  const resolved = path.resolve(sandbox, rawPath);
  const withSep = sandbox.endsWith(path.sep) ? sandbox : sandbox + path.sep;
  return resolved === sandbox || resolved.startsWith(withSep);
}

// ---------------------------------------------------------------------------
// Rule type
// ---------------------------------------------------------------------------

export interface Rule {
  id: string;
  enabled: boolean;
  evaluate(
    proposal: ToolCallProposal,
    meta: ToolMetadata | null,
    state: SessionSecurityState,
    registry: ToolRegistry,
  ): RuleResult;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const R_TOOL_KNOWN: Rule = {
  id: "R-TOOL-KNOWN",
  enabled: true,
  evaluate(proposal, meta): RuleResult {
    if (!meta) {
      return { ruleId: "R-TOOL-KNOWN", outcome: "deny", reason: "Tool is not registered." };
    }
    const enabled = true; // policy.tools[name].enabled checked by engine
    return { ruleId: "R-TOOL-KNOWN", outcome: enabled ? "abstain" : "deny", reason: "Tool is known." };
  },
};

const R_TOOL_DISABLED: Rule = {
  id: "R-TOOL-DISABLED",
  enabled: true,
  evaluate(proposal, meta, state): RuleResult {
    if (!meta) return { ruleId: "R-TOOL-DISABLED", outcome: "abstain", reason: "Unknown tool handled by R-TOOL-KNOWN." };
    const toolPolicy = state.policy.tools[meta.name];
    if (!toolPolicy?.enabled) {
      return { ruleId: "R-TOOL-DISABLED", outcome: "deny", reason: "Tool is disabled by policy." };
    }
    return { ruleId: "R-TOOL-DISABLED", outcome: "abstain", reason: "Tool is enabled." };
  },
};

const R_ARGS_SCHEMA: Rule = {
  id: "R-ARGS-SCHEMA",
  enabled: true,
  evaluate(proposal, meta): RuleResult {
    if (!meta) return { ruleId: "R-ARGS-SCHEMA", outcome: "abstain", reason: "Unknown tool." };
    const parsed = meta.inputSchema.safeParse(proposal.args);
    if (!parsed.success) {
      return { ruleId: "R-ARGS-SCHEMA", outcome: "deny", reason: "Arguments do not match the tool schema." };
    }
    return { ruleId: "R-ARGS-SCHEMA", outcome: "abstain", reason: "Arguments are valid." };
  },
};

const R_PATH_SANDBOX: Rule = {
  id: "R-PATH-SANDBOX",
  enabled: true,
  evaluate(proposal, meta): RuleResult {
    if (!meta || (meta.name !== "file.read" && meta.name !== "file.write" && meta.name !== "file.list")) {
      return { ruleId: "R-PATH-SANDBOX", outcome: "abstain", reason: "Not a file operation." };
    }
    const args = proposal.args as Record<string, unknown>;
    const rawPath = args["path"] ?? args["directory"] ?? args["dir"];
    if (typeof rawPath !== "string" || rawPath.trim() === "") {
      return { ruleId: "R-PATH-SANDBOX", outcome: "deny", reason: "File path is missing or empty." };
    }
    if (!isInsideSandbox(rawPath)) {
      return { ruleId: "R-PATH-SANDBOX", outcome: "deny", reason: "Path is outside the sandbox directory." };
    }
    return { ruleId: "R-PATH-SANDBOX", outcome: "abstain", reason: "Path is inside sandbox." };
  },
};

const R_SECRET_FILE: Rule = {
  id: "R-SECRET-FILE",
  enabled: true,
  evaluate(proposal, meta): RuleResult {
    if (!meta || meta.name !== "file.read") {
      return { ruleId: "R-SECRET-FILE", outcome: "abstain", reason: "Not a file read." };
    }
    const args = proposal.args as Record<string, unknown>;
    const rawPath = typeof args["path"] === "string" ? args["path"] : "";
    if (isSecretFile(rawPath)) {
      return { ruleId: "R-SECRET-FILE", outcome: "deny", reason: "Path matches a credential file pattern." };
    }
    return { ruleId: "R-SECRET-FILE", outcome: "abstain", reason: "Path is not a known secret file." };
  },
};

const R_SENSITIVE_ACTION: Rule = {
  id: "R-SENSITIVE-ACTION",
  enabled: true,
  evaluate(proposal, meta, state): RuleResult {
    if (!meta) return { ruleId: "R-SENSITIVE-ACTION", outcome: "abstain", reason: "Unknown tool." };
    const approval = state.policy.tools[meta.name]?.approval ?? "never";
    if (approval === "always" || (ALWAYS_APPROVE.has(meta.name) && approval !== "never")) {
      return { ruleId: "R-SENSITIVE-ACTION", outcome: "require_approval", reason: "Tool always requires human approval." };
    }
    if (approval === "when_tainted" && state.tainted) {
      return {
        ruleId: "R-SENSITIVE-ACTION",
        outcome: "require_approval",
        reason: "Session is tainted by untrusted content; sensitive action requires approval.",
      };
    }
    // email.send and file.write always need approval regardless of policy default
    if (ALWAYS_APPROVE.has(meta.name)) {
      return { ruleId: "R-SENSITIVE-ACTION", outcome: "require_approval", reason: "Tool always requires human approval." };
    }
    return { ruleId: "R-SENSITIVE-ACTION", outcome: "abstain", reason: "No approval required." };
  },
};

const R_EMAIL_SEND_TAINTED: Rule = {
  id: "R-EMAIL-SEND-TAINTED",
  enabled: true,
  evaluate(proposal, meta, state): RuleResult {
    if (!meta || meta.name !== "email.send") {
      return { ruleId: "R-EMAIL-SEND-TAINTED", outcome: "abstain", reason: "Not email.send." };
    }
    if (!state.tainted) {
      return { ruleId: "R-EMAIL-SEND-TAINTED", outcome: "abstain", reason: "Session is not tainted." };
    }
    // When session is tainted, check recipient provenance
    const args = proposal.args as Record<string, unknown>;
    const to = args["to"];
    const contacts = state.policy.email.contacts.map((c) => c.address.toLowerCase());
    const allowlist = state.policy.email.recipientAllowlist.map((a) => a.toLowerCase());
    const recipients: string[] = Array.isArray(to) ? to.map(String) : typeof to === "string" ? [to] : [];
    for (const r of recipients) {
      const lower = r.toLowerCase();
      if (!contacts.includes(lower) && !allowlist.includes(lower)) {
        return {
          ruleId: "R-EMAIL-SEND-TAINTED",
          outcome: "require_approval",
          reason: "Session is tainted; recipient is not in contacts or allowlist.",
        };
      }
    }
    return { ruleId: "R-EMAIL-SEND-TAINTED", outcome: "abstain", reason: "Recipient provenance satisfied." };
  },
};

const R_WEB_DOMAIN: Rule = {
  id: "R-WEB-DOMAIN",
  enabled: true,
  evaluate(proposal, meta, state): RuleResult {
    if (!meta || meta.name !== "web.fetch") {
      return { ruleId: "R-WEB-DOMAIN", outcome: "abstain", reason: "Not web.fetch." };
    }
    const args = proposal.args as Record<string, unknown>;
    const url = typeof args["url"] === "string" ? args["url"] : "";
    if (!url) {
      return { ruleId: "R-WEB-DOMAIN", outcome: "deny", reason: "URL is missing." };
    }
    let hostname: string;
    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch {
      return { ruleId: "R-WEB-DOMAIN", outcome: "deny", reason: "URL is not valid." };
    }
    if (!url.startsWith("https://")) {
      return { ruleId: "R-WEB-DOMAIN", outcome: "deny", reason: "Only HTTPS URLs are permitted." };
    }
    const { domainAllowlist, allowUnlistedWhenUntainted } = state.policy.web;
    const allowed = domainAllowlist.map((d) => d.toLowerCase());
    if (allowed.length > 0 && !allowed.some((d) => hostname === d || hostname.endsWith("." + d))) {
      if (state.tainted && !allowUnlistedWhenUntainted) {
        return { ruleId: "R-WEB-DOMAIN", outcome: "deny", reason: "Domain is not in the allowlist and session is tainted." };
      }
      if (state.tainted) {
        return {
          ruleId: "R-WEB-DOMAIN",
          outcome: "require_approval",
          reason: "Domain is not in the allowlist; session is tainted.",
        };
      }
    }
    return { ruleId: "R-WEB-DOMAIN", outcome: "abstain", reason: "Domain is permitted." };
  },
};

const R_BUDGET: Rule = {
  id: "R-BUDGET",
  enabled: true,
  evaluate(_proposal, _meta, state): RuleResult {
    const { maxToolCalls } = state.policy.limits;
    if (state.toolCallCount >= maxToolCalls) {
      return {
        ruleId: "R-BUDGET",
        outcome: "deny",
        reason: "Session tool-call budget has been exhausted.",
      };
    }
    return { ruleId: "R-BUDGET", outcome: "abstain", reason: "Within budget." };
  },
};

const R_BUDGET_PER_STEP: Rule = {
  id: "R-BUDGET-PER-STEP",
  enabled: true,
  evaluate(proposal, _meta, state): RuleResult {
    const limit = state.policy.limits?.maxProposalsPerStep ?? 5;
    if (typeof proposal.indexInStep === "number" && proposal.indexInStep >= limit) {
      return {
        ruleId: "R-BUDGET-PER-STEP",
        outcome: "deny",
        reason: `Exceeded maximum proposals per step (${limit}).`,
      };
    }
    return { ruleId: "R-BUDGET-PER-STEP", outcome: "abstain", reason: "Within step proposal budget." };
  },
};

// ---------------------------------------------------------------------------
// Ordered rule list
// ---------------------------------------------------------------------------

/** Evaluation order matters: deny rules run before approval rules. */
export const RULES: ReadonlyArray<Rule> = [
  R_TOOL_KNOWN,         // 1. allowlist
  R_TOOL_DISABLED,      // 2. policy.tools[name].enabled
  R_ARGS_SCHEMA,        // 3. zod validation
  R_BUDGET,             // 4. session budget
  R_BUDGET_PER_STEP,    // 5. per-step proposal limit
  R_PATH_SANDBOX,       // 6. sandbox enforcement
  R_SECRET_FILE,        // 7. credential file protection
  R_SENSITIVE_ACTION,   // 8. approval gate
  R_EMAIL_SEND_TAINTED, // 9. tainted session + email recipient
  R_WEB_DOMAIN,         // 10. domain allowlist + HTTPS
];

/** All rule IDs, for test coverage assertions. */
export const RULE_IDS = RULES.map((r) => r.id);

/** Most restrictive DecisionKind wins. */
export function mostRestrictive(kinds: DecisionKind[]): DecisionKind {
  if (kinds.includes("deny")) return "deny";
  if (kinds.includes("require_approval")) return "require_approval";
  return "allow";
}
