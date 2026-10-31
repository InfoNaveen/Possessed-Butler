/**
 * src/lib/security/engine.ts
 *
 * PolicyEngine implementation. Deterministic — no LLM calls, no network.
 *
 * authorize() never throws (contract requirement from docs/handoff/dev1-to-dev2.md).
 * scan() and recordIngestion() are pure functions.
 */
import { randomUUID } from "node:crypto";
import type {
  AuthorizationDecision,
  ContentSegment,
  DecisionKind,
  InjectionSignal,
  PolicyEngine,
  RuleResult,
  SessionSecurityState,
  ToolCallProposal,
  ToolName,
  ToolRegistry,
} from "@contracts";
import { scanSegment } from "./detectors/index.js";
import { RULES, mostRestrictive } from "./rules/index.js";
import { hashArgs } from "./hash.js";

/** Policy version string stamped into every AuthorizationDecision. */
const POLICY_VERSION = "security-engine-v1.0.0";

export function createPolicyEngine(): PolicyEngine {
  return {
    /**
     * Authorize a tool-call proposal.
     * NEVER throws — any error produces a fail-safe deny decision.
     */
    authorize(
      proposal: ToolCallProposal,
      state: SessionSecurityState,
      registry: ToolRegistry,
    ): AuthorizationDecision {
      const id = randomUUID();
      const now = new Date().toISOString();

      // Fail-safe for garbage input
      if (!proposal || typeof proposal.id !== "string" || typeof proposal.sessionId !== "string") {
        return {
          id,
          proposalId: proposal?.id ?? "unknown",
          sessionId: proposal?.sessionId ?? "unknown",
          kind: "deny",
          tool: null,
          canonicalArgs: null,
          argsHash: null,
          ruleResults: [{ ruleId: "R-FAILSAFE", outcome: "deny", reason: "Malformed proposal." }],
          signals: [],
          policyVersion: POLICY_VERSION,
          decidedAt: now,
        };
      }

      try {
        const meta = registry.get(proposal.tool) ?? null;

        // Run all rules
        const ruleResults: RuleResult[] = [];
        for (const rule of RULES) {
          if (!rule.enabled) continue;
          try {
            ruleResults.push(rule.evaluate(proposal, meta, state, registry));
          } catch {
            ruleResults.push({
              ruleId: rule.id,
              outcome: "deny",
              reason: "Rule threw — fail safe.",
            });
          }
        }

        // Compute final verdict from non-abstain results
        const nonAbstain = ruleResults.filter((r) => r.outcome !== "abstain");
        const kinds = nonAbstain.map((r) => r.outcome as DecisionKind);
        const kind: DecisionKind = kinds.length > 0 ? mostRestrictive(kinds) : "allow";

        // Parse canonical args for the token
        let canonicalArgs: unknown = null;
        let argsHash: string | null = null;
        let toolName: ToolName | null = null;

        if (meta !== null) {
          const parsed = meta.inputSchema.safeParse(proposal.args);
          if (parsed.success) {
            canonicalArgs = parsed.data;
            try {
              argsHash = hashArgs(parsed.data);
            } catch {
              argsHash = null;
            }
            toolName = meta.name;
          }
          // If parse fails, R-ARGS-SCHEMA already produced a deny
        }

        return {
          id,
          proposalId: proposal.id,
          sessionId: proposal.sessionId,
          kind,
          tool: toolName,
          canonicalArgs,
          argsHash,
          ruleResults,
          signals: [] as InjectionSignal[],
          policyVersion: POLICY_VERSION,
          decidedAt: now,
        };
      } catch {
        // Absolute fail-safe
        return {
          id,
          proposalId: proposal.id,
          sessionId: proposal.sessionId,
          kind: "deny",
          tool: null,
          canonicalArgs: null,
          argsHash: null,
          ruleResults: [{ ruleId: "R-FAILSAFE", outcome: "deny", reason: "Engine threw an unexpected error." }],
          signals: [],
          policyVersion: POLICY_VERSION,
          decidedAt: now,
        };
      }
    },

    /**
     * Record that a ContentSegment has been ingested.
     * Returns a new (immutable) state with taint updated. Never mutates.
     */
    recordIngestion(state: SessionSecurityState, segment: ContentSegment): SessionSecurityState {
      if (!segment || segment.trust !== "untrusted") return state;

      let signals: InjectionSignal[] = [];
      try {
        signals = scanSegment(segment);
      } catch {
        signals = [];
      }

      const maxSeverity: SessionSecurityState["taintSources"][number]["maxSignalSeverity"] =
        signals.length === 0
          ? "none"
          : signals.some((s) => s.severity === "high")
            ? "high"
            : signals.some((s) => s.severity === "medium")
              ? "medium"
              : "low";

      return {
        ...state,
        tainted: true,
        taintSources: [
          ...state.taintSources,
          {
            segmentId: segment.id,
            source: segment.source,
            origin: segment.origin,
            maxSignalSeverity: maxSeverity,
          },
        ],
      };
    },

    /**
     * Scan a ContentSegment for injection signals.
     * Pure — no state mutation. Never throws.
     */
    scan(segment: ContentSegment): InjectionSignal[] {
      try {
        if (!segment) return [];
        return scanSegment(segment);
      } catch {
        return [];
      }
    },
  };
}
