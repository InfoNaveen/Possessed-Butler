/**
 * src/lib/security/index.ts
 *
 * Public surface of the security-engine module.
 *
 * Exports the wiring factory `createSecurity()` that Dev 1's agent and
 * tool executor consume, plus standalone utilities.
 *
 * Per docs/handoff/dev1-to-dev2.md:
 *   - createSecurity() → { engine, authority, approvals }
 *   - createAuditLog(dir) → AuditLog
 *   - loadPolicy(path) → Policy
 *   - hashArgs(args) → string  (canonical JSON sha256, no prefix)
 */
import type {
  ApprovalStore,
  AuditLog,
  AuthorizationDecision,
  CallAuthority,
  ContentSegment,
  InjectionSignal,
  Policy,
  PolicyEngine,
  SessionSecurityState,
  ToolCallProposal,
  ToolRegistry,
} from "@contracts";
import { createPolicyEngine } from "./engine.js";
import { createCallAuthority, hasRegister } from "./authority.js";
import { createApprovalStore } from "./approvals.js";
import { createAuditLog as _createAuditLog, createMemoryAuditLog } from "./audit.js";
import { loadPolicy as _loadPolicy, defaultPolicy } from "./policy.js";

export { hashArgs } from "./hash.js";
export { defaultPolicy } from "./policy.js";
export { createMemoryAuditLog } from "./audit.js";
export { AuditWriteError } from "./audit.js";
export { scanSegment, containsEmbeddedToolCall, DETECTOR_IDS } from "./detectors/index.js";
export { RULES, RULE_IDS } from "./rules/index.js";

export interface SecurityBundle {
  engine: PolicyEngine;
  authority: CallAuthority;
  approvals: ApprovalStore;
}

/**
 * Creates a fully wired security bundle.
 *
 * The returned engine has its decisions automatically registered with the
 * authority (so `authority.issue()` works). This is transparent to callers.
 */
export function createSecurity(approvalTtlMs?: number): SecurityBundle {
  const baseEngine = createPolicyEngine();
  const authority = createCallAuthority();
  const approvals = createApprovalStore(approvalTtlMs);

  // Wrap the engine so every AuthorizationDecision is registered with the authority.
  const engine: PolicyEngine = {
    authorize(proposal: ToolCallProposal, state: SessionSecurityState, registry: ToolRegistry): AuthorizationDecision {
      const decision = baseEngine.authorize(proposal, state, registry);
      if (hasRegister(authority)) {
        authority._register(decision);
      }
      return decision;
    },
    recordIngestion: baseEngine.recordIngestion.bind(baseEngine),
    scan: baseEngine.scan.bind(baseEngine),
  };

  return { engine, authority, approvals };
}

/** Creates the file-backed AuditLog. */
export function createAuditLog(dir: string): AuditLog {
  return _createAuditLog(dir);
}

/** Loads a Policy from a JSON file. */
export function loadPolicy(filePath: string): Policy {
  return _loadPolicy(filePath);
}

/**
 * Creates an initial SessionSecurityState from a session ID and policy.
 * Convenience helper mentioned in dev1-to-dev2.md.
 */
export function createSessionSecurityState(
  sessionId: string,
  policy: Policy,
): SessionSecurityState {
  return {
    sessionId,
    tainted: false,
    taintSources: [],
    trustedInstructions: [],
    toolCallCount: 0,
    stepCount: 0,
    policy,
  };
}
