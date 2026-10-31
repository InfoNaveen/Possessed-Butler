/**
 * src/lib/security/index.ts
 *
 * Public surface of the security-engine module.
 *
 * Exports the wiring factory `createSecurity()` that Dev 1's agent and
 * tool executor consume, plus standalone utilities.
 *
 * Per docs/handoff/dev1-to-dev2.md:
 *   - createSecurity() â†’ { engine, authority, approvals }
 *   - createAuditLog(dir) â†’ AuditLog
 *   - loadPolicy(path) â†’ Policy
 *   - hashArgs(args) â†’ string  (canonical JSON sha256, no prefix)
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
import { createPolicyEngine } from "./engine";
import { createCallAuthority, hasRegister } from "./authority";
import { createApprovalStore } from "./approvals";
import { createAuditLog as _createAuditLog, createMemoryAuditLog } from "./audit";
import { loadPolicy as _loadPolicy, defaultPolicy } from "./policy";

export { hashArgs } from "./hash";
export { defaultPolicy } from "./policy";
export { createMemoryAuditLog } from "./audit";
export { AuditWriteError } from "./audit";
export { scanSegment, containsEmbeddedToolCall, DETECTOR_IDS } from "./detectors/index";
export { RULES, RULE_IDS } from "./rules/index";

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
