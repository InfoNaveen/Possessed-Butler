/**
 * TEST DOUBLE ONLY. Not security logic and never imported from src/.
 *
 * Implements the security-engine contracts with the smallest behaviour agent-core and the
 * tool executor need to be tested before Developer 2's engine lands. Decisions are set
 * explicitly per tool by each test (default: deny). It also enforces the contract-level
 * guarantees the agent relies on (single-use tokens, engine-issued decisions only,
 * approval/argsHash binding) so tests fail if agent code tries to bypass them.
 */
import { createHash, randomUUID } from "node:crypto";
import type {
  ApprovalRequest,
  ApprovalStore,
  AuditEvent,
  AuditLog,
  AuthorizationDecision,
  AuthorizedCall,
  CallAuthority,
  DecisionKind,
  Policy,
  PolicyEngine,
  ToolName,
} from "@contracts";
import { TOOL_NAMES } from "@contracts";

/** Test hash: sha256 of JSON with sorted keys. The real one is security-engine's canonicalJson. */
export function testHashArgs(value: unknown): string {
  const canon = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(canon);
    if (v && typeof v === "object") {
      return Object.fromEntries(
        Object.keys(v as object)
          .sort()
          .map((k) => [k, canon((v as Record<string, unknown>)[k])]),
      );
    }
    return v;
  };
  return createHash("sha256").update(JSON.stringify(canon(value) ?? null)).digest("hex");
}

export function testPolicy(overrides: Partial<Policy["limits"]> = {}): Policy {
  return {
    version: "test-1",
    tools: Object.fromEntries(TOOL_NAMES.map((n) => [n, { enabled: true, approval: "never" }])) as Policy["tools"],
    email: { recipientAllowlist: [], contacts: [] },
    web: { domainAllowlist: [], allowUnlistedWhenUntainted: true },
    file: { readExtensions: [".txt"], writeExtensions: [".txt"], maxBytes: 1024 },
    limits: { maxSteps: 6, maxToolCalls: 10, maxProposalsPerStep: 3, ...overrides },
  };
}

export interface SecurityDoubleOptions {
  decisions?: Partial<Record<ToolName, DecisionKind>>;
  /** Make the audit log throw on the n-th append (1-based). */
  failAuditOnAppend?: number;
  approvalTtlMs?: number;
}

export function createSecurityDouble(opts: SecurityDoubleOptions = {}) {
  const issuedDecisions = new WeakSet<AuthorizationDecision>();
  const issuedTokens = new Map<string, AuthorizedCall>(); // decisionId → token object
  const consumed = new Set<string>();
  const approvalsMap = new Map<string, { req: ApprovalRequest; decision: AuthorizationDecision }>();
  const events: AuditEvent[] = [];
  const calls = { authorize: 0, issue: 0, verify: 0 };
  let appendCount = 0;

  const engine: PolicyEngine = {
    authorize(proposal, state, registry) {
      calls.authorize++;
      const meta = registry.get(proposal.tool);
      const base = {
        id: randomUUID(),
        proposalId: proposal.id,
        sessionId: proposal.sessionId,
        signals: [],
        policyVersion: state.policy.version,
        decidedAt: new Date().toISOString(),
      };
      let decision: AuthorizationDecision;
      if (!meta) {
        decision = { ...base, kind: "deny", tool: null, canonicalArgs: null, argsHash: null,
          ruleResults: [{ ruleId: "R-TOOL-KNOWN", outcome: "deny", reason: "unknown tool" }] };
      } else {
        const parsed = meta.inputSchema.safeParse(proposal.args);
        if (!parsed.success) {
          decision = { ...base, kind: "deny", tool: meta.name, canonicalArgs: null, argsHash: null,
            ruleResults: [{ ruleId: "R-ARGS-SCHEMA", outcome: "deny", reason: "invalid args" }] };
        } else {
          const kind = opts.decisions?.[meta.name] ?? "deny";
          decision = { ...base, kind, tool: meta.name, canonicalArgs: parsed.data, argsHash: testHashArgs(parsed.data),
            ruleResults: [{ ruleId: "R-TEST-DOUBLE", outcome: kind, reason: "configured by test" }] };
        }
      }
      issuedDecisions.add(decision);
      return decision;
    },
    recordIngestion(state, segment) {
      if (segment.trust !== "untrusted") return state;
      return {
        ...state,
        tainted: true,
        taintSources: [...state.taintSources,
          { segmentId: segment.id, source: segment.source, origin: segment.origin, maxSignalSeverity: "none" }],
      };
    },
    scan: () => [],
  };

  const authority: CallAuthority = {
    issue(decision, approval) {
      calls.issue++;
      if (!issuedDecisions.has(decision)) throw new Error("ISSUE_REFUSED: decision not from engine");
      if (decision.tool === null || decision.argsHash === null) throw new Error("ISSUE_REFUSED: no tool");
      if (decision.kind === "deny") throw new Error("ISSUE_REFUSED: denied");
      if (decision.kind === "require_approval") {
        if (!approval || approval.status !== "approved" || approval.decisionId !== decision.id ||
            approval.argsHash !== decision.argsHash) throw new Error("ISSUE_REFUSED: approval");
      }
      if (issuedTokens.has(decision.id)) throw new Error("ISSUE_REFUSED: already issued");
      const now = Date.now();
      const token: AuthorizedCall = {
        decisionId: decision.id, proposalId: decision.proposalId, sessionId: decision.sessionId,
        tool: decision.tool, args: decision.canonicalArgs, argsHash: decision.argsHash,
        approvalId: approval?.id ?? null, issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 60_000).toISOString(), signature: "test-double",
      };
      issuedTokens.set(decision.id, token);
      return token;
    },
    verifyAndConsume(call) {
      calls.verify++;
      const original = issuedTokens.get(call?.decisionId);
      if (!original || original !== call) return { ok: false, reason: "not issued" };
      if (consumed.has(call.decisionId)) return { ok: false, reason: "replay" };
      if (Date.parse(call.expiresAt) < Date.now()) return { ok: false, reason: "expired" };
      consumed.add(call.decisionId);
      return { ok: true };
    },
  };

  const approvals: ApprovalStore = {
    create(decision) {
      if (decision.kind !== "require_approval" || !decision.tool || !decision.argsHash) throw new Error("bad decision");
      const now = Date.now();
      const req: ApprovalRequest = {
        id: randomUUID(), sessionId: decision.sessionId, proposalId: decision.proposalId, decisionId: decision.id,
        tool: decision.tool, args: decision.canonicalArgs, argsHash: decision.argsHash, reasons: ["configured by test"],
        status: "pending", createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + (opts.approvalTtlMs ?? 600_000)).toISOString(), resolvedAt: null,
      };
      approvalsMap.set(req.id, { req, decision });
      return { ...req };
    },
    get: (id) => (approvalsMap.has(id) ? { ...approvalsMap.get(id)!.req } : undefined),
    listPending: (sessionId) =>
      [...approvalsMap.values()].map((x) => x.req)
        .filter((r) => r.status === "pending" && (!sessionId || r.sessionId === sessionId)),
    resolve(id, verdict) {
      const entry = approvalsMap.get(id);
      if (!entry || entry.req.status !== "pending") throw new Error("INVALID_TRANSITION");
      if (Date.parse(entry.req.expiresAt) < Date.now()) {
        entry.req.status = "expired";
        throw new Error("INVALID_TRANSITION: expired");
      }
      entry.req.status = verdict === "approve" ? "approved" : "rejected";
      entry.req.resolvedAt = new Date().toISOString();
      return { ...entry.req };
    },
    decisionFor: (id) => approvalsMap.get(id)?.decision,
    markConsumed(id) {
      const entry = approvalsMap.get(id);
      if (!entry || entry.req.status !== "approved") throw new Error("INVALID_TRANSITION");
      entry.req.status = "consumed";
    },
  };

  const audit: AuditLog = {
    append(event) {
      appendCount++;
      if (opts.failAuditOnAppend !== undefined && appendCount >= opts.failAuditOnAppend) {
        throw new Error("AUDIT_WRITE_FAILED");
      }
      const full: AuditEvent = { ...event, id: randomUUID(), ts: new Date().toISOString() };
      events.push(full);
      return full;
    },
    list: (sessionId) => events.filter((e) => e.sessionId === sessionId),
  };

  return { engine, authority, approvals, audit, events, calls, hashArgs: testHashArgs };
}
