/**
 * src/lib/security/approvals.ts
 *
 * In-memory ApprovalStore implementation.
 * Approvals expire after APPROVAL_TTL_MS and cannot be resolved after expiry.
 */
import { randomUUID } from "node:crypto";
import type {
  ApprovalRequest,
  ApprovalStore,
  ApprovalStatus,
  AuthorizationDecision,
} from "@contracts";

/** Default approval TTL: 10 minutes. */
const APPROVAL_TTL_MS = 10 * 60 * 1_000;

interface Entry {
  req: ApprovalRequest;
  decision: AuthorizationDecision;
}

export function createApprovalStore(ttlMs = APPROVAL_TTL_MS): ApprovalStore {
  const store = new Map<string, Entry>();

  function snapshot(entry: Entry): ApprovalRequest {
    return { ...entry.req };
  }

  return {
    create(decision: AuthorizationDecision): ApprovalRequest {
      if (decision.kind !== "require_approval" || !decision.tool || !decision.argsHash) {
        throw new Error("Cannot create approval for a non-require_approval decision.");
      }
      const now = Date.now();
      const req: ApprovalRequest = {
        id: randomUUID(),
        sessionId: decision.sessionId,
        proposalId: decision.proposalId,
        decisionId: decision.id,
        tool: decision.tool,
        args: decision.canonicalArgs,
        argsHash: decision.argsHash,
        reasons: decision.ruleResults
          .filter((r) => r.outcome === "require_approval")
          .map((r) => r.reason),
        status: "pending" as ApprovalStatus,
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + ttlMs).toISOString(),
        resolvedAt: null,
      };
      store.set(req.id, { req, decision });
      return snapshot({ req, decision });
    },

    get(id: string): ApprovalRequest | undefined {
      const entry = store.get(id);
      return entry ? snapshot(entry) : undefined;
    },

    listPending(sessionId?: string): ApprovalRequest[] {
      return [...store.values()]
        .map((e) => e.req)
        .filter((r) => r.status === "pending" && (!sessionId || r.sessionId === sessionId));
    },

    resolve(id: string, verdict: "approve" | "reject"): ApprovalRequest {
      const entry = store.get(id);
      if (!entry) throw new Error("INVALID_TRANSITION: approval not found");
      if (entry.req.status !== "pending") throw new Error("INVALID_TRANSITION: not pending");
      if (Date.parse(entry.req.expiresAt) < Date.now()) {
        entry.req.status = "expired";
        throw new Error("INVALID_TRANSITION: approval has expired");
      }
      entry.req.status = verdict === "approve" ? "approved" : "rejected";
      entry.req.resolvedAt = new Date().toISOString();
      return snapshot(entry);
    },

    decisionFor(id: string): AuthorizationDecision | undefined {
      return store.get(id)?.decision;
    },

    markConsumed(id: string): void {
      const entry = store.get(id);
      if (!entry || entry.req.status !== "approved") {
        throw new Error("INVALID_TRANSITION: approval is not in approved state");
      }
      entry.req.status = "consumed";
    },
  };
}
