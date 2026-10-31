/**
 * src/lib/security/authority.ts
 *
 * CallAuthority implementation.
 *
 * Issues signed capability tokens (AuthorizedCall) for approved decisions.
 * Enforces:
 * - Single-use tokens (one token per decisionId, consumed on verifyAndConsume)
 * - Engine-origin enforcement (only decisions produced by THIS engine instance are accepted)
 * - Approval binding (require_approval decisions need a matching approved ApprovalRequest)
 * - Short TTL (tokens expire after TOKEN_TTL_MS)
 * - Replay prevention (consumed tokens cannot be re-used)
 * - HMAC-SHA256 signature with a random per-process key (per D3 in docs/contracts.md)
 */
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import type {
  ApprovalRequest,
  AuthorizationDecision,
  AuthorizedCall,
  CallAuthority,
} from "@contracts";

/** Token TTL: 60 seconds. */
const TOKEN_TTL_MS = 60_000;

/** Random per-process signing key — prevents forgery across restarts. */
function generateSigningKey(): Buffer {
  return randomBytes(32);
}

function signToken(key: Buffer, token: Omit<AuthorizedCall, "signature">): string {
  const payload = JSON.stringify({
    decisionId: token.decisionId,
    proposalId: token.proposalId,
    sessionId: token.sessionId,
    tool: token.tool,
    argsHash: token.argsHash,
    issuedAt: token.issuedAt,
    expiresAt: token.expiresAt,
  });
  return createHmac("sha256", key).update(payload).digest("hex");
}

export function createCallAuthority(): CallAuthority {
  const signingKey = generateSigningKey();

  // Track decisions this authority has seen (weak — GC'd when decision is GC'd)
  const issuedDecisions = new WeakSet<AuthorizationDecision>();
  // decisionId → issued token (strong reference until consumed)
  const issuedTokens = new Map<string, AuthorizedCall>();
  const consumed = new Set<string>();

  /**
   * Registers a decision as engine-produced.
   * The engine must call this after authorize() so the authority can verify provenance.
   */
  function registerDecision(decision: AuthorizationDecision): void {
    issuedDecisions.add(decision);
  }

  const authority: CallAuthority & { _register: typeof registerDecision } = {
    _register: registerDecision,

    issue(decision: AuthorizationDecision, approval?: ApprovalRequest): AuthorizedCall {
      // Engine-origin check
      if (!issuedDecisions.has(decision)) {
        throw new Error("ISSUE_REFUSED: decision was not produced by this engine");
      }
      // Unknown tool or invalid args
      if (decision.tool === null || decision.argsHash === null || decision.canonicalArgs === null) {
        throw new Error("ISSUE_REFUSED: decision has no valid tool or args hash");
      }
      // Denied decisions cannot be issued
      if (decision.kind === "deny") {
        throw new Error("ISSUE_REFUSED: decision was denied");
      }
      // Require approval — need a valid, approved, matching approval
      if (decision.kind === "require_approval") {
        if (
          !approval ||
          approval.status !== "approved" ||
          approval.decisionId !== decision.id ||
          approval.argsHash !== decision.argsHash
        ) {
          throw new Error("ISSUE_REFUSED: approval is missing, invalid, or does not match this decision");
        }
      }
      // Single-use enforcement
      if (issuedTokens.has(decision.id)) {
        throw new Error("ISSUE_REFUSED: token already issued for this decision");
      }

      const now = Date.now();
      const tokenBase: Omit<AuthorizedCall, "signature"> = {
        decisionId: decision.id,
        proposalId: decision.proposalId,
        sessionId: decision.sessionId,
        tool: decision.tool,
        args: decision.canonicalArgs,
        argsHash: decision.argsHash,
        approvalId: approval?.id ?? null,
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + TOKEN_TTL_MS).toISOString(),
      };

      const token: AuthorizedCall = {
        ...tokenBase,
        signature: signToken(signingKey, tokenBase),
      };

      issuedTokens.set(decision.id, token);
      return token;
    },

    verifyAndConsume(call: AuthorizedCall): { ok: true } | { ok: false; reason: string } {
      if (!call?.decisionId) return { ok: false, reason: "invalid token shape" };

      const original = issuedTokens.get(call.decisionId);
      if (!original) return { ok: false, reason: "not issued by this authority" };
      // Identity check — must be the exact same object reference
      if (original !== call) return { ok: false, reason: "token object does not match issued token" };

      // Replay check
      if (consumed.has(call.decisionId)) return { ok: false, reason: "token already consumed (replay)" };

      // TTL check
      if (Date.parse(call.expiresAt) < Date.now()) return { ok: false, reason: "token expired" };

      // Signature re-verification
      const { signature, ...rest } = call;
      const expected = signToken(signingKey, rest);
      if (signature !== expected) return { ok: false, reason: "signature invalid" };

      consumed.add(call.decisionId);
      return { ok: true };
    },
  };

  return authority;
}

/**
 * Type-narrowing helper: returns true if the authority has the internal _register method.
 * Used by createSecurity() to wire the engine's registerDecision.
 */
export function hasRegister(
  auth: CallAuthority,
): auth is CallAuthority & { _register: (d: AuthorizationDecision) => void } {
  return typeof (auth as unknown as Record<string, unknown>)["_register"] === "function";
}
