/**
 * tests/security/approvals.test.ts
 *
 * ApprovalStore contract compliance tests.
 */
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { AuthorizationDecision, ToolMetadata, ToolRegistry } from "@contracts";
import { TOOL_NAMES } from "@contracts";
import { createSecurity } from "@/lib/security/index.js";
import { testPolicy } from "../doubles/security-double.js";

function makeRegistry(): ToolRegistry {
  const map = new Map<string, ToolMetadata>();
  for (const name of TOOL_NAMES) {
    map.set(name, {
      name,
      description: `Mock ${name}`,
      sensitivity: name === "email.send" || name === "file.write" ? "write" : "read",
      producesUntrustedContent: false,
      inputSchema: z.object({}).passthrough(),
    });
  }
  return { list: () => [...map.values()], get: (n: string) => map.get(n) };
}

function makeState(sessionId = randomUUID()) {
  return {
    sessionId,
    tainted: false,
    taintSources: [],
    trustedInstructions: [],
    toolCallCount: 0,
    stepCount: 0,
    policy: testPolicy(),
  };
}

function getSendDecision(security: ReturnType<typeof createSecurity>): AuthorizationDecision {
  const registry = makeRegistry();
  const state = makeState();
  const proposal = { id: randomUUID(), sessionId: state.sessionId, step: 1, indexInStep: 0, tool: "email.send", args: {} };
  return security.engine.authorize(proposal, state, registry);
}

describe("approvals.create", () => {
  it("creates a pending approval for a require_approval decision", () => {
    const security = createSecurity();
    const decision = getSendDecision(security);
    expect(decision.kind).toBe("require_approval");
    const approval = security.approvals.create(decision);
    expect(approval.status).toBe("pending");
    expect(approval.decisionId).toBe(decision.id);
    expect(approval.tool).toBe("email.send");
  });

  it("throws for a non-require_approval decision", () => {
    const security = createSecurity();
    const registry = makeRegistry();
    const state = makeState();
    const allowDecision = security.engine.authorize(
      { id: randomUUID(), sessionId: state.sessionId, step: 1, indexInStep: 0, tool: "email.read", args: {} },
      state,
      registry,
    );
    expect(allowDecision.kind).toBe("allow");
    expect(() => security.approvals.create(allowDecision)).toThrow();
  });
});

describe("approvals.resolve", () => {
  it("transitions pending → approved on approve", () => {
    const security = createSecurity();
    const decision = getSendDecision(security);
    const approval = security.approvals.create(decision);
    const resolved = security.approvals.resolve(approval.id, "approve");
    expect(resolved.status).toBe("approved");
    expect(resolved.resolvedAt).not.toBeNull();
  });

  it("transitions pending → rejected on reject", () => {
    const security = createSecurity();
    const decision = getSendDecision(security);
    const approval = security.approvals.create(decision);
    const resolved = security.approvals.resolve(approval.id, "reject");
    expect(resolved.status).toBe("rejected");
  });

  it("throws INVALID_TRANSITION when resolving an already-resolved approval", () => {
    const security = createSecurity();
    const decision = getSendDecision(security);
    const approval = security.approvals.create(decision);
    security.approvals.resolve(approval.id, "approve");
    expect(() => security.approvals.resolve(approval.id, "reject")).toThrow();
  });
});

describe("approvals.markConsumed", () => {
  it("transitions approved → consumed", () => {
    const security = createSecurity();
    const decision = getSendDecision(security);
    const approval = security.approvals.create(decision);
    security.approvals.resolve(approval.id, "approve");
    security.approvals.markConsumed(approval.id);
    const stored = security.approvals.get(approval.id);
    expect(stored?.status).toBe("consumed");
  });

  it("throws INVALID_TRANSITION when approval is not approved", () => {
    const security = createSecurity();
    const decision = getSendDecision(security);
    const approval = security.approvals.create(decision);
    expect(() => security.approvals.markConsumed(approval.id)).toThrow();
  });
});

describe("approvals.listPending", () => {
  it("returns only pending approvals for the given session", () => {
    const security = createSecurity();
    const registry = makeRegistry();
    const s1 = makeState();
    const s2 = makeState();

    const d1 = security.engine.authorize(
      { id: randomUUID(), sessionId: s1.sessionId, step: 1, indexInStep: 0, tool: "email.send", args: {} },
      s1, registry,
    );
    const d2 = security.engine.authorize(
      { id: randomUUID(), sessionId: s2.sessionId, step: 1, indexInStep: 0, tool: "email.send", args: {} },
      s2, registry,
    );

    security.approvals.create(d1);
    security.approvals.create(d2);

    const pending = security.approvals.listPending(s1.sessionId);
    expect(pending).toHaveLength(1);
    expect(pending[0]?.sessionId).toBe(s1.sessionId);
  });
});
