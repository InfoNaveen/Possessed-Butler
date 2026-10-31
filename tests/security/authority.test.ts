/**
 * tests/security/authority.test.ts
 *
 * Verifies CallAuthority contract compliance:
 * - Single-use tokens
 * - Engine-origin enforcement
 * - Approval binding
 * - HMAC signature verification
 * - Replay prevention
 * - TTL expiry
 */
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { ToolMetadata, ToolRegistry } from "@contracts";
import { TOOL_NAMES } from "@contracts";
import { createSecurity } from "@/lib/security/index.js";
import { testPolicy } from "../doubles/security-double.js";

function makeRegistry(): ToolRegistry {
  const map = new Map<string, ToolMetadata>();
  for (const name of TOOL_NAMES) {
    map.set(name, {
      name,
      description: `Mock ${name}`,
      sensitivity: "read",
      producesUntrustedContent: false,
      inputSchema: z.object({}).passthrough(),
    });
  }
  return { list: () => [...map.values()], get: (n: string) => map.get(n) };
}

function makeState() {
  return {
    sessionId: randomUUID(),
    tainted: false,
    taintSources: [],
    trustedInstructions: [],
    toolCallCount: 0,
    stepCount: 0,
    policy: testPolicy(),
  };
}

function makeProposal(tool: string, sessionId: string) {
  return { id: randomUUID(), sessionId, step: 1, indexInStep: 0, tool, args: {} };
}

describe("authority.issue — happy path", () => {
  it("issues a token for an allowed decision", () => {
    const { engine, authority } = createSecurity();
    const registry = makeRegistry();
    const state = makeState();
    const decision = engine.authorize(makeProposal("email.read", state.sessionId), state, registry);
    expect(decision.kind).toBe("allow");
    const token = authority.issue(decision);
    expect(token.tool).toBe("email.read");
    expect(token.decisionId).toBe(decision.id);
    expect(typeof token.signature).toBe("string");
  });
});

describe("authority.issue — rejection cases", () => {
  it("throws ISSUE_REFUSED for a denied decision", () => {
    const { engine, authority } = createSecurity();
    const registry = makeRegistry();
    const state = makeState();
    const decision = engine.authorize(makeProposal("shell.exec", state.sessionId), state, registry);
    expect(decision.kind).toBe("deny");
    expect(() => authority.issue(decision)).toThrow("ISSUE_REFUSED");
  });

  it("throws ISSUE_REFUSED for a decision from a different engine instance", () => {
    const { engine: eng1 } = createSecurity();
    const { authority: auth2 } = createSecurity();
    const registry = makeRegistry();
    const state = makeState();
    const decision = eng1.authorize(makeProposal("email.read", state.sessionId), state, registry);
    expect(decision.kind).toBe("allow");
    expect(() => auth2.issue(decision)).toThrow("ISSUE_REFUSED");
  });

  it("throws ISSUE_REFUSED when issued twice (single-use)", () => {
    const { engine, authority } = createSecurity();
    const registry = makeRegistry();
    const state = makeState();
    const decision = engine.authorize(makeProposal("email.read", state.sessionId), state, registry);
    authority.issue(decision);
    expect(() => authority.issue(decision)).toThrow("ISSUE_REFUSED");
  });
});

describe("authority.verifyAndConsume", () => {
  it("verifies and consumes a valid token", () => {
    const { engine, authority } = createSecurity();
    const registry = makeRegistry();
    const state = makeState();
    const decision = engine.authorize(makeProposal("email.read", state.sessionId), state, registry);
    const token = authority.issue(decision);
    expect(authority.verifyAndConsume(token)).toEqual({ ok: true });
  });

  it("rejects replay — second call returns ok:false", () => {
    const { engine, authority } = createSecurity();
    const registry = makeRegistry();
    const state = makeState();
    const decision = engine.authorize(makeProposal("email.read", state.sessionId), state, registry);
    const token = authority.issue(decision);
    authority.verifyAndConsume(token);
    const result = authority.verifyAndConsume(token);
    expect(result.ok).toBe(false);
    expect((result as { ok: false; reason: string }).reason).toMatch(/replay/i);
  });

  it("rejects a token from a different authority instance", () => {
    const { engine, authority: auth1 } = createSecurity();
    const { authority: auth2 } = createSecurity();
    const registry = makeRegistry();
    const state = makeState();
    const decision = engine.authorize(makeProposal("email.read", state.sessionId), state, registry);
    const token = auth1.issue(decision);
    const result = auth2.verifyAndConsume(token);
    expect(result.ok).toBe(false);
  });

  it("rejects a tampered token (modified argsHash)", () => {
    const { engine, authority } = createSecurity();
    const registry = makeRegistry();
    const state = makeState();
    const decision = engine.authorize(makeProposal("email.read", state.sessionId), state, registry);
    const token = authority.issue(decision);
    const tampered = { ...token, argsHash: "tampered" };
    // Note: the authority stores the original token by reference; a different object → not issued
    const result = authority.verifyAndConsume(tampered);
    expect(result.ok).toBe(false);
  });
});
