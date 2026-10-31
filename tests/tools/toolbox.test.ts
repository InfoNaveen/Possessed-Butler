import { describe, expect, it } from "vitest";
import { z } from "zod";
import type { AuthorizedCall, ToolCallProposal } from "@contracts";
import { createEmailReadTools, createToolbox, defineTool, makeSegment, parseMailbox, ToolFailure } from "@/tools";
import { createSecurityDouble, testPolicy } from "../doubles/security-double";
import { testMailbox } from "../doubles/fixtures";

function setup(extra: ReturnType<typeof defineTool>[] = []) {
  const security = createSecurityDouble({ decisions: { "email.list": "allow", "email.read": "allow", "file.read": "allow" } });
  const mailbox = testMailbox();
  const box = createToolbox([...createEmailReadTools(() => mailbox), ...extra], {
    authority: security.authority,
    hashArgs: security.hashArgs,
    audit: security.audit,
  });
  const state = {
    sessionId: "s1", tainted: false, taintSources: [], trustedInstructions: [], toolCallCount: 0, stepCount: 1, policy: testPolicy(),
  };
  const authorize = (tool: string, args: unknown) => {
    const proposal: ToolCallProposal = { id: crypto.randomUUID(), sessionId: "s1", step: 1, indexInStep: 0, tool, args };
    const decision = security.engine.authorize(proposal, state, box.registry);
    return security.authority.issue(decision);
  };
  const ctx = { sessionId: "s1", signal: new AbortController().signal };
  return { ...box, security, authorize, ctx };
}

describe("makeSegment", () => {
  it("always produces untrusted segments and hashes the full text", () => {
    const s = makeSegment({ source: "email", origin: "m", text: "abcdef" }, 3);
    expect(s).toMatchObject({ trust: "untrusted", text: "abc", truncated: true });
    expect(s.sha256).toBe("bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721");
  });

  it("refuses trusted sources even through a cast", () => {
    expect(() => makeSegment({ source: "user" as never, origin: null, text: "x" })).toThrow();
    expect(() => makeSegment({ source: "system" as never, origin: null, text: "x" })).toThrow();
  });
});

describe("registry", () => {
  it("exposes metadata only, and prototype keys are not tools", () => {
    const { registry } = setup();
    expect(registry.list().map((t) => t.name)).toEqual(["email.list", "email.read"]);
    expect(registry.get("email.list")).not.toHaveProperty("run");
    for (const key of ["__proto__", "constructor", "toString", "hasOwnProperty"]) expect(registry.get(key)).toBeUndefined();
  });

  it("rejects unknown or duplicate definitions", () => {
    const security = createSecurityDouble();
    const deps = { authority: security.authority, hashArgs: security.hashArgs, audit: security.audit };
    const bogus = defineTool({ name: "shell.exec" as never, description: "", sensitivity: "read", producesUntrustedContent: true,
      inputSchema: z.strictObject({}), timeoutMs: 1, run: async () => ({ segments: [], summary: "" }) });
    expect(() => createToolbox([bogus], deps)).toThrow();
    const [list] = createEmailReadTools(() => testMailbox());
    expect(() => createToolbox([list, list], deps)).toThrow();
  });
});

describe("executor", () => {
  it("runs an authorized call and returns untrusted email segments", async () => {
    const { executor, authorize, ctx } = setup();
    const res = await executor.execute(authorize("email.list", { unreadOnly: true }), ctx);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.segments.map((s) => s.origin)).toEqual(["msg-2", "msg-1"]);
    expect(res.segments.every((s) => s.trust === "untrusted" && s.source === "email")).toBe(true);
  });

  it("refuses a replayed token", async () => {
    const { executor, authorize, ctx } = setup();
    const call = authorize("email.list", {});
    expect((await executor.execute(call, ctx)).ok).toBe(true);
    const again = await executor.execute(call, ctx);
    expect(!again.ok && again.error.code).toBe("UNAUTHORIZED");
  });

  it("refuses a forged token", async () => {
    const { executor, ctx, security } = setup();
    const forged: AuthorizedCall = {
      decisionId: "d", proposalId: "p", sessionId: "s1", tool: "email.list", args: {}, argsHash: security.hashArgs({}),
      approvalId: null, issuedAt: "", expiresAt: "2999-01-01T00:00:00Z", signature: "x",
    };
    const res = await executor.execute(forged, ctx);
    expect(!res.ok && res.error.code).toBe("UNAUTHORIZED");
    expect(security.events.at(-1)?.type).toBe("tool_failed");
  });

  it("refuses args swapped after authorization", async () => {
    const { executor, authorize, ctx } = setup();
    const call = authorize("email.read", { messageId: "msg-1" });
    (call as { args: unknown }).args = { messageId: "msg-2" };
    const res = await executor.execute(call, ctx);
    expect(!res.ok && res.error.code).toBe("UNAUTHORIZED");
  });

  it("refuses a token used in a different session", async () => {
    const { executor, authorize } = setup();
    const res = await executor.execute(authorize("email.list", {}), { sessionId: "other", signal: new AbortController().signal });
    expect(!res.ok && res.error.code).toBe("UNAUTHORIZED");
  });

  it("maps tool failures and timeouts to fixed messages", async () => {
    const slow = defineTool({ name: "file.read", description: "slow", sensitivity: "read", producesUntrustedContent: true,
      inputSchema: z.strictObject({ path: z.string() }), timeoutMs: 20,
      run: () => new Promise(() => {}) });
    const { executor, authorize, ctx } = setup([slow]);
    const missing = await executor.execute(authorize("email.read", { messageId: "nope" }), ctx);
    expect(!missing.ok && missing.error).toEqual({ code: "NOT_FOUND", message: "Requested item was not found." });
    const timedOut = await executor.execute(authorize("file.read", { path: "a.txt" }), ctx);
    expect(!timedOut.ok && timedOut.error.code).toBe("TIMEOUT");
  });

  it("maps unexpected throws to INTERNAL without leaking the message", async () => {
    const boom = defineTool({ name: "file.read", description: "boom", sensitivity: "read", producesUntrustedContent: true,
      inputSchema: z.strictObject({}), timeoutMs: 1000,
      run: async () => { throw new Error("secret path C:\\keys"); } });
    const { executor, authorize, ctx } = setup([boom]);
    const res = await executor.execute(authorize("file.read", {}), ctx);
    expect(!res.ok && res.error).toEqual({ code: "INTERNAL", message: "Tool failed." });
    expect(ToolFailure).toBeDefined();
  });
});

describe("mailbox fixture validation", () => {
  it("rejects bad ids, duplicate ids and unknown keys", () => {
    const base = testMailbox();
    const msg = base.messages[0];
    expect(() => parseMailbox({ ...base, messages: [{ ...msg, id: "../x" }] })).toThrow();
    expect(() => parseMailbox({ ...base, messages: [msg, msg] })).toThrow();
    expect(() => parseMailbox({ ...base, extra: true })).toThrow();
  });
});
