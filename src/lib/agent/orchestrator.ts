import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  ProviderError,
  TOOL_NAMES,
  type AgentTurnResult,
  type ApprovalRequest,
  type ApprovalStore,
  type AuditEventType,
  type AuditLog,
  type AuthorizationDecision,
  type CallAuthority,
  type LLMProvider,
  type Policy,
  type PolicyEngine,
  type SessionSecurityState,
  type SessionStatus,
  type ToolCallProposal,
  type ToolExecutor,
  type ToolName,
  type ToolRegistry,
} from "@contracts";
import { notices } from "./notices";
import { parseModelAction } from "./parse";
import { buildRequest, type TranscriptEntry } from "./prompt";

export const MAX_USER_MESSAGE_CHARS = 4_000;

export interface AgentSettings {
  providerTimeoutMs: number;
  maxOutputTokens: number;
  maxInvalidOutputRetries: number;
  toolTimeoutMs: number;
}

const DEFAULT_SETTINGS: AgentSettings = {
  providerTimeoutMs: 30_000,
  maxOutputTokens: 1_024,
  maxInvalidOutputRetries: 1,
  toolTimeoutMs: 60_000,
};

/**
 * Everything the agent needs, injected. Security decisions come only from `engine`,
 * `authority` and `approvals` (security-engine); the agent contains no policy logic.
 */
export interface AgentDeps {
  provider: LLMProvider;
  engine: PolicyEngine;
  authority: CallAuthority;
  approvals: ApprovalStore;
  audit: AuditLog;
  registry: ToolRegistry;
  executor: ToolExecutor;
  policy: Policy;
  settings?: Partial<AgentSettings>;
}

interface AgentSession {
  id: string;
  status: SessionStatus;
  nonce: string;
  transcript: TranscriptEntry[];
  security: SessionSecurityState;
  pendingApprovalId: string | null;
  turnSteps: number;
  locked: boolean;
  /** Set when the audit log failed. The session refuses all further work. */
  fatal: boolean;
  lastExecution?: {
    status: AgentTurnResult["executionStatus"];
    details?: AgentTurnResult["executionDetails"];
  };
}

export interface SessionView {
  id: string;
  status: SessionStatus;
  tainted: boolean;
  toolCallCount: number;
  pendingApprovalId: string | null;
}

export interface Agent {
  runTurn(input: { sessionId?: string; message: string }): Promise<AgentTurnResult>;
  resumeAfterApproval(approvalId: string, verdict: "approve" | "reject"): Promise<AgentTurnResult>;
  getSession(sessionId: string): SessionView | undefined;
}

/** Thrown when an audit write fails. Ends the session (security.md rule 6 / requirement 6.8). */
class AuditFailure extends Error {}

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export function createAgent(deps: AgentDeps): Agent {
  const settings: AgentSettings = { ...DEFAULT_SETTINGS, ...deps.settings };
  const sessions = new Map<string, AgentSession>();

  // ---------- helpers ----------

  function log(session: AgentSession, type: AuditEventType, data: Record<string, unknown>): void {
    try {
      deps.audit.append({ sessionId: session.id, type, data });
    } catch {
      session.fatal = true;
      throw new AuditFailure();
    }
  }

  function result(
    session: AgentSession,
    extra: {
      assistantText?: string | null;
      pendingApproval?: ApprovalRequest | null;
      error?: AgentTurnResult["error"];
      executionStatus?: AgentTurnResult["executionStatus"];
      executionDetails?: AgentTurnResult["executionDetails"];
    } = {},
  ): AgentTurnResult {
    let executionStatus = extra.executionStatus ?? session.lastExecution?.status;
    if (!executionStatus) {
      if (extra.pendingApproval || session.status === "awaiting_approval") {
        executionStatus = "APPROVAL_PENDING";
      } else if (session.status === "error" || extra.error) {
        executionStatus = "ERROR";
      } else if (session.status === "completed") {
        executionStatus = "COMPLETED";
      } else if (session.status === "running") {
        executionStatus = "RUNNING";
      } else {
        executionStatus = "IDLE";
      }
    }
    const executionDetails = extra.executionDetails ?? session.lastExecution?.details;

    return {
      sessionId: session.id,
      status: session.status,
      assistantText: extra.assistantText ?? null,
      pendingApproval: extra.pendingApproval ?? null,
      error: extra.error ?? null,
      executionStatus,
      executionDetails,
    };
  }

  function errorResult(sessionId: string, code: string, message: string): AgentTurnResult {
    return { sessionId, status: "error", assistantText: null, pendingApproval: null, error: { code, message } };
  }

  function fail(session: AgentSession, code: string, message: string): AgentTurnResult {
    session.status = "error";
    return result(session, { error: { code, message } });
  }

  function createSession(): AgentSession {
    const id = randomUUID();
    const session: AgentSession = {
      id,
      status: "idle",
      nonce: randomBytes(8).toString("hex"),
      transcript: [],
      security: {
        sessionId: id,
        tainted: false,
        taintSources: [],
        trustedInstructions: [],
        toolCallCount: 0,
        stepCount: 0,
        policy: deps.policy,
      },
      pendingApprovalId: null,
      turnSteps: 0,
      locked: false,
      fatal: false,
    };
    sessions.set(id, session);
    log(session, "session_started", { provider: deps.provider.id, model: deps.provider.model });
    return session;
  }

  /** Runs `work` holding the session lock; maps unexpected failures to a closed, error state. */
  async function guarded(session: AgentSession, work: () => Promise<AgentTurnResult>): Promise<AgentTurnResult> {
    session.locked = true;
    try {
      return await work();
    } catch (err) {
      if (err instanceof AuditFailure) {
        return fail(session, "AUDIT_FAILURE", "The audit log could not be written. This session is stopped.");
      }
      return fail(session, "INTERNAL", "The agent stopped because of an internal error. No further actions were taken.");
    } finally {
      session.locked = false;
    }
  }

  function ruleIds(decision: AuthorizationDecision): string[] {
    return decision.ruleResults.filter((r) => r.outcome !== "abstain").map((r) => r.ruleId);
  }

  // ---------- tool execution ----------

  async function executeAndIngest(
    session: AgentSession,
    decision: AuthorizationDecision,
    approval?: ApprovalRequest,
  ): Promise<void> {
    const tool = decision.tool;
    if (tool === null) {
      session.transcript.push({ kind: "notice", text: notices.denied(null, ruleIds(decision)) });
      return;
    }

    let call;
    try {
      call = deps.authority.issue(decision, approval);
    } catch {
      log(session, "tool_failed", { proposalId: decision.proposalId, tool, code: "ISSUE_REFUSED" });
      session.transcript.push({ kind: "notice", text: notices.denied(tool, ["ISSUE-REFUSED"]) });
      return;
    }
    if (approval) deps.approvals.markConsumed(approval.id);

    const toolResult = await deps.executor.execute(call, {
      sessionId: session.id,
      signal: AbortSignal.timeout(settings.toolTimeoutMs),
    });
    session.security = { ...session.security, toolCallCount: session.security.toolCallCount + 1 };

    if (!toolResult.ok) {
      session.transcript.push({ kind: "notice", text: notices.toolFailed(tool, toolResult.error.code) });
      if (tool === "email.send") {
        session.lastExecution = {
          status: "EMAIL_FAILED",
          details: { tool, summary: toolResult.error.message },
        };
      }
      return;
    }

    if (tool === "email.send") {
      session.lastExecution = {
        status: "EMAIL_SENT",
        details: { tool, summary: toolResult.summary },
      };
    }

    for (const segment of toolResult.segments) {
      // Taint before the content can reach the model. If this throws, the turn fails closed.
      session.security = deps.engine.recordIngestion(session.security, segment);
      log(session, "content_ingested", {
        segmentId: segment.id,
        source: segment.source,
        trust: segment.trust,
        origin: segment.origin,
        sha256: segment.sha256,
        length: segment.text.length,
        truncated: segment.truncated,
      });
      for (const signal of deps.engine.scan(segment)) {
        log(session, "injection_signal", { ...signal });
      }
    }
    session.transcript.push({ kind: "tool_result", tool, segments: toolResult.segments });
  }

  // ---------- main loop ----------

  async function loop(session: AgentSession): Promise<AgentTurnResult> {
    const { limits } = session.security.policy;
    let invalidOutputs = 0;

    while (session.turnSteps < limits.maxSteps) {
      session.turnSteps++;
      session.security = { ...session.security, stepCount: session.security.stepCount + 1 };
      const step = session.security.stepCount;

      const request = buildRequest({
        transcript: session.transcript,
        tools: deps.registry.list(),
        nonce: session.nonce,
        maxOutputTokens: settings.maxOutputTokens,
        timeoutMs: settings.providerTimeoutMs,
      });

      let rawText: string;
      try {
        const raw = await deps.provider.generate(request, AbortSignal.timeout(settings.providerTimeoutMs));
        rawText = raw.text;
      } catch (err) {
        const code = err instanceof ProviderError ? err.code : "UNAVAILABLE";
        log(session, "provider_error", { provider: deps.provider.id, code, step });
        return fail(session, `PROVIDER_${code}`, "The model provider failed. No action was taken in this step.");
      }

      const parsed = parseModelAction(rawText);
      if (!parsed.ok) {
        log(session, "model_output_invalid", {
          step,
          reason: parsed.reason,
          sha256: sha256(String(rawText)),
          length: String(rawText).length,
        });
        if (invalidOutputs++ < settings.maxInvalidOutputRetries) {
          session.transcript.push({ kind: "notice", text: notices.correction() });
          continue;
        }
        return fail(session, "MODEL_OUTPUT_INVALID", "The model did not return a valid response. No action was taken.");
      }

      session.transcript.push({ kind: "assistant_action", raw: rawText });
      const action = parsed.action;

      if (action.action === "final") {
        log(session, "turn_completed", { step, toolCallCount: session.security.toolCallCount });
        session.status = "completed";
        return result(session, { assistantText: action.text });
      }

      const maxProposals = session.security.policy.limits?.maxProposalsPerStep ?? 5;
      for (let i = 0; i < action.calls.length; i++) {
        const call = action.calls[i];
        if (i >= maxProposals) {
          log(session, "budget_exceeded", {
            limit: "maxProposalsPerStep",
            value: maxProposals,
            tool: call.tool,
            step,
            indexInStep: i,
          });
          const toolName: ToolName | null = (TOOL_NAMES as readonly string[]).includes(call.tool)
            ? (call.tool as ToolName)
            : null;
          session.transcript.push({
            kind: "notice",
            text: notices.denied(toolName, ["LIMIT-MAX-PROPOSALS-PER-STEP"]),
          });
          continue;
        }

        const proposal: ToolCallProposal = {
          id: randomUUID(),
          sessionId: session.id,
          step,
          indexInStep: i,
          tool: call.tool,
          args: call.args,
        };
        log(session, "tool_proposed", {
          proposalId: proposal.id,
          step,
          indexInStep: i,
          tool: proposal.tool,
          args: proposal.args,
        });

        let decision: AuthorizationDecision | null = null;
        try {
          decision = deps.engine.authorize(proposal, session.security, deps.registry);
        } catch {
          decision = null; // Contract says authorize never throws; if it does, treat as deny.
        }
        if (!decision || decision.proposalId !== proposal.id || decision.sessionId !== session.id) {
          log(session, "authz_decision", { proposalId: proposal.id, kind: "deny", ruleIds: ["AGENT-NO-VALID-DECISION"] });
          session.transcript.push({ kind: "notice", text: notices.denied(null, ["AGENT-NO-VALID-DECISION"]) });
          continue;
        }

        log(session, "authz_decision", {
          decisionId: decision.id,
          proposalId: proposal.id,
          kind: decision.kind,
          tool: decision.tool,
          argsHash: decision.argsHash,
          ruleIds: ruleIds(decision),
          reasons: decision.ruleResults.filter((r) => r.outcome !== "abstain").map((r) => r.reason),
          signalCount: decision.signals.length,
          policyVersion: decision.policyVersion,
        });

        if (decision.kind === "allow") {
          await executeAndIngest(session, decision);
          continue;
        }

        if (decision.kind === "require_approval" && decision.tool !== null) {
          let approval: ApprovalRequest;
          try {
            approval = deps.approvals.create(decision);
          } catch {
            session.transcript.push({ kind: "notice", text: notices.denied(decision.tool, ["APPROVAL-UNAVAILABLE"]) });
            continue;
          }
          log(session, "approval_requested", {
            approvalId: approval.id,
            decisionId: decision.id,
            proposalId: proposal.id,
            tool: approval.tool,
            argsHash: approval.argsHash,
            expiresAt: approval.expiresAt,
          });

          const dropped = action.calls.slice(i + 1);
          dropped.forEach((d, j) =>
            log(session, "tool_proposed", { step, indexInStep: i + 1 + j, tool: d.tool, args: d.args, dropped: true }),
          );
          if (dropped.length) session.transcript.push({ kind: "notice", text: notices.dropped() });

          session.status = "awaiting_approval";
          session.pendingApprovalId = approval.id;
          return result(session, { pendingApproval: approval });
        }

        // deny (and the impossible require_approval without a tool) end up here.
        session.transcript.push({ kind: "notice", text: notices.denied(decision.tool, ruleIds(decision)) });
      }
    }

    log(session, "budget_exceeded", { limit: "maxSteps", value: limits.maxSteps });
    session.status = "completed";
    return result(session, { assistantText: "I stopped because the step limit for this task was reached." });
  }

  // ---------- public API ----------

  return {
    async runTurn({ sessionId, message }) {
      if (typeof message !== "string" || message.trim().length === 0 || message.length > MAX_USER_MESSAGE_CHARS) {
        return errorResult(sessionId ?? "", "INVALID_MESSAGE", "Message must be 1 to 4000 characters.");
      }

      let session: AgentSession;
      if (sessionId !== undefined) {
        const existing = sessions.get(sessionId);
        if (!existing) return errorResult(sessionId, "SESSION_NOT_FOUND", "Unknown session.");
        session = existing;
      } else {
        try {
          session = createSession();
        } catch {
          return errorResult("", "AUDIT_FAILURE", "The audit log could not be written.");
        }
      }

      if (session.fatal) return result(session, { error: { code: "SESSION_FAILED", message: "This session is stopped." } });
      if (session.locked) return result(session, { error: { code: "SESSION_BUSY", message: "A turn is already running." } });
      if (session.status === "awaiting_approval") {
        return result(session, { error: { code: "AWAITING_APPROVAL", message: "Resolve the pending approval first." } });
      }

      return guarded(session, async () => {
        session.status = "running";
        session.turnSteps = 0;
        log(session, "user_message", { text: message, length: message.length });
        session.security = {
          ...session.security,
          trustedInstructions: [...session.security.trustedInstructions, message],
        };
        session.transcript.push({ kind: "user", text: message });
        return loop(session);
      });
    },

    async resumeAfterApproval(approvalId, verdict) {
      const approval = deps.approvals.get(approvalId);
      const session = approval ? sessions.get(approval.sessionId) : undefined;
      if (!approval || !session) return errorResult("", "APPROVAL_NOT_FOUND", "Unknown approval.");
      if (approval.sessionId !== session.id) {
        return errorResult(session.id, "CROSS_SESSION_APPROVAL", "Approval does not belong to active session.");
      }
      if (session.fatal) return result(session, { error: { code: "SESSION_FAILED", message: "This session is stopped." } });
      if (session.locked) return result(session, { error: { code: "SESSION_BUSY", message: "A turn is already running." } });
      if (session.status !== "awaiting_approval" || session.pendingApprovalId !== approvalId) {
        return result(session, { error: { code: "APPROVAL_NOT_PENDING", message: "This approval is not pending." } });
      }

      return guarded(session, async () => {
        session.status = "running";
        session.pendingApprovalId = null;

        let resolved: ApprovalRequest | null = null;
        try {
          resolved = deps.approvals.resolve(approvalId, verdict);
        } catch {
          resolved = null; // e.g. expired: the store refuses the transition.
        }
        log(session, "approval_resolved", { approvalId, verdict, status: resolved?.status ?? "unavailable" });

        if (!resolved || resolved.status !== (verdict === "approve" ? "approved" : "rejected")) {
          session.transcript.push({ kind: "notice", text: notices.approvalUnavailable(approval.tool) });
        } else if (verdict === "reject") {
          session.lastExecution = {
            status: "APPROVAL_REJECTED",
            details: { tool: approval.tool, summary: "User rejected execution." },
          };
          session.transcript.push({ kind: "notice", text: notices.rejected(approval.tool) });
        } else {
          const decision = deps.approvals.decisionFor(approvalId);
          if (!decision || decision.sessionId !== session.id) {
            session.transcript.push({ kind: "notice", text: notices.approvalUnavailable(approval.tool) });
          } else {
            await executeAndIngest(session, decision, resolved);
          }
        }
        return loop(session);
      });
    },

    getSession(sessionId) {
      const s = sessions.get(sessionId);
      if (!s) return undefined;
      return {
        id: s.id,
        status: s.status,
        tainted: s.security.tainted,
        toolCallCount: s.security.toolCallCount,
        pendingApprovalId: s.pendingApprovalId,
      };
    },
  };
}
