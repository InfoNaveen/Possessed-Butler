/**
 * TEMPORARY LOCAL STUB of docs/contracts.md v0.1.0 (status: PROPOSED).
 *
 * Per .kiro/steering/team-workflow.md, `src/lib/contracts/` must not be implemented until the
 * contracts are AGREED. Until then agent-core, providers and tools compile against this mirror.
 * Everything imports it through the `@contracts` path alias (tsconfig.json, vitest.config.ts),
 * so switching to the real module is a one-line alias change. Delete this file at that point.
 *
 * Rules for this file: mirror the document exactly, add nothing that is not in it.
 */
import { z } from "zod";

// 1. Content and trust
export type ContentSource = "system" | "user" | "email" | "web" | "pdf" | "file" | "tool";
export type TrustLevel = "trusted" | "untrusted";

export interface ContentSegment {
  id: string;
  source: ContentSource;
  trust: TrustLevel;
  origin: string | null;
  text: string;
  sha256: string;
  truncated: boolean;
  createdAt: string;
}

// 2. Tools
export const TOOL_NAMES = [
  "email.list",
  "email.read",
  "email.send",
  "web.fetch",
  "pdf.extract",
  "file.list",
  "file.read",
  "file.write",
] as const;
export type ToolName = (typeof TOOL_NAMES)[number];

export type ToolSensitivity = "read" | "write" | "external_send";

export interface ToolMetadata {
  name: ToolName;
  description: string;
  sensitivity: ToolSensitivity;
  producesUntrustedContent: boolean;
  inputSchema: z.ZodType<unknown>;
}

export interface ToolContext {
  sessionId: string;
  signal: AbortSignal;
}

export type ToolErrorCode =
  | "INVALID_ARGS"
  | "NOT_FOUND"
  | "SANDBOX_VIOLATION"
  | "LIMIT_EXCEEDED"
  | "NETWORK_BLOCKED"
  | "TIMEOUT"
  | "UNAUTHORIZED"
  | "INTERNAL";

export interface ToolError {
  code: ToolErrorCode;
  message: string;
}

export type ToolResult =
  | { ok: true; proposalId: string; tool: ToolName; segments: ContentSegment[]; summary: string }
  | { ok: false; proposalId: string; tool: ToolName; error: ToolError };

export interface ToolRegistry {
  list(): ToolMetadata[];
  get(name: string): ToolMetadata | undefined;
}

export interface ToolExecutor {
  execute(call: AuthorizedCall, ctx: ToolContext): Promise<ToolResult>;
}

// 3. Proposals and authorization
export interface ToolCallProposal {
  id: string;
  sessionId: string;
  step: number;
  indexInStep: number;
  tool: string;
  args: unknown;
}

export type DecisionKind = "allow" | "deny" | "require_approval";

export interface RuleResult {
  ruleId: string;
  outcome: DecisionKind | "abstain";
  reason: string;
}

export interface InjectionSignal {
  detectorId: string;
  segmentId: string;
  severity: "low" | "medium" | "high";
  description: string;
}

export interface AuthorizationDecision {
  id: string;
  proposalId: string;
  sessionId: string;
  kind: DecisionKind;
  tool: ToolName | null;
  canonicalArgs: unknown | null;
  argsHash: string | null;
  ruleResults: RuleResult[];
  signals: InjectionSignal[];
  policyVersion: string;
  decidedAt: string;
}

export interface AuthorizedCall {
  decisionId: string;
  proposalId: string;
  sessionId: string;
  tool: ToolName;
  args: unknown;
  argsHash: string;
  approvalId: string | null;
  issuedAt: string;
  expiresAt: string;
  signature: string;
}

export interface Policy {
  version: string;
  tools: Record<ToolName, { enabled: boolean; approval: "never" | "when_tainted" | "always" }>;
  email: {
    recipientAllowlist: string[];
    contacts: { name: string; address: string }[];
  };
  web: { domainAllowlist: string[]; allowUnlistedWhenUntainted: boolean };
  file: { readExtensions: string[]; writeExtensions: string[]; maxBytes: number };
  limits: { maxSteps: number; maxToolCalls: number; maxProposalsPerStep: number };
}

export interface SessionSecurityState {
  sessionId: string;
  tainted: boolean;
  taintSources: {
    segmentId: string;
    source: ContentSource;
    origin: string | null;
    maxSignalSeverity: "none" | "low" | "medium" | "high";
  }[];
  trustedInstructions: string[];
  toolCallCount: number;
  stepCount: number;
  policy: Policy;
}

export interface PolicyEngine {
  authorize(proposal: ToolCallProposal, state: SessionSecurityState, registry: ToolRegistry): AuthorizationDecision;
  recordIngestion(state: SessionSecurityState, segment: ContentSegment): SessionSecurityState;
  scan(segment: ContentSegment): InjectionSignal[];
}

export interface CallAuthority {
  issue(decision: AuthorizationDecision, approval?: ApprovalRequest): AuthorizedCall;
  verifyAndConsume(call: AuthorizedCall): { ok: true } | { ok: false; reason: string };
}

// 4. Approvals
export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired" | "consumed";

export interface ApprovalRequest {
  id: string;
  sessionId: string;
  proposalId: string;
  decisionId: string;
  tool: ToolName;
  args: unknown;
  argsHash: string;
  reasons: string[];
  status: ApprovalStatus;
  createdAt: string;
  expiresAt: string;
  resolvedAt: string | null;
}

export interface ApprovalStore {
  create(decision: AuthorizationDecision): ApprovalRequest;
  get(id: string): ApprovalRequest | undefined;
  listPending(sessionId?: string): ApprovalRequest[];
  resolve(id: string, verdict: "approve" | "reject"): ApprovalRequest;
  decisionFor(id: string): AuthorizationDecision | undefined;
  markConsumed(id: string): void;
}

// 5. Audit log
export type AuditEventType =
  | "session_started"
  | "user_message"
  | "content_ingested"
  | "injection_signal"
  | "tool_proposed"
  | "authz_decision"
  | "approval_requested"
  | "approval_resolved"
  | "tool_executed"
  | "tool_failed"
  | "provider_error"
  | "model_output_invalid"
  | "budget_exceeded"
  | "turn_completed";

export interface AuditEvent {
  id: string;
  ts: string;
  sessionId: string;
  type: AuditEventType;
  data: Record<string, unknown>;
}

export interface AuditLog {
  append(event: Omit<AuditEvent, "id" | "ts">): AuditEvent;
  list(sessionId: string): AuditEvent[];
}

// 6. LLM providers
export type ProviderId = "ollama" | "gemini" | "openai" | "mock";

export interface LLMMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LLMToolSpec {
  name: ToolName;
  description: string;
  parameters: Record<string, unknown>;
}

export interface LLMRequest {
  messages: LLMMessage[];
  tools: LLMToolSpec[];
  temperature: number;
  maxOutputTokens: number;
  timeoutMs: number;
}

export interface LLMRawResponse {
  provider: ProviderId;
  model: string;
  text: string;
  usage?: { inputTokens?: number; outputTokens?: number };
}

export type ProviderErrorCode = "CONFIG" | "AUTH" | "UNAVAILABLE" | "TIMEOUT" | "RATE_LIMITED" | "BAD_RESPONSE";

export class ProviderError extends Error {
  readonly code: ProviderErrorCode;
  readonly provider: ProviderId;
  readonly retryable: boolean;

  constructor(code: ProviderErrorCode, provider: ProviderId, message: string, retryable = false) {
    super(message);
    this.name = "ProviderError";
    this.code = code;
    this.provider = provider;
    this.retryable = retryable;
  }
}

export interface LLMProvider {
  id: ProviderId;
  model: string;
  generate(req: LLMRequest, signal: AbortSignal): Promise<LLMRawResponse>;
}

/** D1 JSON action protocol. Strict objects: unknown keys make the output invalid (fail closed). */
export const ModelActionSchema = z.discriminatedUnion("action", [
  z.strictObject({ action: z.literal("final"), text: z.string().max(20_000) }),
  z.strictObject({
    action: z.literal("tool_calls"),
    calls: z
      .array(z.strictObject({ tool: z.string().min(1).max(64), args: z.unknown() }))
      .min(1)
      .max(10),
  }),
]);
export type ModelAction = z.infer<typeof ModelActionSchema>;

// 7. Agent sessions and HTTP API
export type SessionStatus = "idle" | "running" | "awaiting_approval" | "completed" | "error";

export type BackendExecutionStatus =
  | "APPROVAL_PENDING"
  | "APPROVAL_REJECTED"
  | "EMAIL_SENT"
  | "EMAIL_FAILED"
  | "IDLE"
  | "RUNNING"
  | "COMPLETED"
  | "ERROR";

export interface AgentTurnResult {
  sessionId: string;
  status: SessionStatus;
  assistantText: string | null;
  pendingApproval: ApprovalRequest | null;
  error: { code: string; message: string } | null;
  executionStatus?: BackendExecutionStatus;
  executionDetails?: {
    tool?: string;
    messageId?: string;
    accepted?: string[];
    rejected?: string[];
    summary?: string;
    reasons?: string[];
    [key: string]: unknown;
  };
}
