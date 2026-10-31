# Shared TypeScript Contracts

**Status: PROPOSED (v0.1.0). Do not implement `src/lib/contracts/` until this says AGREED and the sign-off table is complete.**

This file defines every interface that crosses a module boundary. Module-internal types live in each spec's `design.md`. Each type here will have a matching Zod schema in `src/lib/contracts/` (`XxxSchema`), and the TS type will be derived with `z.infer` so the two cannot drift.

## Open decisions (resolve before AGREED)

| ID | Question | Proposal | Alternatives |
|----|----------|----------|--------------|
| D1 | How does the model request tools? | **JSON action protocol** in the model's text output, parsed with Zod. Same for every provider, easy to mock, easy to fail closed. Providers may enable their JSON output mode. | Native function calling per provider (OpenAI `tools`, Gemini `functionDeclarations`, Ollama `tools`). Better model accuracy, but three different shapes to map and test. Could be added later behind the same `LLMResponse`. |
| D2 | How do we produce JSON Schema from Zod for tool descriptions? | If we install Zod 4, use its built-in JSON Schema conversion (confirm in Zod docs at install time). | Hand-write a short description per tool; or add `zod-to-json-schema` (must be recorded in README). |
| D3 | How is an `AuthorizedCall` protected from forgery inside the process? | HMAC-SHA256 with a random per-process key from `node:crypto`, plus single-use tracking by `decisionId`. | Branded type plus a module-private `WeakSet`. Simpler, but doesn't survive serialization across the approval pause. |
| D4 | Do approvals in the eval runner count as blocked? | Eval operator auto-rejects. Report both "ASR (auto-reject)" and "ASR if operator approved everything" so we are honest about approval fatigue. | Only report auto-reject. |
| D5 | Session storage | In-memory `Map` plus JSON snapshot in `sandbox/state/` so an approval survives a dev-server hot reload. | In-memory only. |

## 1. Content and trust

```ts
export type ContentSource = "system" | "user" | "email" | "web" | "pdf" | "file" | "tool";

/** "system" and "user" are trusted. Everything else is untrusted. Derived, never set by tools. */
export type TrustLevel = "trusted" | "untrusted";

export interface ContentSegment {
  id: string;               // uuid
  source: ContentSource;
  trust: TrustLevel;        // computed from source by makeSegment(); tools cannot pass "trusted"
  origin: string | null;    // email message id, URL, sandbox-relative path, or null
  text: string;             // possibly truncated
  sha256: string;           // hash of the full original text before truncation
  truncated: boolean;
  createdAt: string;        // ISO 8601
}
```

## 2. Tools (owned by tool-execution, read by security-engine)

```ts
export type ToolName =
  | "email.list" | "email.read" | "email.send"
  | "web.fetch"
  | "pdf.extract"
  | "file.list" | "file.read" | "file.write";

/** read: no side effects. write: changes sandbox state. external_send: data leaves the system. */
export type ToolSensitivity = "read" | "write" | "external_send";

export interface ToolMetadata {
  name: ToolName;
  description: string;           // fixed text shown to the model
  sensitivity: ToolSensitivity;
  producesUntrustedContent: boolean;
  inputSchema: z.ZodType<unknown>; // strict object schemas, unknown keys rejected
}

export interface ToolContext {
  sessionId: string;
  signal: AbortSignal;
}

export type ToolErrorCode =
  | "INVALID_ARGS" | "NOT_FOUND" | "SANDBOX_VIOLATION" | "LIMIT_EXCEEDED"
  | "NETWORK_BLOCKED" | "TIMEOUT" | "UNAUTHORIZED" | "INTERNAL";

export interface ToolError { code: ToolErrorCode; message: string } // message never contains raw untrusted content

export type ToolResult =
  | { ok: true;  proposalId: string; tool: ToolName; segments: ContentSegment[]; summary: string }
  | { ok: false; proposalId: string; tool: ToolName; error: ToolError };

export interface ToolRegistry {
  list(): ToolMetadata[];
  get(name: string): ToolMetadata | undefined; // lookup by untrusted string is safe
}

export interface ToolExecutor {
  /** Re-verifies the call with CallAuthority before running. Throws nothing; failures are ToolResult.ok=false. */
  execute(call: AuthorizedCall, ctx: ToolContext): Promise<ToolResult>;
}
```

## 3. Proposals and authorization (owned by security-engine)

```ts
/** What the model asked for. Everything except ids is untrusted. */
export interface ToolCallProposal {
  id: string;          // assigned by agent-core, not by the model
  sessionId: string;
  step: number;
  indexInStep: number; // 0-based position within the model's tool_calls array, for per-step budgets
  tool: string;        // unvalidated string from model output
  args: unknown;       // unvalidated
}

export type DecisionKind = "allow" | "deny" | "require_approval";

export interface RuleResult {
  ruleId: string;                        // stable, e.g. "R-EMAIL-RECIPIENT-PROVENANCE"
  outcome: DecisionKind | "abstain";
  reason: string;                        // fixed template text, no attacker content
}

export interface InjectionSignal {
  detectorId: string;
  segmentId: string;
  severity: "low" | "medium" | "high";
  description: string;                   // fixed template text
}

export interface AuthorizationDecision {
  id: string;
  proposalId: string;
  sessionId: string;
  kind: DecisionKind;                    // most restrictive of all rule outcomes; deny > require_approval > allow
  tool: ToolName | null;                 // null if the proposal named an unknown tool
  canonicalArgs: unknown | null;         // Zod-parsed, key-sorted args; null if invalid
  argsHash: string | null;               // sha256 of canonical JSON of canonicalArgs
  ruleResults: RuleResult[];
  signals: InjectionSignal[];
  policyVersion: string;
  decidedAt: string;
}

/** Capability token. Only CallAuthority can create one. */
export interface AuthorizedCall {
  decisionId: string;
  proposalId: string;
  sessionId: string;
  tool: ToolName;
  args: unknown;              // canonicalArgs from the decision
  argsHash: string;
  approvalId: string | null;  // set when issued after human approval
  issuedAt: string;
  expiresAt: string;          // short TTL, e.g. 60 s
  signature: string;          // see D3
}

export interface Policy {
  version: string;
  tools: Record<ToolName, { enabled: boolean; approval: "never" | "when_tainted" | "always" }>;
  email: {
    recipientAllowlist: string[];                 // lowercase addresses always allowed as recipients
    contacts: { name: string; address: string }[]; // operator-owned address book; a contact is an allowed
                                                    // recipient when its name or address appears in trustedInstructions
  };
  web: { domainAllowlist: string[]; allowUnlistedWhenUntainted: boolean };
  file: { readExtensions: string[]; writeExtensions: string[]; maxBytes: number };
  limits: { maxSteps: number; maxToolCalls: number; maxProposalsPerStep: number };
}

export interface SessionSecurityState {
  sessionId: string;
  tainted: boolean;                       // never resets within a session
  taintSources: {
    segmentId: string;
    source: ContentSource;
    origin: string | null;
    maxSignalSeverity: "none" | "low" | "medium" | "high"; // from PolicyEngine.scan at ingestion
  }[];
  trustedInstructions: string[];          // the user's own chat messages, verbatim
  toolCallCount: number;
  stepCount: number;
  policy: Policy;
}

export interface PolicyEngine {
  /** Pure and deterministic. Never throws: internal errors produce kind="deny". */
  authorize(proposal: ToolCallProposal, state: SessionSecurityState, registry: ToolRegistry): AuthorizationDecision;
  /** Pure. Returns new state with taint applied if the segment is untrusted. */
  recordIngestion(state: SessionSecurityState, segment: ContentSegment): SessionSecurityState;
  /** Pure. Heuristic, signals only. */
  scan(segment: ContentSegment): InjectionSignal[];
}

export interface CallAuthority {
  /** Throws SecurityError unless decision.kind==="allow", or kind==="require_approval" and approval is approved and matches argsHash. */
  issue(decision: AuthorizationDecision, approval?: ApprovalRequest): AuthorizedCall;
  /** Checks signature, expiry, single use. Marks the call consumed on success. */
  verifyAndConsume(call: AuthorizedCall): { ok: true } | { ok: false; reason: string };
}
```

## 4. Approvals (owned by security-engine)

```ts
export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired" | "consumed";

export interface ApprovalRequest {
  id: string;
  sessionId: string;
  proposalId: string;
  decisionId: string;
  tool: ToolName;
  args: unknown;             // canonical args, shown to the operator
  argsHash: string;
  reasons: string[];         // from RuleResults and signals
  status: ApprovalStatus;
  createdAt: string;
  expiresAt: string;
  resolvedAt: string | null;
}

export interface ApprovalStore {
  create(decision: AuthorizationDecision): ApprovalRequest;
  get(id: string): ApprovalRequest | undefined;
  listPending(sessionId?: string): ApprovalRequest[];
  /** Only called from the approvals API route. */
  resolve(id: string, verdict: "approve" | "reject"): ApprovalRequest;
  /** The original decision object (needed by CallAuthority.issue, which only accepts engine-produced decisions). */
  decisionFor(id: string): AuthorizationDecision | undefined;
  markConsumed(id: string): void;
}
```

## 5. Audit log (owned by security-engine, written by everyone)

```ts
export type AuditEventType =
  | "session_started" | "user_message"
  | "content_ingested" | "injection_signal"
  | "tool_proposed" | "authz_decision"
  | "approval_requested" | "approval_resolved"
  | "tool_executed" | "tool_failed"
  | "provider_error" | "model_output_invalid"
  | "budget_exceeded" | "turn_completed";

export interface AuditEvent {
  id: string;
  ts: string;
  sessionId: string;
  type: AuditEventType;
  data: Record<string, unknown>;  // no secrets; large text replaced by { sha256, length, preview(<=200 chars) }
}

export interface AuditLog {
  append(event: Omit<AuditEvent, "id" | "ts">): AuditEvent;
  list(sessionId: string): AuditEvent[];
}
```

## 6. LLM providers (owned by agent-core)

```ts
export type ProviderId = "ollama" | "gemini" | "openai" | "mock";

export interface LLMMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LLMToolSpec {
  name: ToolName;
  description: string;
  parameters: Record<string, unknown>;  // JSON Schema, see D2
}

export interface LLMRequest {
  messages: LLMMessage[];
  tools: LLMToolSpec[];
  temperature: number;     // default 0
  maxOutputTokens: number;
  timeoutMs: number;
}

/** Raw provider text plus metadata. Parsing into actions happens in agent-core, not in providers. */
export interface LLMRawResponse {
  provider: ProviderId;
  model: string;
  text: string;
  usage?: { inputTokens?: number; outputTokens?: number };
}

export type ProviderErrorCode = "CONFIG" | "AUTH" | "UNAVAILABLE" | "TIMEOUT" | "RATE_LIMITED" | "BAD_RESPONSE";

export class ProviderError extends Error { code: ProviderErrorCode; provider: ProviderId; retryable: boolean }

export interface LLMProvider {
  id: ProviderId;
  model: string;
  generate(req: LLMRequest, signal: AbortSignal): Promise<LLMRawResponse>; // throws ProviderError only
}

/** D1: the JSON action protocol the model must emit. Anything else is invalid output. */
export type ModelAction =
  | { action: "final"; text: string }
  | { action: "tool_calls"; calls: { tool: string; args: unknown }[] };
```

## 7. Agent sessions and HTTP API (owned by agent-core)

```ts
export type SessionStatus = "idle" | "running" | "awaiting_approval" | "completed" | "error";

export interface AgentTurnResult {
  sessionId: string;
  status: SessionStatus;
  assistantText: string | null;
  pendingApproval: ApprovalRequest | null;
  error: { code: string; message: string } | null;
}
```

| Route | Body / query | Response |
|-------|--------------|----------|
| `POST /api/agent` | `{ sessionId?: string; message: string }` (max 4000 chars) | `AgentTurnResult` |
| `GET /api/approvals` | `?sessionId=` | `ApprovalRequest[]` |
| `POST /api/approvals/[id]` | `{ verdict: "approve" \| "reject" }` | `AgentTurnResult` (the resumed turn) |
| `GET /api/audit` | `?sessionId=` | `AuditEvent[]` |

All bodies validated with Zod; invalid input returns 400 with no echo of the input.

## 8. Evaluation (owned by evaluation)

```ts
export type AttackGoal =
  | { type: "email_sent_to"; address: string }
  | { type: "file_written"; path: string }
  | { type: "file_read"; path: string }
  | { type: "url_fetched"; urlPrefix: string }
  | { type: "tool_called"; tool: ToolName };

export interface Scenario {
  id: string;                         // e.g. "ATK-EMAIL-001"
  title: string;
  category: "benign" | "attack";
  vector: "email" | "web" | "pdf" | "file" | "none";
  userTask: string;
  fixtures: { mailbox?: string; webPages?: string[]; pdfs?: string[]; files?: string[] }; // paths under fixtures/
  mockScript: string;                 // id of a scripted or "compromised" mock behaviour
  attackGoal?: AttackGoal;            // required when category === "attack"
  successCheck?: string;              // id of a benign-completion check
}

export interface ScenarioOutcome {
  scenarioId: string;
  provider: ProviderId;
  model: string;
  attackSucceeded: boolean | null;          // null for benign
  attackSucceededIfApproved: boolean | null; // see D4
  taskCompleted: boolean | null;            // null for attack-only scenarios
  executedCalls: { tool: ToolName; argsHash: string }[];
  deniedCalls: number;
  approvalsRequested: number;
  error: string | null;
  durationMs: number;
}
```

## Sign-off

| Spec owner | Name | Agreed (date) |
|-----------|------|---------------|
| agent-core | TBD | |
| security-engine | TBD | |
| tool-execution | TBD | |
| evaluation | TBD | |

## Changelog
- v0.1.0 (2026-10-31): initial proposal.
