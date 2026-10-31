# Requirements: security-engine

## Introduction
The security engine is the deterministic authorization layer between the model and the tools. It decides `allow`, `deny` or `require_approval` for every proposed tool call, tracks taint, manages human approvals, issues and verifies capability tokens (`AuthorizedCall`) and writes the audit log. It assumes the model is fully compromised.

Shared types: #[[file:docs/contracts.md]]

## Requirement 1: Deterministic authorization
**User story:** As the operator, I want every tool call decided by fixed rules, so that no text an attacker writes can talk the agent into an action.

**Acceptance criteria**
1. WHEN agent-core submits a `ToolCallProposal` THEN the engine SHALL return an `AuthorizationDecision` produced only from the proposal, the `SessionSecurityState`, the `Policy` and `ToolRegistry` metadata.
2. The engine SHALL produce identical decisions (excluding `id` and `decidedAt`) for identical inputs.
3. The decision path SHALL NOT call an LLM, the network, the clock (except for `decidedAt`), or a random source (except for `id`).
4. WHEN rule outcomes conflict THEN the engine SHALL choose the most restrictive: `deny` over `require_approval` over `allow`.
5. IF no rule returns `allow` THEN the decision SHALL be `deny`.
6. IF any exception is thrown while deciding THEN the decision SHALL be `deny` with rule ID `R-INTERNAL-ERROR`.
7. Every decision SHALL list the result of every evaluated rule with a stable rule ID and a fixed-template reason that contains no untrusted text.

## Requirement 2: Tool and argument validation
**User story:** As the operator, I want malformed or unknown tool requests rejected, so that the model cannot reach unintended behavior.

**Acceptance criteria**
1. IF `proposal.tool` is not a registered `ToolName` THEN the decision SHALL be `deny` (`R-TOOL-KNOWN`).
2. IF the tool is disabled in policy THEN the decision SHALL be `deny` (`R-TOOL-ENABLED`).
3. IF `proposal.args` fails the tool's strict Zod `inputSchema` THEN the decision SHALL be `deny` (`R-ARGS-SCHEMA`).
4. WHEN args are valid THEN the decision SHALL include `canonicalArgs` (parsed, key-sorted) and `argsHash` (SHA-256 of their canonical JSON).

## Requirement 3: Taint tracking
**User story:** As the operator, I want the engine to know when untrusted content has been read, so that side-effecting actions get stricter after that point.

**Acceptance criteria**
1. WHEN an untrusted `ContentSegment` is recorded THEN `tainted` SHALL become `true` and the segment SHALL be appended to `taintSources`.
2. `tainted` SHALL never return to `false` within a session.
3. Segments with source `system` or `user` SHALL NOT taint the session, and tools SHALL NOT be able to create segments with those sources.

## Requirement 4: Sensitivity and approval rules
**User story:** As the operator, I want writes and sends to require my approval once the agent has read untrusted content.

**Acceptance criteria**
1. IF the tool's policy approval mode is `always` THEN the decision SHALL be at least `require_approval`.
2. IF the approval mode is `when_tainted`, the session is tainted, and the tool's sensitivity is `write` or `external_send` THEN the decision SHALL be at least `require_approval`.
3. Tools with sensitivity `read` and valid args SHALL be allowed unless another rule restricts them.

## Requirement 5: Argument provenance rules
**User story:** As the operator, I want destinations chosen by me, not by content I asked the agent to read.

**Acceptance criteria**
1. IF any `email.send` recipient is not in `recipientAllowlist`, not literally present in `trustedInstructions`, and not a contact whose name or address appears in `trustedInstructions`, THEN the decision SHALL be `deny` (`R-EMAIL-RECIPIENT-PROVENANCE`).
2. IF a `web.fetch` URL scheme is not `http` or `https` THEN the decision SHALL be `deny`.
3. IF the session is tainted and the `web.fetch` host is neither in `domainAllowlist` nor present in `trustedInstructions` THEN the decision SHALL be at least `require_approval`.
4. IF the session is untainted, `allowUnlistedWhenUntainted` is false, and the host is not allowlisted or in `trustedInstructions`, THEN the decision SHALL be at least `require_approval`.
5. IF the session is tainted and a `web.fetch` URL's query string plus fragment is longer than 100 characters THEN the decision SHALL be `deny` (`R-WEB-EXFIL-QUERY`).
6. IF a file path argument is absolute, contains `..` segments, a drive letter, a UNC prefix or a null byte THEN the decision SHALL be `deny` (the sandbox enforces this again at execution).
7. IF a file extension is not in the read or write extension allowlist for that tool THEN the decision SHALL be `deny`.
8. IF `file.write` content exceeds `policy.file.maxBytes` THEN the decision SHALL be `deny`.

## Requirement 6: Budgets
**Acceptance criteria**
1. IF `toolCallCount` has reached `limits.maxToolCalls` THEN further proposals SHALL be denied (`R-BUDGET-TOOL-CALLS`).
2. IF a single step contains more than `limits.maxProposalsPerStep` proposals THEN every proposal in that step beyond the limit SHALL be denied.

## Requirement 7: Injection signals
**User story:** As a judge, I want to see when content looked like an injection attempt, so that the audit log explains what happened.

**Acceptance criteria**
1. WHEN content is ingested THEN the engine SHALL run every detector and return `InjectionSignal`s.
2. Signals SHALL be logged as `injection_signal` audit events.
3. IF any `high` severity signal exists in the session's taint sources and the tool's sensitivity is not `read` THEN the decision SHALL be at least `require_approval`.
4. Signals SHALL NEVER cause a decision to become more permissive.

## Requirement 8: Approvals
**User story:** As the operator, I want to approve or reject a specific pending action, and have that approval apply to that exact action only.

**Acceptance criteria**
1. WHEN a decision is `require_approval` THEN the engine SHALL create a `pending` `ApprovalRequest` holding the canonical args, argsHash and reasons.
2. Approvals SHALL only be resolved through `ApprovalStore.resolve`, called only by the approvals API route.
3. IF a pending approval is older than its TTL (default 10 minutes) THEN it SHALL become `expired` and cannot be approved.
4. An approved request SHALL authorize exactly one execution, after which it becomes `consumed`.
5. IF the argsHash of the call being issued differs from the approval's argsHash THEN issuing SHALL fail.

## Requirement 9: Capability tokens
**Acceptance criteria**
1. `CallAuthority.issue` SHALL only succeed for `allow` decisions or `require_approval` decisions with a matching `approved` approval.
2. `verifyAndConsume` SHALL reject tokens with a bad signature, an expired `expiresAt`, or a `decisionId` already consumed.
3. The signing key SHALL be generated at process start and SHALL never be logged or exposed.

## Requirement 10: Audit log
**User story:** As a judge, I want a complete, readable record of every security decision.

**Acceptance criteria**
1. The engine SHALL provide an append-only `AuditLog` writing one JSON object per line to `sandbox/logs/<sessionId>.jsonl` and keeping an in-memory index for `list`.
2. Every proposal, decision, approval request, approval resolution, ingestion and signal SHALL produce an event.
3. Text fields longer than 200 characters SHALL be replaced by `{ sha256, length, preview }`.
4. Values for keys matching `/key|token|secret|authorization|password/i` SHALL be redacted.
5. IF writing the log file fails THEN the engine SHALL deny further tool calls in that session (fail closed).

## Requirement 11: Policy loading
**Acceptance criteria**
1. The engine SHALL load the policy from `POLICY_PATH` (default `fixtures/policies/default.json`) and validate it with Zod.
2. IF the policy is missing or invalid THEN the agent API SHALL refuse to run (503).
3. The default policy SHALL set `email.send` and `file.write` to `when_tainted` or stricter.
