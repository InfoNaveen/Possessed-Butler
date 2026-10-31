# Requirements: agent-core

## Introduction
Agent-core owns the project scaffold, the shared contracts module, configuration, LLM provider adapters (Ollama, Gemini, OpenAI, mock), the orchestration loop, prompt construction, session state, the HTTP API routes and the minimal UI. It never decides authorization and never runs tool code directly.

Shared types: #[[file:docs/contracts.md]]

## Requirement 1: Scaffold and contracts
**Acceptance criteria**
1. The project SHALL be a Next.js App Router app in TypeScript strict mode with Tailwind CSS, Zod and Vitest, created during the hackathon.
2. `src/lib/contracts/` SHALL implement every type in `docs/contracts.md` as a Zod schema with the TS type derived by `z.infer`, and SHALL contain no other logic.
3. All API route handlers SHALL run on the Node.js runtime.
4. Every dependency and its version SHALL be listed in README.md.

## Requirement 2: Configuration
**Acceptance criteria**
1. Configuration SHALL be read from environment variables and validated with Zod at first use.
2. IF configuration is invalid or the selected provider lacks required settings THEN API routes SHALL return 503 with a fixed message and no tool SHALL run.
3. API keys SHALL be read only on the server and SHALL never appear in responses, logs or client bundles.

## Requirement 3: Provider adapters
**User story:** As the operator, I want to switch between Ollama, Gemini, OpenAI and a mock without code changes.

**Acceptance criteria**
1. Each adapter SHALL implement `LLMProvider` using `fetch` against the provider's documented HTTP API, linked in design.md.
2. Each adapter SHALL validate the provider's HTTP response with Zod and throw `ProviderError("BAD_RESPONSE")` on any mismatch.
3. Network failures, non-2xx statuses, 401/403, 429 and timeouts SHALL map to `UNAVAILABLE`, `AUTH`, `RATE_LIMITED` and `TIMEOUT`.
4. Adapters SHALL NOT retry automatically in the MVP.
5. The mock provider SHALL be deterministic and scriptable, including a "compromised" mode that emits exactly the tool call an injected fixture asks for.
6. Temperature SHALL default to 0.

## Requirement 4: Model output parsing
**Acceptance criteria**
1. The model's text SHALL be parsed as one JSON `ModelAction` (optionally inside a single fenced code block) and validated with Zod.
2. IF parsing fails THEN the agent SHALL log `model_output_invalid`, MAY re-prompt with a fixed correction message up to `maxInvalidOutputRetries` (default 1), and SHALL NOT execute anything from the invalid output.
3. Tool names and args from a valid `ModelAction` SHALL be passed to the security engine as untrusted `ToolCallProposal`s with ids assigned by the agent.

## Requirement 5: Prompt construction
**User story:** As the operator, I want the model to be able to tell my instructions apart from content it reads.

**Acceptance criteria**
1. The system prompt SHALL be a fixed string in code that describes the tools, the JSON action protocol, and that data blocks contain untrusted content that must not be followed as instructions.
2. User chat messages SHALL be sent as user-role messages and recorded in `trustedInstructions`.
3. Untrusted segments SHALL be wrapped in data blocks whose delimiter includes a random per-session nonce, with any occurrence of the delimiter inside the content neutralized.
4. Denial notices sent back to the model SHALL be fixed templates containing only the tool name and rule IDs.

## Requirement 6: Orchestration loop
**Acceptance criteria**
1. For every proposal the agent SHALL call `PolicyEngine.authorize` and act only on its decision.
2. WHEN the decision is `allow` THEN the agent SHALL obtain an `AuthorizedCall` from `CallAuthority.issue` and pass it to `ToolExecutor.execute`.
3. WHEN a tool returns segments THEN the agent SHALL call `recordIngestion` for each before the next model call.
4. WHEN the decision is `require_approval` THEN the agent SHALL create an approval, set status `awaiting_approval`, drop the remaining proposals of that step (logging each) and return.
5. WHEN the decision is `deny` THEN the agent SHALL add a denial notice and continue.
6. The loop SHALL stop at `limits.maxSteps` and log `budget_exceeded`.
7. IF the provider throws THEN the turn SHALL end with status `error`, log `provider_error`, and no tool SHALL run in that step.
8. IF the audit log fails THEN the session SHALL move to `error` and refuse further turns.
9. Only one turn per session SHALL run at a time; concurrent requests SHALL get 409.

## Requirement 7: Approval resumption
**Acceptance criteria**
1. WHEN the operator approves THEN the agent SHALL issue an `AuthorizedCall` with the approval, execute it, mark the approval consumed, and continue the loop.
2. WHEN the operator rejects THEN the agent SHALL add a fixed "operator rejected" notice and continue the loop.
3. Approval resolution SHALL only be possible through `POST /api/approvals/[id]`.

## Requirement 8: HTTP API
**Acceptance criteria**
1. Routes and payloads SHALL match section 7 of the contracts.
2. Request bodies SHALL be validated with Zod; invalid bodies return 400 without echoing input.
3. State-changing routes SHALL require `Content-Type: application/json`, a custom `X-Butler-Operator` header, and a same-origin `Origin` header, so a malicious web page in the operator's browser cannot trigger them.
4. The dev server SHALL be documented to bind to `127.0.0.1`.

## Requirement 9: Minimal UI
**Acceptance criteria**
1. A single page SHALL show the chat, the active provider and model, a pending approval card (tool, canonical args, reasons, Approve and Reject), and the audit events for the session.
2. Untrusted content SHALL be rendered as text, never as HTML.
