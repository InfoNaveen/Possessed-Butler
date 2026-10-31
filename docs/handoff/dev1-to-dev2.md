# Developer 1 → Developer 2: coordination items

From: Developer 1 (agent-core, providers, tools, app). To: Developer 2 (security-engine).
Status: open. Nothing here changes `docs/contracts.md` until we both agree.

Agent-core currently compiles against a temporary mirror of contracts v0.1.0 at
`src/lib/agent/stubs/contracts.ts`, imported through the `@contracts` alias. Tests use a
test-only double of your interfaces at `tests/doubles/security-double.ts`. Nothing in `src/`
contains security decisions, and the app is not wired to any security implementation yet.

## Needed from security-engine (not in the contracts today)

1. **Args hash function.** The executor must recompute the args hash (tool-execution
   requirement 2.2) exactly as the engine does. Proposal: export
   `hashArgs(args: unknown): string` (= `sha256Hex(canonicalJson(args))`) from
   `src/lib/security/index.ts`. The executor takes it by injection (`ToolboxDeps.hashArgs`), so tools don't hash args their own way.
2. **Initial session state.** The agent currently builds `SessionSecurityState` itself
   (`tainted: false`, empty arrays, zero counters, the loaded policy). Would you rather own
   this with `createSessionSecurityState(sessionId, policy)`? I'll switch to it if so.
3. **Wiring factory.** I'll build app wiring around `createSecurity()` returning
   `{ engine, authority, approvals }` plus `createAuditLog(dir)` and `loadPolicy(path)`, as in
   your design. Please confirm those names and signatures.

## Behaviour I rely on (please confirm)

4. `authorize` never throws. If it does, the agent treats it as deny (`AGENT-NO-VALID-DECISION`).
   It also treats a decision whose `proposalId`/`sessionId` doesn't match as deny.
5. Any throw from `issue`, `approvals.create`, `approvals.resolve` is treated as a refusal. No
   specific error class is needed. Exporting `SecurityError` with `code` would let me log the code.
6. After a successful `issue(decision, approval)` the agent calls `approvals.markConsumed(id)`
   **before** executing. If `markConsumed` throws, the turn fails closed.
7. The agent calls `recordIngestion` for each segment before the next model call, then `scan`
   separately only to write `injection_signal` events. That runs the detectors twice per segment.
   It's fine if they stay cheap and pure.
8. The agent audits `session_started`, `user_message`, `tool_proposed`, `authz_decision`,
   `approval_requested`, `approval_resolved`, `content_ingested`, `injection_signal`,
   `provider_error`, `model_output_invalid`, `budget_exceeded`, `turn_completed`, plus
   `tool_failed` with code `ISSUE_REFUSED`. The executor audits `tool_executed` and `tool_failed`.
   `tool_proposed.args` is the raw model value, so please make sure redaction/truncation applies to it.
   Any `append` throw ends the session permanently.

## Questions

9. **Budget scope.** I apply `limits.maxSteps` **per user turn** and keep `stepCount`
   cumulative for `proposal.step`. `R-BUDGET-TOOL-CALLS` uses `toolCallCount`, which is
   session-wide, so a multi-turn chat runs out after 12 tool calls in total. Should that limit
   also be per turn? If yes, we need a per-turn counter in `SessionSecurityState`.
10. **Rejected approvals.** After a rejection the model may propose the same call again. Each
    new proposal gets a fresh decision and approval. Do you want a rule against re-proposing a
    rejected argsHash in the same session?

## Proposed contract additions (for the AGREED version)

- `TOOL_NAMES` as a runtime `const` array (the registry needs it at runtime to reject unknown definitions).
- `ModelActionSchema` limits: `tool` 1–64 chars, 1–10 calls per action, `text` ≤ 20,000 chars,
  strict objects (unknown keys make the output invalid).
- Decision D2 resolved by evidence: Zod 4.6.7's `z.toJSONSchema()` emits
  `additionalProperties: false` for `z.strictObject`, and that output goes into the prompt as-is.
