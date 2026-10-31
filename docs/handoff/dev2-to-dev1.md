# Handoff: Developer 2 → Developer 1

**From:** Developer 2 (security-engine)  
**To:** Developer 1 (agent-core, tool-execution, wiring)  
**Branch:** `feature/security-engine`

---

## What's Ready

The security engine is fully implemented at `src/lib/security/`.

### Public surface (`src/lib/security/index.ts`)

```typescript
// Wiring factory — returns the full security bundle
createSecurity(approvalTtlMs?: number): {
  engine: PolicyEngine,
  authority: CallAuthority,
  approvals: ApprovalStore,
}

// Audit log (file-backed JSONL)
createAuditLog(dir: string): AuditLog

// Policy loading
loadPolicy(filePath: string): Policy
defaultPolicy(): Policy

// Args hash — must be injected into ToolboxDeps.hashArgs
hashArgs(args: unknown): string

// Session state factory
createSessionSecurityState(sessionId: string, policy: Policy): SessionSecurityState
```

All interfaces match `docs/contracts.md` v0.1.0 exactly.

---

## Wiring Instructions for Developer 1

### Step 1 — Wire the security bundle into your agent

```typescript
import { createSecurity, createAuditLog, loadPolicy, hashArgs, createSessionSecurityState } from "@/lib/security";
import { createToolbox } from "@/tools";

const policy = loadPolicy("./fixtures/policies/default.json");
const audit = createAuditLog("./sandbox/logs");
const { engine, authority, approvals } = createSecurity();

const { registry, executor } = createToolbox(definitions, { authority, hashArgs, audit });

const agent = createAgent({
  provider,
  engine,
  authority,
  approvals,
  audit,
  registry,
  executor,
  policy,
});
```

### Step 2 — Switch `@contracts` alias (when contracts are AGREED)

Update `tsconfig.json` and `vitest.config.mts`:
```json
"@contracts": ["./src/lib/contracts/index.ts"]
```
Then delete `src/lib/agent/stubs/contracts.ts`.

---

## Confirmed Behavioural Contracts

Per `docs/handoff/dev1-to-dev2.md` items 4–8:

- ✅ **`authorize()` never throws** — guaranteed by try/catch fail-safe returning deny
- ✅ **`issue()` throws `ISSUE_REFUSED`** for denied/unknown/already-issued decisions  
- ✅ **`verifyAndConsume()` prevents replay** — tokens are single-use, identity-checked
- ✅ **`recordIngestion()` is pure** — returns new state, never mutates
- ✅ **`scan()` is pure** — runs detectors, never mutates state
- ✅ **`approvals.markConsumed()` throws** if status is not "approved"
- ✅ **`hashArgs()` matches `testHashArgs()`** — verified by test `tests/security/hash.test.ts`

---

## Policy Behavior Notes

1. **`email.send` and `file.write`** always produce `require_approval` regardless of policy (ALWAYS_APPROVE set enforces this).

2. **`email.send` when tainted with unknown recipient** — `R-EMAIL-SEND-TAINTED` upgrades to `require_approval`. If the recipient is in `policy.email.contacts` or `policy.email.recipientAllowlist`, it passes to the sensitive-action gate.

3. **Unknown tool names** — `R-TOOL-KNOWN` returns deny and `tool: null`. The agent's `decision.tool === null` guard handles this.

4. **Budget exhaustion** — `R-BUDGET` denies once `state.toolCallCount >= policy.limits.maxToolCalls`. The agent already enforces `maxSteps` separately.

---

## Open Questions (from dev1-to-dev2.md)

**Q9 (Budget scope):** Currently `toolCallCount` is session-wide. I'd suggest keeping it session-wide and letting the agent enforce per-turn `maxSteps`. No change needed for MVP.

**Q10 (Rejected re-proposal):** Not implemented in this branch. Add rule `R-REJECTED-REPLAY` post-MVP: track `argsHash` of rejected decisions in `SessionSecurityState` and deny re-proposals within the same session.

---

## Known Limitations (not blocking MVP)

1. `R-ARGS-SCHEMA` uses `passthrough()` schemas via the test registry. Real tool schemas from `src/tools/definitions.ts` will enforce strict validation.

2. `sandbox/` directory path defaults to `./sandbox` via `process.env.SANDBOX_DIR`. Must be set before file tool calls.

3. Audit log (`createAuditLog`) is file-backed. For the dashboard's GET `/api/audit` route, the `AuditLog.list(sessionId)` method reads from the in-memory array only — not from the file. This is fine for a single-process MVP.

4. Approval TTL defaults to 10 minutes. Make this configurable via env for the dashboard.

---

## Files Added

```
src/lib/security/
  index.ts          ← public surface (createSecurity, createAuditLog, hashArgs, …)
  engine.ts         ← PolicyEngine implementation
  authority.ts      ← CallAuthority with HMAC-SHA256 signed tokens
  approvals.ts      ← ApprovalStore (in-memory)
  audit.ts          ← AuditLog (file-backed JSONL + in-memory for tests)
  hash.ts           ← hashArgs() — canonical JSON sha256
  policy.ts         ← defaultPolicy(), loadPolicy()
  detectors/
    index.ts        ← 10 injection-detection patterns + scan()
  rules/
    index.ts        ← 9 deterministic policy rules

tests/security/
  hash.test.ts      ← hashArgs compatibility with testHashArgs
  detectors.test.ts ← 29 injection detector tests
  engine.test.ts    ← 32 policy engine tests
  authority.test.ts ← 8 token lifecycle tests
  approvals.test.ts ← 8 approval lifecycle tests
  adversarial.test.ts ← 30 red-team / threat scenario tests

docs/handoff/dev2-to-dev1.md  ← this file
```

## Test Results

```
 Test Files  6 passed (6)
      Tests  115 passed (115)
   Duration  ~6s (no LLM, no network, no file I/O)
```
