# Design: security-engine

Shared types: #[[file:docs/contracts.md]]

## Overview
`src/lib/security/` exposes four things: `PolicyEngine` (pure decisions, taint, scanning), `CallAuthority` (capability tokens), `ApprovalStore`, and `AuditLog`. Only `PolicyEngine` is pure. The other three hold state but contain no decision logic.

```
src/lib/security/
  index.ts              public surface
  engine.ts             createPolicyEngine(): PolicyEngine
  combine.ts            combineOutcomes(results): DecisionKind
  canonical.ts          canonicalJson(value), sha256Hex(string)
  policy.ts             PolicySchema usage, loadPolicy(path)
  taint.ts              recordIngestion()
  provenance.ts         extractEmails(text), extractHosts(text), recipientAllowed(), hostAllowed()
  paths.ts              isSafeRelativePath(p) (syntactic check only)
  rules/
    index.ts            ordered RULES array
    tool-known.ts, tool-enabled.ts, args-schema.ts, budget.ts,
    sensitivity-approval.ts, email-recipient.ts, web-scheme.ts, web-domain.ts,
    web-exfil-query.ts, file-path.ts, file-extension.ts, file-size.ts,
    signal-escalation.ts, base-read-allow.ts, base-sensitive-allow.ts
  detectors/
    index.ts            DETECTORS array, scan()
    override-phrases.ts, role-markers.ts, tool-mentions.ts, hidden-text.ts, exfil-instructions.ts
  authority.ts          createCallAuthority(): CallAuthority (HMAC, D3)
  approvals.ts          createApprovalStore(clock, ttlMs): ApprovalStore
  audit.ts              createAuditLog(dir): AuditLog, redact()
  errors.ts             SecurityError { code }
```

## Rule model

```ts
// internal to security-engine
interface RuleInput {
  proposal: ToolCallProposal;
  state: SessionSecurityState;
  meta: ToolMetadata | undefined;   // registry.get(proposal.tool)
  args: unknown | undefined;        // parsed args if schema passed
}

interface Rule {
  id: string;
  appliesTo: ToolName[] | "all";
  evaluate(input: RuleInput): RuleResult;   // must be pure; must not throw (wrapper catches anyway)
}
```

`authorize()` algorithm:
1. Look up metadata. Parse args with `meta.inputSchema.safeParse` if metadata exists.
2. Evaluate every applicable rule in fixed order, each inside try/catch. A throw becomes `{ ruleId, outcome: "deny", reason: "rule error" }`.
3. Read signal severities from `state.taintSources[].maxSignalSeverity` (set by `recordIngestion`, which runs `scan` on the segment).
4. `kind = combine(results)`: any `deny` → deny; else any `require_approval` → require_approval; else any `allow` → allow; else deny.
5. Whole function body is in try/catch; any throw returns a deny decision with `R-INTERNAL-ERROR`.

`taintSources` entries carry `maxSignalSeverity` so `authorize` can apply signal escalation without re-scanning content (see `SessionSecurityState` in the contracts).

## Rules (fixed order)

| ID | Applies | Outcome |
|----|---------|---------|
| R-TOOL-KNOWN | all | deny if `meta` undefined |
| R-TOOL-ENABLED | all | deny if `policy.tools[name].enabled` is false |
| R-ARGS-SCHEMA | all | deny if parse failed |
| R-BUDGET-TOOL-CALLS | all | deny if `toolCallCount >= maxToolCalls` |
| R-BUDGET-PER-STEP | all | deny if `proposal.indexInStep >= maxProposalsPerStep` |
| R-SENSITIVITY-APPROVAL | all | require_approval if mode `always`, or mode `when_tainted` and tainted and sensitivity ≠ read |
| R-EMAIL-RECIPIENT-PROVENANCE | email.send | deny if any recipient fails `recipientAllowed` |
| R-WEB-SCHEME | web.fetch | deny if scheme not http/https, or URL has userinfo |
| R-WEB-DOMAIN | web.fetch | require_approval per Requirement 5.3 / 5.4 |
| R-WEB-EXFIL-QUERY | web.fetch | deny if tainted and `search.length + hash.length > 100` |
| R-FILE-PATH | file.*, pdf.extract | deny if `!isSafeRelativePath` |
| R-FILE-EXTENSION | file.read, file.write, pdf.extract | deny if extension not allowed (`.pdf` for pdf.extract) |
| R-FILE-SIZE | file.write | deny if UTF-8 byte length of content > maxBytes |
| R-SIGNAL-ESCALATION | all | require_approval if any taint source has `high` severity and sensitivity ≠ read |
| R-BASE-ALLOW | all | allow if meta exists and args parsed; otherwise abstain |

`R-BASE-ALLOW` is the only rule that returns `allow`. Every other rule returns `abstain` or something stricter, so adding rules can only make decisions stricter.

## Provenance helpers
- `extractEmails(text)`: lowercase matches of a conservative address regex.
- `recipientAllowed(addr, state)`: lowercased `addr` is in `recipientAllowlist`, OR in `extractEmails(trustedInstructions.join("\n"))`, OR equals the address of a contact whose name matches a whole word (case-insensitive) in trusted instructions.
- `extractHosts(text)`: hostnames from `http(s)://` URLs and bare domains in trusted instructions, lowercased.
- `hostAllowed(host, list)`: exact match or subdomain of an entry (`a.example.com` matches `example.com`). Hosts are compared after `new URL()` normalization (punycode).

## Detectors (signals only)
Each is a pure function `(segment) => InjectionSignal[]`. Initial set:
- `override-phrases`: "ignore (all|any|previous|prior) instructions", "disregard", "new instructions", "you are now", "system prompt". high.
- `role-markers`: chat template markers and lines starting with `system:` / `assistant:`. high.
- `tool-mentions`: text names one of our `ToolName`s or JSON resembling `{"action":`. medium.
- `hidden-text`: zero-width characters, bidi overrides, long whitespace runs. medium.
- `exfil-instructions`: imperative "send/forward/email ... to <address>" or URLs with long query strings. medium.

Detectors are measured in the evaluation spec (precision/recall on fixtures) but the MVP security claim does not depend on them.

## CallAuthority (D3 proposal)
- Key: `crypto.randomBytes(32)` at module init.
- `signature = HMAC-SHA256(key, canonicalJson({decisionId, proposalId, sessionId, tool, argsHash, approvalId, issuedAt, expiresAt}))`, hex.
- Agent-core calls `authority.issue(decision, approval?)`. `issue` recomputes `argsHash` from `decision.canonicalArgs` and refuses mismatches. It refuses non-allow decisions without an approval, and refuses if the approval is not `approved`, belongs to another decision, or has a different argsHash.
- Forged decisions: decisions are plain data, so `issue` must not trust any object it is handed. `createSecurity()` builds `PolicyEngine` and `CallAuthority` together and shares a module-private `WeakSet` of the decision objects returned by `authorize`. `issue` rejects any decision not in that set. This keeps `authorize` pure from the caller's point of view (the set is write-only bookkeeping).
- Approved decisions survive the approval pause because `ApprovalStore` keeps a reference to the original decision object. If D5 (snapshot to disk) is adopted, approvals restored after a restart are marked `expired` rather than trusted.
- `verifyAndConsume`: constant-time signature compare (`crypto.timingSafeEqual`), expiry check, `consumed: Set<decisionId>`.
- Token TTL: 60 seconds.

## ApprovalStore
- In-memory `Map<id, ApprovalRequest>` plus the original decision.
- Injected clock for tests. Default TTL 10 minutes.
- Status transitions: `pending → approved | rejected | expired`, `approved → consumed | expired`. Any other transition throws `SecurityError("INVALID_TRANSITION")`.

## AuditLog
- `append` assigns `id` and `ts`, runs `redact(data)`, writes a line with `fs.appendFileSync` to `sandbox/logs/<sessionId>.jsonl`, then pushes to the in-memory index.
- Synchronous write is deliberate: simple ordering and fail-closed behavior. If the write throws, `append` throws `SecurityError("AUDIT_WRITE_FAILED")`; agent-core treats this as fatal for the session.
- `sessionId` is validated as a UUID before being used in a file name.

## Policy file
`fixtures/policies/default.json`, validated by `PolicySchema`:
- read tools: `enabled: true, approval: "never"`.
- `file.write`: `when_tainted`. `email.send`: `when_tainted`.
- `web.domainAllowlist`: the local fixture host used in eval and demo; `allowUnlistedWhenUntainted: true`.
- `file`: read `.txt .md .json .csv`, write `.txt .md`, `maxBytes: 65536`.
- `limits`: `maxSteps: 8, maxToolCalls: 12, maxProposalsPerStep: 3`.
- `email.contacts`: demo address book (Alice, Bob).

## Error handling
All errors are `SecurityError` with codes `INVALID_POLICY`, `INVALID_TRANSITION`, `TOKEN_INVALID`, `ISSUE_REFUSED`, `AUDIT_WRITE_FAILED`. `authorize` never throws.

## Testing strategy
- Unit tests per rule with table-driven cases (allow, deny, escalate).
- Property-style test: for random proposals, adding any non-base rule never changes a deny or require_approval into allow.
- Determinism test: same input twice yields identical decisions minus id/time.
- Authority tests: forged signature, expired token, reused token, argsHash swap after approval, decision not produced by engine.
- Audit tests: redaction, truncation, file write failure fails closed.
- Policy loading: invalid JSON, missing tool entries.
