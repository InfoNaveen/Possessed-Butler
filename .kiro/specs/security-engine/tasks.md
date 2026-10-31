# Tasks: security-engine

Prerequisite: `docs/contracts.md` is AGREED and `src/lib/contracts/` exists (agent-core task 1).

- [ ] 1. Canonicalization and hashing
  - Implement `canonicalJson` (sorted keys, no whitespace, rejects non-JSON values) and `sha256Hex` with `node:crypto`.
  - Unit tests: key order independence, nested objects, arrays, rejection of functions/undefined/BigInt.
  - _Requirements: 2.4_

- [ ] 2. Policy schema and loader
  - `loadPolicy(path)` parses JSON with `PolicySchema`; throws `SecurityError("INVALID_POLICY")`.
  - Write `fixtures/policies/default.json` per design.
  - Tests: valid default, missing tool entry, bad types.
  - _Requirements: 11.1, 11.2, 11.3_

- [ ] 3. Rule framework and combination
  - `Rule` type, `combineOutcomes`, ordered `RULES`, `authorize()` with per-rule and whole-function try/catch.
  - Implement `R-TOOL-KNOWN`, `R-TOOL-ENABLED`, `R-ARGS-SCHEMA`, `R-BASE-ALLOW`.
  - Tests: unknown tool, disabled tool, bad args, throwing rule → deny, determinism.
  - _Requirements: 1.1–1.7, 2.1–2.4_

- [ ] 4. Taint tracking
  - `recordIngestion` returns new state; computes `maxSignalSeverity` via `scan`.
  - Tests: untrusted taints, trusted does not, taint never clears.
  - _Requirements: 3.1–3.3_

- [ ] 5. Sensitivity, budget and signal-escalation rules
  - `R-SENSITIVITY-APPROVAL`, `R-BUDGET-TOOL-CALLS`, `R-BUDGET-PER-STEP`, `R-SIGNAL-ESCALATION`.
  - _Requirements: 4.1–4.3, 6.1–6.2, 7.3, 7.4_

- [ ] 6. Provenance rules
  - `provenance.ts` helpers; `R-EMAIL-RECIPIENT-PROVENANCE`, `R-WEB-SCHEME`, `R-WEB-DOMAIN`, `R-WEB-EXFIL-QUERY`.
  - Tests: recipient only in email body → deny; recipient typed by user → allow path; contact name in user text → allowed; look-alike domains; userinfo URLs; `javascript:` and `file:` schemes; long query after taint.
  - _Requirements: 5.1–5.5_

- [ ] 7. File argument rules
  - `isSafeRelativePath`, `R-FILE-PATH`, `R-FILE-EXTENSION`, `R-FILE-SIZE`.
  - Tests: `../x`, `/etc/passwd`, `C:\x`, `\\server\share`, `a\0b`, mixed separators, `.MD` casing, multibyte content size.
  - _Requirements: 5.6–5.8_

- [ ] 8. Injection detectors
  - Five detectors from design, `scan()` aggregator.
  - Tests with positive and negative strings for each.
  - _Requirements: 7.1, 7.2_

- [ ] 9. Approval store
  - State machine, TTL with injected clock, keeps original decision reference.
  - Tests: every valid and invalid transition, expiry, single use.
  - _Requirements: 8.1–8.5_

- [ ] 10. Call authority
  - `createSecurity()` returning `{ engine, authority, approvals }` sharing the decision `WeakSet`. HMAC signing, `verifyAndConsume`.
  - Tests: forged decision, forged signature, expired token, replay, argsHash mismatch with approval, approval of different decision.
  - _Requirements: 9.1–9.3, 8.5_

- [ ] 11. Audit log
  - `createAuditLog(dir)`, `redact()`, UUID check on session id, fail-closed write.
  - Tests: redaction of key-like fields, truncation to `{sha256,length,preview}`, write failure throws `AUDIT_WRITE_FAILED`.
  - _Requirements: 10.1–10.5_

- [ ] 12. Public surface and boundary check
  - `index.ts` exports only contract implementations and `createSecurity`, `createAuditLog`, `loadPolicy`.
  - Test that fails if any file in `src/lib/security/` imports from `agent`, `providers` or tool implementations.
  - _Requirements: 1.3_
