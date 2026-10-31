# Tasks: tool-execution

Prerequisite: `docs/contracts.md` is AGREED and `src/lib/contracts/` exists. Executor tasks need security-engine tasks 1 and 10 (or an agreed stub of `CallAuthority`).

- [x] 1. Segments helper
  - `makeSegment` with source whitelist, truncation, full-text SHA-256.
  - Tests: rejects `system`/`user`, truncation flag, hash of full text.
  - _Requirements: 3.1–3.3_

- [ ] 2. Sandbox
  - `resolveInSandbox`, symlink walk, Windows case handling, size checks. Create `sandbox/workspace` at startup if missing.
  - Tests: hostile path table, symlink escape, oversize.
  - _Requirements: 4.1–4.6_

- [ ] 3. Registry and definitions
  - [x] `ToolDefinition` type, `Map`-based registry (`src/tools/toolbox.ts`), `list()` returning metadata only, tests.
  - [ ] Strict schemas for the remaining six tools (email.list and email.read are done).
  - Tests: sensitivities, `__proto__`/`constructor` lookups return undefined, schemas reject extra keys.
  - _Requirements: 1.1–1.3_

- [x] 4. Executor
  - Done against the test double. Args hash is injected (`ToolboxDeps.hashArgs`), pending security-engine export (handoff item 1).
  - Flow from design, timeout, error mapping, audit events.
  - Tests: forged/replayed token, args swap, timeout, throwing tool, never throws.
  - _Requirements: 2.1–2.6, 3.4_

- [ ] 5. File tools
  - `file.list`, `file.read`, `file.write` (create/overwrite).
  - _Requirements: 5.1–5.3_

- [ ] 6. Email tools and fixtures
  - [x] `MailboxSchema`, `email.list`, `email.read` (in-memory mailbox), tests.
  - [ ] `fixtures/mailbox/default.json` (benign messages plus one injected message), file loader, `email.send` to outbox (drafting).
  - Tests: invalid fixture rejected, outbox file contents, no `fetch` calls.
  - _Requirements: 6.1–6.5_

- [ ] 7. Checkpoint: first end-to-end slice
  - With agent-core's mock provider: "summarize my emails" succeeds; injected email's `email.send` to the attacker is denied and audited.

- [ ] 8. Web fetch
  - `isBlockedAddress`, `LiveTransport` with manual redirects and size cap, `FixtureTransport`, `html-to-text` (after decision T1), fetch log.
  - Tests per design.
  - _Requirements: 7.1–7.8_

- [ ] 9. PDF extraction
  - Resolve decision T2 with the team, link the library's official docs in design.md, add it to README.md, then implement `pdf.extract` with page and size caps.
  - Tests: benign PDF, injected PDF, corrupt PDF.
  - _Requirements: 8.1–8.4_

- [x] 10. No-execution guard
  - Vitest test that scans `src/**/*.{ts,tsx}` for forbidden primitives (`tests/no-exec.test.ts`).
  - _Requirements: 9.1, 9.2_
