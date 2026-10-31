# Tasks: agent-core

- [ ] 0. Contract agreement (blocking)
  - Review `docs/contracts.md` with all spec owners, resolve open decisions D1–D5, set status to AGREED, fill the sign-off table.

- [ ] 1. Scaffold and contracts
  - [x] Next.js 16.4.3 app via `create-next-app`, Zod 4.6.7, Vitest 5.0.5; versions in README.md.
  - [x] Scripts `test`, `typecheck`, `lint`, `eval`; `.gitignore` for `sandbox/`, `eval-results/`, `.env*` (except `.env.example`); `.env.example`.
  - [ ] Implement `src/lib/contracts/` from the agreed document. **Blocked on task 0.** Until then the code uses the temporary mirror `src/lib/agent/stubs/contracts.ts` via the `@contracts` alias.
  - _Requirements: 1.1–1.4_

- [ ] 2. Configuration
  - [x] `ConfigSchema`, `parseConfig()` (names only in errors), tests.
  - [ ] `getConfig()` from `process.env` and 503 helper for routes (with task 6).
  - _Requirements: 2.1–2.3_

- [ ] 3. Mock provider and model output parser
  - [x] `createMockProvider` with `scripted`, `garbage`, `failAfter` (provider errors); `parseModelAction`; tests.
  - [ ] `compromised` script (with evaluation task 2, which defines the `ATTACK_CALL` fixture marker).
  - _Requirements: 3.5, 4.1–4.3_

- [x] 4. Prompt builder and notices
  - `SYSTEM_PROMPT`, `buildRequest`, delimiter nonce and neutralization, fixed notice templates, tests.
  - _Requirements: 5.1–5.4_

- [x] 5. Session store and orchestrator
  - `runTurn`, `resumeAfterApproval`, `executeAndIngest`, per-session lock. Tests use the test double `tests/doubles/security-double.ts`; re-run against the real engine when it lands.
  - Open question on budget scope: see `docs/handoff/dev1-to-dev2.md` item 9.
  - _Requirements: 6.1–6.9, 7.1–7.2_

- [ ] 6. API routes and guard
  - Four routes, `_guard.ts`, Zod request schemas. No `runtime` export (Cache Components; see design). Needs the real security engine for wiring.
  - Tests for guard and validation.
  - _Requirements: 7.3, 8.1–8.4_

- [ ] 7. Checkpoint: first end-to-end slice (with tool-execution task 7)
  - Through `POST /api/agent` with the mock provider: benign email summary works; injected `email.send` to an unknown address is denied and visible in `GET /api/audit`.

- [ ] 8. Minimal UI
  - Chat, approval card, audit panel. Text-only rendering.
  - _Requirements: 9.1, 9.2_

- [ ] 9. Ollama adapter
  - Confirm request/response fields from the linked docs, implement, test with mocked `fetch`. Manual smoke test against a local model; record model in README.
  - _Requirements: 3.1–3.4, 3.6_

- [ ] 10. Gemini adapter
  - Resolve P2, confirm fields from docs, implement, mocked tests.
  - _Requirements: 3.1–3.4, 3.6_

- [ ] 11. OpenAI adapter
  - Resolve P1, confirm fields from docs, implement, mocked tests.
  - _Requirements: 3.1–3.4, 3.6_
