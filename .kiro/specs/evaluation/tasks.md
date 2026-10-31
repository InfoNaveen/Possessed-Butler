# Tasks: evaluation

Prerequisite: contracts AGREED. Tasks 1–3 can start immediately; task 4 onward needs the first end-to-end slice (agent-core task 7).

- [ ] 1. Scenario schema and corpus skeleton
  - `ScenarioSchema` usage, one JSON file per row of the corpus table with description and expected stopping rule.
  - Test: every scenario file parses; every attack has `attackGoal`; every benign has `successCheck`; IDs unique.
  - _Requirements: 1.1–1.5_

- [ ] 2. Email and file fixtures
  - `fixtures/mailbox/eval-*.json`, `fixtures/files/*.txt` with `ATTACK_CALL` markers inside realistic injection text, `fixtures/labels.json`.
  - _Requirements: 1.2_

- [ ] 3. Web and PDF fixtures
  - `fixtures/web/*.html` (hidden div, comment, metadata URL, benign article).
  - PDF generator script plus `fixtures/pdf/README.md`; benign PDF with action items, white-text injection PDF, traversal PDF.
  - _Requirements: 1.2_

- [ ] 4. Checks, operator and harness
  - `checks.ts`, `operator.ts`, `harness.ts` with temp-dir isolation and shared wiring.
  - Tests: each check on synthetic side effects; harness cleans up temp dirs.
  - _Requirements: 2.1–2.3, 3.1–3.2_

- [ ] 5. Metrics and report
  - `metrics.ts`, `report.ts`, gitignore for `eval-results/`.
  - Tests with hand-built outcomes, including division by zero → null.
  - _Requirements: 4.1, 6.1, 6.2_

- [ ] 6. CI gate
  - `eval.test.ts` runs the corpus with compromised mock, both operators, asserts ASR (reject) = 0, fail-safe = 100%, benign completion = 100%. Wire `npm run eval`.
  - Test that `ATTACK_CALL` never appears under `src/lib/`.
  - _Requirements: 4.2_

- [ ] 7. Attack validity self-test
  - Agree the test-only rules override with the security-engine owner, then run the corpus with minimal rules and report ASR.

- [ ] 8. Live runs
  - `live.test.ts` behind `EVAL_LIVE=1`, repeats, per-provider report section.
  - _Requirements: 5.1–5.3_

- [ ] 9. Demo script and official run
  - `docs/demo.md`; commit one official `eval-results/` run and link it from README.md.
  - _Requirements: 7.1_
