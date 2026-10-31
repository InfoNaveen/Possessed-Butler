# Team Workflow

## Hackathon rules we follow
- All application code is written during the hackathon. No pasting in pre-written project code.
- Every external library, model and API is recorded in `README.md` (name, version, license, purpose, link) in the same PR that introduces it.
- Do not add a dependency or call an API that is not documented in the README and agreed by the team. Do not guess API shapes: link the official docs in the design doc that uses them.

## Spec-first
- Work is organized into four specs under `.kiro/specs/`: `agent-core`, `security-engine`, `tool-execution`, `evaluation`.
- Each spec has `requirements.md`, `design.md` and `tasks.md`. Implement tasks in order; tick them in `tasks.md` when merged.
- If implementation reveals the design is wrong, update the design first, then the code.

## Contract-first
- `docs/contracts.md` holds every shared TypeScript interface. Its status line says `PROPOSED` or `AGREED`.
- Nobody implements `src/lib/contracts/` until the status is `AGREED` and every spec owner has signed off in the sign-off table.
- Changing an agreed contract requires: a PR that edits `docs/contracts.md` first, sign-off from each affected spec owner, and a version bump in the changelog at the bottom of that file.
- Until contracts are agreed, modules may only be developed against local stubs that are deleted afterward.

## Build order (critical path to an end-to-end MVP)
1. Agree contracts. Scaffold Next.js, Tailwind, Zod, Vitest. Implement `src/lib/contracts/`.
2. In parallel:
   - security-engine: policy, rules, authorizer, approvals, audit log.
   - tool-execution: sandbox, registry, executor, file tools, email tools (fixtures + outbox).
   - agent-core: mock provider, orchestrator loop, API route.
3. First end-to-end slice with the mock provider: "summarize my emails" and "an injected email tries to send mail".
4. Real providers (Ollama first, as it needs no key), web and PDF tools, approval UI, audit UI.
5. Evaluation suite and report. Demo script.

The MVP is done when step 3 runs in CI and the compromised-model eval reports ASR = 0%.

## Branches and PRs
- `main` is always green. Work on `feat/<spec>-<short-name>` branches.
- Small PRs, one task (or a tight group of tasks) from `tasks.md` each.
- Every PR states which spec task IDs it completes.
- Any PR touching `src/lib/security/`, `src/lib/tools/executor*`, `src/lib/tools/sandbox*` or `docs/contracts.md` needs review from the security-engine owner.
- Run the security checklist in `.kiro/steering/security.md` on every PR.

## Definition of done
- Code matches the spec design, or the design was updated.
- `npx tsc --noEmit` passes.
- `npx vitest --run` passes.
- New security behavior has a test, preferably an eval scenario.
- New dependencies, models or APIs are in README.md.

## Ownership
| Spec | Owner | Backup |
|------|-------|--------|
| agent-core | TBD | TBD |
| security-engine | TBD | TBD |
| tool-execution | TBD | TBD |
| evaluation | TBD | TBD |

## Commands
- Install: `npm install`
- Dev server (run manually in your own terminal): `npm run dev`
- Typecheck: `npx tsc --noEmit`
- Tests: `npx vitest --run`
- Evaluation: `npm run eval` (defined in the evaluation spec)
