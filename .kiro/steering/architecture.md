# Architecture

## Stack
- Next.js (App Router) with TypeScript in strict mode. Server-side logic runs in Route Handlers under `src/app/api/**/route.ts` on the Node.js runtime (not Edge), because file sandboxing needs `node:fs` and `node:path`.
- Tailwind CSS for styling. Minimal UI.
- Zod for every runtime boundary: HTTP request bodies, model output, tool arguments, tool results, config, fixtures.
- Vitest for unit, integration and evaluation tests. Always run single-shot: `npx vitest --run`.
- LLM providers are called with the built-in `fetch` against their documented HTTP APIs. No provider SDKs unless the team agrees and records them in README.md.

## Module boundaries
Four modules, each owned by one feature spec. Dependencies point only in the directions shown.

```
                  ┌────────────────────┐
  UI / API routes │ src/app            │
                  └─────────┬──────────┘
                            │
                  ┌─────────▼──────────┐       ┌──────────────────┐
                  │ src/lib/agent      │──────►│ src/providers│
                  │ (agent-core)       │       │ (agent-core)     │
                  └───┬────────────┬───┘       └──────────────────┘
                      │            │
        ┌─────────────▼───┐   ┌────▼──────────────┐
        │ src/lib/security│   │ src/tools     │
        │ (security-engine)│◄──│ (tool-execution)  │
        └────────┬────────┘   └────────┬──────────┘
                 │                     │
                 └──────────┬──────────┘
                    ┌───────▼────────┐
                    │ src/lib/contracts│  shared types + Zod schemas only
                    └────────────────┘
```

- `contracts` has no runtime dependencies other than Zod. Everything else may import it.
- `agent` orchestrates: calls the provider, asks `security` to authorize, asks `tools` to execute an `AuthorizedCall`. It never runs tool code directly.
- `providers` know nothing about tools' implementations or security. They translate `LLMRequest` → HTTP → `LLMResponse`.
- `security` is pure and deterministic. It must not import `providers`, `agent` or tool implementations. It reads tool metadata (name, sensitivity, schema) from the registry contract only.
- `tools` may import `security` only to verify an `AuthorizedCall`. Tools must not import `agent` or `providers`.
- `src/eval` (evaluation spec) may import everything; nothing in `src/lib` imports `src/eval`.

## Directory layout (target)
```
src/
  app/
    page.tsx                     chat, approvals panel, audit log panel
    api/agent/route.ts           POST: start/continue a session turn
    api/approvals/route.ts       GET pending approvals
    api/approvals/[id]/route.ts  POST approve/reject
    api/audit/route.ts           GET audit events for a session
  lib/
    contracts/                   shared TS types + Zod schemas (see docs/contracts.md)
    agent/                       orchestrator loop, prompt builder, session store, config
    security/                    engine, policy, rules/, taint, provenance, detectors/, approvals, audit
  providers/                     ollama.ts, gemini.ts, openai.ts, mock.ts, index.ts
  tools/                         toolbox (registry + executor), segments, sandbox, email/, web/, pdf/, file/
  components/                    UI components
  eval/                          scenarios, runner, metrics, report
fixtures/
  mailbox/                       benign + malicious emails (JSON)
  web/                           benign + malicious HTML pages, served via FixtureTransport (no network)
  pdf/                           benign + malicious PDFs
  policies/                      default policy JSON
sandbox/                         runtime state, gitignored
  workspace/                     the only directory file tools can touch
  outbox/                        simulated sent mail
  state/                         approvals, sessions (not reachable from file tools)
  logs/                          audit JSONL (not reachable from file tools)
tests/                           unit + integration tests mirroring src/
```

## Request flow (one agent turn)
1. UI posts the user's message to `POST /api/agent`.
2. Agent appends the user message as a trusted segment and builds the prompt: system prompt + user instructions + untrusted data blocks.
3. Provider returns either a final answer or tool call proposals. Output is parsed with Zod. Parse failure ends the turn safely.
4. For each proposal: `security.authorize(proposal, sessionState)` → `AuthorizationDecision`.
   - `allow` → `tools.execute(authorizedCall)` → result wrapped as untrusted `ContentSegment`, session tainted.
   - `require_approval` → `ApprovalRequest` stored, turn pauses, UI shows the pending action.
   - `deny` → model receives a short, fixed denial notice (no attacker text echoed), loop continues or stops per budget.
5. All of the above is written to the audit log.
6. Loop ends on final answer, budget exhaustion, pending approval or error.

## Shared contracts
All cross-module TypeScript interfaces are defined in one document and must be agreed before any of them are implemented. Implementation of `src/lib/contracts/` mirrors it exactly.

#[[file:docs/contracts.md]]

## Configuration
- `.env.local` (never committed): `LLM_PROVIDER` (`ollama` | `gemini` | `openai` | `mock`), `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `GEMINI_API_KEY`, `GEMINI_MODEL`, `OPENAI_API_KEY`, `OPENAI_MODEL`, `SANDBOX_ROOT`, `POLICY_PATH`.
- `.env.example` is committed with names only, no values.
- Config is parsed with Zod at startup. Invalid config means the agent API returns 503, never a partially configured agent.

## Conventions
- No `any`. Use `unknown` plus Zod parsing at boundaries.
- Errors crossing module boundaries are typed (`ProviderError`, `ToolError`, `SecurityError`) with a stable `code`.
- Pure functions for policy rules so they are unit-testable without I/O.
- Every module exposes a small `index.ts` public surface; other modules import only from it.
