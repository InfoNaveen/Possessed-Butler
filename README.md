# The Possessed Butler

A tool-using AI agent that reads emails, browses websites, processes PDFs and performs controlled file and email actions, built to resist indirect prompt injection. Every tool call passes through a deterministic authorization layer that assumes the model may be fully compromised.

Built for an AI Security hackathon. All application code is written during the hackathon.

## Status
Milestone 1 (agent core): the agent loop, mock provider, tool registry/executor and read-only email tools work end to end in tests, using a test double for the security engine. The app is scaffolded, but its API routes are not wired yet. Contracts are still PROPOSED, so code compiles against a temporary mirror (`src/lib/agent/stubs/contracts.ts`). Open coordination items: [docs/handoff/dev1-to-dev2.md](docs/handoff/dev1-to-dev2.md).

The app was scaffolded with `create-next-app@16.4.3` (TypeScript, Tailwind, ESLint, App Router, `src/`). That generated boilerplate is the only code not written by hand.

- Shared TypeScript contracts: [docs/contracts.md](docs/contracts.md) (**PROPOSED**, awaiting team agreement)
- Steering: [.kiro/steering/](.kiro/steering/) (product, architecture, security, team workflow)
- Specs: [agent-core](.kiro/specs/agent-core/), [security-engine](.kiro/specs/security-engine/), [tool-execution](.kiro/specs/tool-execution/), [evaluation](.kiro/specs/evaluation/)

## How it defends (summary)
1. All content from emails, web pages, PDFs and files is wrapped as untrusted and taints the session.
2. The model only proposes tool calls. A rule-based policy engine decides allow, deny or require approval, using tool sensitivity, taint and argument provenance (for example, an email recipient must come from the user's own words, the address book or an allowlist).
3. Only engine-issued, signed, single-use capability tokens can run a tool.
4. Writes and sends after reading untrusted content need operator approval bound to the exact arguments.
5. No shell execution; file tools are confined to a sandbox; web fetch blocks private networks.
6. Every decision is logged; provider failures and malformed output fail closed.

## Running
Requires Node.js `^22.12` or newer (Vitest 5 requirement). Developed on Node.js 22.21.1, npm 10.9.4.
```powershell
npm install
npm run dev          # binds to 127.0.0.1; run in your own terminal
npm test             # vitest --run
npm run typecheck
npm run lint
npm run eval         # evaluation suite (not written yet)
```
Configuration goes in `.env.local` (copy `.env.example`). Never commit keys.

## External libraries, models and APIs
Every dependency must be listed here, with version and license, in the PR that introduces it. "Planned" entries are not installed yet.

### Libraries
| Name | Version | License | Purpose | Status | Link |
|------|---------|---------|---------|--------|------|
| Next.js | 16.4.3 | MIT | App Router UI and API routes | Installed | https://nextjs.org/docs |
| React / React DOM | 19.3.0 | MIT | UI | Installed | https://react.dev |
| TypeScript | 5.9.3 | Apache-2.0 | Language (dev) | Installed | https://www.typescriptlang.org |
| Tailwind CSS (+ `@tailwindcss/turbopack`) | 4.3.3 | MIT | Styling (dev) | Installed | https://tailwindcss.com/docs |
| Zod | 4.6.7 | MIT | Runtime validation; `z.toJSONSchema` for tool schemas (D2) | Installed | https://zod.dev |
| Vitest | 5.0.5 | MIT | Tests and evaluation suite (dev) | Installed | https://vitest.dev |
| ESLint + `eslint-config-next` | 9.39.5 / 16.4.3 | MIT | Linting (dev, from scaffold) | Installed | https://eslint.org |
| `@types/node`, `@types/react`, `@types/react-dom` | 22.x / 19.x | MIT | Type definitions (dev) | Installed | https://github.com/DefinitelyTyped/DefinitelyTyped |
| PDF text extraction library | TBD (decision T2: `pdfjs-dist`, `pdf-parse` or `unpdf`) | TBD | `pdf.extract` tool | Undecided | — |

Node.js built-ins in use: `node:crypto`. Planned: `node:fs`, `node:path`, `node:dns`, `node:net`, `node:os`. Also global `fetch` and `AbortSignal` (`timeout`, `any`).

### LLM provider APIs (called with `fetch`, no SDKs)
| Provider | API | Docs |
|----------|-----|------|
| Ollama (local) | `POST /api/chat` | https://docs.ollama.com/api/chat |
| Google Gemini | `models.generateContent` (REST) | https://ai.google.dev/api/generate-content |
| OpenAI | Chat Completions or Responses (decision P1) | https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create |

### Models
| Provider | Model | Used for | Date tested |
|----------|-------|----------|-------------|
| Ollama | TBD | Local demo, live eval | |
| Gemini | TBD | Live eval | |
| OpenAI | TBD | Live eval | |
| Mock | built-in | Tests and CI evaluation gate | |

## Known limitations
- Web fetch in live mode checks resolved IPs before connecting, but DNS rebinding between that check and the actual connection is not prevented in the MVP. Demo and evaluation use fixture-served pages.
- Mail is simulated: a JSON fixture mailbox and a local outbox folder. No real mail is read or sent.
- Approval protects only as well as the operator reviews it. The evaluation reports an "approve-all" counterfactual to make this visible.
