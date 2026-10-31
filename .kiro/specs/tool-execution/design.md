# Design: tool-execution

Shared types: #[[file:docs/contracts.md]]

## Overview
```
src/lib/tools/
  index.ts             exports createToolRegistry, createToolExecutor, tool metadata only
  definitions.ts       internal ToolDefinition type
  registry.ts          Map-based registry built from definitions (no plain-object lookup)
  executor.ts          verify → re-parse → re-hash → run with timeout → validate → wrap
  segments.ts          makeSegment(source, origin, text, limit)
  sandbox.ts           resolveInSandbox(), assertNoSymlinks(), size checks
  email/
    mailbox.ts         MailboxSchema, loadMailbox()
    list.ts, read.ts, send.ts
  web/
    fetch.ts           tool definition
    transport.ts       WebTransport interface; LiveTransport, FixtureTransport
    ip-guard.ts        isBlockedAddress(ip)
    html-to-text.ts    minimal extractor (see decision T1)
  pdf/
    extract.ts         wraps the PDF library chosen in T2
  file/
    list.ts, read.ts, write.ts
```

## Internal types

```ts
// internal to tool-execution
interface ToolDeps {
  sandboxRoot: string;     // absolute, realpath'd at startup
  outboxDir: string;
  mailbox: Mailbox;
  web: WebTransport;
  fetchLog: (finalUrl: string) => void;
  limits: { textChars: number; textFileBytes: number; pdfBytes: number; pdfPages: number };
}

interface ToolDefinition<I> extends ToolMetadata {
  inputSchema: z.ZodType<I>;
  timeoutMs: number;
  run(args: I, deps: ToolDeps, ctx: ToolContext): Promise<{ segments: NewSegment[]; summary: string }>;
}

type NewSegment = { source: "email" | "web" | "pdf" | "file" | "tool"; origin: string | null; text: string };

interface WebTransport {
  get(url: URL, signal: AbortSignal): Promise<{ status: number; headers: Headers; body: string; finalUrl: string }>;
}
```

`NewSegment.source` excludes `system` and `user` at the type level, and `makeSegment` re-checks at runtime.

## Executor flow
```
execute(call, ctx):
  1. r = authority.verifyAndConsume(call)            → UNAUTHORIZED on failure
  2. def = registry.internalGet(call.tool)           → UNAUTHORIZED if missing
  3. parsed = def.inputSchema.safeParse(call.args)   → UNAUTHORIZED if fails
  4. sha256Hex(canonicalJson(parsed.data)) === call.argsHash   else UNAUTHORIZED
  5. signal = AbortSignal.any([ctx.signal, AbortSignal.timeout(def.timeoutMs)])
  6. out = await def.run(parsed.data, deps, { ...ctx, signal })   (try/catch → typed ToolError)
  7. segments = out.segments.map(makeSegment)
  8. audit.append(tool_executed {tool, argsHash, segmentIds, hashes}) and return ok result
```
Step 1 consumes the token before anything else, so a failed run cannot be retried with the same token.

`AbortSignal.any` and `AbortSignal.timeout` require a recent Node.js. Confirm the Node version at scaffold time and record it in README; fall back to a manual `AbortController` + `setTimeout` if unavailable.

## Sandbox algorithm
```
resolveInSandbox(rel):
  reject if rel contains "\0", starts with "/" or "\\", matches /^[a-zA-Z]:/, starts with "\\\\" or "//"
  segments = rel.split(/[\\/]+/); reject if any === ".."
  abs = path.resolve(root, ...segments)
  walk from root to abs: for each existing component, lstat; reject if isSymbolicLink()
  real = realpath(nearest existing ancestor of abs)
  contained = (win32 ? lower(real) : real) === rootCmp || startsWith(rootCmp + path.sep)
  reject if !contained
  return abs
```
Writes use `fs.writeFile(abs, content, { flag: mode === "create" ? "wx" : "w" })` after the check. Known limitation: a race between check and use is possible only for a local attacker with filesystem access, which is outside our threat model.

## Email
- Mailbox fixture shape: `{ owner: { name, address }, messages: [{ id, from: { name, address }, to: [...], subject, date, unread, body }] }`.
- `email.list` segment text format (one segment per message so each has its own origin and hash):
  `id: <id>\nfrom: <name> <address>\nsubject: <subject>\ndate: <date>\nsnippet: <first 200 chars>`
- `email.send` writes `sandbox/outbox/<timestamp>-<uuid>.json` with `{ to, subject, body, sessionId, sentAt }` and returns a `tool` segment `"Email queued to N recipient(s)."`.

## Web fetch
- `LiveTransport`: `dns.promises.lookup(host, { all: true })`, check every address with `isBlockedAddress`, then `fetch(url, { redirect: "manual", credentials: "omit", signal })`. Read the body as a stream and stop at 1 MiB. For 3xx, resolve `Location` against the current URL and repeat checks, max 3 hops.
- Known limitation (documented in README): DNS can change between our lookup and `fetch`'s own lookup (DNS rebinding). Closing it needs a custom connection lookup, which would add an HTTP client dependency. Not in MVP. Demo and eval use `FixtureTransport`.
- `FixtureTransport`: maps `https://fixtures.butler.test/<path>` to `fixtures/web/<path>` (path checked with the same sandbox function rooted at `fixtures/web`). Any other host → `NETWORK_BLOCKED`. The `.test` TLD is reserved and never resolves publicly.
- `isBlockedAddress` covers: `0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.168/16, 224/4, 240/4, 255.255.255.255, ::, ::1, fc00::/7, fe80::/10, ff00::/8, ::ffff:0:0/96 (check embedded v4)`. Implemented with `node:net` `isIP` plus manual parsing; no dependency.

## Decision T1: HTML to text
Proposal: write a minimal extractor in-house: drop `<script>`, `<style>`, `<noscript>` and `<template>` blocks, keep the text inside HTML comments (comments can carry injections, and detectors should see them), strip remaining tags, decode a fixed set of entities (`&amp; &lt; &gt; &quot; &#39; &nbsp;` and numeric), collapse whitespace. No dependency, deterministic, adequate for MVP.
Alternative: an HTML parser library. Better fidelity, adds a dependency to record in README.

## Decision T2: PDF library
We need a dependency here; extracting PDF text by hand is out of scope. Candidates to evaluate at implementation time: `pdfjs-dist` (Mozilla PDF.js), `pdf-parse`, `unpdf`. Selection criteria: maintained, works in the Node.js runtime of a Next.js route handler, license compatible, a documented way to disable script evaluation, page-count access. **The chosen library's API must be taken from its official docs and linked here before coding. No guessed calls.**

## Error mapping
| Condition | Code |
|-----------|------|
| verify/hash/parse mismatch | UNAUTHORIZED |
| Schema failure inside tool (should not happen after step 3) | INVALID_ARGS |
| ENOENT, unknown message id | NOT_FOUND |
| sandbox rejection | SANDBOX_VIOLATION |
| size/page/entry caps | LIMIT_EXCEEDED |
| blocked IP, non-fixture host in fixture mode, bad content type | NETWORK_BLOCKED |
| abort by timeout | TIMEOUT |
| anything else | INTERNAL |

## Testing strategy
- Sandbox: table of hostile paths on both POSIX and Windows forms; symlink escape test (skip on Windows if symlink creation is not permitted, and record the skip).
- Executor: forged token, replayed token, args swapped after authorization, timeout, tool throwing.
- Email: fixture validation, outbox write, no network (spy on `fetch`).
- Web: `isBlockedAddress` table, redirect to private IP blocked, size cap, content-type check, fixture mode.
- PDF: benign fixture, injected fixture, corrupt file.
- Static scan for forbidden execution primitives (Requirement 9.2).
