# Requirements: tool-execution

## Introduction
Tool-execution owns the tool registry, the executor that runs only authorized calls, the file sandbox and the tool implementations: email (fixture mailbox and simulated outbox), web fetch, PDF text extraction and sandboxed file operations. Every tool output is returned as untrusted content.

Shared types: #[[file:docs/contracts.md]]

## Requirement 1: Registry
**User story:** As a developer, I want one list of tools with fixed metadata, so that security and the model see the same definitions.

**Acceptance criteria**
1. The registry SHALL contain exactly the `ToolName`s in the contracts, each with description, sensitivity, `producesUntrustedContent` and a strict Zod input schema that rejects unknown keys.
2. Sensitivities SHALL be: `email.list`, `email.read`, `web.fetch`, `pdf.extract`, `file.list`, `file.read` → `read`; `file.write` → `write`; `email.send` → `external_send`.
3. `registry.get(name)` SHALL return `undefined` for any string not in the registry, including prototype keys such as `__proto__` and `constructor`.

## Requirement 2: Executor accepts only authorized calls
**User story:** As the operator, I want it to be impossible to run a tool without the security engine's permission.

**Acceptance criteria**
1. The executor SHALL call `CallAuthority.verifyAndConsume(call)` before running anything and SHALL return `UNAUTHORIZED` if it fails.
2. The executor SHALL re-parse `call.args` with the tool's schema and recompute the args hash. IF either differs from the call THEN it SHALL return `UNAUTHORIZED`.
3. The executor SHALL enforce a per-tool timeout (default 15 s) through `AbortSignal` and return `TIMEOUT` when exceeded.
4. The executor SHALL never throw; all failures are `ToolResult` with `ok: false`.
5. The executor SHALL write `tool_executed` or `tool_failed` audit events.
6. Tool implementations SHALL NOT be exported from the module's public surface; only the executor can invoke them.

## Requirement 3: Untrusted output
**Acceptance criteria**
1. Every successful result SHALL contain `ContentSegment`s created by a single `makeSegment` helper that sets `trust: "untrusted"` for sources `email`, `web`, `pdf`, `file` and `tool`.
2. Tools SHALL NOT be able to create segments with source `system` or `user`.
3. Segment text SHALL be truncated to a configurable limit (default 20,000 characters) with `truncated: true` and `sha256` of the full text.
4. `ToolError.message` SHALL be a fixed string per error code plus safe identifiers, never raw content.

## Requirement 4: File sandbox
**User story:** As the operator, I want file tools confined to one folder.

**Acceptance criteria**
1. All file access SHALL go through `resolveInSandbox(relativePath)`, rooted at `SANDBOX_ROOT` (default `./sandbox/workspace`).
2. IF the path is absolute, has `..` segments, a drive letter, a UNC prefix, a null byte, or resolves (after `realpath` of the nearest existing ancestor) outside the root THEN the tool SHALL return `SANDBOX_VIOLATION`.
3. IF the target or any existing ancestor inside the root is a symlink THEN the tool SHALL return `SANDBOX_VIOLATION`.
4. On Windows, root containment checks SHALL be case-insensitive.
5. Reads and writes SHALL be capped by size (default 64 KiB for text files, 10 MiB for PDFs) and return `LIMIT_EXCEEDED` beyond it.
6. `sandbox/state`, `sandbox/logs` and `sandbox/outbox` SHALL be outside `SANDBOX_ROOT`.

## Requirement 5: File tools
**Acceptance criteria**
1. `file.list { dir? }` SHALL return names, types and sizes of entries directly inside a sandbox directory (non-recursive, max 200 entries).
2. `file.read { path }` SHALL return UTF-8 text as a `file` segment.
3. `file.write { path, content, mode: "create" | "overwrite" }` SHALL write UTF-8 text. `create` SHALL fail with `INVALID_ARGS` if the file exists. Parent directories SHALL NOT be created implicitly.

## Requirement 6: Email tools
**User story:** As a demo user, I want realistic email reading and sending without touching a real mailbox.

**Acceptance criteria**
1. The mailbox SHALL be loaded from a JSON fixture (`MAILBOX_PATH`, default `fixtures/mailbox/default.json`) validated with Zod.
2. `email.list { unreadOnly?, limit? (1–20) }` SHALL return one `email` segment per message containing id, from, subject, date and a snippet. All of these fields are untrusted.
3. `email.read { messageId }` SHALL return headers and body of one message. `messageId` SHALL match `^[A-Za-z0-9_-]{1,64}$`.
4. `email.send { to (1–5 addresses), subject (≤200 chars), body (≤5000 chars) }` SHALL write one JSON file to `sandbox/outbox/` and SHALL NOT contact any mail server.
5. The outbox SHALL be readable by the evaluation harness to check attack goals.

## Requirement 7: Web fetch
**User story:** As a user, I want the agent to read web pages without being usable to attack my network.

**Acceptance criteria**
1. `web.fetch { url }` SHALL accept only `http:` and `https:` URLs without userinfo, max 2048 characters.
2. In `live` mode, the tool SHALL resolve the host and return `NETWORK_BLOCKED` if any resolved address is loopback, private, link-local, CGNAT, multicast, unspecified, or a cloud metadata address, for IPv4 and IPv6 (including IPv4-mapped IPv6).
3. Redirects SHALL be followed manually, at most 3, with the URL and address checks repeated on each hop.
4. Requests SHALL send no cookies or credentials, use a 10 s timeout and stop reading after 1 MiB.
5. Only `text/html` and `text/plain` responses SHALL be accepted.
6. HTML SHALL be converted to plain text with scripts and styles removed. Hidden elements SHALL be kept, because hidden text is a common injection carrier and must be visible to detectors.
7. In `fixtures` mode (`WEB_MODE=fixtures`), URLs under the fixture host SHALL be served from `fixtures/web/` with no network access. Tests and evaluation SHALL use this mode.
8. Every fetched URL (final URL after redirects) SHALL be recorded so evaluation can check `url_fetched` goals.

## Requirement 8: PDF extraction
**Acceptance criteria**
1. `pdf.extract { path }` SHALL read a `.pdf` inside the sandbox (evaluation copies fixture PDFs into a fresh sandbox per scenario) and return extracted text as a `pdf` segment.
2. Extraction SHALL be capped at 50 pages and the text limit from Requirement 3.3.
3. The PDF library SHALL be configured so that no script embedded in the PDF is executed.
4. Corrupt or encrypted PDFs SHALL return `INVALID_ARGS` with a fixed message.

## Requirement 9: No arbitrary execution
**Acceptance criteria**
1. No tool SHALL accept a command, script, expression or code argument.
2. A test SHALL fail if any file under `src/` references `child_process`, `node:vm`, `eval(`, `new Function` or a non-literal dynamic `import(`.
