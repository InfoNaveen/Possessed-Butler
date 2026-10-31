# Security Rules (non-negotiable)

These rules apply to every change. If a task appears to require breaking one, stop and raise it with the team instead.

## Threat model
- The attacker controls the content of emails, web pages, PDFs and files the agent reads.
- The attacker does not control the user's chat input, our system prompt, code, config or policy files.
- **Assume the LLM can be fully compromised.** Any text the model outputs, including tool names and arguments, is attacker-influenced data. Security must hold even if the model does exactly what the injected content says.

## Rule 1: All external content is untrusted
- Every piece of content from a tool (email body, subject, sender name, web page, PDF text, file content) is wrapped as an untrusted `ContentSegment` with source, origin and hash before it reaches the model.
- Untrusted content is placed in clearly delimited data blocks in the prompt, never concatenated into system or user instructions.
- Spotlighting and delimiters are defense in depth, not the defense. The authorization layer is the defense.
- Ingesting untrusted content sets the session taint flag. Taint never clears within a session.

## Rule 2: Deterministic authorization for every tool call
- Every tool call proposed by the model goes through `SecurityEngine.authorize()` before execution. No exceptions, no "trusted" fast path.
- Decisions are produced by pure, deterministic code from: the proposal, the tool's declared sensitivity, the session policy, the session taint state and argument provenance. No LLM, no randomness, no network calls in the decision path.
- Heuristic injection detectors may add signals and raise a decision to `require_approval` or `deny`. They may never lower a decision to `allow`.
- Default is deny. Unknown tools, unknown arguments and schema validation failures are denied.
- The tool executor only accepts an `AuthorizedCall` issued by the security engine. It must re-verify the authorization before running.

## Rule 3: No arbitrary shell execution
- No `child_process`, `exec`, `spawn`, `eval`, `new Function`, `vm` or dynamic `import()` of user- or model-supplied paths anywhere in `src/`.
- No tool may accept a command, script or code string to run.
- A lint/test check enforces this (see tool-execution spec).

## Rule 4: Sandboxed file operations
- All file tools operate under a single sandbox root (`SANDBOX_ROOT`, default `./sandbox/workspace`).
- Paths are resolved and checked after normalization and symlink resolution. Reject absolute paths, `..` escapes, drive letters, UNC paths, null bytes and symlinks that resolve outside the root.
- Enforce size limits and an extension allowlist for reads and writes.
- Audit logs and approval state live outside the file tools' reach.

## Rule 5: Sensitive actions require explicit approval
- Actions with sensitivity `write` or `external_send` require human approval once the session is tainted, and always when policy says so.
- An approval binds to the exact tool name and a hash of the exact canonicalized arguments. If the arguments change, the approval is void.
- Approvals expire, are single-use, and can only be granted through the approval API by the operator, never by model output.
- `email.send` to a recipient that did not appear in the user's own instructions or the policy allowlist is denied, not just escalated.

## Rule 6: Log every security decision
- Log: content ingestion (source, origin, hash), every proposal, every authorization decision with rule IDs and reasons, approval requests and resolutions, executions, failures and provider errors.
- Logs are append-only JSONL. Never log secrets (API keys, auth headers). Truncate large content and log its hash instead.

## Rule 7: Fail safe
- Provider errors, timeouts, rate limits, malformed output and schema failures end the turn with an error message. They never cause a tool to run.
- Any exception inside the security engine results in `deny`.
- Exceeding the step budget, token budget or tool-call budget stops the agent.

## Secrets and network
- API keys come only from environment variables (`.env.local`, never committed). Keys are only read server-side.
- `web.fetch` allows only `http`/`https`, blocks private, loopback, link-local and metadata IP ranges (SSRF), enforces timeouts and response size limits, and does not forward cookies or credentials.
- Never send untrusted content to a provider that the operator has not configured.

## Review checklist for every PR
- [ ] Does any new code path execute a tool without `SecurityEngine.authorize()`?
- [ ] Does any new input from tools reach the model without being wrapped as untrusted?
- [ ] Can any decision be influenced by model output to become more permissive?
- [ ] Are new failure modes failing closed?
- [ ] Are new security decisions logged?
- [ ] Is there a test (ideally an eval scenario) for the new behavior?
