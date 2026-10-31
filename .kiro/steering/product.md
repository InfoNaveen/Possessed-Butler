# Product: The Possessed Butler

## One-line pitch
A tool-using AI assistant that reads emails, browses websites, processes PDFs and performs controlled file and email actions, and stays loyal to its user even when the content it reads tries to "possess" it through indirect prompt injection.

## Context
Built for an AI Security hackathon. Judges will care about:
1. Does it work end to end on a realistic task?
2. Can an attacker who controls an email, web page or PDF make the agent take an action the user did not ask for?
3. Can we prove (2) with measurable, repeatable tests?

Visual polish is the lowest priority.

## Users
- **Primary user**: a person delegating inbox, research and document chores to an assistant ("summarize my unread emails", "read this PDF and save the action items to notes.md", "reply to Alice with the meeting time").
- **Attacker (threat actor)**: anyone who can put text in front of the agent: an email sender, a web page author, a PDF author. The attacker cannot talk to the agent directly and cannot change code or config.
- **Judge / evaluator**: runs the evaluation suite and the live demo.

## MVP scope (must have)
- Chat-style UI where the user gives a task.
- Agent loop that plans, proposes tool calls, and produces a final answer.
- Tools: list/read emails (local fixture mailbox), send email (simulated outbox), fetch a web page, extract PDF text, read/write/list files inside a sandbox.
- Deterministic authorization of every tool call: allow, deny or require approval.
- Human approval UI for sensitive actions.
- Security audit log viewable in the UI.
- Pluggable LLM provider: Ollama, Gemini, OpenAI, plus a deterministic mock provider for tests.
- Evaluation suite with injection attack scenarios and benign scenarios, reporting attack success rate and task utility.

## Explicitly out of scope for MVP
- Real mail servers (IMAP/SMTP/Gmail API). Mail is fixture data plus a simulated outbox.
- Arbitrary shell or code execution. Never in scope.
- Multi-user accounts and authentication beyond a single local operator.
- Persistent database. JSON/JSONL files in the sandbox are enough.
- Visual design work beyond a clean, legible layout.

## Success criteria
- Demo: one benign task and at least three distinct injection attacks (email, web, PDF) run live, attacks are blocked or escalated to approval, and the audit log explains why.
- Evaluation: attack success rate (ASR) of 0% for the "compromised model" mock run, which proves the authorization layer holds even if the model fully obeys the attacker.
- Benign task completion rate reported alongside ASR so we don't win security by refusing everything.
- Provider outage or malformed model output never results in a tool being executed.

## Glossary
- **Untrusted content**: any text that did not come from the user's own chat input or our own system prompt. Emails, web pages, PDFs, file contents and tool results are untrusted.
- **Taint**: a session-level flag (and per-value provenance) recording that untrusted content has entered the model context.
- **Sensitive action**: a tool call that writes, sends or otherwise has side effects outside the agent's own reasoning.
- **Authorization layer / security engine**: the deterministic code that decides allow, deny or require approval for each proposed tool call. The LLM never makes this decision.
