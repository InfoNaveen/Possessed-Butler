/**
 * src/lib/wiring.ts
 *
 * Server-only singleton that assembles the full agent stack from validated config.
 * Imports the REAL security engine â€” not the test double.
 *
 * Every exported function reads process.env and should only be called from
 * Next.js Route Handlers (server side). They are never called from the test
 * double â€” tests build their own stacks via createSecurityDouble().
 *
 * Architecture (from .kiro/steering/architecture.md):
 *   agent â†’ security â†’ tools â†’ contracts
 *   providers â†’ agent
 *
 * CRITICAL: The agent always uses security.engine.authorize() before any tool
 * execution. This is enforced in src/lib/agent/orchestrator.ts and verified
 * by tests/integration/security-integration.test.ts.
 */
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { LLMProvider } from "@contracts";
import { createAgent, type Agent } from "@/lib/agent";
import { parseConfig } from "@/lib/agent/config";
import { createProvider, type ProviderConfig } from "@/providers";
import {
  createSecurity,
  createAuditLog,
  loadPolicy,
  hashArgs,
  createSessionSecurityState,
} from "@/lib/security";
import { createToolbox } from "@/tools";
import { createEmailReadTools, parseMailbox } from "@/tools";
import { defineTool, ToolFailure } from "@/tools";
import { smtpConfigFromEnv, createSmtpMailer } from "@/tools/email/smtp-mailer";
import { z } from "zod";

export { createSessionSecurityState } from "@/lib/security";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
export interface WiredStack {
  agent: Agent;
  /** Exposed for the approvals API route. */
  approvals: ReturnType<typeof createSecurity>["approvals"];
  /** Exposed for the audit API route. */
  audit: ReturnType<typeof createAuditLog>;
}

// ---------------------------------------------------------------------------
// email.send tool definition — real SMTP when configured, sandbox outbox fallback
// ---------------------------------------------------------------------------
const outboxDir = resolve(process.env["SANDBOX_OUTBOX"] ?? "./sandbox/outbox");

/**
 * Build the email.send tool. Uses real SMTP (nodemailer) when SMTP_HOST, SMTP_USER,
 * SMTP_PASS and EMAIL_FROM are all set; falls back to sandbox outbox otherwise.
 * Credentials are read from process.env on the server — never from args, never sent to client.
 */
function buildEmailSendTool() {
  const smtpCfg = smtpConfigFromEnv(process.env as Record<string, string | undefined>);

  return defineTool({
    name: "email.send",
    description:
      "Send an email to one or more recipients. Requires explicit operator approval before sending. " +
      "Never sends without approval.",
    sensitivity: "external_send",
    producesUntrustedContent: false,
    inputSchema: z.strictObject({
      to: z.array(z.email().max(320)).min(1).max(5),
      subject: z.string().min(1).max(200),
      body: z.string().min(1).max(5000),
    }),
    timeoutMs: 30_000,
    async run(args, ctx) {
      if (smtpCfg) {
        // ── Real SMTP delivery ─────────────────────────────────────────────
        let mailer;
        try {
          mailer = await createSmtpMailer(smtpCfg);
        } catch (err) {
          throw new ToolFailure(
            "INTERNAL",
            `SMTP transport setup failed: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
        let result;
        try {
          result = await mailer.send({ to: args.to, subject: args.subject, body: args.body });
        } catch (err) {
          // Never report success if SMTP rejected the message
          throw new ToolFailure(
            "INTERNAL",
            `SMTP delivery failed: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
        if (result.rejected.length > 0) {
          throw new ToolFailure(
            "INTERNAL",
            `SMTP rejected ${result.rejected.length} recipient(s): ${result.rejected.join(", ")}`,
          );
        }
        return {
          segments: [
            {
              source: "tool" as const,
              origin: null,
              text: [
                `Email delivered successfully.`,
                `Message-ID: ${result.messageId}`,
                `Accepted: ${result.accepted.join(", ")}`,
              ].join("\n"),
            },
          ],
          summary: `Sent to: ${args.to.join(", ")} (ID: ${result.messageId})`,
        };
      } else {
        // ── Sandbox outbox fallback (no SMTP configured) ───────────────────
        const { writeFileSync, mkdirSync } = await import("node:fs");
        const { randomUUID } = await import("node:crypto");
        mkdirSync(outboxDir, { recursive: true });
        const filename = `${Date.now()}-${randomUUID()}.json`;
        const outboxPath = join(outboxDir, filename);
        const entry = {
          to: args.to,
          subject: args.subject,
          body: args.body,
          sessionId: ctx.sessionId,
          sentAt: new Date().toISOString(),
          mode: "sandbox_outbox",
        };
        try {
          writeFileSync(outboxPath, JSON.stringify(entry, null, 2), "utf8");
        } catch {
          throw new ToolFailure("INTERNAL", "Failed to write to outbox.");
        }
        return {
          segments: [
            {
              source: "tool" as const,
              origin: null,
              text: `[SANDBOX] Email queued to outbox (no SMTP configured). Recipients: ${args.to.join(", ")}`,
            },
          ],
          summary: `[SANDBOX] Queued to: ${args.to.join(", ")}`,
        };
      }
    },
  });
}


// ---------------------------------------------------------------------------
// Stack factory
// ---------------------------------------------------------------------------
let _stack: WiredStack | null = null;
let _stackError: string | null = null;

/**
 * Returns a memoized, fully-wired agent stack. Throws if config is invalid.
 * Resets when called with `reset: true` (for tests that need a fresh stack).
 */
export function getStack(opts?: { reset?: boolean }): WiredStack {
  if (opts?.reset) _stack = null;
  if (_stack) return _stack;

  // 1. Parse config
  const configResult = parseConfig(process.env as Record<string, string | undefined>);
  if (!configResult.ok) {
    _stackError = configResult.issues.join("; ");
    throw new Error(`Agent configuration invalid: ${_stackError}`);
  }
  const config = configResult.config;

  // 2. Load policy (falls back to defaultPolicy() if file missing)
  const policyPath = resolve(process.env["POLICY_PATH"] ?? "./fixtures/policies/default.json");
  const policy = loadPolicy(policyPath);

  // 3. Build audit log
  const logDir = resolve(process.env["AUDIT_LOG_DIR"] ?? "./sandbox/logs");
  const audit = createAuditLog(logDir);

  // 4. Build security bundle (real engine, real authority, real approvals)
  const security = createSecurity();

  // 5. Build tool registry + executor, injecting the real security authority and hashArgs
  const mailboxPath = resolve(process.env["MAILBOX_PATH"] ?? "./fixtures/mailbox/default.json");
  let mailbox;
  try {
    const raw = JSON.parse(readFileSync(mailboxPath, "utf8"));
    mailbox = parseMailbox(raw);
  } catch {
    throw new Error(`Failed to load mailbox fixture from ${mailboxPath}`);
  }

  const emailSendTool = buildEmailSendTool();
  const { registry, executor } = createToolbox(
    [...createEmailReadTools(() => mailbox), emailSendTool],
    { authority: security.authority, hashArgs, audit },
  );

  // 6. Build provider
  const providerConfig: ProviderConfig = config as unknown as ProviderConfig;
  const provider: LLMProvider = createProvider(providerConfig);

  // 7. Build agent â€” EVERY tool call goes through security.engine.authorize() inside the
  //    orchestrator before executor.execute() is called. This is the critical invariant.
  const agent = createAgent({
    provider,
    engine: security.engine,          // REAL PolicyEngine â€” deterministic, rule-based
    authority: security.authority,    // REAL CallAuthority â€” HMAC-signed single-use tokens
    approvals: security.approvals,    // REAL ApprovalStore
    audit,
    registry,
    executor,
    policy,
    settings: {
      providerTimeoutMs: config.AGENT_PROVIDER_TIMEOUT_MS,
      maxOutputTokens: config.AGENT_MAX_OUTPUT_TOKENS,
      maxInvalidOutputRetries: config.AGENT_MAX_INVALID_OUTPUT_RETRIES,
    },
  });

  _stack = { agent, approvals: security.approvals, audit };
  return _stack;
}

/** Returns 503 response data if config is invalid; null otherwise. */
export function configError(): string | null {
  try {
    const r = parseConfig(process.env as Record<string, string | undefined>);
    return r.ok ? null : r.issues.join("; ");
  } catch {
    return "Configuration check failed";
  }
}

