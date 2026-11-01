/**
 * src/tools/email/smtp-mailer.ts
 *
 * Real SMTP delivery via nodemailer. Used by the email.send tool definition in wiring.ts.
 *
 * Credentials are read exclusively from environment variables — never from args, never from
 * the browser. The module is server-only (no "use client").
 *
 * For automated tests, pass the mock transport returned by createMockMailer() instead.
 * The email.send tool itself is unchanged; only the run() implementation differs.
 */
import type { Transporter } from "nodemailer";

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean; // true = port 465 TLS, false = STARTTLS on 587
  requireTLS?: boolean;
  user: string;
  pass: string;
  from: string; // "Display Name <addr@domain>" or just "addr@domain"
  connectionTimeoutMs?: number;
  greetingTimeoutMs?: number;
  socketTimeoutMs?: number;
}

export interface SendResult {
  messageId: string;
  accepted: string[];
  rejected: string[];
  envelopeTime?: number;
  messageTime?: number;
}

export interface VerifyResult {
  ok: boolean;
  error?: string;
}

export interface IMailer {
  send(opts: { to: string[]; subject: string; body: string }): Promise<SendResult>;
  verifyConnection(): Promise<VerifyResult>;
}

export interface SmtpValidationResult {
  valid: boolean;
  issues: string[];
  config: SmtpConfig | null;
}

/** Sanitize any error so credentials and passwords are never exposed. */
export function sanitizeSmtpError(err: unknown, pass?: string, user?: string): string {
  let msg = err instanceof Error ? err.message : String(err ?? "Unknown SMTP error");

  // Redact actual password or user if present in error message
  if (pass && pass.length > 0) {
    msg = msg.split(pass).join("[REDACTED_PASSWORD]");
  }
  if (user && user.length > 0) {
    msg = msg.split(user).join("[REDACTED_USER]");
  }

  // Friendly categorization of common SMTP error codes
  const errCode = (err as Record<string, unknown>)?.["code"];
  const responseCode = (err as Record<string, unknown>)?.["responseCode"];

  if (errCode === "EAUTH" || responseCode === 535 || /auth/i.test(msg) && /fail|invalid|denied/i.test(msg)) {
    return "SMTP authentication failed: Invalid username or password (check your Gmail App Password).";
  }
  if (errCode === "ETIMEDOUT" || /timeout/i.test(msg)) {
    return "SMTP connection timed out: Server took too long to respond.";
  }
  if (errCode === "ECONNREFUSED" || /econnrefused/i.test(msg)) {
    return "SMTP connection refused: Could not connect to the mail server on the specified port.";
  }
  if (errCode === "ENOTFOUND" || /getaddrinfo/i.test(msg)) {
    return "SMTP host lookup failed: Could not resolve SMTP host.";
  }

  return `SMTP error: ${msg}`;
}

/** Validate SMTP environment variables without exposing their secret values. */
export function validateSmtpConfig(env: Record<string, string | undefined>): SmtpValidationResult {
  const issues: string[] = [];

  const host = env["SMTP_HOST"]?.trim();
  const portStr = env["SMTP_PORT"]?.trim() ?? "587";
  const user = env["SMTP_USER"]?.trim();
  const pass = env["SMTP_PASS"]?.trim();
  const from = env["EMAIL_FROM"]?.trim();

  if (!host) issues.push("SMTP_HOST is required");
  if (!user) issues.push("SMTP_USER is required");
  if (!pass) issues.push("SMTP_PASS is required");
  if (!from) issues.push("EMAIL_FROM is required");

  const port = parseInt(portStr, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    issues.push(`SMTP_PORT must be a valid port number between 1 and 65535 (got '${portStr}')`);
  }

  if (issues.length > 0 || !host || !user || !pass || !from) {
    return { valid: false, issues, config: null };
  }

  const isSecure = port === 465;
  const isStartTls = port === 587;

  return {
    valid: true,
    issues: [],
    config: {
      host,
      port,
      secure: isSecure,
      requireTLS: isStartTls,
      user,
      pass,
      from,
      connectionTimeoutMs: 10_000,
      greetingTimeoutMs: 10_000,
      socketTimeoutMs: 15_000,
    },
  };
}

/** Read SMTP config from env. Returns null if any required variable is missing. */
export function smtpConfigFromEnv(env: Record<string, string | undefined>): SmtpConfig | null {
  const result = validateSmtpConfig(env);
  return result.config;
}

/** Create a real SMTP mailer backed by nodemailer with STARTTLS and timeouts. */
export async function createSmtpMailer(config: SmtpConfig): Promise<IMailer> {
  // Dynamic import keeps nodemailer out of the browser bundle
  const nodemailer = await import("nodemailer");

  const cleanPass = config.pass.replace(/\s+/g, "");

  const transporter: Transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    requireTLS: config.requireTLS ?? (config.port === 587),
    auth: { user: config.user, pass: cleanPass },
    connectionTimeout: config.connectionTimeoutMs ?? 10_000,
    greetingTimeout: config.greetingTimeoutMs ?? 10_000,
    socketTimeout: config.socketTimeoutMs ?? 15_000,
    // Never write credentials to logs
    logger: false,
    debug: false,
  });

  return {
    async verifyConnection(): Promise<VerifyResult> {
      try {
        await transporter.verify();
        return { ok: true };
      } catch (err) {
        return { ok: false, error: sanitizeSmtpError(err, config.pass, config.user) };
      }
    },

    async send({ to, subject, body }) {
      try {
        const info = await transporter.sendMail({
          from: config.from,
          to: to.join(", "),
          subject,
          text: body,
        });

        // nodemailer's sendMail resolves only after the SMTP server accepts the message.
        return {
          messageId: info.messageId ?? "",
          accepted: Array.isArray(info.accepted)
            ? (info.accepted as string[])
            : typeof info.accepted === "string"
            ? [info.accepted]
            : [],
          rejected: Array.isArray(info.rejected)
            ? (info.rejected as string[])
            : typeof info.rejected === "string"
            ? [info.rejected]
            : [],
          envelopeTime: (info as Record<string, unknown>)["envelopeTime"] as number | undefined,
          messageTime: (info as Record<string, unknown>)["messageTime"] as number | undefined,
        };
      } catch (err) {
        throw new Error(sanitizeSmtpError(err, config.pass, config.user));
      }
    },
  };
}

/**
 * Mock mailer for tests. Records sent emails in memory; never touches the network.
 * Call .sent() to inspect what was "delivered".
 */
export function createMockMailer(): IMailer & {
  sent: () => Array<{ to: string[]; subject: string; body: string; messageId: string }>;
  failNext: (err: Error) => void;
  setVerifyFailure: (err: Error | null) => void;
} {
  const log: Array<{ to: string[]; subject: string; body: string; messageId: string }> = [];
  let nextError: Error | null = null;
  let verifyError: Error | null = null;
  let msgCounter = 0;

  return {
    sent: () => [...log],
    failNext(err: Error) {
      nextError = err;
    },
    setVerifyFailure(err: Error | null) {
      verifyError = err;
    },
    async verifyConnection(): Promise<VerifyResult> {
      if (verifyError) {
        return { ok: false, error: sanitizeSmtpError(verifyError) };
      }
      return { ok: true };
    },
    async send({ to, subject, body }) {
      if (nextError) {
        const err = nextError;
        nextError = null;
        throw new Error(sanitizeSmtpError(err));
      }
      const messageId = `<mock-${++msgCounter}@possessed-butler.local>`;
      log.push({ to, subject, body, messageId });
      return { messageId, accepted: [...to], rejected: [] };
    },
  };
}
