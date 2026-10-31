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
  user: string;
  pass: string;
  from: string; // "Display Name <addr@domain>" or just "addr@domain"
}

export interface SendResult {
  messageId: string;
  accepted: string[];
  rejected: string[];
  envelopeTime?: number;
  messageTime?: number;
}

export interface IMailer {
  send(opts: { to: string[]; subject: string; body: string }): Promise<SendResult>;
}

/** Read SMTP config from env. Returns null if any required variable is missing. */
export function smtpConfigFromEnv(env: Record<string, string | undefined>): SmtpConfig | null {
  const host = env["SMTP_HOST"];
  const portStr = env["SMTP_PORT"] ?? "587";
  const user = env["SMTP_USER"];
  const pass = env["SMTP_PASS"];
  const from = env["EMAIL_FROM"];

  if (!host || !user || !pass || !from) return null;

  const port = parseInt(portStr, 10);
  if (isNaN(port)) return null;

  return { host, port, secure: port === 465, user, pass, from };
}

/** Create a real SMTP mailer backed by nodemailer. */
export async function createSmtpMailer(config: SmtpConfig): Promise<IMailer> {
  // Dynamic import keeps nodemailer out of the browser bundle
  const nodemailer = await import("nodemailer");
  const transporter: Transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: { user: config.user, pass: config.pass },
    // No credentials appear in logs
    logger: false,
    debug: false,
  });

  return {
    async send({ to, subject, body }) {
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
    },
  };
}

/**
 * Mock mailer for tests. Records sent emails in memory; never touches the network.
 * Call .sent() to inspect what was "delivered".
 */
export function createMockMailer(): IMailer & {
  sent: () => Array<{ to: string[]; subject: string; body: string; messageId: string }>;
  failNext(err: Error): void;
} {
  const log: Array<{ to: string[]; subject: string; body: string; messageId: string }> = [];
  let nextError: Error | null = null;
  let msgCounter = 0;

  return {
    sent: () => [...log],
    failNext(err: Error) {
      nextError = err;
    },
    async send({ to, subject, body }) {
      if (nextError) {
        const err = nextError;
        nextError = null;
        throw err;
      }
      const messageId = `<mock-${++msgCounter}@possessed-butler.local>`;
      log.push({ to, subject, body, messageId });
      return { messageId, accepted: [...to], rejected: [] };
    },
  };
}
