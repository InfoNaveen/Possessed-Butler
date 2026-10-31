import { z } from "zod";
import { defineTool, ToolFailure, type ToolDefinition } from "../definitions";
import { MESSAGE_ID_PATTERN, type Mailbox, type MailMessage } from "./mailbox";

const SNIPPET_CHARS = 200;

export const EmailListArgs = z.strictObject({
  unreadOnly: z.boolean().optional(),
  limit: z.number().int().min(1).max(20).optional(),
});

export const EmailReadArgs = z.strictObject({
  messageId: z.string().regex(MESSAGE_ID_PATTERN),
});

function formatAddress(a: { name: string; address: string }): string {
  return a.name ? `${a.name} <${a.address}>` : a.address;
}

function newestFirst(a: MailMessage, b: MailMessage): number {
  return Date.parse(b.date) - Date.parse(a.date);
}

/**
 * Read-only email tools over a mailbox supplied by the caller (fixture data for now).
 * Every field, including sender name and subject, is returned as untrusted content.
 */
export function createEmailReadTools(getMailbox: () => Mailbox): ToolDefinition[] {
  const list = defineTool({
    name: "email.list",
    description:
      "List messages in the user's inbox, newest first. Returns id, sender, subject, date and a short snippet for each.",
    sensitivity: "read",
    producesUntrustedContent: true,
    inputSchema: EmailListArgs,
    timeoutMs: 5_000,
    async run(args) {
      const all = [...getMailbox().messages].sort(newestFirst);
      const selected = all.filter((m) => !args.unreadOnly || m.unread).slice(0, args.limit ?? 10);
      return {
        segments: selected.map((m) => ({
          source: "email" as const,
          origin: m.id,
          text: [
            `id: ${m.id}`,
            `from: ${formatAddress(m.from)}`,
            `subject: ${m.subject}`,
            `date: ${m.date}`,
            `snippet: ${m.body.replace(/\s+/g, " ").trim().slice(0, SNIPPET_CHARS)}`,
          ].join("\n"),
        })),
        summary: `Listed ${selected.length} message(s).`,
      };
    },
  });

  const read = defineTool({
    name: "email.read",
    description: "Read the full headers and body of one message by its id.",
    sensitivity: "read",
    producesUntrustedContent: true,
    inputSchema: EmailReadArgs,
    timeoutMs: 5_000,
    async run(args) {
      const message = getMailbox().messages.find((m) => m.id === args.messageId);
      if (!message) throw new ToolFailure("NOT_FOUND", "Message not found.");
      return {
        segments: [
          {
            source: "email" as const,
            origin: message.id,
            text: [
              `id: ${message.id}`,
              `from: ${formatAddress(message.from)}`,
              `to: ${message.to.map(formatAddress).join(", ")}`,
              `subject: ${message.subject}`,
              `date: ${message.date}`,
              "",
              message.body,
            ].join("\n"),
          },
        ],
        summary: "Read 1 message.",
      };
    },
  });

  return [list, read];
}
