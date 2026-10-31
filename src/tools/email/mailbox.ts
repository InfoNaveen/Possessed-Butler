import { z } from "zod";

export const MESSAGE_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

const AddressSchema = z.strictObject({
  name: z.string().max(200),
  address: z.email().max(320),
});

const MessageSchema = z.strictObject({
  id: z.string().regex(MESSAGE_ID_PATTERN),
  from: AddressSchema,
  to: z.array(AddressSchema).min(1).max(50),
  subject: z.string().max(1_000),
  date: z.iso.datetime({ offset: true }),
  unread: z.boolean(),
  body: z.string().max(100_000),
});

/** Fixture mailbox format (tool-execution design). All message fields are untrusted content. */
export const MailboxSchema = z
  .strictObject({
    owner: AddressSchema,
    messages: z.array(MessageSchema).max(1_000),
  })
  .refine((m) => new Set(m.messages.map((x) => x.id)).size === m.messages.length, {
    message: "Message ids must be unique",
  });

export type Mailbox = z.infer<typeof MailboxSchema>;
export type MailMessage = Mailbox["messages"][number];

/** Validates unknown fixture data. Throws on invalid input so a bad fixture never loads. */
export function parseMailbox(data: unknown): Mailbox {
  return MailboxSchema.parse(data);
}
