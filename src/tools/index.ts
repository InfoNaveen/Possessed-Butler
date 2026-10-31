// Public surface of the tools module. Tool implementations (`run`) are reachable only
// through the executor returned by createToolbox.
export { createToolbox, type Toolbox, type ToolboxDeps } from "./toolbox";
export { defineTool, ToolFailure, type ToolDefinition } from "./definitions";
export { makeSegment, type NewSegment } from "./segments";
export { createEmailReadTools } from "./email/read-tools";
export { parseMailbox, MailboxSchema, type Mailbox } from "./email/mailbox";
