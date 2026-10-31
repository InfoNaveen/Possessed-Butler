import type { z } from "zod";
import type { ToolContext, ToolErrorCode, ToolMetadata } from "@contracts";
import type { NewSegment } from "./segments";

/**
 * Internal tool definition. Metadata is shared with the security engine through the
 * registry; `run` is only reachable through the executor.
 */
export interface ToolDefinition<I = unknown> extends Omit<ToolMetadata, "inputSchema"> {
  inputSchema: z.ZodType<I>;
  timeoutMs: number;
  run(args: I, ctx: ToolContext): Promise<{ segments: NewSegment[]; summary: string }>;
}

/** Typed failure a tool can throw. `message` must be a fixed string, never raw content. */
export class ToolFailure extends Error {
  readonly code: ToolErrorCode;
  constructor(code: ToolErrorCode, message: string) {
    super(message);
    this.name = "ToolFailure";
    this.code = code;
  }
}

/** Helper that keeps `I` inferred from the schema while storing definitions in one list. */
export function defineTool<I>(def: ToolDefinition<I>): ToolDefinition<unknown> {
  return def as unknown as ToolDefinition<unknown>;
}
