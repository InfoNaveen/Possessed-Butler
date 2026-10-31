import { createHash, randomUUID } from "node:crypto";
import type { ContentSegment } from "@contracts";

/** Sources a tool may produce. "system" and "user" are deliberately absent. */
export type ToolSegmentSource = "email" | "web" | "pdf" | "file" | "tool";
const TOOL_SOURCES: ReadonlySet<string> = new Set<ToolSegmentSource>(["email", "web", "pdf", "file", "tool"]);

export interface NewSegment {
  source: ToolSegmentSource;
  origin: string | null;
  text: string;
}

export const DEFAULT_SEGMENT_CHAR_LIMIT = 20_000;

export class SegmentSourceError extends Error {
  constructor() {
    super("Tools may not create trusted segments.");
    this.name = "SegmentSourceError";
  }
}

/**
 * The only way tool output becomes a ContentSegment. Tool output is always untrusted:
 * trust is fixed here and a tool cannot choose it. The runtime check backs up the type,
 * because a tool implementation could pass a cast value.
 */
export function makeSegment(input: NewSegment, limit = DEFAULT_SEGMENT_CHAR_LIMIT): ContentSegment {
  if (!TOOL_SOURCES.has(input.source)) throw new SegmentSourceError();
  const full = String(input.text);
  const truncated = full.length > limit;
  return {
    id: randomUUID(),
    source: input.source,
    trust: "untrusted",
    origin: input.origin,
    text: truncated ? full.slice(0, limit) : full,
    sha256: createHash("sha256").update(full, "utf8").digest("hex"),
    truncated,
    createdAt: new Date().toISOString(),
  };
}
