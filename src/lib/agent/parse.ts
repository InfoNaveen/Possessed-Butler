import { ModelActionSchema, type ModelAction } from "@contracts";

export const MAX_MODEL_OUTPUT_CHARS = 20_000;

export type ParseResult = { ok: true; action: ModelAction } | { ok: false; reason: ParseFailure };
export type ParseFailure = "too_long" | "not_json" | "schema";

const FENCE = /^```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n?```$/i;

/**
 * Parse model output into a ModelAction. The whole output must be one JSON object, optionally
 * wrapped in a single code fence. There is no partial salvage: if anything is off, nothing
 * from this output is acted on.
 */
export function parseModelAction(text: string): ParseResult {
  if (typeof text !== "string" || text.length > MAX_MODEL_OUTPUT_CHARS) return { ok: false, reason: "too_long" };
  let body = text.trim();
  const fenced = FENCE.exec(body);
  if (fenced) body = fenced[1].trim();

  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return { ok: false, reason: "not_json" };
  }
  const parsed = ModelActionSchema.safeParse(json);
  return parsed.success ? { ok: true, action: parsed.data } : { ok: false, reason: "schema" };
}
