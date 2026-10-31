import { z } from "zod";

/**
 * Server-only configuration, parsed from environment variables.
 * Secrets (API keys) stay inside the provider adapters; they are never placed in prompts,
 * session state, audit events or API responses.
 */
const nonEmpty = z.string().trim().min(1);

const Common = {
  AGENT_PROVIDER_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(120_000).default(30_000),
  AGENT_MAX_OUTPUT_TOKENS: z.coerce.number().int().min(64).max(8_192).default(1_024),
  AGENT_MAX_INVALID_OUTPUT_RETRIES: z.coerce.number().int().min(0).max(3).default(1),
};

export const ConfigSchema = z.discriminatedUnion("LLM_PROVIDER", [
  z.object({ LLM_PROVIDER: z.literal("mock"), ...Common }),
  z.object({
    LLM_PROVIDER: z.literal("ollama"),
    OLLAMA_BASE_URL: z.url({ protocol: /^https?$/ }).default("http://127.0.0.1:11434"),
    OLLAMA_MODEL: nonEmpty,
    ...Common,
  }),
  z.object({ LLM_PROVIDER: z.literal("gemini"), GEMINI_API_KEY: nonEmpty, GEMINI_MODEL: nonEmpty, ...Common }),
  z.object({ LLM_PROVIDER: z.literal("openai"), OPENAI_API_KEY: nonEmpty, OPENAI_MODEL: nonEmpty, ...Common }),
]);

export type AgentConfig = z.infer<typeof ConfigSchema>;

export type ConfigResult = { ok: true; config: AgentConfig } | { ok: false; issues: string[] };

/**
 * Parse configuration. Error output lists only variable names, never values,
 * so a misconfigured key cannot leak through an error message.
 */
export function parseConfig(env: Record<string, string | undefined>): ConfigResult {
  const result = ConfigSchema.safeParse(env);
  if (result.success) return { ok: true, config: result.data };
  const names = new Set(result.error.issues.map((issue) => String(issue.path[0] ?? "LLM_PROVIDER")));
  return { ok: false, issues: [...names].map((name) => `${name} is missing or invalid`) };
}
