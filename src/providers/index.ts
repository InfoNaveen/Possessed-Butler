import { ProviderError, type LLMProvider } from "@contracts";
import { createMockProvider, mockAction, type MockScript } from "./mock";

export { createMockProvider, mockAction, mockScripts, type MockScript } from "./mock";

/**
 * The provider-relevant subset of agent config. Defined here so providers do not import
 * from agent-core (dependency direction in .kiro/steering/architecture.md).
 */
export type ProviderConfig =
  | { LLM_PROVIDER: "mock" }
  | { LLM_PROVIDER: "ollama"; OLLAMA_BASE_URL: string; OLLAMA_MODEL: string }
  | { LLM_PROVIDER: "gemini"; GEMINI_API_KEY: string; GEMINI_MODEL: string }
  | { LLM_PROVIDER: "openai"; OPENAI_API_KEY: string; OPENAI_MODEL: string };

/**
 * Select a provider from validated config. Every provider implements the same LLMProvider
 * contract, so the agent cannot tell them apart.
 *
 * Ollama, Gemini and OpenAI adapters are the next milestone (agent-core tasks 9–11): their
 * request/response fields must be confirmed against the official docs linked in
 * .kiro/specs/agent-core/design.md before they are written. Until then they fail closed.
 */
export function createProvider(config: ProviderConfig, mockScript?: MockScript): LLMProvider {
  switch (config.LLM_PROVIDER) {
    case "mock":
      return createMockProvider(
        mockScript ?? (() => mockAction.final("Mock provider: no script configured.")),
      );
    case "ollama":
    case "gemini":
    case "openai":
      return notYetImplemented(config.LLM_PROVIDER);
  }
}

function notYetImplemented(id: "ollama" | "gemini" | "openai"): LLMProvider {
  return {
    id,
    model: "unavailable",
    async generate() {
      throw new ProviderError("CONFIG", id, "Provider adapter is not implemented yet.");
    },
  };
}
