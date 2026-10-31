import { ProviderError, type LLMProvider } from "@contracts";
import { createMockProvider, mockAction, type MockScript } from "./mock";
import { createOllamaProvider } from "./ollama";

export { createMockProvider, mockAction, mockScripts, type MockScript } from "./mock";
export { createOllamaProvider } from "./ollama";

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
 */
export function createProvider(config: ProviderConfig, mockScript?: MockScript): LLMProvider {
  switch (config.LLM_PROVIDER) {
    case "mock":
      return createMockProvider(
        mockScript ?? (() => mockAction.final("Mock provider: no script configured.")),
      );
    case "ollama":
      return createOllamaProvider(config.OLLAMA_BASE_URL, config.OLLAMA_MODEL);
    case "gemini":
    case "openai":
      return notYetImplemented(config.LLM_PROVIDER);
  }
}

function notYetImplemented(id: "gemini" | "openai"): LLMProvider {
  return {
    id,
    model: "unavailable",
    async generate() {
      throw new ProviderError("CONFIG", id, `${id} adapter is not yet implemented. Use LLM_PROVIDER=ollama.`);
    },
  };
}

