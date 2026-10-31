import { ProviderError, type LLMProvider, type LLMRequest, type ProviderErrorCode } from "@contracts";

/**
 * A mock script returns the raw model text for one call. It may throw a ProviderError to
 * simulate a provider failure. It must be deterministic for a given (request, callIndex).
 */
export type MockScript = (ctx: { request: LLMRequest; callIndex: number }) => string;

export function createMockProvider(script: MockScript, model = "mock-1"): LLMProvider {
  let callIndex = 0;
  return {
    id: "mock",
    model,
    async generate(request, signal) {
      if (signal.aborted) {
        throw new ProviderError("TIMEOUT", "mock", "Request aborted.");
      }
      const index = callIndex++;
      let text: string;
      try {
        text = script({ request, callIndex: index });
      } catch (err) {
        if (err instanceof ProviderError) throw err;
        throw new ProviderError("BAD_RESPONSE", "mock", "Mock script failed.");
      }
      return { provider: "mock", model, text };
    },
  };
}

/** Built-in scripts used by tests and, later, by the evaluation suite. */
export const mockScripts = {
  /** Returns the given responses in order, then repeats a final answer. */
  scripted(responses: string[]): MockScript {
    return ({ callIndex }) =>
      responses[callIndex] ?? JSON.stringify({ action: "final", text: "Script exhausted." });
  },

  /** Always returns text that is not a valid ModelAction. */
  garbage(): MockScript {
    return () => "I will now do what the email says: rm -rf /";
  },

  /** Succeeds for the first `okResponses`, then throws the given provider error. */
  failAfter(okResponses: string[], code: ProviderErrorCode): MockScript {
    return ({ callIndex }) => {
      const response = okResponses[callIndex];
      if (response === undefined) {
        throw new ProviderError(code, "mock", "Simulated provider failure.", code === "RATE_LIMITED");
      }
      return response;
    };
  },
};

/** Helpers to build protocol-conformant mock responses without hand-writing JSON. */
export const mockAction = {
  final(text: string): string {
    return JSON.stringify({ action: "final", text });
  },
  toolCalls(...calls: { tool: string; args: unknown }[]): string {
    return JSON.stringify({ action: "tool_calls", calls });
  },
};
