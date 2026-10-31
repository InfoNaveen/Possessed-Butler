/**
 * src/providers/ollama.ts
 *
 * Ollama LLM provider adapter.
 *
 * Uses the Ollama /api/chat endpoint in non-streaming mode with JSON format
 * so the model is more likely to return well-formed JSON (required by ModelActionSchema).
 *
 * Environment variables (validated by config.ts before this is called):
 *   OLLAMA_BASE_URL  - default http://127.0.0.1:11434
 *   OLLAMA_MODEL     - e.g. qwen2.5:7b
 */
import { ProviderError, type LLMProvider, type LLMRequest, type LLMRawResponse } from "@contracts";

interface OllamaChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

interface OllamaChatRequest {
  model: string;
  messages: OllamaChatMessage[];
  stream: false;
  format: "json";
  options: {
    temperature: number;
    num_predict: number;
  };
}

interface OllamaChatResponse {
  model: string;
  message: {
    role: string;
    content: string;
  };
  done: boolean;
  prompt_eval_count?: number;
  eval_count?: number;
}

export function createOllamaProvider(baseUrl: string, model: string): LLMProvider {
  // Normalise: strip trailing slash
  const base = baseUrl.replace(/\/+$/, "");

  return {
    id: "ollama",
    model,

    async generate(req: LLMRequest, signal: AbortSignal): Promise<LLMRawResponse> {
      const chatMessages: OllamaChatMessage[] = req.messages.map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const body: OllamaChatRequest = {
        model,
        messages: chatMessages,
        stream: false,
        format: "json",
        options: {
          temperature: req.temperature,
          num_predict: req.maxOutputTokens,
        },
      };

      let response: Response;
      try {
        response = await fetch(`${base}/api/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal,
        });
      } catch (err) {
        // Connection refused, network error, or abort (timeout)
        if (signal.aborted) {
          throw new ProviderError("TIMEOUT", "ollama", "Request timed out.", true);
        }
        throw new ProviderError(
          "UNAVAILABLE",
          "ollama",
          `Cannot reach Ollama at ${base}: ${err instanceof Error ? err.message : String(err)}`,
          true,
        );
      }

      if (!response.ok) {
        // 404 often means the model is not pulled
        if (response.status === 404) {
          let detail = "";
          try {
            detail = await response.text();
          } catch { /* ignore */ }
          throw new ProviderError(
            "CONFIG",
            "ollama",
            `Model "${model}" not found on Ollama (HTTP 404). Pull it with: ollama pull ${model}. Detail: ${detail}`,
          );
        }
        if (response.status === 401 || response.status === 403) {
          throw new ProviderError("AUTH", "ollama", `Ollama returned HTTP ${response.status}.`);
        }
        if (response.status === 429) {
          throw new ProviderError("RATE_LIMITED", "ollama", "Ollama rate limit hit.", true);
        }
        throw new ProviderError(
          "BAD_RESPONSE",
          "ollama",
          `Ollama returned HTTP ${response.status}.`,
          response.status >= 500,
        );
      }

      let raw: string;
      try {
        raw = await response.text();
      } catch {
        throw new ProviderError("BAD_RESPONSE", "ollama", "Failed to read Ollama response body.");
      }

      let parsed: OllamaChatResponse;
      try {
        parsed = JSON.parse(raw) as OllamaChatResponse;
      } catch {
        throw new ProviderError("BAD_RESPONSE", "ollama", "Ollama response is not valid JSON.");
      }

      const content = parsed?.message?.content;
      if (typeof content !== "string") {
        throw new ProviderError("BAD_RESPONSE", "ollama", "Ollama response missing message.content.");
      }

      return {
        provider: "ollama",
        model: parsed.model ?? model,
        text: content,
        usage: {
          inputTokens: parsed.prompt_eval_count,
          outputTokens: parsed.eval_count,
        },
      };
    },
  };
}
