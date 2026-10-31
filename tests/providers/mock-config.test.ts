import { describe, expect, it } from "vitest";
import { ProviderError, type LLMRequest } from "@contracts";
import { parseConfig } from "@/lib/agent";
import { createMockProvider, createProvider, mockAction, mockScripts } from "@/providers";

const req: LLMRequest = { messages: [], tools: [], temperature: 0, maxOutputTokens: 10, timeoutMs: 10 };
const signal = () => new AbortController().signal;

describe("mock provider", () => {
  it("returns scripted responses in order", async () => {
    const p = createMockProvider(mockScripts.scripted([mockAction.final("a"), mockAction.final("b")]));
    expect((await p.generate(req, signal())).text).toBe('{"action":"final","text":"a"}');
    expect((await p.generate(req, signal())).text).toBe('{"action":"final","text":"b"}');
  });

  it("throws ProviderError only", async () => {
    const p = createMockProvider(mockScripts.failAfter([], "RATE_LIMITED"));
    await expect(p.generate(req, signal())).rejects.toMatchObject({ code: "RATE_LIMITED", retryable: true });
    const broken = createMockProvider(() => { throw new TypeError("x"); });
    await expect(broken.generate(req, signal())).rejects.toBeInstanceOf(ProviderError);
  });

  it("honours an aborted signal", async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(createMockProvider(() => "x").generate(req, ac.signal)).rejects.toMatchObject({ code: "TIMEOUT" });
  });
});

describe("provider selection", () => {
  it("unimplemented real adapters fail closed with CONFIG", async () => {
    const p = createProvider({ LLM_PROVIDER: "openai", OPENAI_API_KEY: "k", OPENAI_MODEL: "m" });
    await expect(p.generate(req, signal())).rejects.toMatchObject({ code: "CONFIG" });
  });
});

describe("config", () => {
  it("parses mock config with defaults", () => {
    const r = parseConfig({ LLM_PROVIDER: "mock" });
    expect(r.ok && r.config.AGENT_MAX_INVALID_OUTPUT_RETRIES).toBe(1);
  });

  it("names missing variables without echoing values", () => {
    const r = parseConfig({ LLM_PROVIDER: "openai", OPENAI_API_KEY: "sk-SECRET-VALUE" });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.issues).toEqual(["OPENAI_MODEL is missing or invalid"]);
    expect(JSON.stringify(r)).not.toContain("SECRET");
  });

  it("rejects unknown providers and non-http Ollama URLs", () => {
    expect(parseConfig({ LLM_PROVIDER: "evil" }).ok).toBe(false);
    expect(parseConfig({ LLM_PROVIDER: "ollama", OLLAMA_MODEL: "m", OLLAMA_BASE_URL: "file:///etc" }).ok).toBe(false);
  });
});
