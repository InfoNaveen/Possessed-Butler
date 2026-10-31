import type {
  AuditLog,
  AuthorizedCall,
  CallAuthority,
  ToolContext,
  ToolErrorCode,
  ToolExecutor,
  ToolMetadata,
  ToolName,
  ToolRegistry,
  ToolResult,
} from "@contracts";
import { TOOL_NAMES } from "@contracts";
import { ToolFailure, type ToolDefinition } from "./definitions";
import { DEFAULT_SEGMENT_CHAR_LIMIT, makeSegment } from "./segments";

export interface ToolboxDeps {
  /** From the security engine. The executor runs nothing it has not verified. */
  authority: CallAuthority;
  /**
   * Canonical args hash, owned by the security engine (canonicalJson + sha256).
   * Injected so tools never re-implement security logic and both sides hash identically.
   */
  hashArgs: (args: unknown) => string;
  audit: AuditLog;
  segmentCharLimit?: number;
}

export interface Toolbox {
  registry: ToolRegistry;
  executor: ToolExecutor;
}

/** Fixed, content-free messages per error code (contract: messages never carry untrusted text). */
const MESSAGES: Record<ToolErrorCode, string> = {
  INVALID_ARGS: "Invalid tool arguments.",
  NOT_FOUND: "Requested item was not found.",
  SANDBOX_VIOLATION: "Path is outside the sandbox.",
  LIMIT_EXCEEDED: "A size or count limit was exceeded.",
  NETWORK_BLOCKED: "Network destination is blocked.",
  TIMEOUT: "Tool timed out.",
  UNAUTHORIZED: "Call is not authorized.",
  INTERNAL: "Tool failed.",
};

class TimeoutSignalError extends Error {}

export function createToolbox(definitions: ToolDefinition[], deps: ToolboxDeps): Toolbox {
  const defs = new Map<string, ToolDefinition>();
  const known: ReadonlySet<string> = new Set(TOOL_NAMES);
  for (const def of definitions) {
    if (!known.has(def.name)) throw new Error(`Unknown tool name in definitions: ${def.name}`);
    if (defs.has(def.name)) throw new Error(`Duplicate tool definition: ${def.name}`);
    defs.set(def.name, def);
  }

  const metadata = new Map<string, ToolMetadata>(
    [...defs.values()].map((d) => [
      d.name,
      Object.freeze({
        name: d.name,
        description: d.description,
        sensitivity: d.sensitivity,
        producesUntrustedContent: d.producesUntrustedContent,
        inputSchema: d.inputSchema,
      }),
    ]),
  );

  const registry: ToolRegistry = {
    list: () => [...metadata.values()],
    // Map lookup: prototype keys like "__proto__" or "constructor" are simply absent.
    get: (name) => (typeof name === "string" ? metadata.get(name) : undefined),
  };

  const limit = deps.segmentCharLimit ?? DEFAULT_SEGMENT_CHAR_LIMIT;

  const executor: ToolExecutor = {
    async execute(call: AuthorizedCall, ctx: ToolContext): Promise<ToolResult> {
      const proposalId = typeof call?.proposalId === "string" ? call.proposalId : "unknown";
      const tool = call?.tool as ToolName;

      const fail = (code: ToolErrorCode, detail?: string): ToolResult => {
        safeAudit(deps.audit, ctx.sessionId, "tool_failed", { tool, proposalId, code, detail: detail ?? null });
        return { ok: false, proposalId, tool, error: { code, message: MESSAGES[code] } };
      };

      // 1. Verify and consume the capability token before anything else.
      let verified: ReturnType<CallAuthority["verifyAndConsume"]>;
      try {
        verified = deps.authority.verifyAndConsume(call);
      } catch {
        return fail("UNAUTHORIZED", "verify threw");
      }
      if (!verified.ok) return fail("UNAUTHORIZED", "token rejected");
      if (call.sessionId !== ctx.sessionId) return fail("UNAUTHORIZED", "session mismatch");

      // 2–4. Tool must exist; args must re-parse and hash to exactly what was authorized.
      const def = defs.get(call.tool);
      if (!def) return fail("UNAUTHORIZED", "unknown tool");
      const parsed = def.inputSchema.safeParse(call.args);
      if (!parsed.success) return fail("UNAUTHORIZED", "args do not match schema");
      let hash: string;
      try {
        hash = deps.hashArgs(parsed.data);
      } catch {
        return fail("UNAUTHORIZED", "args not hashable");
      }
      if (hash !== call.argsHash) return fail("UNAUTHORIZED", "args hash mismatch");

      // 5–6. Run with timeout.
      const timeout = AbortSignal.timeout(def.timeoutMs);
      const signal = AbortSignal.any([ctx.signal, timeout]);
      let output: Awaited<ReturnType<ToolDefinition["run"]>>;
      try {
        output = await raceAbort(def.run(parsed.data, { sessionId: ctx.sessionId, signal }), signal);
      } catch (err) {
        if (err instanceof TimeoutSignalError || signal.aborted) return fail("TIMEOUT");
        if (err instanceof ToolFailure) return fail(err.code);
        return fail("INTERNAL");
      }

      // 7. Wrap as untrusted segments.
      let segments;
      try {
        segments = output.segments.map((s) => makeSegment(s, limit));
      } catch {
        return fail("INTERNAL", "invalid segment");
      }

      try {
        deps.audit.append({
          sessionId: ctx.sessionId,
          type: "tool_executed",
          data: {
            tool,
            proposalId,
            decisionId: call.decisionId,
            argsHash: call.argsHash,
            approvalId: call.approvalId,
            segments: segments.map((s) => ({ id: s.id, source: s.source, origin: s.origin, sha256: s.sha256 })),
          },
        });
      } catch {
        // The tool ran but we could not record it. Do not hand its output to the model.
        return { ok: false, proposalId, tool, error: { code: "INTERNAL", message: MESSAGES.INTERNAL } };
      }

      return { ok: true, proposalId, tool, segments, summary: String(output.summary).slice(0, 200) };
    },
  };

  return { registry, executor };
}

function raceAbort<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new TimeoutSignalError());
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new TimeoutSignalError());
    signal.addEventListener("abort", onAbort, { once: true });
    work.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (err) => {
        signal.removeEventListener("abort", onAbort);
        reject(err);
      },
    );
  });
}

function safeAudit(audit: AuditLog, sessionId: string, type: "tool_failed", data: Record<string, unknown>) {
  try {
    audit.append({ sessionId, type, data });
  } catch {
    // Failure result is returned regardless; the agent's own next audit write will surface a broken log.
  }
}
