/**
 * src/lib/security/audit.ts
 *
 * AuditLog implementation — append-only JSONL file writer.
 *
 * Writes one JSON line per event to `{dir}/audit.jsonl`.
 * Parent directories are created on first write.
 * Never throws — a failed write throws AuditWriteError which the agent
 * maps to a session-fatal AUDIT_FAILURE (per security.md rule 6.8).
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import type { AuditEvent, AuditLog } from "@contracts";

/** Thrown when the file write itself fails (not when the app logic fails). */
export class AuditWriteError extends Error {
  constructor(cause: unknown) {
    super("Audit log write failed");
    this.name = "AuditWriteError";
    this.cause = cause;
  }
}

export function createAuditLog(dir: string): AuditLog {
  const logPath = path.resolve(dir, "audit.jsonl");
  let dirEnsured = false;

  const events: AuditEvent[] = [];

  function ensureDir() {
    if (dirEnsured) return;
    try {
      mkdirSync(path.dirname(logPath), { recursive: true });
      dirEnsured = true;
    } catch (err) {
      throw new AuditWriteError(err);
    }
  }

  return {
    append(event: Omit<AuditEvent, "id" | "ts">): AuditEvent {
      const full: AuditEvent = {
        ...event,
        id: randomUUID(),
        ts: new Date().toISOString(),
      };
      try {
        ensureDir();
        appendFileSync(logPath, JSON.stringify(full) + "\n", "utf8");
      } catch (err) {
        if (err instanceof AuditWriteError) throw err;
        throw new AuditWriteError(err);
      }
      events.push(full);
      return full;
    },

    list(sessionId: string): AuditEvent[] {
      return events.filter((e) => e.sessionId === sessionId);
    },
  };
}

/**
 * In-memory audit log for testing (does NOT write to disk).
 * Throws on the N-th append if `failOnAppend` is set.
 */
export function createMemoryAuditLog(failOnAppend?: number): AuditLog & {
  events: AuditEvent[];
} {
  const events: AuditEvent[] = [];
  let count = 0;

  return {
    events,
    append(event: Omit<AuditEvent, "id" | "ts">): AuditEvent {
      count++;
      if (failOnAppend !== undefined && count >= failOnAppend) {
        throw new AuditWriteError("Configured to fail");
      }
      const full: AuditEvent = {
        ...event,
        id: randomUUID(),
        ts: new Date().toISOString(),
      };
      events.push(full);
      return full;
    },
    list(sessionId: string): AuditEvent[] {
      return events.filter((e) => e.sessionId === sessionId);
    },
  };
}
