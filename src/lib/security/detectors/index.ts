/**
 * src/lib/security/detectors/index.ts
 *
 * Prompt-injection detectors. Each detector scans a ContentSegment and
 * returns InjectionSignal objects. Detectors are pure functions — no side effects.
 *
 * All description strings are fixed templates that NEVER echo back untrusted content.
 */
import type { ContentSegment, InjectionSignal } from "@contracts";

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------

interface Pattern {
  detectorId: string;
  pattern: RegExp;
  severity: InjectionSignal["severity"];
  description: string; // fixed, no attacker content
}

const PATTERNS: Pattern[] = [
  {
    detectorId: "D-ROLE-OVERRIDE",
    pattern: /ignore\s+(previous|all|prior|above)\s+instructions/gi,
    severity: "high",
    description: "Content contains a role-override instruction attempt.",
  },
  {
    detectorId: "D-TOOL-CALL-JSON",
    pattern: /\{\s*"(?:tool|name)"\s*:/g,
    severity: "high",
    description: "Content contains an embedded JSON tool-call object.",
  },
  {
    detectorId: "D-DELIMITER-ESCAPE",
    pattern: /(?:<\/?\s*(?:system|im_start|im_end|INST|SYS|human|assistant)\s*[>|])|(?:<\|(?:im_start|im_end|endoftext)\|>)|(?:\[\/?\s*(?:INST|SYS)\s*\])/gi,
    severity: "high",
    description: "Content attempts to escape chat-template delimiters.",
  },
  {
    detectorId: "D-NEW-INSTRUCTIONS",
    pattern: /(?:your|the)\s+new\s+(?:instructions?|task|objective|goal|mission|directive)\s*(?:is|are|:)/gi,
    severity: "high",
    description: "Content attempts to replace agent instructions.",
  },
  {
    detectorId: "D-SECRET-EXTRACTION",
    pattern: /(?:repeat|print|reveal|show|output|display|return|leak)\s+(?:your\s+)?(?:system\s+prompt|instructions?|api\s+key|secret|password|token|credential)/gi,
    severity: "high",
    description: "Content attempts to extract secrets or the system prompt.",
  },
  {
    detectorId: "D-URGENCY-ESCALATION",
    pattern: /URGENT\s*[:\-]?\s*.{0,80}(?:instructions?|task|send|exfil|forward|delete|write)/gi,
    severity: "medium",
    description: "Content uses urgency framing to escalate a command.",
  },
  {
    detectorId: "D-PERSONA-OVERRIDE",
    pattern: /(?:you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be)|behave\s+as|roleplay\s+as|simulate\s+being)/gi,
    severity: "medium",
    description: "Content attempts a persona or role override.",
  },
  {
    detectorId: "D-SAFETY-BYPASS",
    pattern: /(?:disregard|bypass|override|disable|circumvent|ignore)\s+(?:your\s+)?(?:safety|security|restrictions?|guidelines?|rules?|policies?|limits?)/gi,
    severity: "medium",
    description: "Content instructs the agent to bypass safety measures.",
  },
  {
    detectorId: "D-INDIRECT-COMMAND",
    pattern: /(?:the\s+(?:document|email|page|pdf|content|message)\s+says?|according\s+to\s+(?:this|the)\b)[^.!?]*(?:you\s+(?:must|should|need\s+to|have\s+to)|send|delete|write|exfil|forward)/gi,
    severity: "medium",
    description: "Content uses indirect framing to issue a command.",
  },
  {
    detectorId: "D-JAILBREAK",
    pattern: /(?:do\s+anything\s+now|dan\s+mode|jailbreak|developer\s+mode\s+enabled|no\s+restrictions)/gi,
    severity: "low",
    description: "Content contains jailbreak or DAN-mode phrasing.",
  },
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scans a ContentSegment for injection signals.
 * Returns a flat array of InjectionSignal — one per pattern match.
 * Never throws; returns [] on any error.
 *
 * Only operates on untrusted content — trusted segments are skipped.
 */
export function scanSegment(segment: ContentSegment): InjectionSignal[] {
  if (segment.trust !== "untrusted") return [];

  const signals: InjectionSignal[] = [];
  try {
    for (const def of PATTERNS) {
      def.pattern.lastIndex = 0;
      if (def.pattern.test(segment.text)) {
        signals.push({
          detectorId: def.detectorId,
          segmentId: segment.id,
          severity: def.severity,
          description: def.description, // fixed text, no attacker content
        });
      }
    }
  } catch {
    // Never surface detector errors to callers
  }
  return signals;
}

/**
 * Returns true if the segment text contains what looks like an embedded tool-call
 * JSON targeting a sensitive action. Used by policy rules.
 */
export function containsEmbeddedToolCall(text: string): {
  found: boolean;
  toolName: string | null;
} {
  // Walk balanced braces to find {"tool":...} or {"name":...} blobs
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== "{") continue;
    let depth = 0;
    let j = i;
    for (; j < text.length; j++) {
      if (text[j] === "{") depth++;
      else if (text[j] === "}") {
        depth--;
        if (depth === 0) break;
      }
    }
    if (depth !== 0) continue;
    const blob = text.slice(i, j + 1);
    if (!/"(?:tool|name)"\s*:/.test(blob)) continue;
    try {
      const parsed = JSON.parse(blob) as Record<string, unknown>;
      const name =
        typeof parsed["tool"] === "string"
          ? parsed["tool"]
          : typeof parsed["name"] === "string"
            ? parsed["name"]
            : null;
      return { found: true, toolName: name };
    } catch {
      // malformed JSON — keep scanning
    }
  }
  return { found: false, toolName: null };
}

/** All detector IDs for test coverage assertions. */
export const DETECTOR_IDS = PATTERNS.map((p) => p.detectorId);
