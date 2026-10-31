/**
 * src/lib/security/hash.ts
 *
 * Canonical argument hashing. Must produce the same result as testHashArgs() in
 * tests/doubles/security-double.ts so the executor's re-hash check always passes.
 *
 * Algorithm: sha256( JSON.stringify( canonicalJson(args) ) ) — no prefix, lowercase hex.
 * Keys are sorted recursively so {b:2,a:1} and {a:1,b:2} produce the same hash.
 */
import { createHash } from "node:crypto";

/** Recursively sort object keys for canonical representation. */
function canonicalJson(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonicalJson);
  if (v !== null && typeof v === "object") {
    return Object.fromEntries(
      Object.keys(v as object)
        .sort()
        .map((k) => [k, canonicalJson((v as Record<string, unknown>)[k])]),
    );
  }
  return v;
}

/**
 * Returns the SHA-256 hex digest of the canonical JSON representation of `args`.
 * Matches the algorithm in tests/doubles/security-double.ts `testHashArgs()`.
 */
export function hashArgs(args: unknown): string {
  const canonical = canonicalJson(args ?? null);
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}
