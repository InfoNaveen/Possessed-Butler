/**
 * tests/security/hash.test.ts
 *
 * Verifies that hashArgs() is compatible with testHashArgs() from the test double.
 * If this test passes, the executor's re-hash check will never reject a valid token.
 */
import { hashArgs } from "@/lib/security/hash.js";
import { testHashArgs } from "../doubles/security-double.js";

describe("hashArgs — compatibility with test double", () => {
  it("produces the same hash as testHashArgs for a simple object", () => {
    const args = { path: "notes.txt" };
    expect(hashArgs(args)).toBe(testHashArgs(args));
  });

  it("is key-order-independent", () => {
    const a = hashArgs({ b: 2, a: 1 });
    const b = hashArgs({ a: 1, b: 2 });
    expect(a).toBe(b);
    expect(a).toBe(testHashArgs({ a: 1, b: 2 }));
  });

  it("handles nested objects recursively", () => {
    const args = { outer: { z: 3, a: 1 }, x: "hello" };
    expect(hashArgs(args)).toBe(testHashArgs(args));
  });

  it("handles arrays (no key-sorting inside arrays)", () => {
    const args = { items: [3, 1, 2] };
    expect(hashArgs(args)).toBe(testHashArgs(args));
  });

  it("handles null and undefined", () => {
    expect(hashArgs(null)).toBe(testHashArgs(null));
    expect(hashArgs(undefined)).toBe(testHashArgs(undefined));
  });

  it("handles empty object", () => {
    expect(hashArgs({})).toBe(testHashArgs({}));
  });

  it("returns different hashes for different inputs", () => {
    expect(hashArgs({ a: 1 })).not.toBe(hashArgs({ a: 2 }));
  });

  it("is deterministic (same output on multiple calls)", () => {
    const args = { url: "https://example.com", method: "GET" };
    expect(hashArgs(args)).toBe(hashArgs(args));
  });
});
