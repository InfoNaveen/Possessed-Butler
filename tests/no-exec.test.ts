import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

// security.md rule 3 / tool-execution requirement 9.2: no execution primitives anywhere in src/.
const FORBIDDEN: [string, RegExp][] = [
  ["child_process", /\bchild_process\b/],
  ["node:vm", /["'](node:)?vm["']/],
  ["eval(", /\beval\s*\(/],
  ["new Function", /\bnew\s+Function\b/],
  ["dynamic import with non-literal", /\bimport\s*\(\s*[^"'`\s)]/],
];

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? files(p) : /\.(ts|tsx|js|mjs|cjs)$/.test(name) ? [p] : [];
  });
}

describe("no arbitrary execution primitives in src/", () => {
  it("finds none", () => {
    const root = join(process.cwd(), "src");
    const hits: string[] = [];
    for (const file of files(root)) {
      const text = readFileSync(file, "utf8");
      for (const [label, re] of FORBIDDEN) if (re.test(text)) hits.push(`${relative(root, file)}: ${label}`);
    }
    expect(hits).toEqual([]);
  });
});
