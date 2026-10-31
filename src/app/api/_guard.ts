/**
 * src/app/api/_guard.ts
 *
 * CSRF guard for state-changing POST routes (agent, approvals).
 *
 * Requires:
 *   1. Content-Type: application/json
 *   2. x-butler-operator: 1  (custom header — cross-site pages can't set this without CORS)
 *   3. Origin header present and matches the request URL's origin (same-origin check)
 *
 * A browser page served from a different origin would need a CORS preflight to set the
 * custom header, which we never allow, so cross-site request forgery is blocked.
 * Per agent-core design.md.
 */
import { NextRequest, NextResponse } from "next/server";

export function guardPost(req: NextRequest): NextResponse | null {
  const contentType = req.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return NextResponse.json({ error: "Content-Type must be application/json" }, { status: 415 });
  }
  if (req.headers.get("x-butler-operator") !== "1") {
    return NextResponse.json({ error: "Missing x-butler-operator header" }, { status: 403 });
  }
  const origin = req.headers.get("origin");
  if (!origin) {
    return NextResponse.json({ error: "Missing Origin header" }, { status: 403 });
  }
  try {
    const reqOrigin = new URL(req.url).origin;
    if (origin !== reqOrigin) {
      return NextResponse.json({ error: "Cross-origin request rejected" }, { status: 403 });
    }
  } catch {
    return NextResponse.json({ error: "Invalid request URL" }, { status: 400 });
  }
  return null; // all checks passed
}
