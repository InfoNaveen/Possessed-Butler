/**
 * GET /api/audit?sessionId=<id>
 *
 * Returns audit events for a session. Shows security decisions without secrets.
 */
import { NextRequest, NextResponse } from "next/server";
import { configError, getStack } from "@/lib/wiring";

export async function GET(req: NextRequest): Promise<NextResponse> {
  const err = configError();
  if (err) return NextResponse.json({ error: `Agent not configured: ${err}` }, { status: 503 });

  const sessionId = req.nextUrl.searchParams.get("sessionId");
  if (!sessionId) {
    return NextResponse.json({ error: "sessionId query parameter required" }, { status: 400 });
  }
  try {
    const { audit } = getStack();
    return NextResponse.json(audit.list(sessionId));
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "error" }, { status: 500 });
  }
}
