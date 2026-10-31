/**
 * GET /api/approvals?sessionId=<id>
 *
 * Returns pending approvals for a session.
 */
import { NextRequest, NextResponse } from "next/server";
import { configError, getStack } from "@/lib/wiring";

export async function GET(req: NextRequest): Promise<NextResponse> {
  const err = configError();
  if (err) return NextResponse.json({ error: `Agent not configured: ${err}` }, { status: 503 });

  const sessionId = req.nextUrl.searchParams.get("sessionId") ?? undefined;
  try {
    const { approvals } = getStack();
    return NextResponse.json(approvals.listPending(sessionId));
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "error" }, { status: 500 });
  }
}
