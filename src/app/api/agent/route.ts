/**
 * POST /api/agent — Start or continue an agent turn. Returns AgentTurnResult.
 * GET  /api/agent — List active sessions or inspect specific session.
 *
 * Reads from the real stack (real security engine).
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { configError, getStack } from "@/lib/wiring";
import { guardPost } from "../_guard";

const BodySchema = z.strictObject({
  sessionId: z.string().uuid().optional(),
  message: z.string().min(1).max(4000),
});

export async function POST(req: NextRequest): Promise<NextResponse> {
  const err = configError();
  if (err) return NextResponse.json({ error: `Agent not configured: ${err}` }, { status: 503 });

  const guard = guardPost(req);
  if (guard) return guard;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const parsed = BodySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }

  try {
    const { agent } = getStack();
    const result = await agent.runTurn(parsed.data);
    return NextResponse.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function GET(req: NextRequest): Promise<NextResponse> {
  const err = configError();
  if (err) return NextResponse.json({ error: `Agent not configured: ${err}` }, { status: 503 });

  const sessionId = req.nextUrl.searchParams.get("sessionId");
  try {
    const { agent } = getStack();
    if (sessionId) {
      const session = agent.getSession(sessionId);
      if (!session) return NextResponse.json({ error: "Session not found" }, { status: 404 });
      return NextResponse.json(session);
    }
    const sessions = (agent as unknown as { listSessions?: () => unknown }).listSessions
      ? (agent as unknown as { listSessions: () => unknown }).listSessions()
      : [];
    return NextResponse.json({ sessions });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
