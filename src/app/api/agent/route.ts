/**
 * POST /api/agent
 *
 * Start or continue an agent turn. Returns AgentTurnResult.
 * Reads from the real stack (real security engine).
 *
 * Per Next.js 16 / Cache Components guidance: no `runtime` export, no `dynamic` export.
 * Reading request.json() makes this run at request time automatically.
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
    // Stack init failures (bad config, missing mailbox, etc.) are caught here
    const message = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
