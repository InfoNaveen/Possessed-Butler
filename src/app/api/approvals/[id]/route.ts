/**
 * POST /api/approvals/[id]
 *
 * Operator approves or rejects a pending tool call.
 * This is the ONLY path through which an approval can be granted.
 * Returns AgentTurnResult (the resumed turn).
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { configError, getStack } from "@/lib/wiring";
import { guardPost } from "../../_guard";

const BodySchema = z.strictObject({
  verdict: z.enum(["approve", "reject"]),
});

export async function POST(req: NextRequest, ctx: RouteContext<"/api/approvals/[id]">): Promise<NextResponse> {
  const err = configError();
  if (err) return NextResponse.json({ error: `Agent not configured: ${err}` }, { status: 503 });

  const guard = guardPost(req);
  if (guard) return guard;

  const { id } = await ctx.params;

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
    const result = await agent.resumeAfterApproval(id, parsed.data.verdict);
    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "error" }, { status: 500 });
  }
}
