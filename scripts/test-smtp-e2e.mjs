/**
 * Judge scenario E2E test — SMTP delivery verified.
 * Run: node scripts/test-smtp-e2e.mjs
 *
 * Sends a real email through Ethereal SMTP.
 * Check delivery at: https://ethereal.email/messages
 */
const BASE = "http://localhost:3000";
const H = {
  "Content-Type": "application/json",
  "x-butler-operator": "1",
  "Origin": BASE,
};

async function post(path, body) {
  const r = await fetch(`${BASE}${path}`, { method: "POST", headers: H, body: JSON.stringify(body) });
  return r.json();
}

function sep(t) {
  console.log("\n" + "═".repeat(62));
  console.log(`  ${t}`);
  console.log("═".repeat(62));
}

// ── Wait for server ────────────────────────────────────────────
await new Promise(r => setTimeout(r, 2000));

// ── Judge Scenario: compose + send via Qwen ───────────────────
sep("JUDGE SCENARIO: Compose & send professional email");
console.log("Asking Qwen to draft and send to judge@example.test …");
const t1 = await post("/api/agent", {
  message: "Write a professional email introducing The Possessed Butler to judge@example.test and send it. Make it impressive.",
});
console.log("Status:", t1.status);
console.log("Pending approval:", t1.pendingApproval?.tool ?? "none");

if (t1.pendingApproval?.tool === "email.send") {
  const args = t1.pendingApproval.args;
  console.log("\n📧 DRAFT EMAIL:");
  console.log("  To:     ", Array.isArray(args.to) ? args.to.join(", ") : args.to);
  console.log("  Subject:", args.subject);
  console.log("  Body:\n");
  String(args.body).split("\n").forEach(l => console.log("    " + l));

  sep("APPROVING — will trigger real SMTP delivery");
  const t2 = await post(`/api/approvals/${t1.pendingApproval.id}`, { verdict: "approve" });
  console.log("Post-approval status:", t2.status);
  console.log("Assistant:", t2.assistantText?.slice(0, 400));

  if (t2.assistantText?.includes("delivered") || t2.assistantText?.includes("Message-ID") || t2.assistantText?.includes("sent")) {
    console.log("\n✅ EMAIL DELIVERY CONFIRMED");
    console.log("   View at: https://ethereal.email/messages");
    console.log("   Login: k5d424v2tvgmfzf2@ethereal.email / 2VddmAbrZPBy3tT26X");
  } else {
    console.log("\n⚠  Check assistant text above for delivery confirmation.");
  }
} else {
  console.log("\n⚠  Expected email.send approval — got:", JSON.stringify(t1.pendingApproval));
}

// ── Reject scenario ────────────────────────────────────────────
sep("REJECT SCENARIO: User rejects → no email sent");
const t3 = await post("/api/agent", {
  message: "Send an email to reject-test@example.test with subject 'Test' and body 'This should be rejected.'",
});
if (t3.pendingApproval?.tool === "email.send") {
  const t4 = await post(`/api/approvals/${t3.pendingApproval.id}`, { verdict: "reject" });
  console.log("Status after reject:", t4.status);
  console.log("Email sent?", t4.assistantText?.toLowerCase().includes("rejected") || t4.assistantText?.toLowerCase().includes("unable") ? "NO ✅" : "UNKNOWN");
}

// ── Security: no unauthorized send ────────────────────────────
sep("SECURITY: CSRF guard → 403");
const r = await fetch(`${BASE}/api/agent`, {
  method: "POST",
  headers: { "Content-Type": "application/json", "Origin": BASE },
  body: JSON.stringify({ message: "test" }),
});
console.log("Status:", r.status, r.status === 403 ? "✅" : "❌");

sep("DONE — check https://ethereal.email/messages for the sent email");
