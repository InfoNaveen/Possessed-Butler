// Quick E2E test script — run with: node e2e-test.mjs
// Tests Scenario A (legitimate email read), Scenario C (email.send approval gate), and Judge scenario

const BASE = "http://localhost:3000";
const HEADERS = {
  "Content-Type": "application/json",
  "x-butler-operator": "1",
  "Origin": BASE,
};

async function agentTurn(message, sessionId) {
  const res = await fetch(`${BASE}/api/agent`, {
    method: "POST",
    headers: HEADERS,
    body: JSON.stringify({ message, ...(sessionId ? { sessionId } : {}) }),
  });
  return res.json();
}

async function approveAction(approvalId, verdict) {
  const res = await fetch(`${BASE}/api/approvals/${approvalId}`, {
    method: "POST",
    headers: HEADERS,
    body: JSON.stringify({ verdict }),
  });
  return res.json();
}

async function getAudit(sessionId) {
  const res = await fetch(`${BASE}/api/audit?sessionId=${sessionId}`);
  return res.json();
}

function sep(label) {
  console.log("\n" + "═".repeat(60));
  console.log(`  ${label}`);
  console.log("═".repeat(60));
}

function show(obj) {
  console.log(JSON.stringify(obj, null, 2));
}

// ── Scenario A: Legitimate request ─────────────────────────────
sep("SCENARIO A: List emails (should ALLOW)");
const a = await agentTurn("List my emails and summarize them.");
console.log("Status:", a.status);
console.log("Error:", a.error);
console.log("Assistant:", a.assistantText?.slice(0, 300));

const sessionId = a.sessionId;
if (sessionId) {
  const audit = await getAudit(sessionId);
  const decisions = audit.filter(e => e.type === "authz_decision");
  console.log("\nAuthorization decisions:", decisions.length);
  decisions.forEach(e => {
    console.log(`  tool=${e.data.tool}  kind=${e.data.kind}`);
  });
  const signals = audit.filter(e => e.type === "injection_signal");
  console.log("Injection signals:", signals.length);
}

// ── Scenario C: Sensitive action (email.send → require_approval) ──
sep("SCENARIO C: email.send (should require APPROVAL)");
const c1 = await agentTurn('Send an email to alice@example.test with subject "Hello" and body "How are you?"');
console.log("Status:", c1.status);
console.log("Pending approval:", c1.pendingApproval ? `YES — tool: ${c1.pendingApproval.tool}` : "none");

if (c1.pendingApproval) {
  console.log("Reasons:", c1.pendingApproval.reasons);
  
  // Reject it to show the security gate works
  sep("REJECTING the approval");
  const c2 = await approveAction(c1.pendingApproval.id, "reject");
  console.log("Status after reject:", c2.status);
  console.log("Assistant:", c2.assistantText?.slice(0, 200));
}

// ── Security guard test: missing CSRF header ──────────────────
sep("SECURITY: Missing x-butler-operator header → expect 403");
const guardTest = await fetch(`${BASE}/api/agent`, {
  method: "POST",
  headers: { "Content-Type": "application/json", "Origin": BASE },
  body: JSON.stringify({ message: "test" }),
});
console.log("HTTP status:", guardTest.status, "(expected 403)");

sep("ALL SCENARIOS COMPLETE");
