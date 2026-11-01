"use client";

import { useState, useRef, useEffect, useCallback } from "react";

// ── Types (mirrors server contracts) ──────────────────────────────────────────
type SessionStatus = "idle" | "running" | "awaiting_approval" | "completed" | "error";

type BackendExecutionStatus =
  | "APPROVAL_PENDING"
  | "APPROVAL_REJECTED"
  | "EMAIL_SENT"
  | "EMAIL_FAILED"
  | "IDLE"
  | "RUNNING"
  | "COMPLETED"
  | "ERROR";

interface ApprovalRequest {
  id: string;
  sessionId: string;
  tool: string;
  args: unknown;
  argsHash: string;
  reasons: string[];
  status: string;
  createdAt: string;
  expiresAt: string;
}

interface AgentTurnResult {
  sessionId: string;
  status: SessionStatus;
  assistantText: string | null;
  pendingApproval: ApprovalRequest | null;
  error: { code: string; message: string } | null;
  executionStatus?: BackendExecutionStatus;
  executionDetails?: {
    tool?: string;
    messageId?: string;
    accepted?: string[];
    rejected?: string[];
    summary?: string;
    reasons?: string[];
    [key: string]: unknown;
  };
}

interface AuditEvent {
  id: string;
  ts: string;
  sessionId: string;
  type: string;
  data: Record<string, unknown>;
}

interface Message {
  role: "user" | "assistant" | "notice" | "error" | "security_alert";
  text: string;
  ts: number;
  executionStatus?: BackendExecutionStatus;
  details?: Record<string, unknown>;
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function statusColor(s: SessionStatus): string {
  switch (s) {
    case "running":
      return "dot-blue animate-pulse-dot";
    case "awaiting_approval":
      return "dot-amber animate-pulse-dot";
    case "completed":
      return "dot-green";
    case "error":
      return "dot-red";
    default:
      return "dot-gray";
  }
}

function statusLabel(s: SessionStatus): string {
  switch (s) {
    case "running":
      return "Agent Executing…";
    case "awaiting_approval":
      return "Security Approval Required";
    case "completed":
      return "Security Engine Ready";
    case "error":
      return "Execution Interrupted";
    default:
      return "Standing Guard";
  }
}

function eventBadge(type: string) {
  if (type.includes("denied") || type === "authz_decision") return "badge-blue";
  if (type.includes("injection") || type.includes("signal")) return "badge-red";
  if (type === "tool_executed" || type.includes("success")) return "badge-green";
  if (type === "approval_requested" || type.includes("approval")) return "badge-amber";
  if (type === "tool_proposed") return "badge-violet";
  return "badge-gray";
}

function toolBadge(decision: string | undefined) {
  if (decision === "allow") return "badge-green";
  if (decision === "deny") return "badge-red";
  if (decision === "require_approval") return "badge-amber";
  return "badge-gray";
}

const CSRF_HEADERS = {
  "Content-Type": "application/json",
  "x-butler-operator": "1",
};

function fmtTime(ts: string | number) {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function Dashboard() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [sessionId, setSessionId] = useState<string | undefined>();
  const [status, setStatus] = useState<SessionStatus>("idle");
  const [executionStatus, setExecutionStatus] = useState<BackendExecutionStatus>("IDLE");
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [activeTab, setActiveTab] = useState<"security" | "audit">("security");
  const [loading, setLoading] = useState(false);
  const [approvalLoading, setApprovalLoading] = useState(false);
  const [lastEmailSentDetails, setLastEmailSentDetails] = useState<{
    to: string[];
    subject: string;
    messageId?: string;
  } | null>(null);

  const chatEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll chat
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  // Fetch audit log safely without exposing secrets
  const fetchAudit = useCallback(async (sid: string) => {
    try {
      const res = await fetch(`/api/audit?sessionId=${encodeURIComponent(sid)}`);
      if (res.ok) {
        const data = (await res.json()) as AuditEvent[];
        setAuditEvents(data);
      }
    } catch {
      /* non-critical audit fetch failure */
    }
  }, []);

  function pushMsg(
    role: Message["role"],
    text: string,
    extra?: { executionStatus?: BackendExecutionStatus; details?: Record<string, unknown> }
  ) {
    setMessages((prev) => [
      ...prev,
      {
        role,
        text,
        ts: Date.now(),
        executionStatus: extra?.executionStatus,
        details: extra?.details,
      },
    ]);
  }

  function applyResult(result: AgentTurnResult) {
    setSessionId(result.sessionId);
    setStatus(result.status);
    setPendingApproval(result.pendingApproval);
    if (result.executionStatus) {
      setExecutionStatus(result.executionStatus);
    }

    if (result.error) {
      pushMsg("error", `[${result.error.code}] ${result.error.message}`);
    }

    // ── STRICT BACKEND-DRIVEN STATUS HANDLING ──────────────────────────
    // The UI uses backend execution status as the source of truth,
    // never relying solely on LLM conversational text.
    if (result.executionStatus === "EMAIL_SENT") {
      const msgId = result.executionDetails?.summary ?? "SMTP accepted";
      pushMsg(
        "notice",
        `✅ BACKEND CONFIRMED: Email accepted by SMTP server for delivery.\n${msgId}`,
        { executionStatus: "EMAIL_SENT", details: result.executionDetails }
      );
    } else if (result.executionStatus === "EMAIL_FAILED") {
      pushMsg(
        "error",
        `❌ SMTP DELIVERY FAILED: ${result.executionDetails?.summary ?? "SMTP rejected transmission"}`,
        { executionStatus: "EMAIL_FAILED", details: result.executionDetails }
      );
    } else if (result.executionStatus === "APPROVAL_REJECTED") {
      pushMsg(
        "security_alert",
        `🛡️ ACTION REJECTED: Operator denied authorization. Zero emails sent. Execution cancelled safely.`,
        { executionStatus: "APPROVAL_REJECTED" }
      );
    }

    if (result.assistantText) {
      pushMsg("assistant", result.assistantText);
    }

    if (result.pendingApproval) {
      pushMsg(
        "notice",
        `⏳ Security hold: Approval required for "${result.pendingApproval.tool}".\nPolicy: ${result.pendingApproval.reasons.join("; ")}`,
        { executionStatus: "APPROVAL_PENDING" }
      );
    }

    fetchAudit(result.sessionId);
  }

  async function sendMessage() {
    const msg = input.trim();
    if (!msg || loading || status === "awaiting_approval") return;
    setInput("");
    if (textareaRef.current) textareaRef.current.style.height = "auto";
    pushMsg("user", msg);
    setLoading(true);
    setStatus("running");
    setExecutionStatus("RUNNING");

    try {
      const res = await fetch("/api/agent", {
        method: "POST",
        headers: CSRF_HEADERS,
        body: JSON.stringify({ sessionId, message: msg }),
      });
      const data = (await res.json()) as AgentTurnResult;
      applyResult(data);
    } catch {
      pushMsg("error", "Network error — could not reach the Butler backend.");
      setStatus("error");
      setExecutionStatus("ERROR");
    } finally {
      setLoading(false);
    }
  }

  async function resolveApproval(verdict: "approve" | "reject") {
    if (!pendingApproval || approvalLoading) return;
    setApprovalLoading(true);

    if (verdict === "approve" && pendingApproval.tool === "email.send") {
      const args = pendingApproval.args as Record<string, unknown>;
      const to = Array.isArray(args.to) ? (args.to as string[]) : [];
      setLastEmailSentDetails({
        to,
        subject: String(args.subject ?? ""),
      });
    }

    pushMsg(
      "notice",
      `${verdict === "approve" ? "⚡ OPERATOR APPROVED" : "🛑 OPERATOR REJECTED"}: ${pendingApproval.tool}. Verifying HMAC authority…`
    );

    try {
      const res = await fetch(`/api/approvals/${pendingApproval.id}`, {
        method: "POST",
        headers: CSRF_HEADERS,
        body: JSON.stringify({ verdict }),
      });
      const data = (await res.json()) as AgentTurnResult;
      applyResult(data);
    } catch {
      pushMsg("error", "Network communication error while submitting approval.");
    } finally {
      setApprovalLoading(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  function autoResize(e: React.ChangeEvent<HTMLTextAreaElement>) {
    setInput(e.target.value);
    e.target.style.height = "auto";
    e.target.style.height = Math.min(e.target.scrollHeight, 160) + "px";
  }

  // Derived security signals from audit events
  const injectionSignals = auditEvents.filter((e) => e.type === "injection_signal");
  const deniedActions = auditEvents.filter(
    (e) => e.type === "authz_decision" && (e.data as Record<string, unknown>)["kind"] === "deny"
  );
  const approvalEvents = auditEvents.filter((e) => e.type === "approval_requested");
  const toolExecutions = auditEvents.filter((e) => e.type === "tool_executed");
  const tainted = auditEvents.some(
    (e) => e.type === "content_ingested" && (e.data as Record<string, unknown>)["trust"] === "untrusted"
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", overflow: "hidden", background: "var(--bg-base)" }}>
      {/* ── Top Bar ── */}
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 20px",
          background: "var(--bg-panel)",
          borderBottom: "1px solid var(--border)",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div
            style={{
              width: 34,
              height: 34,
              borderRadius: "var(--radius-sm)",
              background: "linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 0 12px rgba(59, 130, 246, 0.3)",
            }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontWeight: 800, fontSize: 16, letterSpacing: "-.3px", color: "var(--text-primary)" }}>
                THE POSSESSED BUTLER
              </span>
              <span className="badge badge-blue">HMAC ARMED</span>
              <span className="badge badge-violet">INDIRECT INJECTION DEFENSE</span>
            </div>
            <p style={{ fontSize: 11, color: "var(--text-muted)", margin: 0 }}>
              Deterministic Security Policy Engine · Fail-Closed Tool Authorization
            </p>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {tainted ? (
            <span className="badge badge-amber" title="Untrusted content loaded into context">
              <span className="status-dot dot-amber animate-pulse-dot" />
              TAINT TRACKED
            </span>
          ) : (
            <span className="badge badge-green" title="Context is clean">
              <span className="status-dot dot-green" />
              CLEAN CONTEXT
            </span>
          )}

          {injectionSignals.length > 0 && (
            <span className="badge badge-red" title="Injection patterns detected in data stream">
              ⚠ {injectionSignals.length} INJECTION BLOCKED
            </span>
          )}

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "4px 10px",
              background: "var(--bg-card)",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--border)",
              fontSize: 12,
            }}
          >
            <span className={`status-dot ${statusColor(status)}`} />
            <span style={{ color: "var(--text-secondary)", fontWeight: 500 }}>{statusLabel(status)}</span>
          </div>
          <a
            href="/sentinel"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              padding: "5px 12px",
              borderRadius: "var(--radius-sm)",
              background: "#2E151B",
              color: "#DA7B93",
              border: "1px solid #DA7B9350",
              fontSize: 12,
              fontWeight: 700,
              textDecoration: "none",
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            🛡️ Sentinel Command Center ↗
          </a>
          <div style={{ display: "none" }}>
          </div>
        </div>
      </header>

      {/* ── Main Layout ── */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* ── Left: Agent Chat & Email Composer ── */}
        <main
          style={{
            display: "flex",
            flexDirection: "column",
            flex: 1,
            overflow: "hidden",
            minWidth: 0,
            background: "var(--bg-base)",
          }}
        >
          {/* Messages Scroll Area */}
          <div
            id="chat-messages"
            style={{
              flex: 1,
              overflowY: "auto",
              padding: "20px 24px",
              display: "flex",
              flexDirection: "column",
              gap: 16,
            }}
          >
            {messages.length === 0 && (
              <div
                style={{
                  margin: "auto",
                  textAlign: "center",
                  color: "var(--text-muted)",
                  maxWidth: 540,
                  padding: "32px 16px",
                }}
              >
                <div
                  style={{
                    width: 64,
                    height: 64,
                    borderRadius: "50%",
                    background: "rgba(59, 130, 246, 0.08)",
                    border: "1px solid rgba(59, 130, 246, 0.25)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    margin: "0 auto 16px",
                    fontSize: 28,
                  }}
                >
                  🛡️
                </div>
                <h2 style={{ fontWeight: 700, fontSize: 18, color: "var(--text-primary)", marginBottom: 8 }}>
                  The Butler is Guarding Your Actions
                </h2>
                <p style={{ fontSize: 13, lineHeight: 1.7, color: "var(--text-secondary)", marginBottom: 20 }}>
                  The AI proposes. The security engine authorizes. The tools execute.
                  <br />
                  Sensitive actions like <strong>email sending</strong> require explicit operator approval with full draft inspection before SMTP transmission.
                </p>

                <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "stretch" }}>
                  {[
                    "Write a professional email introducing The Possessed Butler to judge@example.com and send it",
                    "List my unread emails and summarize them",
                    "Read suspicious email and check for prompt injection",
                  ].map((s) => (
                    <button
                      key={s}
                      className="btn btn-ghost"
                      style={{ fontSize: 13, textAlign: "left", justifyContent: "flex-start", padding: "10px 14px" }}
                      onClick={() => {
                        setInput(s);
                        textareaRef.current?.focus();
                      }}
                    >
                      <span style={{ color: "var(--accent-blue)", marginRight: 6 }}>➜</span> {s}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((m, i) => (
              <div
                key={i}
                className="animate-fade-in"
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: m.role === "user" ? "flex-end" : "flex-start",
                }}
              >
                {/* User Message */}
                {m.role === "user" && (
                  <div
                    style={{
                      background: "linear-gradient(135deg, #1d4ed8 0%, #2563eb 100%)",
                      color: "#fff",
                      padding: "10px 16px",
                      borderRadius: "14px 14px 4px 14px",
                      maxWidth: "75%",
                      fontSize: 14,
                      lineHeight: 1.5,
                      boxShadow: "0 2px 8px rgba(0, 0, 0, 0.25)",
                    }}
                  >
                    {m.text}
                  </div>
                )}

                {/* Assistant Message */}
                {m.role === "assistant" && (
                  <div
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--border)",
                      padding: "14px 18px",
                      borderRadius: "4px 14px 14px 14px",
                      maxWidth: "85%",
                      fontSize: 14,
                      lineHeight: 1.65,
                      color: "var(--text-primary)",
                      whiteSpace: "pre-wrap",
                      boxShadow: "0 2px 6px rgba(0,0,0,0.15)",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, color: "var(--text-secondary)", fontSize: 12 }}>
                      <span className="status-dot dot-blue" />
                      <span style={{ fontWeight: 600, color: "var(--accent-blue)" }}>Possessed Butler</span>
                      <span style={{ color: "var(--text-muted)" }}>· {fmtTime(m.ts)}</span>
                    </div>
                    {m.text}
                  </div>
                )}

                {/* Security Alert / Notice Message */}
                {m.role === "security_alert" && (
                  <div
                    style={{
                      background: "#ef444415",
                      border: "1px solid #ef444440",
                      color: "#fca5a5",
                      padding: "10px 14px",
                      borderRadius: "var(--radius-sm)",
                      fontSize: 13,
                      maxWidth: "90%",
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                    }}
                  >
                    <span style={{ fontSize: 18 }}>🛑</span>
                    <div>{m.text}</div>
                  </div>
                )}

                {/* Notice Message */}
                {m.role === "notice" && (
                  <div
                    style={{
                      background: m.text.includes("CONFIRMED") ? "#22c55e10" : "#f59e0b10",
                      border: `1px solid ${m.text.includes("CONFIRMED") ? "#22c55e30" : "#f59e0b30"}`,
                      color: m.text.includes("CONFIRMED") ? "#86efac" : "#fbbf24",
                      padding: "10px 14px",
                      borderRadius: "var(--radius-sm)",
                      fontSize: 13,
                      maxWidth: "90%",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {m.text}
                  </div>
                )}

                {/* Error Message */}
                {m.role === "error" && (
                  <div
                    style={{
                      background: "#ef444410",
                      border: "1px solid #ef444430",
                      color: "#f87171",
                      padding: "10px 14px",
                      borderRadius: "var(--radius-sm)",
                      fontSize: 13,
                      maxWidth: "90%",
                    }}
                  >
                    ⚠ {m.text}
                  </div>
                )}
              </div>
            ))}

            {loading && (
              <div className="animate-fade-in" style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--text-muted)", fontSize: 13 }}>
                <span className="status-dot dot-blue animate-pulse-dot" />
                <span>Security Engine evaluating proposals & model output…</span>
              </div>
            )}

            <div ref={chatEndRef} />
          </div>

          {/* ── Email Approval Composer UI (Section 4) ── */}
          {pendingApproval && (
            <div
              className="animate-fade-in"
              style={{
                margin: "0 24px 14px",
                background: "linear-gradient(180deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.95) 100%)",
                border: "1px solid rgba(59, 130, 246, 0.4)",
                boxShadow: "0 4px 20px rgba(0, 0, 0, 0.4)",
                borderRadius: "var(--radius-md)",
                padding: "18px 20px",
              }}
            >
              {/* Header */}
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span className="status-dot dot-amber animate-pulse-dot" />
                  <span style={{ fontWeight: 800, fontSize: 14, color: "#fbbf24", letterSpacing: ".3px" }}>
                    {pendingApproval.tool === "email.send" ? "📧 EMAIL COMPOSITION & AUTHORIZATION GATE" : "SECURITY HOLD: HUMAN APPROVAL REQUIRED"}
                  </span>
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  <span className="badge badge-amber">{pendingApproval.tool}</span>
                  <span className="badge badge-red">EXECUTION HOLD</span>
                </div>
              </div>

              {/* Dedicated Email Composer Draft View for email.send */}
              {pendingApproval.tool === "email.send" &&
                (() => {
                  const args = pendingApproval.args as Record<string, unknown>;
                  const to = Array.isArray(args.to) ? (args.to as string[]) : [String(args.to ?? "")];
                  const subject = String(args.subject ?? "(No subject)");
                  const body = String(args.body ?? "");

                  return (
                    <div
                      style={{
                        background: "var(--bg-card)",
                        border: "1px solid var(--border)",
                        borderRadius: "var(--radius-sm)",
                        overflow: "hidden",
                        marginBottom: 14,
                      }}
                    >
                      {/* To Field */}
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 12,
                          padding: "10px 14px",
                          borderBottom: "1px solid var(--border)",
                          background: "rgba(22, 27, 34, 0.6)",
                        }}
                      >
                        <span style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", width: 60, flexShrink: 0 }}>
                          RECIPIENT:
                        </span>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          {to.map((addr) => (
                            <span
                              key={addr}
                              style={{
                                background: "rgba(59, 130, 246, 0.15)",
                                border: "1px solid rgba(59, 130, 246, 0.35)",
                                color: "#93c5fd",
                                borderRadius: 4,
                                padding: "2px 8px",
                                fontSize: 13,
                                fontFamily: "monospace",
                              }}
                            >
                              {addr}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Subject Field */}
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 12,
                          padding: "10px 14px",
                          borderBottom: "1px solid var(--border)",
                          background: "rgba(22, 27, 34, 0.4)",
                        }}
                      >
                        <span style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", width: 60, flexShrink: 0 }}>
                          SUBJECT:
                        </span>
                        <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>{subject}</span>
                      </div>

                      {/* Body Field — Never hidden, clearly readable */}
                      <div style={{ padding: "14px" }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", marginBottom: 8, letterSpacing: ".5px" }}>
                          EMAIL BODY PREVIEW (UNTRUNCATED):
                        </div>
                        <div
                          style={{
                            fontSize: 13,
                            color: "var(--text-primary)",
                            lineHeight: 1.7,
                            whiteSpace: "pre-wrap",
                            maxHeight: 220,
                            overflowY: "auto",
                            background: "#0d1117",
                            padding: "12px 14px",
                            borderRadius: "var(--radius-sm)",
                            border: "1px solid var(--border)",
                          }}
                        >
                          {body}
                        </div>
                      </div>
                    </div>
                  );
                })()}

              {/* Generic parameters for other tools */}
              {pendingApproval.tool !== "email.send" && (
                <div className="code-block" style={{ marginBottom: 12, fontSize: 12 }}>
                  {JSON.stringify(pendingApproval.args, null, 2)}
                </div>
              )}

              {/* Security Policy Verification & HMAC Details */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 12,
                  padding: "8px 12px",
                  background: "rgba(34, 197, 94, 0.06)",
                  border: "1px solid rgba(34, 197, 94, 0.2)",
                  borderRadius: "var(--radius-sm)",
                  marginBottom: 14,
                  fontSize: 12,
                  color: "var(--text-secondary)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ color: "var(--accent-green)", fontWeight: 700 }}>✓</span>
                  <span>Evaluated by Deterministic Policy Engine · HMAC-signed token bound to arguments</span>
                </div>
                <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-muted)" }}>
                  SHA256: {pendingApproval.argsHash.slice(0, 14)}…
                </span>
              </div>

              {/* Policy Reasons */}
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 14 }}>
                <strong>Policy triggers:</strong> {pendingApproval.reasons.join(" · ")}
              </div>

              {/* Approve & Reject Actions */}
              <div style={{ display: "flex", gap: 10 }}>
                <button
                  id="btn-approve"
                  className="btn btn-primary"
                  style={{
                    background: "#16a34a",
                    borderColor: "#22c55e",
                    fontWeight: 600,
                    padding: "9px 20px",
                    boxShadow: "0 2px 10px rgba(34, 197, 94, 0.25)",
                  }}
                  disabled={approvalLoading}
                  onClick={() => resolveApproval("approve")}
                >
                  {approvalLoading ? (
                    <>
                      <span className="animate-spin" style={{ display: "inline-block", width: 14, height: 14, border: "2px solid #fff4", borderTopColor: "#fff", borderRadius: "50%" }} />
                      <span>Transmitting via SMTP…</span>
                    </>
                  ) : pendingApproval.tool === "email.send" ? (
                    "✓ Approve & Send via SMTP"
                  ) : (
                    "✓ Authorize Action"
                  )}
                </button>

                <button
                  id="btn-reject"
                  className="btn btn-reject"
                  style={{ fontWeight: 600, padding: "9px 18px" }}
                  disabled={approvalLoading}
                  onClick={() => resolveApproval("reject")}
                >
                  {approvalLoading ? "Processing…" : "✗ Reject Action"}
                </button>
              </div>
            </div>
          )}

          {/* ── Input Bar ── */}
          <div
            style={{
              padding: "14px 24px 18px",
              borderTop: "1px solid var(--border)",
              background: "var(--bg-panel)",
              flexShrink: 0,
            }}
          >
            <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
              <textarea
                id="chat-input"
                ref={textareaRef}
                className="input-field"
                rows={1}
                placeholder={
                  status === "awaiting_approval"
                    ? "Security hold: Please Approve or Reject the pending email above before continuing…"
                    : "Instruct The Possessed Butler… (Enter to send, Shift+Enter for newline)"
                }
                value={input}
                onChange={autoResize}
                onKeyDown={handleKeyDown}
                disabled={loading || status === "awaiting_approval"}
                style={{
                  minHeight: 46,
                  maxHeight: 160,
                  fontSize: 14,
                  lineHeight: 1.5,
                  opacity: status === "awaiting_approval" ? 0.6 : 1,
                }}
              />
              <button
                id="btn-send"
                className="btn btn-primary"
                style={{
                  minWidth: 46,
                  height: 46,
                  padding: "0 16px",
                  flexShrink: 0,
                  background: loading ? "var(--bg-hover)" : "var(--accent-blue)",
                }}
                disabled={!input.trim() || loading || status === "awaiting_approval"}
                onClick={sendMessage}
              >
                {loading ? (
                  <span
                    className="animate-spin"
                    style={{
                      display: "inline-block",
                      width: 16,
                      height: 16,
                      border: "2px solid #fff4",
                      borderTopColor: "#fff",
                      borderRadius: "50%",
                    }}
                  />
                ) : (
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="22" y1="2" x2="11" y2="13" />
                    <polygon points="22 2 15 22 11 13 2 9 22 2" />
                  </svg>
                )}
              </button>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 8 }}>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {sessionId ? (
                  <>
                    Session: <span style={{ fontFamily: "monospace", color: "var(--text-secondary)" }}>{sessionId.slice(0, 8)}…</span>
                  </>
                ) : (
                  "Ready for new session"
                )}
              </span>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                Backend Status: <strong style={{ color: "var(--text-secondary)" }}>{executionStatus}</strong>
              </span>
            </div>
          </div>
        </main>

        {/* ── Right Sidebar: Security & Audit Console (Section 5) ── */}
        <aside
          style={{
            width: 360,
            flexShrink: 0,
            display: "flex",
            flexDirection: "column",
            borderLeft: "1px solid var(--border)",
            overflow: "hidden",
            background: "var(--bg-panel)",
          }}
        >
          {/* Tabs */}
          <div style={{ display: "flex", borderBottom: "1px solid var(--border)", flexShrink: 0 }}>
            {(["security", "audit"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  flex: 1,
                  padding: "12px 0",
                  background: "none",
                  border: "none",
                  borderBottom: activeTab === tab ? "2px solid var(--accent-blue)" : "2px solid transparent",
                  color: activeTab === tab ? "var(--accent-blue)" : "var(--text-muted)",
                  fontWeight: activeTab === tab ? 700 : 500,
                  fontSize: 12,
                  cursor: "pointer",
                  letterSpacing: ".5px",
                  textTransform: "uppercase",
                  transition: "all .15s",
                }}
              >
                {tab === "security" ? "🛡 Security Console" : "📋 Real-Time Audit"}
              </button>
            ))}
          </div>

          <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
            {/* Security Tab */}
            {activeTab === "security" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                {/* 4 Security Counters */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                  {[
                    { label: "Injection Signals", value: injectionSignals.length, badge: injectionSignals.length > 0 ? "badge-red" : "badge-gray" },
                    { label: "Denied Actions", value: deniedActions.length, badge: deniedActions.length > 0 ? "badge-red" : "badge-gray" },
                    { label: "Human Approvals", value: approvalEvents.length, badge: approvalEvents.length > 0 ? "badge-amber" : "badge-gray" },
                    { label: "Tool Executions", value: toolExecutions.length, badge: "badge-green" },
                  ].map(({ label, value }) => (
                    <div
                      key={label}
                      className="card"
                      style={{
                        padding: "12px 14px",
                        background: "rgba(28, 34, 48, 0.7)",
                        border: "1px solid var(--border)",
                      }}
                    >
                      <div style={{ fontSize: 24, fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-.5px" }}>{value}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{label}</div>
                    </div>
                  ))}
                </div>

                {/* Taint & Provenance Status */}
                <div className="card" style={{ padding: "14px", border: "1px solid var(--border)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)" }}>Data Taint Tracking</span>
                    <span className={`badge ${tainted ? "badge-amber" : "badge-green"}`}>
                      {tainted ? "⚠ TAINTED BY EXTERNAL CONTENT" : "✓ PROVENANCE CLEAN"}
                    </span>
                  </div>
                  <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 8, lineHeight: 1.5 }}>
                    {tainted
                      ? "Untrusted external data ingested. The policy engine mandates human operator sign-off for any outbound actions."
                      : "No external untrusted data has entered the agent context."}
                  </p>
                </div>

                {/* Injection Signals Detected */}
                <div>
                  <div className="section-header" style={{ display: "flex", justifyContent: "space-between" }}>
                    <span>Injection Signals</span>
                    <span>{injectionSignals.length} Total</span>
                  </div>
                  {injectionSignals.length === 0 ? (
                    <div className="card" style={{ padding: "12px", fontSize: 12, color: "var(--text-muted)", textAlign: "center" }}>
                      Zero injection signals detected in stream.
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      {injectionSignals.slice(-6).map((e) => {
                        const d = e.data as Record<string, unknown>;
                        const sev = String(d["severity"] ?? "low");
                        return (
                          <div key={e.id} className="card animate-fade-in" style={{ padding: "8px 12px", borderLeft: "3px solid #ef4444" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)" }}>
                                {String(d["detectorId"] ?? "INJECTION_DETECTOR")}
                              </span>
                              <span className={`badge ${sev === "high" ? "badge-red" : "badge-amber"}`}>
                                {sev.toUpperCase()}
                              </span>
                            </div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                              {String(d["description"] ?? "")}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Policy Decisions Timeline */}
                <div>
                  <div className="section-header">Authorization Decisions</div>
                  {auditEvents.filter((e) => e.type === "authz_decision").length === 0 ? (
                    <div className="card" style={{ padding: "12px", fontSize: 12, color: "var(--text-muted)", textAlign: "center" }}>
                      No policy evaluations recorded yet.
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      {auditEvents
                        .filter((e) => e.type === "authz_decision")
                        .slice(-5)
                        .map((e) => {
                          const d = e.data as Record<string, unknown>;
                          const kind = String(d["kind"] ?? "");
                          return (
                            <div key={e.id} className="card animate-fade-in" style={{ padding: "10px 12px" }}>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-primary)" }}>
                                  {String(d["tool"] ?? "Tool Proposal")}
                                </span>
                                <span className={`badge ${toolBadge(kind)}`}>{kind.toUpperCase().replace("_", " ")}</span>
                              </div>
                              {Array.isArray(d["reasons"]) && (d["reasons"] as string[]).length > 0 && (
                                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                                  {(d["reasons"] as string[]).join("; ")}
                                </div>
                              )}
                              <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 3 }}>{fmtTime(e.ts)}</div>
                            </div>
                          );
                        })}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Audit Tab */}
            {activeTab === "audit" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {auditEvents.length === 0 ? (
                  <div style={{ color: "var(--text-muted)", fontSize: 12, textAlign: "center", paddingTop: 32 }}>
                    Audit events will stream here live during turns.
                  </div>
                ) : (
                  [...auditEvents].reverse().map((e) => (
                    <div key={e.id} className="card animate-fade-in" style={{ padding: "10px 12px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                        <span className={`badge ${eventBadge(e.type)}`} style={{ flexShrink: 0 }}>
                          {e.type.replace(/_/g, " ")}
                        </span>
                        <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "monospace" }}>{fmtTime(e.ts)}</span>
                      </div>
                      {Object.keys(e.data).length > 0 && (
                        <div className="code-block" style={{ marginTop: 6, fontSize: 10, maxHeight: 120, overflowY: "auto" }}>
                          {JSON.stringify(e.data, null, 2)}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}
