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

// ── Status Helpers ────────────────────────────────────────────────────────────
function statusDot(s: SessionStatus): string {
  switch (s) {
    case "running":
      return "dot-pink animate-pulse-dot";
    case "awaiting_approval":
      return "dot-amber animate-pulse-dot";
    case "completed":
      return "dot-teal";
    case "error":
      return "dot-red";
    default:
      return "dot-gray";
  }
}

function statusLabel(s: SessionStatus): string {
  switch (s) {
    case "running":
      return "Evaluating Action…";
    case "awaiting_approval":
      return "Operator Approval Required";
    case "completed":
      return "Engine Standing Guard";
    case "error":
      return "Execution Interrupted";
    default:
      return "System Armed";
  }
}

function eventBadge(type: string) {
  if (type.includes("denied") || type === "authz_decision") return "badge-teal";
  if (type.includes("injection") || type.includes("signal")) return "badge-red";
  if (type === "tool_executed" || type.includes("success")) return "badge-green";
  if (type === "approval_requested" || type.includes("approval")) return "badge-amber";
  if (type === "tool_proposed") return "badge-pink";
  return "badge-slate";
}

function toolBadge(decision: string | undefined) {
  if (decision === "allow") return "badge-green";
  if (decision === "deny") return "badge-red";
  if (decision === "require_approval") return "badge-amber";
  return "badge-slate";
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

  const chatEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll chat smoothly
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  // Fetch real-time audit trail without leaking secrets
  const fetchAudit = useCallback(async (sid: string) => {
    try {
      const res = await fetch(`/api/audit?sessionId=${encodeURIComponent(sid)}`);
      if (res.ok) {
        const data = (await res.json()) as AuditEvent[];
        setAuditEvents(data);
      }
    } catch {
      /* audit fetch error suppressed */
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

    // STRICT BACKEND-DRIVEN STATUS HANDLING: source of truth
    if (result.executionStatus === "EMAIL_SENT") {
      const msgId = result.executionDetails?.summary ?? "Accepted by Gmail SMTP (STARTTLS 587)";
      pushMsg(
        "notice",
        `✅ GMAIL SMTP DISPATCH CONFIRMED\nServer accepted message for external delivery.\n${msgId}`,
        { executionStatus: "EMAIL_SENT", details: result.executionDetails }
      );
    } else if (result.executionStatus === "EMAIL_FAILED") {
      pushMsg(
        "error",
        `❌ SMTP DELIVERY FAILED: ${result.executionDetails?.summary ?? "SMTP rejected message or connection failed"}`,
        { executionStatus: "EMAIL_FAILED", details: result.executionDetails }
      );
    } else if (result.executionStatus === "APPROVAL_REJECTED") {
      pushMsg(
        "security_alert",
        `🛑 OPERATOR REJECTED ACTION: Human approval was denied. Execution token voided. 0 emails transmitted.`,
        { executionStatus: "APPROVAL_REJECTED" }
      );
    }

    if (result.assistantText) {
      pushMsg("assistant", result.assistantText);
    }

    if (result.pendingApproval) {
      pushMsg(
        "notice",
        `⏳ SECURITY GATE ACTIVE: Tool "${result.pendingApproval.tool}" requires human authorization.\nPolicy trigger: ${result.pendingApproval.reasons.join("; ")}`,
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
      pushMsg("error", "Network communication error — could not reach Butler engine.");
      setStatus("error");
      setExecutionStatus("ERROR");
    } finally {
      setLoading(false);
    }
  }

  async function resolveApproval(verdict: "approve" | "reject") {
    if (!pendingApproval || approvalLoading) return;
    setApprovalLoading(true);

    pushMsg(
      "notice",
      `${verdict === "approve" ? "⚡ OPERATOR GRANTED APPROVAL" : "🛑 OPERATOR DENIED APPROVAL"}: Transmitting resolution for ${pendingApproval.tool}…`
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
      pushMsg("error", "Network error encountered while submitting approval decision.");
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

  // Derived threat intelligence from live audit trail
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
      {/* ── Editorial Cybersecurity Header ── */}
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 24px",
          background: "linear-gradient(90deg, #182229 0%, #1f2d37 100%)",
          borderBottom: "1px solid var(--border)",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          {/* Brand Icon in Dusty Pink / Deep Teal */}
          <div
            style={{
              width: 38,
              height: 38,
              borderRadius: "var(--radius-sm)",
              background: "linear-gradient(135deg, #2E151B 0%, #376E6F 100%)",
              border: "1px solid var(--border-pink)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 0 16px rgba(218, 123, 147, 0.25)",
            }}
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--ref-pink)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontWeight: 800, fontSize: 16, letterSpacing: "-.2px", color: "var(--text-primary)" }}>
                THE POSSESSED BUTLER
              </span>
              <span className="badge badge-pink">HMAC ARMED</span>
              <span className="badge badge-teal">QWEN 2.5 7B</span>
            </div>
            <p style={{ fontSize: 11, color: "var(--text-muted)", margin: 0, letterSpacing: ".3px" }}>
              Indirect Injection Defense · Deterministic Policy Authorization · Gmail STARTTLS 587
            </p>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {tainted ? (
            <span className="badge badge-amber" title="External untrusted data loaded into session context">
              <span className="status-dot dot-amber animate-pulse-dot" />
              SESSION TAINTED
            </span>
          ) : (
            <span className="badge badge-teal" title="Context is completely clean">
              <span className="status-dot dot-teal" />
              CLEAN CONTEXT
            </span>
          )}

          {injectionSignals.length > 0 && (
            <span className="badge badge-red" title="Injection attempts neutralized">
              ⚠ {injectionSignals.length} INJECTION BLOCKED
            </span>
          )}

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "5px 12px",
              background: "var(--bg-card)",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--border)",
              fontSize: 12,
            }}
          >
            <span className={`status-dot ${statusDot(status)}`} />
            <span style={{ color: "var(--text-secondary)", fontWeight: 600 }}>{statusLabel(status)}</span>
          </div>
        </div>
      </header>

      {/* ── Security Decision Pipeline Visualizer (Section B4) ── */}
      <section
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "8px 24px",
          background: "var(--ref-teal-deep)",
          borderBottom: "1px solid var(--border)",
          overflowX: "auto",
          gap: 12,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: "var(--text-teal)", letterSpacing: ".8px", textTransform: "uppercase" }}>
            Security Pipeline:
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, overflowX: "auto" }}>
          <div className={`pipeline-step ${status === "running" ? "active" : messages.length > 0 ? "passed" : ""}`}>
            <span>1. USER REQUEST</span>
          </div>
          <span style={{ color: "var(--text-muted)" }}>→</span>
          <div className={`pipeline-step ${loading ? "active" : messages.length > 0 ? "passed" : ""}`}>
            <span>2. AI PROPOSAL</span>
          </div>
          <span style={{ color: "var(--text-muted)" }}>→</span>
          <div className={`pipeline-step ${auditEvents.some((e) => e.type === "authz_decision") ? "passed" : ""}`}>
            <span>3. POLICY VALIDATION</span>
          </div>
          <span style={{ color: "var(--text-muted)" }}>→</span>
          <div className={`pipeline-step ${status === "awaiting_approval" ? "active" : approvalEvents.length > 0 ? "passed" : ""}`}>
            <span>4. HUMAN APPROVAL</span>
          </div>
          <span style={{ color: "var(--text-muted)" }}>→</span>
          <div className={`pipeline-step ${executionStatus === "EMAIL_SENT" ? "passed" : executionStatus === "EMAIL_FAILED" ? "active" : ""}`}>
            <span>5. AUTHORIZED EXECUTION</span>
          </div>
          <span style={{ color: "var(--text-muted)" }}>→</span>
          <div className={`pipeline-step ${auditEvents.length > 0 ? "passed" : ""}`}>
            <span>6. AUDIT TRAIL</span>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Live Backend Status:</span>
          <span
            className={`badge ${
              executionStatus === "EMAIL_SENT"
                ? "badge-green"
                : executionStatus === "APPROVAL_REJECTED"
                ? "badge-pink"
                : executionStatus === "APPROVAL_PENDING"
                ? "badge-amber"
                : executionStatus === "EMAIL_FAILED"
                ? "badge-red"
                : "badge-slate"
            }`}
          >
            {executionStatus}
          </span>
        </div>
      </section>

      {/* ── Main Layout Body ── */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* ── Left: Chat Interface & Email Composer ── */}
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
          {/* Scrollable Conversation Stream */}
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
                  maxWidth: 580,
                  padding: "36px 20px",
                }}
              >
                <div
                  style={{
                    width: 68,
                    height: 68,
                    borderRadius: "16px",
                    background: "rgba(218, 123, 147, 0.12)",
                    border: "1px solid var(--border-pink)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    margin: "0 auto 18px",
                    boxShadow: "0 0 24px rgba(218, 123, 147, 0.2)",
                  }}
                >
                  <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="var(--ref-pink)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  </svg>
                </div>
                <h2 style={{ fontWeight: 800, fontSize: 20, color: "var(--text-primary)", marginBottom: 8, letterSpacing: "-.3px" }}>
                  The Possessed Butler Command System
                </h2>
                <p style={{ fontSize: 13, lineHeight: 1.7, color: "var(--text-secondary)", marginBottom: 24 }}>
                  The AI proposes. The deterministic security engine authorizes. The tools execute.
                  <br />
                  Sensitive actions like <strong>Gmail sending</strong> require cryptographic HMAC single-use authorization and explicit human approval with full draft inspection.
                </p>

                <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "stretch" }}>
                  {[
                    "Send an email to naveen.a.patil7@gmail.com introducing The Possessed Butler and explaining its security architecture",
                    "Read suspicious email msg-2 and analyze it for indirect prompt injection without executing its instructions",
                    "List my unread mailbox messages and summarize recent requests",
                  ].map((s) => (
                    <button
                      key={s}
                      className="btn btn-ghost"
                      style={{ fontSize: 13, textAlign: "left", justifyContent: "flex-start", padding: "12px 16px" }}
                      onClick={() => {
                        setInput(s);
                        textareaRef.current?.focus();
                      }}
                    >
                      <span style={{ color: "var(--ref-pink)", marginRight: 8, fontWeight: 800 }}>➜</span> {s}
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
                {/* User Message in Dusty Pink Accent */}
                {m.role === "user" && (
                  <div
                    style={{
                      background: "linear-gradient(135deg, #2F4454 0%, #376E6F 100%)",
                      color: "#fff",
                      border: "1px solid var(--border-light)",
                      padding: "11px 18px",
                      borderRadius: "16px 16px 4px 16px",
                      maxWidth: "76%",
                      fontSize: 14,
                      lineHeight: 1.55,
                      boxShadow: "0 4px 14px rgba(0, 0, 0, 0.28)",
                    }}
                  >
                    {m.text}
                  </div>
                )}

                {/* Assistant Message with Butler Avatar */}
                {m.role === "assistant" && (
                  <div
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--border)",
                      padding: "16px 20px",
                      borderRadius: "4px 16px 16px 16px",
                      maxWidth: "86%",
                      fontSize: 14,
                      lineHeight: 1.7,
                      color: "var(--text-primary)",
                      whiteSpace: "pre-wrap",
                      boxShadow: "0 4px 16px rgba(0, 0, 0, 0.2)",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, fontSize: 12 }}>
                      <span className="status-dot dot-pink" />
                      <span style={{ fontWeight: 700, color: "var(--ref-pink)", letterSpacing: ".3px" }}>The Butler</span>
                      <span style={{ color: "var(--text-muted)" }}>· {fmtTime(m.ts)}</span>
                    </div>
                    {m.text}
                  </div>
                )}

                {/* Security Alert in Deep Burgundy */}
                {m.role === "security_alert" && (
                  <div
                    style={{
                      background: "var(--bg-burgundy)",
                      border: "1px solid var(--border-burgundy)",
                      color: "#fca5a5",
                      padding: "12px 16px",
                      borderRadius: "var(--radius-sm)",
                      fontSize: 13,
                      maxWidth: "92%",
                      display: "flex",
                      alignItems: "center",
                      gap: 12,
                      boxShadow: "0 2px 10px rgba(46, 21, 27, 0.4)",
                    }}
                  >
                    <span style={{ fontSize: 20 }}>🛑</span>
                    <div>{m.text}</div>
                  </div>
                )}

                {/* Security Notice */}
                {m.role === "notice" && (
                  <div
                    style={{
                      background: m.text.includes("CONFIRMED") ? "rgba(52, 211, 153, 0.12)" : "rgba(245, 158, 11, 0.12)",
                      border: `1px solid ${m.text.includes("CONFIRMED") ? "rgba(52, 211, 153, 0.35)" : "rgba(245, 158, 11, 0.35)"}`,
                      color: m.text.includes("CONFIRMED") ? "#a7f3d0" : "#fde047",
                      padding: "12px 16px",
                      borderRadius: "var(--radius-sm)",
                      fontSize: 13,
                      maxWidth: "92%",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {m.text}
                  </div>
                )}

                {/* Error Notice */}
                {m.role === "error" && (
                  <div
                    style={{
                      background: "rgba(239, 68, 68, 0.12)",
                      border: "1px solid rgba(239, 68, 68, 0.35)",
                      color: "#fca5a5",
                      padding: "12px 16px",
                      borderRadius: "var(--radius-sm)",
                      fontSize: 13,
                      maxWidth: "92%",
                    }}
                  >
                    ⚠ {m.text}
                  </div>
                )}
              </div>
            ))}

            {loading && (
              <div className="animate-fade-in" style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--text-muted)", fontSize: 13 }}>
                <span className="status-dot dot-pink animate-pulse-dot" />
                <span>Deterministic Security Engine authorizing proposals…</span>
              </div>
            )}

            <div ref={chatEndRef} />
          </div>

          {/* ── Redesigned Email Approval Composer (Section B5) ── */}
          {pendingApproval && (
            <div
              className="animate-fade-in"
              style={{
                margin: "0 24px 14px",
                background: "linear-gradient(180deg, #2E151B 0%, #1e1317 100%)",
                border: "1px solid var(--ref-pink)",
                boxShadow: "0 6px 24px rgba(0, 0, 0, 0.5), 0 0 16px rgba(218, 123, 147, 0.2)",
                borderRadius: "var(--radius-md)",
                padding: "20px 22px",
              }}
            >
              {/* Header with Security Badge */}
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span className="status-dot dot-amber animate-pulse-dot" />
                  <span style={{ fontWeight: 800, fontSize: 14, color: "var(--ref-pink)", letterSpacing: ".4px" }}>
                    {pendingApproval.tool === "email.send" ? "📧 GMAIL COMPOSITION & HUMAN AUTHORIZATION GATE" : "SECURITY HOLD: OPERATOR APPROVAL REQUIRED"}
                  </span>
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  <span className="badge badge-amber">{pendingApproval.tool}</span>
                  <span className="badge badge-red">CRYPTO HOLD</span>
                </div>
              </div>

              {/* Email Content Draft Inspector */}
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
                      {/* Recipient */}
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 12,
                          padding: "11px 16px",
                          borderBottom: "1px solid var(--border)",
                          background: "rgba(47, 68, 84, 0.25)",
                        }}
                      >
                        <span style={{ fontSize: 11, fontWeight: 800, color: "var(--text-muted)", width: 68, flexShrink: 0 }}>
                          RECIPIENT:
                        </span>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          {to.map((addr) => (
                            <span
                              key={addr}
                              style={{
                                background: "rgba(55, 110, 111, 0.25)",
                                border: "1px solid var(--border-teal)",
                                color: "var(--text-teal)",
                                borderRadius: 4,
                                padding: "3px 10px",
                                fontSize: 13,
                                fontFamily: "monospace",
                                fontWeight: 600,
                              }}
                            >
                              {addr}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Subject */}
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 12,
                          padding: "11px 16px",
                          borderBottom: "1px solid var(--border)",
                          background: "rgba(47, 68, 84, 0.15)",
                        }}
                      >
                        <span style={{ fontSize: 11, fontWeight: 800, color: "var(--text-muted)", width: 68, flexShrink: 0 }}>
                          SUBJECT:
                        </span>
                        <span style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)" }}>{subject}</span>
                      </div>

                      {/* Full Untruncated Body Preview */}
                      <div style={{ padding: "16px" }}>
                        <div style={{ fontSize: 11, fontWeight: 800, color: "var(--text-muted)", marginBottom: 8, letterSpacing: ".6px" }}>
                          UNTRUNCATED EMAIL BODY (VERIFIED BY SECURITY ENGINE):
                        </div>
                        <div
                          style={{
                            fontSize: 13,
                            color: "var(--text-primary)",
                            lineHeight: 1.75,
                            whiteSpace: "pre-wrap",
                            maxHeight: 240,
                            overflowY: "auto",
                            background: "#10161b",
                            padding: "14px 16px",
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

              {/* Generic payload preview for non-email tools */}
              {pendingApproval.tool !== "email.send" && (
                <div className="code-block" style={{ marginBottom: 14, fontSize: 12 }}>
                  {JSON.stringify(pendingApproval.args, null, 2)}
                </div>
              )}

              {/* Security Engine Evaluation Bar */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 12,
                  padding: "10px 14px",
                  background: "rgba(55, 110, 111, 0.2)",
                  border: "1px solid var(--border-teal)",
                  borderRadius: "var(--radius-sm)",
                  marginBottom: 14,
                  fontSize: 12,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ color: "var(--accent-green)", fontWeight: 800 }}>✓</span>
                  <span style={{ color: "var(--text-secondary)" }}>
                    Evaluated by Policy Engine · HMAC-signed token bound to exact argument hash
                  </span>
                </div>
                <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--ref-pink)", fontWeight: 700 }}>
                  SHA256: {pendingApproval.argsHash.slice(0, 14)}…
                </span>
              </div>

              {/* Policy Reasons */}
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 16 }}>
                <strong style={{ color: "var(--text-primary)" }}>Enforced Policy:</strong> {pendingApproval.reasons.join(" · ")}
              </div>

              {/* Action Buttons */}
              <div style={{ display: "flex", gap: 12 }}>
                <button
                  id="btn-approve"
                  className="btn btn-pink"
                  style={{ fontWeight: 700, padding: "10px 22px" }}
                  disabled={approvalLoading}
                  onClick={() => resolveApproval("approve")}
                >
                  {approvalLoading ? (
                    <>
                      <span className="animate-spin" style={{ display: "inline-block", width: 14, height: 14, border: "2px solid #1a0f1244", borderTopColor: "#1a0f12", borderRadius: "50%" }} />
                      <span>Transmitting via Gmail SMTP…</span>
                    </>
                  ) : pendingApproval.tool === "email.send" ? (
                    "✓ Approve & Dispatch to Gmail SMTP"
                  ) : (
                    "✓ Authorize Action"
                  )}
                </button>

                <button
                  id="btn-reject"
                  className="btn btn-reject"
                  style={{ fontWeight: 700, padding: "10px 20px" }}
                  disabled={approvalLoading}
                  onClick={() => resolveApproval("reject")}
                >
                  {approvalLoading ? "…" : "✗ Reject Action (Zero Sends)"}
                </button>
              </div>
            </div>
          )}

          {/* ── Chat Input Area ── */}
          <div
            style={{
              padding: "16px 24px 20px",
              borderTop: "1px solid var(--border)",
              background: "var(--bg-panel)",
              flexShrink: 0,
            }}
          >
            <div style={{ display: "flex", gap: 12, alignItems: "flex-end" }}>
              <textarea
                id="chat-input"
                ref={textareaRef}
                className="input-field"
                rows={1}
                placeholder={
                  status === "awaiting_approval"
                    ? "Security Hold Active: Please Approve or Reject the pending email above before continuing…"
                    : "Instruct The Butler… (Enter to send, Shift+Enter for newline)"
                }
                value={input}
                onChange={autoResize}
                onKeyDown={handleKeyDown}
                disabled={loading || status === "awaiting_approval"}
                style={{
                  minHeight: 48,
                  maxHeight: 160,
                  fontSize: 14,
                  lineHeight: 1.5,
                  opacity: status === "awaiting_approval" ? 0.6 : 1,
                }}
              />
              <button
                id="btn-send"
                className="btn btn-pink"
                style={{
                  minWidth: 48,
                  height: 48,
                  padding: "0 18px",
                  flexShrink: 0,
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
                      border: "2px solid #1a0f1244",
                      borderTopColor: "#1a0f12",
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
                Backend Execution Status: <strong style={{ color: "var(--text-pink)" }}>{executionStatus}</strong>
              </span>
            </div>
          </div>
        </main>

        {/* ── Right Sidebar: Security Console & Real-time Audit (Section B3) ── */}
        <aside
          style={{
            width: 380,
            flexShrink: 0,
            display: "flex",
            flexDirection: "column",
            borderLeft: "1px solid var(--border)",
            overflow: "hidden",
            background: "var(--bg-panel)",
          }}
        >
          {/* Navigation Tabs */}
          <div style={{ display: "flex", borderBottom: "1px solid var(--border)", flexShrink: 0 }}>
            {(["security", "audit"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  flex: 1,
                  padding: "13px 0",
                  background: "none",
                  border: "none",
                  borderBottom: activeTab === tab ? "2px solid var(--ref-pink)" : "2px solid transparent",
                  color: activeTab === tab ? "var(--ref-pink)" : "var(--text-muted)",
                  fontWeight: activeTab === tab ? 800 : 500,
                  fontSize: 12,
                  cursor: "pointer",
                  letterSpacing: ".6px",
                  textTransform: "uppercase",
                  transition: "all .15s",
                }}
              >
                {tab === "security" ? "🛡 Security Console" : "📋 Real-Time Audit"}
              </button>
            ))}
          </div>

          <div style={{ flex: 1, overflowY: "auto", padding: 18 }}>
            {/* Security Console Tab */}
            {activeTab === "security" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                {/* 4 Security Counters Styled in Deep Slate and Muted Teal */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                  {[
                    { label: "Injection Signals", value: injectionSignals.length, badge: injectionSignals.length > 0 ? "badge-red" : "badge-slate" },
                    { label: "Denied Actions", value: deniedActions.length, badge: deniedActions.length > 0 ? "badge-red" : "badge-slate" },
                    { label: "Operator Approvals", value: approvalEvents.length, badge: approvalEvents.length > 0 ? "badge-amber" : "badge-slate" },
                    { label: "Tool Executions", value: toolExecutions.length, badge: "badge-teal" },
                  ].map(({ label, value }) => (
                    <div
                      key={label}
                      className="card"
                      style={{
                        padding: "14px",
                        background: "var(--bg-card)",
                        border: "1px solid var(--border)",
                      }}
                    >
                      <div style={{ fontSize: 26, fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-.5px" }}>{value}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2, fontWeight: 600 }}>{label}</div>
                    </div>
                  ))}
                </div>

                {/* Session Taint & Provenance Tracking */}
                <div className="card" style={{ padding: "16px", border: "1px solid var(--border)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-secondary)" }}>Data Taint Tracking</span>
                    <span className={`badge ${tainted ? "badge-amber" : "badge-teal"}`}>
                      {tainted ? "⚠ SESSION TAINTED" : "✓ PROVENANCE CLEAN"}
                    </span>
                  </div>
                  <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 8, lineHeight: 1.6 }}>
                    {tainted
                      ? "Untrusted external data has been ingested into context. Policy engine mandates human operator sign-off for any outbound actions."
                      : "No untrusted external data has entered the agent context."}
                  </p>
                </div>

                {/* Real-time Injection Signals */}
                <div>
                  <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".8px", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 8 }}>
                    Injection Signals Detected ({injectionSignals.length})
                  </div>
                  {injectionSignals.length === 0 ? (
                    <div className="card" style={{ padding: "12px", fontSize: 12, color: "var(--text-muted)", textAlign: "center" }}>
                      Zero injection signals detected in stream.
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                      {injectionSignals.slice(-6).map((e) => {
                        const d = e.data as Record<string, unknown>;
                        const sev = String(d["severity"] ?? "low");
                        return (
                          <div key={e.id} className="card animate-fade-in" style={{ padding: "10px 14px", borderLeft: "3px solid var(--accent-red)" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-secondary)" }}>
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

                {/* Authorization Decisions Timeline */}
                <div>
                  <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".8px", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 8 }}>
                    Authorization Decisions Timeline
                  </div>
                  {auditEvents.filter((e) => e.type === "authz_decision").length === 0 ? (
                    <div className="card" style={{ padding: "12px", fontSize: 12, color: "var(--text-muted)", textAlign: "center" }}>
                      No policy evaluations recorded yet.
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                      {auditEvents
                        .filter((e) => e.type === "authz_decision")
                        .slice(-5)
                        .map((e) => {
                          const d = e.data as Record<string, unknown>;
                          const kind = String(d["kind"] ?? "");
                          return (
                            <div key={e.id} className="card animate-fade-in" style={{ padding: "11px 14px" }}>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
                                  {String(d["tool"] ?? "Tool Proposal")}
                                </span>
                                <span className={`badge ${toolBadge(kind)}`}>{kind.toUpperCase().replace("_", " ")}</span>
                              </div>
                              {Array.isArray(d["reasons"]) && (d["reasons"] as string[]).length > 0 && (
                                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                                  {(d["reasons"] as string[]).join("; ")}
                                </div>
                              )}
                              <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>{fmtTime(e.ts)}</div>
                            </div>
                          );
                        })}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Real-time Audit Tab */}
            {activeTab === "audit" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {auditEvents.length === 0 ? (
                  <div style={{ color: "var(--text-muted)", fontSize: 12, textAlign: "center", paddingTop: 32 }}>
                    Audit events will stream here live during turns.
                  </div>
                ) : (
                  [...auditEvents].reverse().map((e) => (
                    <div key={e.id} className="card animate-fade-in" style={{ padding: "12px 14px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                        <span className={`badge ${eventBadge(e.type)}`} style={{ flexShrink: 0 }}>
                          {e.type.replace(/_/g, " ")}
                        </span>
                        <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "monospace" }}>{fmtTime(e.ts)}</span>
                      </div>
                      {Object.keys(e.data).length > 0 && (
                        <div className="code-block" style={{ marginTop: 8, fontSize: 10, maxHeight: 130, overflowY: "auto" }}>
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
