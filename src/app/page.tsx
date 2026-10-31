"use client";

import { useState, useRef, useEffect, useCallback } from "react";

// ── Types (mirrors server contracts) ──────────────────────────────────────────
type SessionStatus = "idle" | "running" | "awaiting_approval" | "completed" | "error";

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
}

interface AuditEvent {
  id: string;
  ts: string;
  sessionId: string;
  type: string;
  data: Record<string, unknown>;
}

interface Message {
  role: "user" | "assistant" | "notice" | "error";
  text: string;
  ts: number;
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function statusColor(s: SessionStatus): string {
  return s === "running" ? "dot-blue animate-pulse-dot"
    : s === "awaiting_approval" ? "dot-amber animate-pulse-dot"
    : s === "completed" ? "dot-green"
    : s === "error" ? "dot-red"
    : "dot-gray";
}

function statusLabel(s: SessionStatus): string {
  return s === "running" ? "Thinking…"
    : s === "awaiting_approval" ? "Awaiting approval"
    : s === "completed" ? "Ready"
    : s === "error" ? "Error"
    : "Idle";
}

function eventBadge(type: string) {
  if (type.includes("denied") || type === "authz_decision") return "badge-blue";
  if (type.includes("injection") || type.includes("signal")) return "badge-red";
  if (type === "tool_executed") return "badge-green";
  if (type === "approval_requested") return "badge-amber";
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
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ── Component ─────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [sessionId, setSessionId] = useState<string | undefined>();
  const [status, setStatus] = useState<SessionStatus>("idle");
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [activeTab, setActiveTab] = useState<"security" | "audit">("security");
  const [loading, setLoading] = useState(false);
  const [approvalLoading, setApprovalLoading] = useState(false);

  const chatEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll chat
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Fetch audit log whenever sessionId changes or a turn completes
  const fetchAudit = useCallback(async (sid: string) => {
    try {
      const res = await fetch(`/api/audit?sessionId=${encodeURIComponent(sid)}`);
      if (res.ok) {
        const data = await res.json() as AuditEvent[];
        setAuditEvents(data);
      }
    } catch { /* non-critical */ }
  }, []);

  function pushMsg(role: Message["role"], text: string) {
    setMessages(prev => [...prev, { role, text, ts: Date.now() }]);
  }

  function applyResult(result: AgentTurnResult) {
    setSessionId(result.sessionId);
    setStatus(result.status);
    setPendingApproval(result.pendingApproval);

    if (result.error) {
      pushMsg("error", `[${result.error.code}] ${result.error.message}`);
    }
    if (result.assistantText) {
      // Detect email delivery confirmation in assistant response
      const text = result.assistantText;
      if (text.includes("Email delivered successfully") || text.includes("Message-ID:")) {
        pushMsg("notice", `✅ SUCCESS — EMAIL SENT\n${text}`);
      } else if (text.includes("SMTP delivery failed") || text.includes("SMTP rejected")) {
        pushMsg("error", `❌ DELIVERY FAILED\n${text}`);
      } else {
        pushMsg("assistant", text);
      }
    }
    if (result.pendingApproval) {
      pushMsg(
        "notice",
        `⏳ Approval required for tool "${result.pendingApproval.tool}". Reasons: ${result.pendingApproval.reasons.join("; ")}`,
      );
    }

    fetchAudit(result.sessionId);
  }

  async function sendMessage() {
    const msg = input.trim();
    if (!msg || loading) return;
    setInput("");
    if (textareaRef.current) textareaRef.current.style.height = "auto";
    pushMsg("user", msg);
    setLoading(true);
    setStatus("running");

    try {
      const res = await fetch("/api/agent", {
        method: "POST",
        headers: CSRF_HEADERS,
        body: JSON.stringify({ sessionId, message: msg }),
      });
      const data = await res.json() as AgentTurnResult;
      applyResult(data);
    } catch {
      pushMsg("error", "Network error — could not reach the agent.");
      setStatus("error");
    } finally {
      setLoading(false);
    }
  }

  async function resolveApproval(verdict: "approve" | "reject") {
    if (!pendingApproval || approvalLoading) return;
    setApprovalLoading(true);
    pushMsg("notice", `${verdict === "approve" ? "✅" : "❌"} You ${verdict}d the action: ${pendingApproval.tool}`);

    try {
      const res = await fetch(`/api/approvals/${pendingApproval.id}`, {
        method: "POST",
        headers: CSRF_HEADERS,
        body: JSON.stringify({ verdict }),
      });
      const data = await res.json() as AgentTurnResult;
      applyResult(data);
    } catch {
      pushMsg("error", "Network error during approval.");
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
  const injectionSignals = auditEvents.filter(e => e.type === "injection_signal");
  const deniedActions   = auditEvents.filter(e => e.type === "authz_decision" && (e.data as Record<string,unknown>)["kind"] === "deny");
  const approvalEvents  = auditEvents.filter(e => e.type === "approval_requested");
  const tainted = auditEvents.some(e => e.type === "content_ingested" && (e.data as Record<string,unknown>)["trust"] === "untrusted");

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", overflow: "hidden" }}>

      {/* ── Top bar ── */}
      <header style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "12px 20px",
        background: "var(--bg-panel)",
        borderBottom: "1px solid var(--border)",
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: ".3px" }}>The Possessed Butler</span>
          <span className="badge badge-violet" style={{ marginLeft: 4 }}>Security AI</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {tainted && (
            <span className="badge badge-amber">
              <span className="status-dot dot-amber animate-pulse-dot" />
              Session Tainted
            </span>
          )}
          {injectionSignals.length > 0 && (
            <span className="badge badge-red">
              ⚠ {injectionSignals.length} injection signal{injectionSignals.length !== 1 ? "s" : ""}
            </span>
          )}
          <div style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--text-secondary)", fontSize: 13 }}>
            <span className={`status-dot ${statusColor(status)}`} />
            {statusLabel(status)}
          </div>
        </div>
      </header>

      {/* ── Main ── */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>

        {/* ── Left: Chat ── */}
        <main style={{
          display: "flex", flexDirection: "column", flex: 1,
          overflow: "hidden", minWidth: 0,
        }}>
          {/* Messages */}
          <div id="chat-messages" style={{
            flex: 1, overflowY: "auto",
            padding: "20px 24px",
            display: "flex", flexDirection: "column", gap: 14,
          }}>
            {messages.length === 0 && (
              <div style={{
                margin: "auto", textAlign: "center",
                color: "var(--text-muted)", maxWidth: 460,
              }}>
                <div style={{ fontSize: 40, marginBottom: 16 }}>🛡️</div>
                <p style={{ fontWeight: 600, fontSize: 16, color: "var(--text-secondary)", marginBottom: 8 }}>
                  Secure AI Assistant
                </p>
                <p style={{ fontSize: 13, lineHeight: 1.7, marginBottom: 16 }}>
                  Every tool call is authorized by the security engine before execution.
                  Email sending requires your explicit approval — the full draft is shown before you decide.
                </p>
                <div style={{ display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap" }}>
                  {[
                    "Write a professional email introducing The Possessed Butler to judge@example.com and send it",
                    "List my emails and summarize them",
                    "Read my latest email",
                  ].map(s => (
                    <button
                      key={s}
                      className="btn btn-ghost"
                      style={{ fontSize: 12, textAlign: "left" }}
                      onClick={() => { setInput(s); textareaRef.current?.focus(); }}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}


            {messages.map((m, i) => (
              <div key={i} className="animate-fade-in" style={{ display: "flex", flexDirection: "column", alignItems: m.role === "user" ? "flex-end" : "flex-start" }}>
                {m.role === "user" && (
                  <div style={{
                    background: "var(--accent-blue)",
                    color: "#fff",
                    padding: "10px 14px",
                    borderRadius: "14px 14px 4px 14px",
                    maxWidth: "75%",
                    fontSize: 14,
                    lineHeight: 1.5,
                  }}>
                    {m.text}
                  </div>
                )}
                {m.role === "assistant" && (
                  <div style={{
                    background: "var(--bg-card)",
                    border: "1px solid var(--border)",
                    padding: "12px 16px",
                    borderRadius: "4px 14px 14px 14px",
                    maxWidth: "80%",
                    fontSize: 14,
                    lineHeight: 1.65,
                    color: "var(--text-primary)",
                    whiteSpace: "pre-wrap",
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8, color: "var(--text-secondary)", fontSize: 12 }}>
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                      Butler · {fmtTime(m.ts)}
                    </div>
                    {m.text}
                  </div>
                )}
                {m.role === "notice" && (
                  <div style={{
                    background: "#f59e0b10",
                    border: "1px solid #f59e0b30",
                    color: "#fbbf24",
                    padding: "8px 12px",
                    borderRadius: "var(--radius-sm)",
                    fontSize: 12,
                    maxWidth: "90%",
                    fontStyle: "italic",
                  }}>
                    {m.text}
                  </div>
                )}
                {m.role === "error" && (
                  <div style={{
                    background: "#ef444410",
                    border: "1px solid #ef444430",
                    color: "#f87171",
                    padding: "8px 12px",
                    borderRadius: "var(--radius-sm)",
                    fontSize: 12,
                    maxWidth: "90%",
                  }}>
                    ⚠ {m.text}
                  </div>
                )}
              </div>
            ))}

            {loading && (
              <div className="animate-fade-in" style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-muted)", fontSize: 13 }}>
                <span className="status-dot dot-blue animate-pulse-dot" />
                Thinking…
              </div>
            )}

            <div ref={chatEndRef} />
          </div>

          {/* Approval card — smart email preview for email.send, generic for other tools */}
          {pendingApproval && (
            <div className="animate-fade-in" style={{
              margin: "0 24px 12px",
              background: pendingApproval.tool === "email.send" ? "#3b82f608" : "#f59e0b08",
              border: `1px solid ${pendingApproval.tool === "email.send" ? "#3b82f640" : "#f59e0b40"}`,
              borderRadius: "var(--radius-md)",
              padding: "16px 18px",
            }}>
              {/* Header */}
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <span className="status-dot dot-amber animate-pulse-dot" />
                <span style={{ fontWeight: 700, fontSize: 13, color: "#fbbf24" }}>
                  {pendingApproval.tool === "email.send" ? "📧 Email Composition Preview" : "Approval Required"}
                </span>
                <span className="badge badge-amber">{pendingApproval.tool}</span>
                <span className="badge badge-red" style={{ marginLeft: "auto" }}>SECURITY HOLD</span>
              </div>

              {/* Email preview for email.send */}
              {pendingApproval.tool === "email.send" && (() => {
                const args = pendingApproval.args as Record<string, unknown>;
                const to = Array.isArray(args.to) ? (args.to as string[]) : [];
                const subject = String(args.subject ?? "");
                const body = String(args.body ?? "");
                return (
                  <div style={{
                    background: "var(--bg-card)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    overflow: "hidden",
                    marginBottom: 12,
                  }}>
                    {/* Email header fields */}
                    {[
                      { label: "To", value: to.join(", ") },
                      { label: "Subject", value: subject },
                    ].map(({ label, value }) => (
                      <div key={label} style={{
                        display: "flex", alignItems: "flex-start", gap: 10,
                        padding: "8px 14px",
                        borderBottom: "1px solid var(--border)",
                      }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", width: 52, flexShrink: 0, paddingTop: 1 }}>{label.toUpperCase()}</span>
                        <span style={{ fontSize: 13, color: "var(--text-primary)", wordBreak: "break-all" }}>{value}</span>
                      </div>
                    ))}
                    {/* Email body */}
                    <div style={{ padding: "12px 14px" }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", marginBottom: 8 }}>BODY</div>
                      <div style={{
                        fontSize: 13,
                        color: "var(--text-primary)",
                        lineHeight: 1.65,
                        whiteSpace: "pre-wrap",
                        maxHeight: 200,
                        overflowY: "auto",
                      }}>
                        {body}
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Generic args for other tools */}
              {pendingApproval.tool !== "email.send" && (
                <div className="code-block" style={{ marginBottom: 12, fontSize: 11 }}>
                  {JSON.stringify(pendingApproval.args, null, 2)}
                </div>
              )}

              {/* Security status */}
              <div style={{
                display: "flex", alignItems: "center", gap: 8,
                padding: "8px 12px",
                background: "#22c55e08",
                border: "1px solid #22c55e20",
                borderRadius: "var(--radius-sm)",
                marginBottom: 12,
                fontSize: 11,
                color: "var(--text-secondary)",
              }}>
                <span style={{ color: "var(--accent-green)" }}>✓</span>
                <span>Security engine evaluated · HMAC token will be verified before execution</span>
                <span style={{ marginLeft: "auto", fontFamily: "monospace", fontSize: 10, color: "var(--text-muted)" }}>
                  {pendingApproval.argsHash.slice(0, 12)}…
                </span>
              </div>

              {/* Reasons */}
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 12 }}>
                Policy: {pendingApproval.reasons.join(" · ")}
              </div>

              {/* Action buttons */}
              <div style={{ display: "flex", gap: 8 }}>
                <button id="btn-approve" className="btn btn-approve" disabled={approvalLoading} onClick={() => resolveApproval("approve")}>
                  {approvalLoading ? "Sending…" : pendingApproval.tool === "email.send" ? "✓ Approve & Send" : "✓ Approve"}
                </button>
                <button id="btn-reject" className="btn btn-reject" disabled={approvalLoading} onClick={() => resolveApproval("reject")}>
                  {approvalLoading ? "…" : "✗ Reject"}
                </button>
              </div>
            </div>
          )}


          {/* Input bar */}
          <div style={{
            padding: "12px 24px 16px",
            borderTop: "1px solid var(--border)",
            background: "var(--bg-panel)",
            flexShrink: 0,
          }}>
            <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
              <textarea
                id="chat-input"
                ref={textareaRef}
                className="input-field"
                rows={1}
                placeholder="Message the Butler… (Enter to send, Shift+Enter for newline)"
                value={input}
                onChange={autoResize}
                onKeyDown={handleKeyDown}
                disabled={loading || status === "awaiting_approval"}
                style={{ minHeight: 44, maxHeight: 160 }}
              />
              <button
                id="btn-send"
                className="btn btn-primary"
                style={{ minWidth: 44, height: 44, padding: "0 14px", flexShrink: 0 }}
                disabled={!input.trim() || loading || status === "awaiting_approval"}
                onClick={sendMessage}
              >
                {loading
                  ? <span className="animate-spin" style={{ display: "inline-block", width: 14, height: 14, border: "2px solid #fff4", borderTopColor: "#fff", borderRadius: "50%" }} />
                  : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                }
              </button>
            </div>
            {sessionId && (
              <p style={{ marginTop: 6, fontSize: 11, color: "var(--text-muted)" }}>
                Session: <span style={{ fontFamily: "monospace" }}>{sessionId.slice(0, 8)}…</span>
              </p>
            )}
          </div>
        </main>

        {/* ── Right sidebar ── */}
        <aside style={{
          width: 340,
          flexShrink: 0,
          display: "flex",
          flexDirection: "column",
          borderLeft: "1px solid var(--border)",
          overflow: "hidden",
          background: "var(--bg-panel)",
        }}>
          {/* Tabs */}
          <div style={{ display: "flex", borderBottom: "1px solid var(--border)", flexShrink: 0 }}>
            {(["security", "audit"] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  flex: 1, padding: "11px 0", background: "none", border: "none",
                  borderBottom: activeTab === tab ? "2px solid var(--accent-blue)" : "2px solid transparent",
                  color: activeTab === tab ? "var(--accent-blue)" : "var(--text-muted)",
                  fontWeight: activeTab === tab ? 600 : 400,
                  fontSize: 12, cursor: "pointer", letterSpacing: ".3px",
                  textTransform: "uppercase",
                  transition: "color .15s",
                }}
              >
                {tab === "security" ? "🛡 Security" : "📋 Audit Log"}
              </button>
            ))}
          </div>

          <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>

            {/* Security tab */}
            {activeTab === "security" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

                {/* Threat summary cards */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                  {[
                    { label: "Injection Signals", value: injectionSignals.length, badge: injectionSignals.length > 0 ? "badge-red" : "badge-gray" },
                    { label: "Denied Actions",    value: deniedActions.length,    badge: deniedActions.length > 0 ? "badge-red" : "badge-gray" },
                    { label: "Approvals",         value: approvalEvents.length,   badge: approvalEvents.length > 0 ? "badge-amber" : "badge-gray" },
                    { label: "Tool Executions",   value: auditEvents.filter(e => e.type === "tool_executed").length, badge: "badge-green" },
                  ].map(({ label, value, badge }) => (
                    <div key={label} className="card" style={{ padding: "12px 14px" }}>
                      <div style={{ fontSize: 22, fontWeight: 700, color: "var(--text-primary)" }}>{value}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{label}</div>
                    </div>
                  ))}
                </div>

                {/* Taint status */}
                <div className="card" style={{ padding: "12px 14px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>Session Taint</span>
                    <span className={`badge ${tainted ? "badge-amber" : "badge-green"}`}>
                      {tainted ? "⚠ TAINTED" : "✓ CLEAN"}
                    </span>
                  </div>
                  <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                    {tainted
                      ? "Untrusted external content has been ingested. Sensitive actions require approval."
                      : "No untrusted content ingested yet."}
                  </p>
                </div>

                {/* Injection signals */}
                {injectionSignals.length > 0 && (
                  <div>
                    <div className="section-header">Injection Signals</div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      {injectionSignals.slice(-8).map(e => {
                        const d = e.data as Record<string, unknown>;
                        const sev = String(d["severity"] ?? "");
                        return (
                          <div key={e.id} className="card animate-fade-in" style={{ padding: "8px 12px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-secondary)" }}>{String(d["detectorId"] ?? "")}</span>
                              <span className={`badge ${sev === "high" ? "badge-red" : sev === "medium" ? "badge-amber" : "badge-gray"}`}>
                                {sev.toUpperCase()}
                              </span>
                            </div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3 }}>
                              {String(d["description"] ?? "")}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Authorization decisions */}
                {auditEvents.filter(e => e.type === "authz_decision").length > 0 && (
                  <div>
                    <div className="section-header">Authorization Decisions</div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      {auditEvents.filter(e => e.type === "authz_decision").slice(-6).map(e => {
                        const d = e.data as Record<string, unknown>;
                        const kind = String(d["kind"] ?? "");
                        return (
                          <div key={e.id} className="card animate-fade-in" style={{ padding: "8px 12px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                              <span style={{ fontSize: 12, fontWeight: 500 }}>{String(d["tool"] ?? "unknown tool")}</span>
                              <span className={`badge ${toolBadge(kind)}`}>{kind.toUpperCase().replace("_", " ")}</span>
                            </div>
                            {Array.isArray(d["reasons"]) && (d["reasons"] as string[]).length > 0 && (
                              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3 }}>
                                {(d["reasons"] as string[]).join("; ")}
                              </div>
                            )}
                            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>{fmtTime(e.ts)}</div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {auditEvents.length === 0 && (
                  <div style={{ color: "var(--text-muted)", fontSize: 12, textAlign: "center", paddingTop: 32 }}>
                    Security events will appear here once you start a conversation.
                  </div>
                )}
              </div>
            )}

            {/* Audit tab */}
            {activeTab === "audit" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {auditEvents.length === 0 ? (
                  <div style={{ color: "var(--text-muted)", fontSize: 12, textAlign: "center", paddingTop: 32 }}>
                    Audit events will appear here during a session.
                  </div>
                ) : (
                  [...auditEvents].reverse().map(e => (
                    <div key={e.id} className="card animate-fade-in" style={{ padding: "8px 12px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                        <span className={`badge ${eventBadge(e.type)}`} style={{ flexShrink: 0 }}>
                          {e.type.replace(/_/g, " ")}
                        </span>
                        <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "monospace" }}>{fmtTime(e.ts)}</span>
                      </div>
                      {Object.keys(e.data).length > 0 && (
                        <div className="code-block" style={{ marginTop: 6, fontSize: 10, maxHeight: 100, overflowY: "auto" }}>
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

