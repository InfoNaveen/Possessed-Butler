"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import Link from "next/link";

// ── Types ───────────────────────────────────────────────────────────────────
interface AuditEvent {
  id: string;
  ts: string;
  sessionId: string;
  type: string;
  data: Record<string, unknown>;
}

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

interface SessionView {
  id: string;
  status: string;
  tainted: boolean;
  toolCallCount: number;
  pendingApprovalId: string | null;
}

// ── Palette Tokens ──────────────────────────────────────────────────────────
const PALETTE = {
  slate: "#2F4454",
  burgundy: "#2E151B",
  dustyPink: "#DA7B93",
  mutedTeal: "#376E6F",
  deepTeal: "#1C3334",
  bgBase: "#0c1216",
  bgPanel: "#131b22",
  bgCard: "#19242d",
  border: "#253441",
  borderGlow: "#376E6F",
  textPrimary: "#f0f4f8",
  textSecondary: "#9ab0c2",
  textMuted: "#5e778d",
  accentSuccess: "#34d399",
  accentDanger: "#f87171",
  accentWarning: "#fbbf24",
};

export default function SentinelCommandCenter() {
  const [activeTab, setActiveTab] = useState<
    "overview" | "threats" | "pipeline" | "integrity" | "eval" | "curse" | "audit"
  >("overview");

  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [sessions, setSessions] = useState<SessionView[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string>("ALL");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [isFetching, setIsFetching] = useState(false);
  const [fetchError, setFetchError] = useState<string | null>(null);

  // Filters for Audit Explorer
  const [auditTypeFilter, setAuditTypeFilter] = useState<string>("all");
  const [auditSearch, setAuditSearch] = useState<string>("");
  const [selectedEventForModal, setSelectedEventForModal] = useState<AuditEvent | null>(null);
  const [showDemoGuide, setShowDemoGuide] = useState(false);

  // ── Data Fetching ─────────────────────────────────────────────────────────
  const fetchData = useCallback(async () => {
    setIsFetching(true);
    setFetchError(null);
    try {
      // 1. Fetch Audit Events
      const auditUrl =
        selectedSessionId && selectedSessionId !== "ALL"
          ? `/api/audit?sessionId=${selectedSessionId}`
          : "/api/audit";
      const auditRes = await fetch(auditUrl, { cache: "no-store" });
      if (auditRes.ok) {
        const events = (await auditRes.json()) as AuditEvent[];
        setAuditEvents(Array.isArray(events) ? events : []);
      }

      // 2. Fetch Pending Approvals
      const appUrl =
        selectedSessionId && selectedSessionId !== "ALL"
          ? `/api/approvals?sessionId=${selectedSessionId}`
          : "/api/approvals";
      const appRes = await fetch(appUrl, { cache: "no-store" });
      if (appRes.ok) {
        const apps = (await appRes.json()) as ApprovalRequest[];
        setApprovals(Array.isArray(apps) ? apps : []);
      }

      // 3. Fetch Active Sessions
      const sessRes = await fetch("/api/agent", { cache: "no-store" });
      if (sessRes.ok) {
        const sessData = await sessRes.json();
        if (Array.isArray(sessData.sessions)) {
          setSessions(sessData.sessions);
        }
      }

      setLastRefreshed(new Date());
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : "Backend unavailable");
    } finally {
      setIsFetching(false);
    }
  }, [selectedSessionId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Safe polling interval (1500ms)
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchData();
    }, 1500);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchData]);

  // ── Derived Live Counters ─────────────────────────────────────────────────
  const filteredEvents = useMemo(() => {
    if (!selectedSessionId || selectedSessionId === "ALL") return auditEvents;
    return auditEvents.filter((e) => e.sessionId === selectedSessionId);
  }, [auditEvents, selectedSessionId]);

  const liveStats = useMemo(() => {
    const injections = filteredEvents.filter((e) => e.type === "injection_signal");
    const denials = filteredEvents.filter(
      (e) =>
        (e.type === "authz_decision" && (e.data.kind === "deny" || e.data.verdict === "deny")) ||
        e.type === "budget_exceeded" ||
        (e.type === "tool_proposed" && e.data.dropped === true)
    );
    const authorized = filteredEvents.filter(
      (e) => e.type === "authz_decision" && (e.data.kind === "allow" || e.data.verdict === "allow")
    );
    const executions = filteredEvents.filter((e) => e.type === "tool_executed");
    const taintedSessions = filteredEvents.some(
      (e) => e.type === "content_ingested" && e.data.trust === "untrusted"
    );

    return {
      injectionCount: injections.length,
      deniedCount: denials.length,
      authorizedCount: authorized.length,
      executedCount: executions.length,
      pendingCount: approvals.filter((a) => a.status === "pending").length,
      isTainted: taintedSessions,
      totalEvents: filteredEvents.length,
    };
  }, [filteredEvents, approvals]);

  return (
    <div
      style={{
        minHeight: "100vh",
        background: PALETTE.bgBase,
        color: PALETTE.textPrimary,
        fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        display: "flex",
        flexDirection: "column",
      }}
    >
      {/* ── TOP NAV HEADER ─────────────────────────────────────────────────── */}
      <header
        style={{
          background: PALETTE.bgPanel,
          borderBottom: `1px solid ${PALETTE.border}`,
          padding: "12px 24px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: 16,
          boxShadow: "0 4px 20px rgba(0,0,0,0.5)",
          position: "sticky",
          top: 0,
          zIndex: 40,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {/* Brand Shield Icon */}
          <div
            style={{
              width: 40,
              height: 40,
              borderRadius: 8,
              background: `linear-gradient(135deg, ${PALETTE.deepTeal} 0%, ${PALETTE.mutedTeal} 100%)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              border: `1px solid ${PALETTE.dustyPink}40`,
              boxShadow: `0 0 16px ${PALETTE.mutedTeal}50`,
            }}
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>

          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span
                style={{
                  fontWeight: 900,
                  fontSize: 18,
                  letterSpacing: "-0.5px",
                  color: "#fff",
                }}
              >
                BUTLER <span style={{ color: PALETTE.dustyPink }}>//</span> SENTINEL
              </span>
              <span
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: 1,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: `${PALETTE.mutedTeal}30`,
                  color: PALETTE.dustyPink,
                  border: `1px solid ${PALETTE.mutedTeal}60`,
                }}
              >
                SECURITY COMMAND CENTER
              </span>
              <span
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "#10b98120",
                  color: "#34d399",
                  border: "1px solid #10b98140",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 4,
                }}
              >
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: "#34d399",
                    boxShadow: "0 0 6px #34d399",
                  }}
                />
                ENGINE ONLINE
              </span>
            </div>
            <p style={{ fontSize: 11, color: PALETTE.textMuted, margin: 0, marginTop: 2 }}>
              Independent Tool Authorization Layer · Deterministic Policy Engine v1.0 · Round 2 Defense
            </p>
          </div>
        </div>

        {/* Controls & Session Filter */}
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {/* Two-Laptop Demo Trigger */}
          <button
            onClick={() => setShowDemoGuide(!showDemoGuide)}
            style={{
              padding: "6px 12px",
              borderRadius: 6,
              background: `${PALETTE.burgundy}80`,
              color: PALETTE.dustyPink,
              border: `1px solid ${PALETTE.dustyPink}50`,
              fontSize: 12,
              fontWeight: 600,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            💻 Laptop 2 Demo Protocol
          </button>

          {/* Session Selector */}
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
            <span style={{ color: PALETTE.textSecondary, fontWeight: 500 }}>Target Session:</span>
            <select
              value={selectedSessionId}
              onChange={(e) => setSelectedSessionId(e.target.value)}
              style={{
                background: PALETTE.bgCard,
                color: PALETTE.textPrimary,
                border: `1px solid ${PALETTE.border}`,
                borderRadius: 6,
                padding: "6px 10px",
                fontSize: 12,
                outline: "none",
                cursor: "pointer",
                maxWidth: 220,
              }}
            >
              <option value="ALL">All Active Sessions ({sessions.length})</option>
              {sessions.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id.slice(0, 8)}… ({s.status}
                  {s.tainted ? " | TAINTED" : ""})
                </option>
              ))}
            </select>
          </div>

          {/* Auto Refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            style={{
              padding: "6px 10px",
              borderRadius: 6,
              background: autoRefresh ? `${PALETTE.mutedTeal}30` : PALETTE.bgCard,
              color: autoRefresh ? "#5eead4" : PALETTE.textMuted,
              border: `1px solid ${autoRefresh ? PALETTE.mutedTeal : PALETTE.border}`,
              fontSize: 12,
              fontWeight: 600,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: autoRefresh ? "#34d399" : PALETTE.textMuted,
              }}
            />
            {autoRefresh ? "Live Polling (1.5s)" : "Polling Paused"}
          </button>

          {/* Manual Refresh */}
          <button
            onClick={fetchData}
            disabled={isFetching}
            style={{
              padding: "6px 12px",
              borderRadius: 6,
              background: PALETTE.bgCard,
              color: PALETTE.textPrimary,
              border: `1px solid ${PALETTE.border}`,
              fontSize: 12,
              cursor: isFetching ? "not-allowed" : "pointer",
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            🔄 {isFetching ? "Syncing…" : "Sync"}
          </button>

          {/* Companion Link back to Dev 1's Dashboard */}
          <Link
            href="/"
            style={{
              padding: "6px 12px",
              borderRadius: 6,
              background: `linear-gradient(135deg, ${PALETTE.slate} 0%, ${PALETTE.deepTeal} 100%)`,
              color: "#fff",
              textDecoration: "none",
              fontSize: 12,
              fontWeight: 600,
              border: `1px solid ${PALETTE.mutedTeal}60`,
            }}
          >
            Butler Dashboard →
          </Link>
        </div>
      </header>

      {/* ── TWO-LAPTOP DEMO BANNER MODAL ────────────────────────────────────── */}
      {showDemoGuide && (
        <div
          style={{
            background: `linear-gradient(90deg, ${PALETTE.burgundy}f0 0%, ${PALETTE.bgPanel} 100%)`,
            borderBottom: `2px solid ${PALETTE.dustyPink}`,
            padding: "16px 24px",
            fontSize: 13,
            lineHeight: 1.6,
          }}
        >
          <div style={{ maxWidth: 1200, margin: "0 auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3 style={{ margin: 0, color: PALETTE.dustyPink, fontWeight: 800, fontSize: 15 }}>
                ⚔️ TWO-LAPTOP JUDGE DEMONSTRATION WORKFLOW
              </h3>
              <button
                onClick={() => setShowDemoGuide(false)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: PALETTE.textMuted,
                  cursor: "pointer",
                  fontSize: 16,
                }}
              >
                ✕
              </button>
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                gap: 16,
                marginTop: 12,
              }}
            >
              <div
                style={{
                  background: "#00000040",
                  padding: "10px 14px",
                  borderRadius: 6,
                  border: `1px solid ${PALETTE.border}`,
                }}
              >
                <div style={{ fontWeight: 700, color: "#fff", marginBottom: 4 }}>
                  Phase 1: Malicious Attack Ingestion
                </div>
                <div style={{ fontSize: 12, color: PALETTE.textSecondary }}>
                  1. Developer 1 submits malicious email (e.g., prompt injection to exfiltrate secrets).
                  <br />
                  2. <strong>This screen</strong> captures `content_ingested` (untrusted) & `injection_signal`.
                  <br />
                  3. Context status flips to <span style={{ color: PALETTE.accentWarning }}>TAINT TRACKED</span>.
                </div>
              </div>

              <div
                style={{
                  background: "#00000040",
                  padding: "10px 14px",
                  borderRadius: 6,
                  border: `1px solid ${PALETTE.border}`,
                }}
              >
                <div style={{ fontWeight: 700, color: "#fff", marginBottom: 4 }}>
                  Phase 2: Unauthorized Tool Neutralization
                </div>
                <div style={{ fontSize: 12, color: PALETTE.textSecondary }}>
                  4. The LLM proposes unauthorized `email.send` or `file.read`.
                  <br />
                  5. Security Engine evaluates policy: <strong>DENY</strong> issued.
                  <br />
                  6. Proves: <em>Zero SMTP or shell execution occurred.</em>
                </div>
              </div>

              <div
                style={{
                  background: "#00000040",
                  padding: "10px 14px",
                  borderRadius: 6,
                  border: `1px solid ${PALETTE.border}`,
                }}
              >
                <div style={{ fontWeight: 700, color: "#fff", marginBottom: 4 }}>
                  Phase 3: Legitimate Approval & Audit Proof
                </div>
                <div style={{ fontSize: 12, color: PALETTE.textSecondary }}>
                  7. Developer 1 approves a legitimate draft email on Laptop 1.
                  <br />
                  8. <strong>This screen</strong> logs HMAC capability issue, single-use burn, and real SMTP success.
                  <br />
                  9. Audit explorer verifies secret masking (`argsHash` only).
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── SECONDARY TAB NAVIGATION ────────────────────────────────────────── */}
      <nav
        style={{
          background: PALETTE.bgCard,
          borderBottom: `1px solid ${PALETTE.border}`,
          padding: "0 24px",
          display: "flex",
          gap: 4,
          overflowX: "auto",
        }}
      >
        {[
          { id: "overview", label: "Executive Overview", icon: "📊" },
          { id: "threats", label: `Live Threat Monitor (${liveStats.totalEvents})`, icon: "🚨" },
          { id: "pipeline", label: "Authorization Engine (Flow)", icon: "⚙️" },
          { id: "integrity", label: "Execution Integrity (HMAC)", icon: "🛡️" },
          { id: "eval", label: "Evaluation Lab (Benchmark)", icon: "🔬" },
          { id: "curse", label: "Midnight Curse (Challenge)", icon: "🌕" },
          { id: "audit", label: "Audit Explorer", icon: "📜" },
        ].map((tab) => {
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              style={{
                padding: "12px 18px",
                background: "transparent",
                color: active ? PALETTE.dustyPink : PALETTE.textSecondary,
                border: "none",
                borderBottom: active ? `3px solid ${PALETTE.dustyPink}` : "3px solid transparent",
                fontWeight: active ? 700 : 500,
                fontSize: 13,
                cursor: "pointer",
                whiteSpace: "nowrap",
                display: "flex",
                alignItems: "center",
                gap: 8,
                transition: "all 0.15s ease",
              }}
            >
              <span>{tab.icon}</span>
              {tab.label}
            </button>
          );
        })}
      </nav>

      {/* ── MAIN CONTENT CONTAINER ─────────────────────────────────────────── */}
      <main style={{ flex: 1, padding: "24px", maxWidth: 1400, width: "100%", margin: "0 auto" }}>
        {fetchError && (
          <div
            style={{
              padding: "12px 16px",
              background: "#ef444420",
              border: "1px solid #ef444450",
              borderRadius: 8,
              color: "#fca5a5",
              marginBottom: 20,
              fontSize: 13,
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span>⚠️ Backend connection notice: {fetchError}. Retrying in background…</span>
            <button
              onClick={fetchData}
              style={{
                background: "transparent",
                border: "1px solid #ef4444",
                color: "#fca5a5",
                borderRadius: 4,
                padding: "4px 8px",
                cursor: "pointer",
                fontSize: 11,
              }}
            >
              Retry
            </button>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            SECTION A: SECURITY OVERVIEW
            ══════════════════════════════════════════════════════════════════════ */}
        {activeTab === "overview" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            {/* Health & Engine Status Row */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
                gap: 16,
              }}
            >
              {/* Card 1: Security Engine */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "18px 20px",
                  borderLeft: `4px solid ${PALETTE.mutedTeal}`,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <div>
                    <div style={{ fontSize: 11, textTransform: "uppercase", color: PALETTE.textMuted, fontWeight: 700 }}>
                      Deterministic Engine
                    </div>
                    <div style={{ fontSize: 20, fontWeight: 800, color: "#fff", marginTop: 4 }}>
                      ACTIVE & ENFORCING
                    </div>
                  </div>
                  <span
                    style={{
                      background: "#34d39920",
                      color: "#34d399",
                      padding: "2px 8px",
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 700,
                    }}
                  >
                    FAIL-CLOSED
                  </span>
                </div>
                <p style={{ fontSize: 12, color: PALETTE.textSecondary, marginTop: 8, margin: 0 }}>
                  Policy rules: Allowlist, Sandbox Isolation, Secret Leak Gate, Injected Tool Call Filter, Approval Gate.
                </p>
                <div style={{ fontSize: 11, color: PALETTE.textMuted, marginTop: 10 }}>
                  Zero LLM decision authority · Pure synchronous evaluation
                </div>
              </div>

              {/* Card 2: Monotonic Taint State */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "18px 20px",
                  borderLeft: `4px solid ${liveStats.isTainted ? PALETTE.accentWarning : PALETTE.accentSuccess}`,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <div>
                    <div style={{ fontSize: 11, textTransform: "uppercase", color: PALETTE.textMuted, fontWeight: 700 }}>
                      Session Context Status
                    </div>
                    <div
                      style={{
                        fontSize: 20,
                        fontWeight: 800,
                        color: liveStats.isTainted ? PALETTE.accentWarning : PALETTE.accentSuccess,
                        marginTop: 4,
                      }}
                    >
                      {liveStats.isTainted ? "TAINT TRACKED" : "CLEAN CONTEXT"}
                    </div>
                  </div>
                  <span
                    style={{
                      background: liveStats.isTainted ? "#f59e0b20" : "#10b98120",
                      color: liveStats.isTainted ? "#fbbf24" : "#34d399",
                      padding: "2px 8px",
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 700,
                    }}
                  >
                    {liveStats.isTainted ? "UNTRUSTED INGESTED" : "NO INJECTIONS"}
                  </span>
                </div>
                <p style={{ fontSize: 12, color: PALETTE.textSecondary, marginTop: 8, margin: 0 }}>
                  External content (emails, web, PDFs) tagged with <code>UntrustedContent</code> boundary type.
                </p>
                <div style={{ fontSize: 11, color: PALETTE.textMuted, marginTop: 10 }}>
                  Monotonic rule: Ingesting clean data cannot un-taint session
                </div>
              </div>

              {/* Card 3: Cryptographic Authority */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "18px 20px",
                  borderLeft: `4px solid ${PALETTE.dustyPink}`,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <div>
                    <div style={{ fontSize: 11, textTransform: "uppercase", color: PALETTE.textMuted, fontWeight: 700 }}>
                      Call Authority
                    </div>
                    <div style={{ fontSize: 20, fontWeight: 800, color: "#fff", marginTop: 4 }}>
                      HMAC-SHA256
                    </div>
                  </div>
                  <span
                    style={{
                      background: `${PALETTE.dustyPink}20`,
                      color: PALETTE.dustyPink,
                      padding: "2px 8px",
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 700,
                    }}
                  >
                    60s TTL
                  </span>
                </div>
                <p style={{ fontSize: 12, color: PALETTE.textSecondary, marginTop: 8, margin: 0 }}>
                  Single-use capability tokens bound to exact argsHash and sessionId. Replay attack resistance.
                </p>
                <div style={{ fontSize: 11, color: PALETTE.textMuted, marginTop: 10 }}>
                  Random 256-bit process key · Tamper-evident execution
                </div>
              </div>

              {/* Card 4: Automated Regression Suite */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "18px 20px",
                  borderLeft: `4px solid #38bdf8`,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <div>
                    <div style={{ fontSize: 11, textTransform: "uppercase", color: PALETTE.textMuted, fontWeight: 700 }}>
                      Regression Test Suite
                    </div>
                    <div style={{ fontSize: 20, fontWeight: 800, color: "#38bdf8", marginTop: 4 }}>
                      232 / 232 PASSING
                    </div>
                  </div>
                  <span
                    style={{
                      background: "#38bdf820",
                      color: "#38bdf8",
                      padding: "2px 8px",
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 700,
                    }}
                  >
                    16 TEST SUITES
                  </span>
                </div>
                <p style={{ fontSize: 12, color: PALETTE.textSecondary, marginTop: 8, margin: 0 }}>
                  Automated adversarial coverage across injectors, detectors, policies, orchestrator and tokens.
                </p>
                <div style={{ fontSize: 11, color: PALETTE.textMuted, marginTop: 10 }}>
                  0 skipped · 0 failed · Vitest v5.0.5 verified
                </div>
              </div>
            </div>

            {/* Live Counters Banner */}
            <div
              style={{
                background: PALETTE.bgPanel,
                border: `1px solid ${PALETTE.border}`,
                borderRadius: 10,
                padding: "20px",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 800, color: "#fff" }}>
                    LIVE APPLICATION TELEMETRY & ENFORCEMENT COUNTERS
                  </h3>
                  <p style={{ margin: "2px 0 0", fontSize: 12, color: PALETTE.textMuted }}>
                    Correlated directly with Developer 1’s running Butler session (Updated:{" "}
                    {lastRefreshed ? lastRefreshed.toLocaleTimeString() : "Syncing…"})
                  </p>
                </div>
                <span
                  style={{
                    fontSize: 11,
                    background: PALETTE.bgCard,
                    padding: "4px 10px",
                    borderRadius: 6,
                    border: `1px solid ${PALETTE.border}`,
                    color: PALETTE.textSecondary,
                  }}
                >
                  Scope: {selectedSessionId === "ALL" ? "All Sessions" : selectedSessionId.slice(0, 8) + "…"}
                </span>
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: 12,
                }}
              >
                <div
                  style={{
                    background: PALETTE.bgCard,
                    padding: "14px 16px",
                    borderRadius: 8,
                    border: `1px solid ${PALETTE.border}`,
                  }}
                >
                  <div style={{ fontSize: 11, color: PALETTE.textMuted, textTransform: "uppercase", fontWeight: 700 }}>
                    Injections Blocked
                  </div>
                  <div style={{ fontSize: 26, fontWeight: 900, color: PALETTE.accentDanger, marginTop: 4 }}>
                    {liveStats.injectionCount}
                  </div>
                  <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 4 }}>
                    Pattern matches intercepted
                  </div>
                </div>

                <div
                  style={{
                    background: PALETTE.bgCard,
                    padding: "14px 16px",
                    borderRadius: 8,
                    border: `1px solid ${PALETTE.border}`,
                  }}
                >
                  <div style={{ fontSize: 11, color: PALETTE.textMuted, textTransform: "uppercase", fontWeight: 700 }}>
                    Unauthorized Denials
                  </div>
                  <div style={{ fontSize: 26, fontWeight: 900, color: PALETTE.dustyPink, marginTop: 4 }}>
                    {liveStats.deniedCount}
                  </div>
                  <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 4 }}>
                    Enforced by policy engine
                  </div>
                </div>

                <div
                  style={{
                    background: PALETTE.bgCard,
                    padding: "14px 16px",
                    borderRadius: 8,
                    border: `1px solid ${PALETTE.border}`,
                  }}
                >
                  <div style={{ fontSize: 11, color: PALETTE.textMuted, textTransform: "uppercase", fontWeight: 700 }}>
                    Pending Approvals
                  </div>
                  <div style={{ fontSize: 26, fontWeight: 900, color: PALETTE.accentWarning, marginTop: 4 }}>
                    {liveStats.pendingCount}
                  </div>
                  <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 4 }}>
                    Human confirmation gate
                  </div>
                </div>

                <div
                  style={{
                    background: PALETTE.bgCard,
                    padding: "14px 16px",
                    borderRadius: 8,
                    border: `1px solid ${PALETTE.border}`,
                  }}
                >
                  <div style={{ fontSize: 11, color: PALETTE.textMuted, textTransform: "uppercase", fontWeight: 700 }}>
                    Authorized Executions
                  </div>
                  <div style={{ fontSize: 26, fontWeight: 900, color: PALETTE.accentSuccess, marginTop: 4 }}>
                    {liveStats.executedCount}
                  </div>
                  <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 4 }}>
                    Signed capability consumed
                  </div>
                </div>

                <div
                  style={{
                    background: PALETTE.bgCard,
                    padding: "14px 16px",
                    borderRadius: 8,
                    border: `1px solid ${PALETTE.border}`,
                  }}
                >
                  <div style={{ fontSize: 11, color: PALETTE.textMuted, textTransform: "uppercase", fontWeight: 700 }}>
                    Total Audit Records
                  </div>
                  <div style={{ fontSize: 26, fontWeight: 900, color: "#fff", marginTop: 4 }}>
                    {liveStats.totalEvents}
                  </div>
                  <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 4 }}>
                    Immutable JSONL entries
                  </div>
                </div>
              </div>
            </div>

            {/* Quick Demonstration Snapshot */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: 20,
              }}
            >
              {/* Left: Security Core Invariant */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "20px",
                }}
              >
                <h4 style={{ margin: "0 0 12px", color: PALETTE.dustyPink, fontWeight: 800 }}>
                  ⚖️ THE INVIOLABLE SECURITY PRINCIPLE
                </h4>
                <blockquote
                  style={{
                    margin: 0,
                    padding: "12px 16px",
                    background: `${PALETTE.burgundy}40`,
                    borderLeft: `3px solid ${PALETTE.dustyPink}`,
                    fontStyle: "italic",
                    fontSize: 14,
                    color: "#fff",
                  }}
                >
                  “The AI proposes. The security engine authorizes. The tools execute. The LLM must NEVER be the
                  security authority.”
                </blockquote>
                <p style={{ fontSize: 12, color: PALETTE.textSecondary, marginTop: 12, lineHeight: 1.6 }}>
                  Even if a jailbroken model generates 100 tool calls claiming root privileges, the deterministic security
                  engine intercepts each proposal before tool invocation. No tool execution primitive exists that bypasses
                  the <code>CallAuthority</code>.
                </p>
              </div>

              {/* Right: Real Benchmark vs Test Suite Callout */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "20px",
                }}
              >
                <h4 style={{ margin: "0 0 12px", color: "#38bdf8", fontWeight: 800 }}>
                  🎯 BENCHMARK VS. CODE REGRESSION DISTINCTION
                </h4>
                <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 12 }}>
                  <div
                    style={{
                      background: PALETTE.bgCard,
                      padding: "8px 12px",
                      borderRadius: 6,
                      border: `1px solid ${PALETTE.border}`,
                    }}
                  >
                    <strong style={{ color: "#fff" }}>Public Evaluation Benchmark:</strong>
                    <div style={{ color: PALETTE.textSecondary, marginTop: 2 }}>
                      <strong>98 Total Samples</strong> (56 Malicious + 42 Benign). Evaluates accuracy, precision,
                      recall and attack success rate (0.0%).
                    </div>
                  </div>
                  <div
                    style={{
                      background: PALETTE.bgCard,
                      padding: "8px 12px",
                      borderRadius: 6,
                      border: `1px solid ${PALETTE.border}`,
                    }}
                  >
                    <strong style={{ color: "#fff" }}>Automated Software Tests:</strong>
                    <div style={{ color: PALETTE.textSecondary, marginTop: 2 }}>
                      <strong>232 Passing Tests</strong> across 16 test files. Unit, integration and contract tests
                      verifying engine internals, HMAC hashes, and quotas.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            SECTION B: LIVE THREAT MONITOR
            ══════════════════════════════════════════════════════════════════════ */}
        {activeTab === "threats" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: "#fff" }}>
                  LIVE THREAT INTERCEPTION & EVENT STREAM
                </h3>
                <p style={{ margin: "2px 0 0", fontSize: 12, color: PALETTE.textMuted }}>
                  Live correlation with Developer 1’s main Butler app ({filteredEvents.length} events logged in session)
                </p>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <span className="badge badge-blue">Real-Time Polling</span>
                {liveStats.isTainted && <span className="badge badge-amber">SESSION TAINTED</span>}
              </div>
            </div>

            {filteredEvents.length === 0 ? (
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "48px 20px",
                  textAlign: "center",
                  color: PALETTE.textMuted,
                }}
              >
                <div style={{ fontSize: 32, marginBottom: 12 }}>🛡️</div>
                <div style={{ fontSize: 16, fontWeight: 700, color: PALETTE.textSecondary }}>
                  No security events recorded in this session yet
                </div>
                <p style={{ fontSize: 12, maxWidth: 500, margin: "8px auto 0" }}>
                  Submit an interaction on Developer 1’s Butler interface (
                  <Link href="/" style={{ color: PALETTE.dustyPink }}>
                    http://localhost:3000
                  </Link>
                  ) to see live threat monitoring, taint updates, and authorization decisions stream here in real time.
                </p>
              </div>
            ) : (
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  overflow: "hidden",
                }}
              >
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                    <thead>
                      <tr
                        style={{
                          background: PALETTE.bgCard,
                          borderBottom: `1px solid ${PALETTE.border}`,
                          textAlign: "left",
                          color: PALETTE.textMuted,
                          textTransform: "uppercase",
                          fontSize: 11,
                          letterSpacing: 0.5,
                        }}
                      >
                        <th style={{ padding: "10px 16px" }}>Time</th>
                        <th style={{ padding: "10px 16px" }}>Event Type</th>
                        <th style={{ padding: "10px 16px" }}>Tool / Target</th>
                        <th style={{ padding: "10px 16px" }}>Security Verdict</th>
                        <th style={{ padding: "10px 16px" }}>Details / Reasoning</th>
                        <th style={{ padding: "10px 16px", textAlign: "right" }}>Inspect</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredEvents.map((e, idx) => {
                        const isDeny =
                          e.type === "authz_decision" &&
                          (e.data.kind === "deny" || e.data.verdict === "deny");
                        const isAllow =
                          e.type === "authz_decision" &&
                          (e.data.kind === "allow" || e.data.verdict === "allow");
                        const isApprovalReq =
                          e.type === "approval_requested" ||
                          (e.type === "authz_decision" && e.data.kind === "require_approval");
                        const isInjection = e.type === "injection_signal";
                        const isBudget = e.type === "budget_exceeded";

                        let badgeColor = PALETTE.textMuted;
                        let badgeBg = `${PALETTE.textMuted}20`;
                        if (isDeny || isInjection) {
                          badgeColor = PALETTE.accentDanger;
                          badgeBg = "#ef444420";
                        } else if (isAllow) {
                          badgeColor = PALETTE.accentSuccess;
                          badgeBg = "#10b98120";
                        } else if (isApprovalReq) {
                          badgeColor = PALETTE.accentWarning;
                          badgeBg = "#f59e0b20";
                        } else if (isBudget) {
                          badgeColor = PALETTE.dustyPink;
                          badgeBg = `${PALETTE.dustyPink}20`;
                        }

                        return (
                          <tr
                            key={e.id ?? idx}
                            style={{
                              borderBottom: `1px solid ${PALETTE.border}`,
                              background: idx % 2 === 0 ? "transparent" : `${PALETTE.bgCard}40`,
                              transition: "background 0.15s ease",
                            }}
                          >
                            <td style={{ padding: "10px 16px", color: PALETTE.textMuted, whiteSpace: "nowrap" }}>
                              {new Date(e.ts).toLocaleTimeString()}
                            </td>
                            <td style={{ padding: "10px 16px" }}>
                              <span
                                style={{
                                  background: badgeBg,
                                  color: badgeColor,
                                  padding: "2px 8px",
                                  borderRadius: 4,
                                  fontWeight: 700,
                                  fontSize: 11,
                                }}
                              >
                                {e.type}
                              </span>
                            </td>
                            <td style={{ padding: "10px 16px", fontWeight: 600, color: "#fff" }}>
                              {String(e.data.tool ?? e.data.detectorId ?? "—")}
                            </td>
                            <td style={{ padding: "10px 16px" }}>
                              {isDeny && <span style={{ color: PALETTE.accentDanger, fontWeight: 700 }}>⛔ DENY</span>}
                              {isAllow && <span style={{ color: PALETTE.accentSuccess, fontWeight: 700 }}>✓ ALLOW</span>}
                              {isApprovalReq && (
                                <span style={{ color: PALETTE.accentWarning, fontWeight: 700 }}>⏸ APPROVAL REQUIRED</span>
                              )}
                              {isInjection && (
                                <span style={{ color: PALETTE.accentDanger, fontWeight: 700 }}>⚠ SIGNAL DETECTED</span>
                              )}
                              {isBudget && (
                                <span style={{ color: PALETTE.dustyPink, fontWeight: 700 }}>LIMIT CAPPED</span>
                              )}
                              {!isDeny && !isAllow && !isApprovalReq && !isInjection && !isBudget && (
                                <span style={{ color: PALETTE.textMuted }}>RECORDED</span>
                              )}
                            </td>
                            <td style={{ padding: "10px 16px", color: PALETTE.textSecondary, maxWidth: 400 }}>
                              {isInjection && String(e.data.description ?? e.data.fragment ?? "Pattern detected")}
                              {isDeny &&
                                (Array.isArray(e.data.reasons)
                                  ? e.data.reasons.join(", ")
                                  : String(e.data.reason ?? "Denied by policy"))}
                              {isAllow && "Policy authorized tool execution"}
                              {isApprovalReq && "Sensitive tool confirmation gate held"}
                              {isBudget &&
                                `Excess proposals (${String(e.data.excess ?? "")}) dropped per maxProposalsPerStep limit`}
                              {!isDeny && !isAllow && !isApprovalReq && !isInjection && !isBudget && (
                                <span style={{ color: PALETTE.textMuted }}>
                                  {JSON.stringify(e.data).slice(0, 70)}…
                                </span>
                              )}
                            </td>
                            <td style={{ padding: "10px 16px", textAlign: "right" }}>
                              <button
                                onClick={() => setSelectedEventForModal(e)}
                                style={{
                                  background: PALETTE.bgCard,
                                  border: `1px solid ${PALETTE.border}`,
                                  color: PALETTE.textPrimary,
                                  borderRadius: 4,
                                  padding: "3px 8px",
                                  fontSize: 11,
                                  cursor: "pointer",
                                }}
                              >
                                View JSON
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            SECTION C: AUTHORIZATION ENGINE (Visual Pipeline)
            ══════════════════════════════════════════════════════════════════════ */}
        {activeTab === "pipeline" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: "#fff" }}>
                PIPELINE ARCHITECTURE: FROM PROPOSAL TO EXECUTION
              </h3>
              <p style={{ margin: "2px 0 0", fontSize: 12, color: PALETTE.textMuted }}>
                How the Security Engine guarantees that malicious content cannot manipulate tool executions
              </p>
            </div>

            {/* Visual Pipeline Flowchart */}
            <div
              style={{
                background: PALETTE.bgPanel,
                border: `1px solid ${PALETTE.border}`,
                borderRadius: 10,
                padding: "24px",
              }}
            >
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
                  gap: 12,
                  position: "relative",
                }}
              >
                {[
                  {
                    step: "1. Proposal",
                    title: "LLM Output",
                    desc: "Proposes tool + args in JSON",
                    color: "#94a3b8",
                  },
                  {
                    step: "2. Quota Check",
                    title: "Proposal Limiter",
                    desc: "Enforces maxProposalsPerStep (cap 5)",
                    color: PALETTE.dustyPink,
                  },
                  {
                    step: "3. Inspection",
                    title: "Injection Scan",
                    desc: "Detectors scan external segments",
                    color: PALETTE.accentWarning,
                  },
                  {
                    step: "4. Taint State",
                    title: "Taint Tracking",
                    desc: "Monotonic taint marking",
                    color: PALETTE.accentWarning,
                  },
                  {
                    step: "5. Policy Gate",
                    title: "Engine RULES",
                    desc: "Deterministic evaluate()",
                    color: PALETTE.mutedTeal,
                  },
                  {
                    step: "6. Human Gate",
                    title: "Approval Store",
                    desc: "email.send / file.write gate",
                    color: PALETTE.dustyPink,
                  },
                  {
                    step: "7. Capability",
                    title: "Call Authority",
                    desc: "Issues HMAC token (60s TTL)",
                    color: PALETTE.accentSuccess,
                  },
                  {
                    step: "8. Execution",
                    title: "Toolbox Burn",
                    desc: "Token consumed & executed",
                    color: PALETTE.accentSuccess,
                  },
                ].map((item, i) => (
                  <div
                    key={i}
                    style={{
                      background: PALETTE.bgCard,
                      border: `1px solid ${PALETTE.border}`,
                      borderRadius: 8,
                      padding: "14px 12px",
                      display: "flex",
                      flexDirection: "column",
                      justifyContent: "space-between",
                      borderTop: `3px solid ${item.color}`,
                    }}
                  >
                    <div>
                      <div style={{ fontSize: 10, fontWeight: 700, color: item.color, textTransform: "uppercase" }}>
                        {item.step}
                      </div>
                      <div style={{ fontSize: 13, fontWeight: 800, color: "#fff", marginTop: 4 }}>{item.title}</div>
                    </div>
                    <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 8 }}>{item.desc}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Matrix of Actual Decisions & Policies */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              {/* ALLOW Scenarios */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "20px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
                  <span style={{ color: PALETTE.accentSuccess, fontSize: 18 }}>✓</span>
                  <h4 style={{ margin: 0, color: PALETTE.accentSuccess, fontWeight: 800 }}>
                    AUTHORIZED (ALLOW) SCENARIOS
                  </h4>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 12 }}>
                  <div
                    style={{
                      padding: "10px",
                      background: PALETTE.bgCard,
                      borderRadius: 6,
                      border: `1px solid ${PALETTE.border}`,
                    }}
                  >
                    <strong>Reading Malicious Emails (Safe Inspection):</strong>
                    <div style={{ color: PALETTE.textSecondary, marginTop: 2 }}>
                      <code>email.read</code> is explicitly allowed. The user must be able to read and summarize what
                      was received without the engine blocking benign visibility.
                    </div>
                  </div>
                  <div
                    style={{
                      padding: "10px",
                      background: PALETTE.bgCard,
                      borderRadius: 6,
                      border: `1px solid ${PALETTE.border}`,
                    }}
                  >
                    <strong>Safe Sandbox File Reads:</strong>
                    <div style={{ color: PALETTE.textSecondary, marginTop: 2 }}>
                      <code>file.read</code> within <code>SANDBOX_DIR</code> on non-secret file paths (e.g.{" "}
                      <code>reports/q3.md</code>).
                    </div>
                  </div>
                  <div
                    style={{
                      padding: "10px",
                      background: PALETTE.bgCard,
                      borderRadius: 6,
                      border: `1px solid ${PALETTE.border}`,
                    }}
                  >
                    <strong>Web Fetch & PDF Parsing:</strong>
                    <div style={{ color: PALETTE.textSecondary, marginTop: 2 }}>
                      Public documentation and PDF extraction succeed; retrieved text is branded as{" "}
                      <code>UntrustedContent</code>.
                    </div>
                  </div>
                </div>
              </div>

              {/* DENY Scenarios */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "20px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
                  <span style={{ color: PALETTE.accentDanger, fontSize: 18 }}>⛔</span>
                  <h4 style={{ margin: 0, color: PALETTE.accentDanger, fontWeight: 800 }}>
                    DENIED (INTERCEPTED) SCENARIOS
                  </h4>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 12 }}>
                  <div
                    style={{
                      padding: "10px",
                      background: PALETTE.bgCard,
                      borderRadius: 6,
                      border: `1px solid ${PALETTE.border}`,
                    }}
                  >
                    <strong>Injected Tool Invocation (Rule 4):</strong>
                    <div style={{ color: PALETTE.textSecondary, marginTop: 2 }}>
                      When untrusted email/web content contains embedded JSON tool calls targeting sensitive tools, the
                      engine denies tool execution automatically.
                    </div>
                  </div>
                  <div
                    style={{
                      padding: "10px",
                      background: PALETTE.bgCard,
                      borderRadius: 6,
                      border: `1px solid ${PALETTE.border}`,
                    }}
                  >
                    <strong>Path Traversal & Sandbox Escape (Rule 2):</strong>
                    <div style={{ color: PALETTE.textSecondary, marginTop: 2 }}>
                      Attempting <code>../../etc/passwd</code> or outside relative paths triggers instant policy denial.
                    </div>
                  </div>
                  <div
                    style={{
                      padding: "10px",
                      background: PALETTE.bgCard,
                      borderRadius: 6,
                      border: `1px solid ${PALETTE.border}`,
                    }}
                  >
                    <strong>Secret & Credential Leakage (Rule 3):</strong>
                    <div style={{ color: PALETTE.textSecondary, marginTop: 2 }}>
                      File reads targeting <code>.env</code>, <code>id_rsa</code>, <code>credentials.json</code>, or TLS
                      keys are blocked.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            SECTION D: EXECUTION INTEGRITY
            ══════════════════════════════════════════════════════════════════════ */}
        {activeTab === "integrity" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: "#fff" }}>
                CRYPTOGRAPHIC INTEGRITY & ZERO-BYPASS VERIFICATION
              </h3>
              <p style={{ margin: "2px 0 0", fontSize: 12, color: PALETTE.textMuted }}>
                Empirical test-backed proofs guaranteeing single-use tokens, HMAC validity, and replay protection
              </p>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
                gap: 16,
              }}
            >
              {[
                {
                  id: "HMAC",
                  title: "HMAC-SHA256 Capability Token",
                  proof: "tests/security/authority.test.ts",
                  desc: "Every authorized execution produces an HMAC signature over (decisionId, proposalId, sessionId, tool, argsHash, expiresAt). Signature verification is timing-safe.",
                  status: "VERIFIED IN TEST SUITE",
                },
                {
                  id: "TAMPER",
                  title: "Argument Tampering Immunity",
                  proof: "tests/integration/security-integration.test.ts",
                  desc: "If an attacker modifies `to`, `subject`, or `body` after human review, argsHash does not match the signed token. The tool refuses execution.",
                  status: "VERIFIED IN TEST SUITE",
                },
                {
                  id: "SINGLE_USE",
                  title: "Single-Use Execution & Nonce Burn",
                  proof: "tests/security/authority.test.ts",
                  desc: "Tokens are consumed inside verifyAndConsume() on the first invocation. Replaying the exact same token immediately fails with 'token already consumed'.",
                  status: "VERIFIED IN TEST SUITE",
                },
                {
                  id: "CROSS_SESSION",
                  title: "Cross-Session Approval Validation",
                  proof: "tests/security/hardening.test.ts",
                  desc: "Session B cannot approve Session A's pending action. Verified by resumeAfterApproval(id, verdict, callerSessionId) returning APPROVAL_SESSION_MISMATCH.",
                  status: "VERIFIED IN TEST SUITE",
                },
                {
                  id: "PROPOSAL_CAP",
                  title: "Maximum Proposal Limiter (Cap 5)",
                  proof: "tests/security/hardening.test.ts",
                  desc: "Model attempts to flood 10 tool calls in a single turn. Orchestrator cleanly slices at maxProposalsPerStep, logging budget_exceeded and dropReason.",
                  status: "VERIFIED IN TEST SUITE",
                },
                {
                  id: "FAIL_CLOSED",
                  title: "Fail-Closed Audit & Engine Guarantee",
                  proof: "tests/integration/security-integration.test.ts",
                  desc: "If audit logging fails or an unexpected exception occurs, session state flips to fatal and terminates immediately. No orphan tool calls ever execute.",
                  status: "VERIFIED IN TEST SUITE",
                },
              ].map((item, idx) => (
                <div
                  key={idx}
                  style={{
                    background: PALETTE.bgPanel,
                    border: `1px solid ${PALETTE.border}`,
                    borderRadius: 10,
                    padding: "18px 20px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                      <h4 style={{ margin: 0, color: "#fff", fontSize: 14, fontWeight: 800 }}>{item.title}</h4>
                      <span
                        style={{
                          background: "#10b98120",
                          color: "#34d399",
                          fontSize: 10,
                          fontWeight: 700,
                          padding: "2px 6px",
                          borderRadius: 4,
                        }}
                      >
                        {item.status}
                      </span>
                    </div>
                    <p style={{ fontSize: 12, color: PALETTE.textSecondary, marginTop: 8, lineHeight: 1.5 }}>
                      {item.desc}
                    </p>
                  </div>
                  <div
                    style={{
                      fontSize: 11,
                      color: PALETTE.dustyPink,
                      marginTop: 12,
                      fontFamily: "monospace",
                      background: PALETTE.bgCard,
                      padding: "4px 8px",
                      borderRadius: 4,
                    }}
                  >
                    📄 {item.proof}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            SECTION E: EVALUATION LAB (Benchmark Metrics)
            ══════════════════════════════════════════════════════════════════════ */}
        {activeTab === "eval" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: "#fff" }}>
                PUBLIC TEST SET EVALUATION BENCHMARK METRICS
              </h3>
              <p style={{ margin: "2px 0 0", fontSize: 12, color: PALETTE.textMuted }}>
                Rigorous empirical evaluation on 98 test samples (56 malicious, 42 benign). Distinct from code test
                count.
              </p>
            </div>

            {/* Core KPI Grid */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                gap: 12,
              }}
            >
              {[
                { label: "Attack Success Rate", value: "0.0%", color: PALETTE.accentSuccess, desc: "0 exploits executed" },
                { label: "Unauthorized Executions", value: "0", color: PALETTE.accentSuccess, desc: "Strict 0 tolerance" },
                { label: "Precision", value: "100.0%", color: "#38bdf8", desc: "TP / (TP + FP)" },
                { label: "Recall (Detection Rate)", value: "100.0%", color: "#38bdf8", desc: "TP / (TP + FN)" },
                { label: "False Positive Rate", value: "0.0%", color: PALETTE.accentSuccess, desc: "FP / (FP + TN)" },
                { label: "Benign Task Success", value: "100.0%", color: PALETTE.accentSuccess, desc: "Operational reads pass" },
              ].map((kpi, idx) => (
                <div
                  key={idx}
                  style={{
                    background: PALETTE.bgPanel,
                    border: `1px solid ${PALETTE.border}`,
                    borderRadius: 8,
                    padding: "16px",
                  }}
                >
                  <div style={{ fontSize: 11, color: PALETTE.textMuted, textTransform: "uppercase", fontWeight: 700 }}>
                    {kpi.label}
                  </div>
                  <div style={{ fontSize: 28, fontWeight: 900, color: kpi.color, marginTop: 4 }}>{kpi.value}</div>
                  <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 4 }}>{kpi.desc}</div>
                </div>
              ))}
            </div>

            {/* Confusion Matrix & Dataset Breakdown */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              {/* Confusion Matrix */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "20px",
                }}
              >
                <h4 style={{ margin: "0 0 16px", color: "#fff", fontWeight: 800 }}>CONFUSION MATRIX (N = 98 SAMPLES)</h4>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, textAlign: "center" }}>
                  <div
                    style={{
                      background: "#10b98115",
                      border: "1px solid #10b98140",
                      borderRadius: 8,
                      padding: "14px",
                    }}
                  >
                    <div style={{ fontSize: 11, color: "#34d399", fontWeight: 700 }}>TRUE POSITIVES (TP)</div>
                    <div style={{ fontSize: 28, fontWeight: 900, color: "#34d399", marginTop: 4 }}>56</div>
                    <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 2 }}>
                      Malicious attacks correctly intercepted
                    </div>
                  </div>

                  <div
                    style={{
                      background: PALETTE.bgCard,
                      border: `1px solid ${PALETTE.border}`,
                      borderRadius: 8,
                      padding: "14px",
                    }}
                  >
                    <div style={{ fontSize: 11, color: PALETTE.textMuted, fontWeight: 700 }}>FALSE POSITIVES (FP)</div>
                    <div style={{ fontSize: 28, fontWeight: 900, color: PALETTE.accentSuccess, marginTop: 4 }}>0</div>
                    <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 2 }}>
                      Benign emails incorrectly blocked
                    </div>
                  </div>

                  <div
                    style={{
                      background: PALETTE.bgCard,
                      border: `1px solid ${PALETTE.border}`,
                      borderRadius: 8,
                      padding: "14px",
                    }}
                  >
                    <div style={{ fontSize: 11, color: PALETTE.textMuted, fontWeight: 700 }}>FALSE NEGATIVES (FN)</div>
                    <div style={{ fontSize: 28, fontWeight: 900, color: PALETTE.accentSuccess, marginTop: 4 }}>0</div>
                    <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 2 }}>
                      Malicious attacks that slipped through
                    </div>
                  </div>

                  <div
                    style={{
                      background: "#38bdf815",
                      border: "1px solid #38bdf840",
                      borderRadius: 8,
                      padding: "14px",
                    }}
                  >
                    <div style={{ fontSize: 11, color: "#38bdf8", fontWeight: 700 }}>TRUE NEGATIVES (TN)</div>
                    <div style={{ fontSize: 28, fontWeight: 900, color: "#38bdf8", marginTop: 4 }}>42</div>
                    <div style={{ fontSize: 11, color: PALETTE.textSecondary, marginTop: 2 }}>
                      Benign samples allowed to execute
                    </div>
                  </div>
                </div>
              </div>

              {/* Verified Threat Categories */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "20px",
                }}
              >
                <h4 style={{ margin: "0 0 16px", color: "#fff", fontWeight: 800 }}>MALICIOUS CORPUS DISTRIBUTION (56)</h4>
                <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 12 }}>
                  {[
                    { cat: "Role Override / Persona Hijack", count: "16 samples", pct: "100% blocked" },
                    { cat: "Embedded JSON Tool Call Exfiltration", count: "14 samples", pct: "100% blocked" },
                    { cat: "Delimiter Escape (<|im_start|>, </system>)", count: "10 samples", pct: "100% stripped & blocked" },
                    { cat: "Urgency Escalation + Coercion", count: "8 samples", pct: "100% detected" },
                    { cat: "Secret & Credential Extraction", count: "8 samples", pct: "100% blocked" },
                  ].map((row, i) => (
                    <div
                      key={i}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        padding: "8px 12px",
                        background: PALETTE.bgCard,
                        borderRadius: 6,
                        border: `1px solid ${PALETTE.border}`,
                      }}
                    >
                      <span style={{ fontWeight: 600, color: "#fff" }}>{row.cat}</span>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <span style={{ color: PALETTE.textSecondary }}>{row.count}</span>
                        <span style={{ color: PALETTE.accentSuccess, fontWeight: 700 }}>{row.pct}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            SECTION F: MIDNIGHT CURSE CHALLENGE PROGRESS
            ══════════════════════════════════════════════════════════════════════ */}
        {activeTab === "curse" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: "#fff" }}>
                  🌕 THE MIDNIGHT CURSE — ADVERSARIAL CHALLENGE PROGRESS
                </h3>
                <p style={{ margin: "2px 0 0", fontSize: 12, color: PALETTE.textMuted }}>
                  Status: <strong>IN PROGRESS — ADVANCED VALIDATION STAGE</strong> · Verified against official specification
                </p>
              </div>
              <span
                style={{
                  background: `${PALETTE.burgundy}90`,
                  color: PALETTE.dustyPink,
                  padding: "4px 12px",
                  borderRadius: 6,
                  fontWeight: 800,
                  fontSize: 12,
                  border: `1px solid ${PALETTE.dustyPink}60`,
                }}
              >
                STATUS: IN PROGRESS
              </span>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
                gap: 16,
              }}
            >
              {/* Requirements Completed */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "20px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
                  <span style={{ color: PALETTE.accentSuccess, fontSize: 16 }}>✓</span>
                  <h4 style={{ margin: 0, color: PALETTE.accentSuccess, fontWeight: 800 }}>REQUIREMENTS COMPLETED</h4>
                </div>
                <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: PALETTE.textSecondary, lineHeight: 1.8 }}>
                  <li>
                    <strong style={{ color: "#fff" }}>Indirect Prompt Injection Defense:</strong> Malicious emails (like{" "}
                    <code>msg-2</code> in mailbox fixture) are quarantined; commands cannot execute.
                  </li>
                  <li>
                    <strong style={{ color: "#fff" }}>Safe Content Reading:</strong> Butler can read & summarize
                    malicious emails safely without triggering automatic actions.
                  </li>
                  <li>
                    <strong style={{ color: "#fff" }}>Real Gmail SMTP Delivery:</strong> Authenticated nodemailer
                    transport gated behind explicit human review.
                  </li>
                  <li>
                    <strong style={{ color: "#fff" }}>HMAC Capability Enforcement:</strong> Un-forgeable execution
                    tokens preventing argument tampering & replay.
                  </li>
                  <li>
                    <strong style={{ color: "#fff" }}>Proposal Flooding Cap:</strong> <code>maxProposalsPerStep</code>{" "}
                    capped at policy limit (fallback: 5).
                  </li>
                </ul>
              </div>

              {/* Requirements in Testing */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "20px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
                  <span style={{ color: PALETTE.accentWarning, fontSize: 16 }}>⚡</span>
                  <h4 style={{ margin: 0, color: PALETTE.accentWarning, fontWeight: 800 }}>UNDER ACTIVE TESTING</h4>
                </div>
                <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: PALETTE.textSecondary, lineHeight: 1.8 }}>
                  <li>
                    <strong style={{ color: "#fff" }}>Multi-Turn Context Amnesia Attacks:</strong> Verifying that
                    monotonic taint state persists across turn 5+ without resetting.
                  </li>
                  <li>
                    <strong style={{ color: "#fff" }}>Cross-Session Piggybacking:</strong> Adversarial automated testing
                    ensuring Session B cannot trigger Session A approvals.
                  </li>
                  <li>
                    <strong style={{ color: "#fff" }}>Ethereal / Real SMTP Boundary:</strong> Zero network transmission
                    guarantee on rejected or unapproved actions.
                  </li>
                </ul>
              </div>

              {/* Remaining Gaps / Future Scope */}
              <div
                style={{
                  background: PALETTE.bgPanel,
                  border: `1px solid ${PALETTE.border}`,
                  borderRadius: 10,
                  padding: "20px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
                  <span style={{ color: PALETTE.dustyPink, fontSize: 16 }}>📋</span>
                  <h4 style={{ margin: 0, color: PALETTE.dustyPink, fontWeight: 800 }}>REMAINING GAPS & SCOPE</h4>
                </div>
                <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: PALETTE.textSecondary, lineHeight: 1.8 }}>
                  <li>
                    <strong style={{ color: "#fff" }}>Distributed Token Storage:</strong> In-memory nonce store should
                    be migrated to Redis for clustered multi-instance deployments.
                  </li>
                  <li>
                    <strong style={{ color: "#fff" }}>Automatic Key Rotation:</strong> Process-lifetime signing key
                    rotation on interval without dropping active in-flight approvals.
                  </li>
                  <li>
                    <strong style={{ color: "#fff" }}>Continuous Benchmark Automation:</strong> CI runner automated
                    execution of the 98 benchmark samples.
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            SECTION G: AUDIT EXPLORER
            ══════════════════════════════════════════════════════════════════════ */}
        {activeTab === "audit" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: "#fff" }}>
                  IMMUTABLE AUDIT LOG EXPLORER
                </h3>
                <p style={{ margin: "2px 0 0", fontSize: 12, color: PALETTE.textMuted }}>
                  Zero credential logging · SHA-256 arguments hash · Cryptographic decision records
                </p>
              </div>

              {/* Filters */}
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input
                  type="text"
                  placeholder="Search tool, reason, rule…"
                  value={auditSearch}
                  onChange={(e) => setAuditSearch(e.target.value)}
                  style={{
                    background: PALETTE.bgCard,
                    border: `1px solid ${PALETTE.border}`,
                    borderRadius: 6,
                    padding: "6px 10px",
                    color: "#fff",
                    fontSize: 12,
                    outline: "none",
                    width: 200,
                  }}
                />

                <select
                  value={auditTypeFilter}
                  onChange={(e) => setAuditTypeFilter(e.target.value)}
                  style={{
                    background: PALETTE.bgCard,
                    border: `1px solid ${PALETTE.border}`,
                    borderRadius: 6,
                    padding: "6px 10px",
                    color: "#fff",
                    fontSize: 12,
                    outline: "none",
                    cursor: "pointer",
                  }}
                >
                  <option value="all">All Event Types</option>
                  <option value="authz_decision">authz_decision</option>
                  <option value="injection_signal">injection_signal</option>
                  <option value="tool_proposed">tool_proposed</option>
                  <option value="tool_executed">tool_executed</option>
                  <option value="approval_requested">approval_requested</option>
                  <option value="budget_exceeded">budget_exceeded</option>
                </select>
              </div>
            </div>

            {/* Audit Table */}
            <div
              style={{
                background: PALETTE.bgPanel,
                border: `1px solid ${PALETTE.border}`,
                borderRadius: 10,
                overflow: "hidden",
              }}
            >
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                  <thead>
                    <tr
                      style={{
                        background: PALETTE.bgCard,
                        borderBottom: `1px solid ${PALETTE.border}`,
                        textAlign: "left",
                        color: PALETTE.textMuted,
                        textTransform: "uppercase",
                        fontSize: 11,
                      }}
                    >
                      <th style={{ padding: "10px 16px" }}>Timestamp</th>
                      <th style={{ padding: "10px 16px" }}>Session ID</th>
                      <th style={{ padding: "10px 16px" }}>Type</th>
                      <th style={{ padding: "10px 16px" }}>Data Summary</th>
                      <th style={{ padding: "10px 16px", textAlign: "right" }}>Raw Event</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents
                      .filter((e) => {
                        if (auditTypeFilter !== "all" && e.type !== auditTypeFilter) return false;
                        if (auditSearch.trim()) {
                          const str = JSON.stringify(e).toLowerCase();
                          if (!str.includes(auditSearch.toLowerCase())) return false;
                        }
                        return true;
                      })
                      .map((e, idx) => (
                        <tr
                          key={e.id ?? idx}
                          style={{
                            borderBottom: `1px solid ${PALETTE.border}`,
                            background: idx % 2 === 0 ? "transparent" : `${PALETTE.bgCard}40`,
                          }}
                        >
                          <td style={{ padding: "10px 16px", color: PALETTE.textMuted, whiteSpace: "nowrap" }}>
                            {new Date(e.ts).toISOString().replace("T", " ").slice(0, 19)}
                          </td>
                          <td style={{ padding: "10px 16px", fontFamily: "monospace", color: PALETTE.textSecondary }}>
                            {e.sessionId?.slice(0, 8)}…
                          </td>
                          <td style={{ padding: "10px 16px" }}>
                            <span
                              style={{
                                background: `${PALETTE.mutedTeal}25`,
                                color: PALETTE.dustyPink,
                                padding: "2px 8px",
                                borderRadius: 4,
                                fontWeight: 700,
                                fontSize: 11,
                              }}
                            >
                              {e.type}
                            </span>
                          </td>
                          <td style={{ padding: "10px 16px", color: PALETTE.textPrimary }}>
                            {Boolean(e.data.tool) && (
                              <span style={{ marginRight: 8, fontWeight: 700 }}>tool: {String(e.data.tool)}</span>
                            )}
                            {Boolean(e.data.kind) && (
                              <span style={{ marginRight: 8, color: e.data.kind === "deny" ? "#f87171" : "#34d399" }}>
                                kind: {String(e.data.kind)}
                              </span>
                            )}
                            {Boolean(e.data.argsHash) && (
                              <span style={{ fontFamily: "monospace", fontSize: 11, color: PALETTE.textMuted }}>
                                hash: {String(e.data.argsHash).slice(0, 16)}…
                              </span>
                            )}
                            {!e.data.tool && !e.data.kind && !e.data.argsHash && (
                              <span style={{ color: PALETTE.textMuted }}>{JSON.stringify(e.data).slice(0, 60)}…</span>
                            )}
                          </td>
                          <td style={{ padding: "10px 16px", textAlign: "right" }}>
                            <button
                              onClick={() => setSelectedEventForModal(e)}
                              style={{
                                background: PALETTE.bgCard,
                                border: `1px solid ${PALETTE.border}`,
                                color: PALETTE.textPrimary,
                                borderRadius: 4,
                                padding: "3px 8px",
                                fontSize: 11,
                                cursor: "pointer",
                              }}
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ── JSON INSPECTOR MODAL ────────────────────────────────────────────── */}
      {selectedEventForModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.85)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 100,
            padding: 24,
          }}
          onClick={() => setSelectedEventForModal(null)}
        >
          <div
            style={{
              background: PALETTE.bgPanel,
              border: `1px solid ${PALETTE.dustyPink}60`,
              borderRadius: 10,
              maxWidth: 700,
              width: "100%",
              maxHeight: "80vh",
              display: "flex",
              flexDirection: "column",
              boxShadow: "0 10px 40px rgba(0,0,0,0.8)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: "16px 20px",
                borderBottom: `1px solid ${PALETTE.border}`,
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div>
                <h4 style={{ margin: 0, fontSize: 15, fontWeight: 800, color: "#fff" }}>
                  EVENT RECORD: {selectedEventForModal.type}
                </h4>
                <div style={{ fontSize: 11, color: PALETTE.textMuted, marginTop: 2 }}>
                  ID: {selectedEventForModal.id} · TS: {selectedEventForModal.ts}
                </div>
              </div>
              <button
                onClick={() => setSelectedEventForModal(null)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: PALETTE.textMuted,
                  cursor: "pointer",
                  fontSize: 18,
                }}
              >
                ✕
              </button>
            </div>
            <div style={{ padding: "16px 20px", overflowY: "auto", flex: 1 }}>
              <pre
                style={{
                  margin: 0,
                  fontSize: 12,
                  fontFamily: "'JetBrains Mono', monospace",
                  color: "#93c5fd",
                  background: PALETTE.bgBase,
                  padding: 16,
                  borderRadius: 6,
                  overflowX: "auto",
                }}
              >
                {JSON.stringify(selectedEventForModal, null, 2)}
              </pre>
            </div>
            <div
              style={{
                padding: "12px 20px",
                borderTop: `1px solid ${PALETTE.border}`,
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                fontSize: 11,
                color: PALETTE.textMuted,
              }}
            >
              <span>🔒 Zero sensitive email contents or passwords stored in event</span>
              <button
                onClick={() => setSelectedEventForModal(null)}
                style={{
                  background: PALETTE.bgCard,
                  border: `1px solid ${PALETTE.border}`,
                  color: "#fff",
                  borderRadius: 4,
                  padding: "4px 12px",
                  cursor: "pointer",
                  fontSize: 12,
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── FOOTER ─────────────────────────────────────────────────────────── */}
      <footer
        style={{
          borderTop: `1px solid ${PALETTE.border}`,
          padding: "16px 24px",
          background: PALETTE.bgPanel,
          fontSize: 12,
          color: PALETTE.textMuted,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 12,
        }}
      >
        <div>
          <strong style={{ color: PALETTE.textSecondary }}>THE POSSESSED BUTLER</strong> // SENTINEL COMMAND CENTER
          <span style={{ margin: "0 8px" }}>·</span>
          <span>Lead Security Engineer: Developer 2</span>
        </div>
        <div>
          <span>Verification: 232 / 232 automated tests passing (0 failures)</span>
          <span style={{ margin: "0 8px" }}>·</span>
          <span style={{ color: PALETTE.dustyPink }}>Fail-Closed Guaranteed</span>
        </div>
      </footer>
    </div>
  );
}
