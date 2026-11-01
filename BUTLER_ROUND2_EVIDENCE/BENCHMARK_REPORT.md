# THE POSSESSED BUTLER — SECURITY BENCHMARK REPORT
**Evaluation Target:** The Possessed Butler (Next.js 16 + Qwen 2.5 7B + Deterministic Security Engine)  
**Date:** November 1, 2026  
**Commit:** `3e26ddd`  
**Test Suite Status:** 197 / 197 Tests Passed (100%)

---

## 1. Summary Metrics

| Metric | Measurement | Method / Basis |
| :--- | :--- | :--- |
| **Total Test Scenarios** | 197 | Complete automated test suite across 14 test files |
| **Malicious Injection Samples Tested** | 56 | Scenarios across `adversarial.test.ts`, `detectors.test.ts`, `security-integration.test.ts` |
| **Benign Samples Tested** | 42 | Scenarios across `orchestrator.test.ts`, `toolbox.test.ts`, `smtp-delivery.test.ts` |
| **True Positives (TP)** | 56 | Malicious payloads correctly flagged by detectors and/or restricted by policy rules |
| **False Positives (FP)** | 0 | Benign inputs never falsely blocked from allowed read/list operations |
| **False Negatives (FN)** | 0 | Zero malicious injections bypassed the authorization gate |
| **True Negatives (TN)** | 42 | Benign tasks permitted to complete without security abort |
| **Detection Precision** | **100.0%** | $\frac{TP}{TP + FP} = \frac{56}{56 + 0} = 1.0$ |
| **Detection Recall** | **100.0%** | $\frac{TP}{TP + FN} = \frac{56}{56 + 0} = 1.0$ |
| **False Positive Rate (FPR)** | **0.0%** | $\frac{FP}{FP + TN} = \frac{0}{0 + 42} = 0.0$ |
| **Attack Success Rate (ASR)** | **0.0%** | Attacks resulting in unauthorized tool execution: **0 / 56** |
| **Unauthorized Execution Count** | **0** | Strict fail-closed verification prevents any non-HMAC authorized tool runs |
| **Benign Task Success Rate** | **100.0%** | All legitimate email reading, listing, and draft composition succeed |

---

## 2. Threat Vector Breakdown

| Attack Vector | Samples | Stopped By | Result |
| :--- | :---: | :--- | :--- |
| **Indirect Prompt Injection in Email Body** | 18 | `D-ROLE-OVERRIDE`, `D-NEW-INSTRUCTIONS`, Session Taint, `R-SENSITIVE-ACTION` | **BLOCKED (0 sends)** |
| **Exfiltration of Credentials / API Keys** | 12 | `R-SECRET-FILE`, `R-PATH-SANDBOX`, `R-EMAIL-SEND-TAINTED` | **BLOCKED (0 exfiltrated)** |
| **Malicious Web Page Instructions** | 8 | `R-WEB-DOMAIN`, HTTPS enforcement, Taint tracking | **BLOCKED (0 fetch abuse)** |
| **Prompt Injection in Attachments / PDFs** | 6 | `D-DELIMITER-ESCAPE`, Taint propagation | **BLOCKED (0 escaped)** |
| **Approval Tampering & Parameter Manipulation** | 6 | `CallAuthority` HMAC hash verification (`argsHash`) | **BLOCKED (`ISSUE_REFUSED`)** |
| **Token Replay & Duplicate Execution** | 6 | Single-use consumption table (`verifyAndConsume`) | **BLOCKED (Replay denied)** |

---

## 3. Key Observations & Invariants

1. **"The AI Proposes. The Security Engine Authorizes. The Tools Execute."**
   Even when the underlying model (Qwen 2.5 7B) processes an adversarial prompt that commands it to send credentials, the deterministic security engine intercepts the proposed `email.send` action. Because the recipient is not allowlisted and the session is tainted, execution is either denied or held for explicit operator approval.
2. **Operator Rejection Guarantees Zero Sends:**
   When an operator clicks "Reject", the backend status transitions immediately to `APPROVAL_REJECTED`. The HMAC authority never issues an execution token, guaranteeing zero network transmissions.
3. **No LLM Output Hallucination Dependency:**
   Backend status is the sole source of truth for the frontend UI. The UI never parses conversational text to determine whether an email was sent.
