# FirmwareX — Priority 1, Phase 2 Implementation Plan
## Safe Dynamic Analysis Engine & Execution Containment

**Date:** October 2026  
**Auditor / Engineer:** Senior Firmware Security Engineer, Dynamic Binary Analysis Engineer, Sandbox Security Engineer  
**Workspace:** `C:\Users\Hala\Downloads\Project Files\FirmwareX`  
**Specification:** Original `Project Unit42-FirmwareX` PRD v1.0 (SC-1.1–1.3, SC-2.1–2.2, FR-2.1, FR-3.1–3.4, SC-3.1–3.2, Appendix A)  

---

## 1. Executive Summary & Audit Baseline

Phase 1 successfully resolved core static firmware extraction (FR-1.1 through FR-1.4), adding CPIO initramfs extraction, 64KB chunked streaming file inventory, deep cross-architecture ELF discovery, and the static hardening mitigation matrix. All 110 tests (108 passed, 2 skipped docker integration) and Ruff checks pass cleanly.

Priority 1 — Phase 2 focuses on **Safe Dynamic Analysis Engine & Execution Containment**:
1. **Sandbox & Containment (SC-1.1–1.3, SC-2.1–2.2):** Dedicated isolated execution environment for untrusted binaries, fail-closed preflight, egress denial (`--network none`), read-only rootfs (`--read-only`), CPU/memory/timeout limits, controlled temporary directories, and reliable cleanup.
2. **QEMU User-Mode Emulation (FR-2.1):** Cross-architecture mapping (MIPS, ARM32, ARM64, x86_64), input validation, timeout/budget enforcement, structured exit/crash/timeout status capture, and clear tool-availability reporting.
3. **angr Symbolic Execution & Bounded Exploration (FR-3.1, FR-3.4):** Transparent handling of Python 3.14 Windows environment limitations, bounded symbolic path budgets (instruction, depth, time, memory), and honest reporting of incomplete analysis.
4. **Taint-to-Sink Analysis (FR-3.2):** Explicit input-source models (`argv`, `getenv`, `recv`, `read`) and dangerous sinks (`strcpy`, `memcpy`, `sprintf`, `system`, `popen`), with established tainted paths and distinction between confirmed, probable, and heuristic findings.
5. **Non-Weaponized Crash-State Reporting (FR-3.3):** Structured diagnostic telemetry for observed crash states (`fault_address`, registers, `overflow_offset`, `stack_hash`, candidate CWE) without weaponized exploits or shellcode.
6. **Secret & Cryptographic Scanning (SC-3.1, SC-3.2):** Pattern and entropy-based credential detection, weak crypto discovery, salted SHA-256 fingerprinting, and non-reversible redaction.
7. **Finding Normalization & API Compatibility:** Appendix A compliant schema population across all dynamic, symbolic, and crash findings, preserving full backward compatibility with the existing SQLite storage, FastAPI endpoints, and SOC Command Center UI.

---

## 2. Requirement Gap Analysis & Implementation Mapping

| Requirement | PRD Reference | Existing Component | Identified Gaps / Current State | Planned Improvements |
| :--- | :--- | :--- | :--- | :--- |
| **1. Sandbox & Containment** | SC-1.1, SC-1.2, SC-1.3, SC-2.1, SC-2.2 | `firmwarex/isolation/sandbox_manager.py` | Fail-closed preflight and disposable sandbox exist; need explicit job states for timeout, quota exceeded, unsupported analysis, and verified cleanup telemetry. | Ensure `SandboxExecutionResult` records distinct status codes (`completed`, `timeout`, `quota_exceeded`, `isolation_blocked`, `failed`) and enforce anti-traversal path isolation. |
| **2. QEMU User-Mode Emulation** | FR-2.1 | `firmwarex/emulation/qemu_adapter.py` | Architecture mapping covers MIPS, ARM, AArch64, x86_64; mock scenario harness exists. Needs explicit input validation, binary presence verification, and integration into the main analysis pipeline. | Add input validation (file size, existence, ELF magic), explicit tool discovery, sanitized stderr/stdout capture, and non-crashing execution bounds. |
| **3. angr Symbolic Execution** | FR-3.1, FR-3.4 | `firmwarex/core/symbolic_analyzer.py` | angr wheels unavailable on Windows Python 3.14. Static symbol reachability exists but lacks formal source modeling and bounded state budget enforcement. | Document Python 3.14 blocker; enhance bounded reachability with explicit state budgets, input models, and clear "REVIEW_LEAD" classification without false negatives. |
| **4. Taint-to-Sink Analysis** | FR-3.2 | `firmwarex/core/symbolic_analyzer.py` | Detects symbol co-occurrence; does not establish discrete tainted paths `[source, ..., sink]` or model `argv`, `getenv`, `read`, `recv`. | Implement structured `TaintedPath` tracking, support for `argv`/`getenv`/`recv`/`read` sources, and `strcpy`/`memcpy`/`sprintf`/`system`/`popen` sinks. |
| **5. Crash-State Reporting** | FR-3.3 | `firmwarex/core/normaliser.py` | Crash state dictionary had nulls; lacks structured crash parser for QEMU SIGSEGV output (fault address, register dump parsing, stack hash). | Implement `CrashStateParser` in `firmwarex/emulation/` extracting faulting address, registers, signal, and generating non-weaponized diagnostic telemetry. |
| **6. Secret & Crypto Scanning** | SC-3.1, SC-3.2 | `firmwarex/core/secret_scanner.py`<br>`firmwarex/core/redactor.py` | Shannon entropy and regex scanning work; ensure salted SHA-256 fingerprint consistency, prevent raw secret leakage into exceptions or logs. | Audit regex and entropy thresholds, verify salted fingerprint stability, ensure zero raw secret leakage in any report or API payload. |
| **7. Finding Normalization** | PRD Appendix A | `firmwarex/core/normaliser.py` | Normalizer handled static mitigations and secrets; lacked dedicated methods for dynamic crash findings and symbolic review leads. | Add `from_symbolic_lead` and `from_dynamic_crash` with exact Appendix A schema alignment (`vulnerability_id`, `tainted_path`, `crash_state`). |

---

## 3. Implementation Steps

1. **Step 1 — Sandbox & Containment Hardening (SC-1.1–SC-2.2):**
   - Add explicit quota check and cleanup verification to `DisposableSandbox`.
   - Ensure fail-closed checks on unverified Docker runtimes report `isolation_blocked` without running on host.
2. **Step 2 — QEMU Emulation Pipeline & Architecture Validation (FR-2.1):**
   - Add input path verification, execution argument sanitization, and explicit toolchain availability diagnostics to `QemuEmulationAdapter`.
   - Support MIPS, MIPSEL, ARM, ARM64, and x86_64.
3. **Step 3 — Crash-State Diagnostic Parser (FR-3.3):**
   - Create `firmwarex/emulation/crash_parser.py` to parse QEMU user-mode crash dumps (e.g., `qemu: uncaught target signal 11`, register lines, fault address).
   - Generate deduplicated stack/backtrace hash and non-weaponized diagnostic data.
4. **Step 4 — Taint-to-Sink & Bounded Symbolic Exploration (FR-3.1, FR-3.2, FR-3.4):**
   - Expand `firmwarex/core/symbolic_analyzer.py` with modeled input sources (`argv`, `getenv`, `recv`, `read`) and dangerous sinks (`strcpy`, `memcpy`, `sprintf`, `system`, `popen`).
   - Populate `tainted_path` and establish confidence ratings (`confirmed`, `probable`, `heuristic`).
5. **Step 5 — Secret & Cryptographic Hardening (SC-3.1, SC-3.2):**
   - Verify salt stability, redactor edge cases (short strings, unicode, malformed keys), and zero raw leak in all logs/APIs.
6. **Step 6 — Finding Normalization & API Integration:**
   - Expand `firmwarex/core/normaliser.py` with `from_symbolic_lead` and `from_dynamic_crash`.
   - Update `firmwarex/api/routes.py` to seamlessly incorporate dynamic findings into full reports.
7. **Step 7 — Unit & Regression Test Suite:**
   - Add comprehensive tests in `tests/test_priority1_phase2.py`.
   - Run full regression suite (110+ tests) and Ruff checks.
8. **Step 8 — Priority 1 Phase 2 Report:**
   - Author `docs/PRIORITY_1_PHASE_2_REPORT.md` documenting verified items, test metrics, and environment blockers.

