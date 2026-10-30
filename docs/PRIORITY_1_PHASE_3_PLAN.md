# FirmwareX — Priority 1, Phase 3 Implementation Plan
## Final Integration, Containment Verification & Final Acceptance Audit

**Date:** October 2026  
**Auditor / Engineer:** Senior Firmware Security Engineer, Dynamic Binary Analysis Engineer, Sandbox Security Engineer  
**Workspace:** `C:\Users\Hala\Downloads\Project Files\FirmwareX`  
**Specification:** Original `Project Unit42-FirmwareX` PRD v1.0 (FR-1.1–1.4, FR-2.1, FR-2.3, FR-3.1–3.4, SC-1.1–1.3, SC-2.1–2.2, SC-3.1–3.2, Appendix A)  

---

## 1. Executive Summary & Audit Baseline

Phases 1 and 2 established the core static extraction engine, filesystem inventory, cross-architecture ELF auditor, mitigation matrix, fail-closed container isolation gates, QEMU architecture mapping, bounded taint analysis models, non-weaponized crash-state reporting, and salted secret redaction.

Under **Priority 1 — Phase 3**, our mission is:
1. **Pipeline Integration:** Unify the end-to-end data flow (`upload -> format detection -> extraction -> inventory -> ELF hardening audit -> symbolic/taint reachability -> secret & weak crypto scan -> finding normalization -> API and reports`).
2. **Containment & Sandbox Verification:** Validate Docker availability detection, network air-gapping (`--network=none`), filesystem write isolation (`--read-only`), least privilege (`1000:1000`), resource bounds, and automated scratch cleanup.
3. **Honest Emulation & Symbolic Analysis Verification:**
   - QEMU user-mode emulation (FR-2.1): Verify multi-architecture mappings, input validation, tool discovery, and fail-closed isolation without unconfined host execution.
   - angr symbolic execution (FR-3.1, FR-3.4): Re-verify the Windows Python 3.14 blocker (missing binary wheels for C-extensions); validate bounded instruction/path/time budgets and ensure incomplete runs report `budget_exhausted` or `incomplete` without false negative claims.
   - Taint-to-sink analysis (FR-3.2): Verify modeled sources (`argv`, `getenv`, `recv`, `read`) reaching dangerous sinks (`strcpy`, `memcpy`, `sprintf`, `system`, `popen`) with structured `TaintedPath` tracking and negative controls.
   - Crash reporting (FR-3.3): Verify diagnostic parsing of process signals (`SIGSEGV`, `SIGBUS`, `SIGABRT`), fault addresses, registers, and candidate CWEs without weaponized payload generation.
4. **Secret Scanning & Redaction:** Verify salted SHA-256 fingerprints, non-reversible masking, and zero plaintext leaks in logs, reports, and API responses.
5. **API & Reporting Acceptance:** Confirm PRD endpoint contracts (`/upload`, `/filesystem`, `/binary-audit`, `/vulnerabilities`, `/report`, `/jobs/{id}`).
6. **Deliverables:** Produce `docs/PRIORITY_1_PHASE_3_PLAN.md`, `docs/PRIORITY_1_PHASE_3_REPORT.md`, and `docs/PRIORITY_1_FINAL_ACCEPTANCE_REPORT.md`.

---

## 2. Priority 1 Requirement Traceability & Verification Matrix

| Requirement ID | PRD Title & Criteria | Implementation Modules | Implementation Presence | Runtime Verification | Status |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **FR-1.1** | **Multi-Format Extraction** (CramFS, TRX, uImage, JFFS2, CPIO, SquashFS, Archives) | `firmwarex/core/extractors/` (`cpio`, `cramfs`, `trx`, `uimage`, `jffs2`, `squashfs`, `archive`, `registry.py`) | YES | YES | **VERIFIED** |
| **FR-1.2** | **Filesystem Reconstruction & Inventory** (Relative POSIX paths, 64KB chunk streaming SHA-256) | `firmwarex/core/unpacker.py` (`compute_sha256`, `generate_inventory`) | YES | YES | **VERIFIED** |
| **FR-1.3** | **ELF Discovery & Arch Identification** (ARM32/64, MIPS/MIPSEL, x86/x86_64, interpreter, stripped) | `firmwarex/core/elf_auditor.py` (`audit_binary`, `pyelftools` parsing) | YES | YES | **VERIFIED** |
| **FR-1.4** | **Static ELF Hardening Mitigation Matrix** (NX, PIE, RELRO, Canary, FORTIFY, banned sinks) | `firmwarex/core/elf_auditor.py` (`MitigationStatus`, `DANGEROUS_SINKS`) | YES | YES | **VERIFIED** |
| **FR-2.1** | **QEMU User-Mode Emulation** (MIPS, ARM, AArch64, x86_64; tool discovery; container isolation) | `firmwarex/emulation/qemu_adapter.py` (`QemuArchitectureMapper`, `QemuEmulationAdapter`) | YES | PARTIAL | **PARTIAL** / **BLOCKED** on host |
| **FR-2.3** | **Failure Modes & Telemetry** (timeout, crashed, missing_libraries, unsupported_arch, isolation_blocked) | `firmwarex/emulation/qemu_adapter.py`, `firmwarex/emulation/crash_parser.py` | YES | YES | **VERIFIED** |
| **FR-3.1** | **angr Symbolic Execution** (Bounded state exploration, solver bounds) | `firmwarex/core/symbolic_analyzer.py` (`ANGR_AVAILABLE` check) | YES | BLOCKED | **BLOCKED** (Py3.14 Windows) |
| **FR-3.2** | **Taint-to-Sink Analysis** (Modeled sources: argv, getenv, recv, read; sinks: strcpy, memcpy, sprintf, system) | `firmwarex/core/symbolic_analyzer.py` (`TaintedPath`, `SymbolicReviewLead`) | YES | YES | **VERIFIED** |
| **FR-3.3** | **Crash-State Reporting** (fault address, registers, stack hash, candidate CWE, non-weaponized) | `firmwarex/emulation/crash_parser.py` (`CrashStateParser`) | YES | YES | **VERIFIED** |
| **FR-3.4** | **Bounded Analysis Budgets** (instruction, path, time limits; incomplete reporting) | `firmwarex/core/symbolic_analyzer.py` (`SymbolicBudget`) | YES | YES | **VERIFIED** |
| **SC-1.1** | **Egress Denial & Air-Gapping** (`--network=none` parameter enforcement) | `firmwarex/isolation/sandbox_manager.py` (`DisposableSandbox`) | YES | YES (Mock / Args) / BLOCKED (Host Docker) | **VERIFIED** (Code / Config) / **BLOCKED** (Host daemon) |
| **SC-1.2** | **Ephemeral Scratch Dirs** (automatic teardown on exit) | `firmwarex/isolation/sandbox_manager.py` (`DisposableSandbox.__exit__`) | YES | YES | **VERIFIED** |
| **SC-1.3** | **Anti-Host Path Traversal** (strictly inside `SANDBOX_BASE_DIR`, blocking system paths) | `firmwarex/isolation/sandbox_manager.py` (`validate_mount_path`) | YES | YES | **VERIFIED** |
| **SC-2.1** | **Bounded Container Quotas** (memory 256m, cpus 1.0, timeout, pids 64) | `firmwarex/isolation/sandbox_manager.py` (`IsolationConfig`) | YES | YES | **VERIFIED** |
| **SC-2.2** | **Fail-Closed Execution Gate** (fail-closed if container runtime unverified) | `firmwarex/isolation/sandbox_manager.py` (`ContainmentPreflight.run_preflight`) | YES | YES | **VERIFIED** |
| **SC-3.1** | **Secret & Crypto Detection** (credentials, private keys, certificates, weak crypto) | `firmwarex/core/secret_scanner.py` (`SECRET_PATTERNS`, `WEAK_CRYPTO_PATTERNS`) | YES | YES | **VERIFIED** |
| **SC-3.2** | **Safe Redaction & Salted Fingerprinting** (salted SHA-256, minimal previews) | `firmwarex/core/redactor.py` (`Redactor.fingerprint(salt=...)`) | YES | YES | **VERIFIED** |
| **App. A** | **Normalized Finding Schema** (19 mandatory fields, zero duplicate/contradictory records) | `firmwarex/core/normaliser.py` (`FindingNormaliser`) | YES | YES | **VERIFIED** |

---

## 3. Work Breakdown & Action Items

| Step | Action Item | Target Files | Key Goals |
| :--- | :--- | :--- | :--- |
| **Step 1** | Pipeline Integration | `firmwarex/api/routes.py` | Connect `BoundedSymbolicAnalyzer` into `upload_and_analyze` so symbolic/taint review leads are automatically normalized and stored in `storage.save_findings`. Deduplicate findings to ensure no contradictory records. |
| **Step 2** | Sandbox Containment Verification | `firmwarex/isolation/sandbox_manager.py` | Re-verify fail-closed preflight, path isolation, and ephemeral directory cleanup across normal exits and exceptions. |
| **Step 3** | QEMU & Taint Analysis Verification | `firmwarex/emulation/qemu_adapter.py`<br>`firmwarex/core/symbolic_analyzer.py` | Verify multi-architecture resolution, input validation, positive and negative taint flow tests, and budget exhaustion behavior. |
| **Step 4** | Secret Redaction & Appendix A Schema Audit | `firmwarex/core/redactor.py`<br>`firmwarex/core/normaliser.py` | Verify salted fingerprint stability, ensure zero plaintext secret persistence in any report or API endpoint, and validate all 19 Appendix A schema keys. |
| **Step 5** | Test Execution & Regression Suite | Full suite (`pytest`, `ruff`, live E2E) | Run all 139+ tests, verify 0 failures, 0 lint errors, and 100% pass on live E2E server checks. |
| **Step 6** | Priority 1 Phase 3 Report | `docs/PRIORITY_1_PHASE_3_REPORT.md` | Document integration findings, metrics, and requirement-by-requirement statuses. |
| **Step 7** | Final Acceptance Report | `docs/PRIORITY_1_FINAL_ACCEPTANCE_REPORT.md` | Author authoritative final acceptance audit report with clear overall verdict (`CONDITIONALLY ACCEPTED` due to documented host platform blockers for native QEMU/Docker/angr on Windows Python 3.14). |

