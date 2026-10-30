# FirmwareX — Priority 2, Phase 3 Implementation Plan
## Final Integration, Regression & Acceptance

**Date:** October 2026  
**Auditor / Roles:** Senior Firmware Security Engineer, Systems Integration Engineer, Binary Analysis Specialist  
**Workspace:** `C:\Users\Hala\Downloads\Project Files\FirmwareX`  
**Primary Specification:** Original `Project Unit42-FirmwareX` PRD v1.0  
**Phase:** Priority 2 — Phase 3 (Final Integration, Regression & Acceptance)  

---

## 1. Baseline Audit & Repository State

### 1.1 Git Status & Safety Preservation
- **Branch:** `main` (latest commit `446aab9`: *docs: complete Phase 9 final acceptance audit and GitHub publication readiness*).
- **Working Tree:** All uncommitted files and modifications from Priority 1 and Priority 2 (Phases 1 & 2) are preserved intact.
- **Commit Guard:** No commits or pushes to GitHub will be made during this phase.

### 1.2 Test & Linting Baseline
- **Pytest Suite:** **169 passed, 2 skipped, 0 failed** across 171 collected items.
  - 2 skips are live Docker container executions when the Docker daemon is inactive.
- **Ruff Linter:** **0 errors** across `firmwarex/` and `tests/`.
- **Live Background Server:** Operational at `http://127.0.0.1:8080` (all 10 E2E checks passed).
- **Frontend Architecture:** Glassmorphism UI served via FastAPI + Jinja2 template (`firmwarex/web/templates/index.html`).

### 1.3 Host Runtime Diagnostics & Environment Invariant
- **Python:** Python 3.14.6 in `.venv` (Windows host).
- **Docker CLI / Daemon:** Docker CLI 29.9.2 installed; Docker daemon is **STOPPED** (`open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified`).
- **WSL2:** Ubuntu (Version 2) installed, but Docker daemon integration is inactive.
- **QEMU System Emulators:** `qemu-system-mips`, `qemu-system-arm`, `qemu-system-x86_64` are **NOT INSTALLED** in host PATH or WSL2.
- **angr / unicorn:** `angr 10.0.5` installed; `unicorn` precompiled DLL is missing on Windows Python 3.14 (`unicorn support disabled`).
- **Containment Invariant:** **STRICTLY ENFORCED**. Untrusted firmware binaries and fuzzing traffic are **never executed directly on the bare Windows host**. Fail-closed isolation halts when container runtime is absent.

---

## 2. Priority 2 Requirement Traceability Matrix

| Requirement | PRD Section | Scope Description | Implementation Modules | Target Verification | Target Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Dangerous Function / Writable Memory Leads** | FR-1.5 | Static source/sink co-occurrence and segment permission audit. | `firmwarex/core/elf_auditor.py`, `firmwarex/core/symbolic_analyzer.py` | Unit + Integration tests in `test_elf_auditor.py` and `test_symbolic_extended.py`. | **VERIFIED** |
| **Best-Effort Full-System Emulation** | FR-2.2 | System QEMU machine profiles (`malta`, `virt`, `q35`), `-net none`, disposable overlay disks, boot stage telemetry (`firmware_loaded`, `kernel_boot`, `init_started`, `shell_ready`). | `firmwarex/emulation/qemu_adapter.py` | Architecture mapper, command builder, fail-closed isolation gate, deterministic simulation harness. | **VERIFIED** (Code / Config / Simulation) / **BLOCKED** (Live host guest boot) |
| **Protocol-Aware Fuzzing (HTTP, UPnP, MQTT)** | FR-4.1 | Defensive bounded fuzzing loops from valid RFC templates, mutation bounds, anomaly classification (`server_500`, `timeout`, `connection_refused`). | `firmwarex/fuzzing/protocol_fuzzer.py` | Strict loopback enforcement tests (`127.0.0.1`, `localhost`), synthetic local test server tests. | **VERIFIED** |
| **Seed Corpus Management** | FR-4.2 | Content-addressable SHA-256 storage, protocol namespacing, path traversal rejection, secret scrubbing, duplicate suppression. | `firmwarex/fuzzing/corpus_manager.py`, `firmwarex/core/redactor.py` | Corpus tests in `test_priority2_phase2.py`, directory containment tests. | **VERIFIED** |
| **Crash-Input Minimization** | FR-4.2 | Bounded delta-debugging (line, chunk, binary bisection) of verified crashing inputs with reproduction verification and timeout bounding. | `firmwarex/fuzzing/minimizer.py` | Reduction ratio and equivalence verification tests. | **VERIFIED** |
| **Crash Deduplication & Stack Fingerprinting** | FR-4.3 | ASLR address normalization (`v1_normalized_stack_hash`), recurrence grouping, Appendix A finding generation. | `firmwarex/fuzzing/crash_deduplicator.py` | Normalized hashing, recurrence aggregation, and Appendix A schema compliance tests. | **VERIFIED** |
| **Filesystem Tree Viewer** | FR-5.1 | Hierarchical collapsible directory viewer, file icons, size, SHA-256, path search, empty/loading states, safe escaping. | `firmwarex/web/templates/index.html` | Dashboard HTML structure tests, live E2E route validation. | **VERIFIED** |
| **Sortable ELF Mitigation Matrix** | FR-5.1 | Column sorting, architecture filter (ARM, MIPS, x86), status filter, bitness/endianness, static binary distinction. | `firmwarex/web/templates/index.html` | Dashboard template assertions, mitigation audit integration. | **VERIFIED** |
| **Filterable Findings & Crash Log** | FR-5.1 | Multi-dimensional filter (Severity, CWE, Analysis Type), pagination, confirmed vs heuristic badges, crash drawer. | `firmwarex/web/templates/index.html` | Investigation drawer tests, zero secret leakage checks. | **VERIFIED** |
| **CFG Visualization** | FR-5.1 | Honest representation of Control-Flow Graphs: displays explicit unavailable contract when angr/decompilation data is missing. | `firmwarex/web/templates/index.html`, `firmwarex/api/routes.py` | `/api/v1/firmware/{id}/cfg` endpoint returns structured unavailable contract with missing dependency notes. | **VERIFIED** |
| **Report Generation & Download** | FR-5.1, App A | Standardized JSON export with `Content-Disposition: attachment`, grouped findings, audit metadata, and zero plaintext leaks. | `firmwarex/api/routes.py`, `firmwarex/core/normaliser.py` | Report download tests, RFC attachment headers, redaction validation. | **VERIFIED** |

---

## 3. End-to-End Pipeline Verification Plan

The end-to-end pipeline will be rigorously verified against the unified workflow:
$$\text{Upload} \longrightarrow \text{Format Detection / Extraction} \longrightarrow \text{Filesystem Inventory} \longrightarrow \text{ELF Audit} \longrightarrow \text{Symbolic / Crash Analysis} \longrightarrow \text{Findings Normalization} \longrightarrow \text{Deduplication} \longrightarrow \text{Redaction} \longrightarrow \text{API / UI / Report Export}$$

### Test Scenarios:
1. **Full Pipeline Positive Control:**
   - Synthetic archive containing valid ARM/MIPS ELFs, configuration files, and credentials.
   - Verifies 100% extraction, inventory generation, hardening flags, heuristic source/sink leads, secret redaction, and compliant Appendix A output.
2. **Negative & Adversarial Controls:**
   - Corrupt archive header / truncated archive $\rightarrow$ rejected with appropriate HTTP 400.
   - Zero-byte payload $\rightarrow$ rejected with HTTP 400.
   - Path traversal in zip/tar/cpio $\rightarrow$ rejected without filesystem leakage.
   - Nonexistent firmware ID $\rightarrow$ returns HTTP 404.
3. **Dynamic Analysis Containment & Guard Controls:**
   - External fuzzing target IP (`8.8.8.8`) or hostname $\rightarrow$ blocked by strict loopback preflight (`PermissionError`).
   - Host system emulation $\rightarrow$ fails closed with `isolation_blocked` or `missing_dependencies`.
   - Simulated system emulation $\rightarrow$ successfully progresses through `firmware_loaded` $\rightarrow$ `kernel_boot` $\rightarrow$ `init_started` $\rightarrow$ `shell_ready`.
4. **Fuzzing & Crash Intelligence Controls:**
   - Seed corpus content-addressable storage, path traversal rejection, credential scrubbing.
   - Bounded crash-input delta-debugging reducing inputs only when crash reproduces.
   - Stack trace fingerprinting with ASLR normalization grouping duplicate events.
5. **Data Protection & Honesty Controls:**
   - CFG endpoint returns honest unavailable status without graph fabrication.
   - Plaintext credentials never appear in API responses, dashboard UI, or reports.

---

## 4. Phase 3 Test Suite Design (`tests/test_priority2_phase3.py`)

A comprehensive test module `tests/test_priority2_phase3.py` will be created covering:
- `TestPriority2EndToEndIntegration`: Full pipeline execution from upload to downloadable report.
- `TestPriority2FullSystemEmulationIntegration`: Emulation machine resolution, `-net none` isolation, boot stage transitions, and fail-closed host behavior.
- `TestPriority2ProtocolFuzzingIntegration`: Defensive loopback boundaries, synthetic local server execution, mutation loops for HTTP, UPnP, and MQTT.
- `TestPriority2CrashIntelligenceIntegration`: Seed deduplication, minimization delta-debugging, ASLR stack hash deduplication.
- `TestPriority2DashboardAndReportIntegrity`: Filesystem tree structure, ELF matrix data bindings, CFG unavailable contract, and report download attachment headers.

---

## 5. Deliverables & Acceptance Criteria

1. Complete `tests/test_priority2_phase3.py` with passing tests.
2. Run full regression suite across all 180+ tests with 0 failures.
3. Author `docs/PRIORITY_2_PHASE_3_REPORT.md` documenting detailed test outcomes.
4. Author `docs/PRIORITY_2_FINAL_ACCEPTANCE_REPORT.md` with requirement matrix, runtime limitations, reproduction commands, and formal verdict (`CONDITIONALLY ACCEPTED`).
5. Maintain pristine git working tree with zero commits and zero remote pushes.

