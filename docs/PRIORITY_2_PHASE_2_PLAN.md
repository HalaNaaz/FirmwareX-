# FirmwareX — Priority 2, Phase 2 Implementation Plan
## Advanced Emulation, Protocol Fuzzing & Crash Intelligence

**Date:** October 2026  
**Auditor / Roles:** Senior Firmware Security Engineer, Dynamic Emulation Specialist, Fuzzing & Crash Intelligence Lead  
**Workspace:** `C:\Users\Hala\Downloads\Project Files\FirmwareX`  
**Primary Specification:** Original `Project Unit42-FirmwareX` PRD v1.0 (FR-2.2, FR-4.1, FR-4.2, FR-4.3, SC-1.1–1.3, SC-2.1–2.2, Appendix A)  

---

## 1. Baseline Audit & Pre-Implementation State

### 1.1 Git Status & Test Baseline
- **Git Branch:** `main` (commit baseline: `446aab9` / `543e239`).
- **Working Tree:** All uncommitted changes from Priority 1 and Priority 2 Phase 1 are preserved cleanly.
- **Pytest Suite:** 148 passed, 2 skipped, 0 failed across 150 items.
- **Linting:** 0 errors under `ruff check .`.
- **Extraction Benchmark:** 100.0% Pass Rate across CramFS, TRX, uImage, JFFS2, CPIO, and archives.
- **Live Server:** Operational on `http://127.0.0.1:8080`.

### 1.2 Environment Dependencies & Availability
- **Python:** Python 3.14.6 in `.venv` (Windows).
- **Docker CLI / Daemon:** Docker CLI 29.9.2 installed; Docker daemon is **STOPPED / UNAVAILABLE**. Dynamic execution fails closed per **SC-2.2**.
- **WSL2:** Installed (`Ubuntu`, Version 2), but Docker daemon integration is inactive.
- **QEMU System Emulators:** `qemu-system-mips`, `qemu-system-arm`, `qemu-system-x86_64` are **NOT INSTALLED** in host PATH or WSL2.
- **Containment Invariant:** **Strictly Enforced**. Untrusted firmware binaries and fuzzing traffic are **never** executed or routed unconfined on the bare Windows host or external networks.

---

## 2. PRD Requirement Traceability & Gap Analysis

| PRD Ref | Requirement Title & Specification | Existing Implementation | Identified Gaps | Planned Implementation in Phase 2 |
| :--- | :--- | :--- | :--- | :--- |
| **FR-2.2** | **Best-Effort Full-System Emulation**<br>System-mode QEMU emulation for MIPS, ARM, x86; hardware board configurations (`malta`, `virt`, `q35`); disposable disk overlays; default-deny networking (`-net none`); boot progress telemetry; resource caps; fail-closed isolation. | `firmwarex/emulation/qemu_adapter.py` (User-mode only). | No system-mode architecture mapping, no board/machine config builder, no kernel/initrd/rootfs parameter builder, no boot log parser or exit state machine. | Implement `QemuSystemEmulator` in `firmwarex/emulation/qemu_adapter.py` supporting `malta`, `virt`, `q35`, `-net none`, ephemeral overlays, boot stages (`firmware_loaded`, `kernel_boot`, `init_started`, `shell_ready`, `failed`), and fail-closed isolation telemetry. |
| **FR-4.1** | **Protocol-Aware Fuzzing (HTTP, UPnP, MQTT)**<br>Controlled fuzzing loops starting from valid baseline messages; structured protocol mutations; bounded iterations/timeout; strict loopback target validation (rejects external hosts); capture timeouts, connection reset, 500s, crashes. | `firmwarex/fuzzing/protocol_fuzzer.py` has mutators and basic runner. | Target host validation only checks loopback string; lacks integration with seed corpus; lacks crash-input minimization and stack fingerprinting; no job queue integration. | Enhance `ProtocolFuzzRunner` with strict IP parsing, connection anomaly classification (distinguishing normal HTTP 400 from server crashes), per-job timeout budgets, and seed corpus integration. |
| **FR-4.2** | **Seed Corpus Management**<br>Stable seed storage with content hashing; protocol association; size validation; deduplication; execution tracking; path traversal protection; salted secret scrubbing; job lifecycle cleanup. | Seeds are transiently generated in-memory. | No persistent or structured seed corpus manager; no content-hash deduplication; no seed execution metrics or provenance tracking. | Implement `CorpusManager` in `firmwarex/fuzzing/corpus_manager.py` with content-addressable storage (SHA-256), protocol namespaces, seed metadata, secret scrubbing, and deduplication. |
| **FR-4.2** | **Crash-Input Minimization**<br>Bounded minimization of fuzzing payloads that reproduce verified crashes; chunk reduction and bisection; preserves original input; verifies reproduction equivalence; timeout and iteration bounds. | None. | No payload minimizer exists. Fuzzing anomalies retain only raw mutation strings without delta-debugging or minimization. | Implement `CrashInputMinimizer` in `firmwarex/fuzzing/minimizer.py` supporting chunk removal and binary bisection with strict reproduction checks, size reduction metrics, and timeout limits. |
| **FR-4.3** | **Crash Deduplication & Stack Fingerprinting**<br>Group crash events using normalized stack/backtrace fingerprints; normalize unstable addresses (ASLR); retain individual event records; algorithm versioning (`v1_normalized_stack_hash`); Appendix A finding integration. | `CrashStateParser` computes simple hash from registers and signal. | Does not group or track recurring crashes across iterations; does not normalize ASLR offsets; lacks explicit confidence scoring for incomplete backtraces. | Implement `CrashDeduplicator` in `firmwarex/fuzzing/crash_deduplicator.py` with normalized frame parsing, ASLR offset stripping, recurrence counters (`first_seen`, `last_seen`, `count`), and Appendix A finding mapping. |

---

## 3. Work Breakdown & Action Items

### Step 1: Best-Effort Full-System Emulation (FR-2.2)
- In `firmwarex/emulation/qemu_adapter.py`:
  - Implement `QemuSystemArchitectureMapper`:
    - MIPS (BE) -> `qemu-system-mips`, machine `malta`, default kernel/disk config.
    - MIPSEL (LE) -> `qemu-system-mipsel`, machine `malta`.
    - ARM 32-bit -> `qemu-system-arm`, machine `virt`, CPU `cortex-a15`.
    - ARM64 (AArch64) -> `qemu-system-aarch64`, machine `virt`, CPU `cortex-a57`.
    - x86_64 -> `qemu-system-x86_64`, machine `q35`, CPU `max`.
  - Implement `SystemEmulationConfig`:
    - Memory cap (default 256MB/512MB), CPU quota (1.0 core), timeout (default 30s), `-net none` default-deny network parameter, `-nographic`, `-no-reboot`.
    - Disposable overlay disk support via qcow2/raw temporary scratch file.
  - Implement `QemuSystemEmulator`:
    - Validates firmware/kernel path existence and format.
    - Checks containment preflight (fails closed if container runtime is unavailable).
    - Checks host/container QEMU system binary availability.
    - Monitors boot progress: parses boot stages (`firmware_loaded`, `kernel_boot`, `init_started`, `shell_ready`, `failed`).
    - Handles timeouts and process cleanup.
    - Explicit failure states: `unsupported_architecture`, `tool_unavailable`, `isolation_blocked`, `missing_kernel`, `boot_failed`, `timeout`, `boot_successful`.

### Step 2: Seed Corpus Management (FR-4.2)
- In `firmwarex/fuzzing/corpus_manager.py`:
  - Implement `Seed`:
    - `seed_id`, `protocol`, `name`, `content` (bytes), `content_hash` (SHA-256), `size_bytes`, `created_at`, `execution_count`, `anomalies_triggered`.
  - Implement `CorpusManager`:
    - Directory confinement: stores seeds under `data/corpus/{protocol}/`, strictly rejecting path traversal (`..`).
    - Deduplication: checks SHA-256 content hash before storing new seeds.
    - Secret scrubbing: rejects or redacts seeds containing plaintext credentials.
    - Seed retrieval, listing, selection, and mutation tracking.
    - Built-in baseline seeds for HTTP (GET, POST JSON, POST multipart), UPnP (SSDP M-SEARCH, SOAP control), and MQTT (CONNECT, PUBLISH, SUBSCRIBE).

### Step 3: Protocol-Aware Fuzzing Enhancements (FR-4.1)
- In `firmwarex/fuzzing/protocol_fuzzer.py`:
  - Integrate `CorpusManager` to seed fuzzing iterations from valid baselines before applying controlled mutations.
  - Strict target address validation: resolves and confirms destination is strictly loopback (`127.0.0.1`, `localhost`, `::1`); rejects external IPs or hostnames with `PermissionError`.
  - Diagnostic response classification:
    - Normal HTTP client errors (400, 404) are NOT crashes.
    - Server crashes / faults: HTTP 500 (Internal Server Error), connection reset (`ECONNRESET`), connection refused after traffic (`ECONNREFUSED` indicating server died), unhandled signal termination.
  - Telemetry capture: records protocol, seed ID, mutation strategy, target, duration, and anomaly telemetry.

### Step 4: Bounded Crash-Input Minimization (FR-4.2)
- In `firmwarex/fuzzing/minimizer.py`:
  - Implement `CrashInputMinimizer`:
    - Takes a verified crashing payload and target verifier function.
    - Applies delta-debugging:
      - Line / chunk removal.
      - Binary bisection on payload blocks.
      - Single-byte removal.
    - Equivalence criteria: accepts a minimized candidate ONLY if the target produces the exact same anomaly or crash signal.
    - Bounded limits: max 50 iterations, max 5 seconds, min payload size.
    - Returns `MinimizationResult`: `original_size`, `minimized_size`, `reduction_ratio`, `iterations_run`, `reproduced`, `minimized_payload`.

### Step 5: Crash Deduplication & Stack Fingerprinting (FR-4.3)
- In `firmwarex/fuzzing/crash_deduplicator.py`:
  - Implement `CrashFingerprinter`:
    - Normalizes stack trace frames: strips ASLR variable base addresses (e.g., `0x7f...` -> `[OFFSET]`), extracts function symbols and module offsets.
    - Generates stable SHA-256 fingerprint: `hash(signal + candidate_cwe + normalized_frames)`.
    - Handles missing/incomplete backtraces: marks `confidence="candidate"` and `completeness="partial"` without inventing fake frames.
    - Algorithm version: `v1_normalized_stack_hash`.
  - Implement `CrashDeduplicator`:
    - Groups crashes into `CrashGroup` records: `fingerprint`, `cwe`, `signal`, `affected_binary`, `event_count`, `first_seen`, `last_seen`, `sample_crash_report`, `minimized_payload`.
    - Converts unique crash groups into normalized Appendix A findings via `FindingNormaliser.from_dynamic_crash()`.

### Step 6: API & Job Lifecycle Integration
- In `firmwarex/api/routes.py`:
  - `POST /api/v1/emulation/system/boot`: Trigger full-system emulation probe under verified isolation.
  - `GET /api/v1/fuzzing/corpus`: Query seed corpus items by protocol.
  - `POST /api/v1/fuzzing/corpus`: Add a verified seed to the corpus.
  - `POST /api/v1/fuzzing/run`: Run bounded fuzzing session with corpus seeds and deduplication.
  - `POST /api/v1/fuzzing/minimize`: Run bounded crash-input minimization on a reproducing payload.
  - `GET /api/v1/fuzzing/crashes`: Retrieve deduplicated crash groups with stack fingerprints.

### Step 7: Dashboard Integration
- Extend `index.html`:
  - In `view-analysis`: Add System Emulation Telemetry card displaying boot stages, emulator binary resolution, and containment gate status.
  - Add Fuzzing & Crash Intelligence panel displaying seed corpus counts, active protocol targets, and deduplicated crash fingerprints.

### Step 8: Testing & Verification Suite
- Create `tests/test_priority2_phase2.py`:
  - Full-system QEMU architecture and machine configuration validation.
  - Full-system emulation state transitions (`unsupported_architecture`, `tool_unavailable`, `isolation_blocked`, `completed`).
  - Seed corpus storage, content-hash deduplication, path traversal rejection, and secret scrubbing.
  - Protocol-aware HTTP, UPnP, and MQTT fuzzing loopback enforcement (external target rejection).
  - Crash-input minimization bounding and reproduction verification.
  - Crash stack trace normalization and deduplication grouping.
- Run complete regression suite (150+ tests).
- Run `ruff check .`.
- Run live server E2E validation.

### Step 9: Final Report Documentation
- Author `docs/PRIORITY_2_PHASE_2_REPORT.md` documenting all changes, verification results, and statuses.

---

## 4. Requirement Verification Status Goals

| PRD Ref | Requirement | Implementation Target | Verification Target | Status Goal |
| :--- | :--- | :--- | :--- | :---: |
| **FR-2.2** | Full-System Emulation | `qemu_adapter.py` (`QemuSystemEmulator`) | Pytest + Config / Containment checks | **VERIFIED** (Scaffolding / Logic)<br>**BLOCKED** (Host QEMU/Docker) |
| **FR-4.1** | Protocol-Aware Fuzzing | `protocol_fuzzer.py` (`ProtocolFuzzRunner`) | Pytest + Local target tests | **VERIFIED** |
| **FR-4.2** | Seed Corpus Management | `corpus_manager.py` (`CorpusManager`) | Pytest + Deduplication / Path tests | **VERIFIED** |
| **FR-4.2** | Crash-Input Minimization | `minimizer.py` (`CrashInputMinimizer`) | Pytest + Synthetic delta-debug tests | **VERIFIED** |
| **FR-4.3** | Crash Deduplication | `crash_deduplicator.py` (`CrashDeduplicator`) | Pytest + Stack fingerprint tests | **VERIFIED** |
| **App. A** | Finding Schema Integration | `normaliser.py`, `routes.py` | Pytest + API schema tests | **VERIFIED** |

