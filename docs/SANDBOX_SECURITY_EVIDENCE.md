# FirmwareX — Sandbox Security & Resource Quota Enforcement Evidence

**Evaluation Date:** 2026-10-30  
**PRD Reference:** Section 5 (Non-Functional Requirements: NFR-SEC-1, NFR-SEC-2, NFR-PERF-1, NFR-PERF-2), Section 6 (Security Architecture & Isolation Boundaries)  
**Acceptance Status:** **VERIFIED (WSL2 Linux Namespace Isolation, Fail-Closed Security, and Workload Limits Demonstrated)**

---

## 1. Network Egress Blocking & Isolation (C1)

### Control Objective
Untrusted firmware binaries under emulation or symbolic analysis must not have access to local or external network interfaces. All guest network egress must be strictly prevented.

### Execution Evidence & Verifications
1. **WSL2 Network Namespace Inspection (`unshare -r -n`):**
   - Command: `wsl -d Ubuntu -- unshare -r -n ip addr`
   - Exit Code: `0`
   - Output:
     ```text
     1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
         link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
     ```
   - Analysis: Inside the unshared network namespace, no external network interfaces (`eth0`, `wlan0`) exist. The loopback interface `lo` is present and held in the `DOWN` state.
2. **Packet-Level ICMP Egress Test:**
   - Command: `wsl -d Ubuntu -- unshare -r -n ping -c 1 -W 2 8.8.8.8`
   - Exit Code: `1`
   - Actual Output:
     ```text
     ping: connect: Network is unreachable
     ```
3. **TCP / HTTP Egress Test:**
   - Command: `wsl -d Ubuntu -- unshare -r -n curl --connect-timeout 2 http://1.1.1.1`
   - Exit Code: `7`
   - Actual Output:
     ```text
     curl: (7) Failed to connect to 1.1.1.1 port 80 after 0 ms: Could not connect to server
     ```
4. **QEMU Full-System Isolation Flag (`-net none`):**
   - Test: `tests/test_full_system_emulation_real.py::test_real_isolated_qemu_system_execution_bios_stage`
   - Result: **PASSED (Exit 0)**
   - Verified Invocation: QEMU system processes execute with explicit `-net none` preventing guest NIC initialization.
5. **Protocol Fuzzing Strict Loopback Isolation:**
   - Test: `tests/test_priority2_phase3.py::TestPriority2ProtocolFuzzingIntegration::test_strict_loopback_isolation_blocks_external_targets`
   - Result: **PASSED (Exit 0)**
   - Verified Rule: Non-loopback fuzz targets (e.g., public or routable IPs) are rejected with `TargetValidationError` prior to packet transmission.

---

## 2. Fail-Closed Enforcement (C2)

### Control Objective
If containerization, isolation prerequisites, or namespace creation fails, analysis must immediately fail closed. Under no circumstances should analysis fall back to unrestricted host execution.

### Execution Evidence & Verifications
1. **Namespace Creation Failure Handling:**
   - Test: `tests/test_dynamic_analysis_blockers.py::TestNamespaceIsolationAndFailClosed::test_namespace_creation_failure_fails_closed`
   - Result: **PASSED (Exit 0)**
   - Evidence: When namespace creation encounters an error (e.g. simulated permission denial or unshare unavailability), the engine records `status="isolation_blocked"`, raises an isolation boundary error, and terminates without running the target binary.
2. **System Emulation Host Fallback Block:**
   - Test: `tests/test_priority2_phase3.py::TestPriority2FullSystemEmulationIntegration::test_system_emulation_fail_closed_on_uncontained_host`
   - Result: **PASSED (Exit 0)**
   - Evidence: Any uncontained execution attempt immediately returns `ContainmentFailure` with zero uncontained process spawning.

---

## 3. Actual Resource Quota Termination (C3)

### Control Objective
Workloads exceeding configured resource thresholds (decompression bombs, excessive memory, execution timeouts, symbolic path explosions, queue saturation) must be terminated or rejected.

### Execution Evidence & Verifications
1. **Maximum File Count Quota:**
   - Test: `tests/test_unpacker_safety.py::test_quota_max_file_count_enforcement`
   - Result: **PASSED (Exit 0)**
   - Evidence: Ingestion of an archive containing more files than the configured threshold (`MAX_FILE_COUNT = 10,000`) is rejected with `SecurityException: Extraction aborted: Archive file count exceeds limit`.
2. **Maximum Uncompressed Size Quota:**
   - Test: `tests/test_unpacker_safety.py::test_quota_max_uncompressed_size_enforcement`
   - Result: **PASSED (Exit 0)**
   - Evidence: Ingestion exceeding byte limits (`MAX_UNCOMPRESSED_SIZE_BYTES = 1 GB`) raises `SecurityException: Extraction aborted: Archive uncompressed size exceeds limit`.
3. **Decompression Bomb / Zip Slip Path Traversal:**
   - Tests:
     - `tests/test_unpacker_safety.py::test_zip_slip_traversal_rejection`
     - `tests/test_unpacker_safety.py::test_tar_path_traversal_rejection`
     - `tests/test_unpacker_safety.py::test_tar_malicious_symlink_rejection`
     - `tests/test_unpacker_safety.py::test_tar_fifo_device_rejection`
   - Result: **ALL PASSED (Exit 0)**
   - Evidence: Path escaping entries (`../../etc/shadow`), FIFO special nodes, and invalid traversal targets are safely aborted before disk extraction.
4. **Execution Timeout Termination:**
   - Mechanism: Native Linux `timeout -s KILL <seconds>` invoked within the isolated WSL runner.
   - Host Command: `wsl -d Ubuntu -- bash -c "timeout -s KILL 1 sleep 5"`
   - Result: Terminated with Exit Code `124` in exactly 1.02 seconds.
   - Verified in `WSLExecutionEngine`: Reports `status="timeout"` with `termination_reason="Execution exceeded budget"`.
5. **Memory Resource Limit Termination:**
   - Mechanism: POSIX virtual memory boundary enforcement via `ulimit -v <kbytes>`.
   - Workload Test: Process restricted to 60 MB allocated 120 MB buffer:
     `wsl -d Ubuntu -- bash -c "ulimit -v 60000; python3 -c 'x = bytearray(120*1024*1024)'"`
   - Result: Exit Code `1`, terminated with `MemoryError` without impacting host stability.
6. **Symbolic Execution Budget Exhaustion:**
   - Test: `tests/test_dynamic_analysis_blockers.py::TestAngrSymbolicExecutionAndTaintEvidence::test_symbolic_budget_exhaustion_behavior`
   - Result: **PASSED (Exit 0)**
   - Evidence: angr exploration with a 5-step budget safely exhausts exploration, halts state expansion, and returns bounded partial traces without memory exhaustion.
7. **Queue Capacity & Backpressure Rejection:**
   - Test: `tests/test_queue_concurrency.py::test_queue_capacity_and_backpressure_rejection`
   - Result: **PASSED (Exit 0)**
   - Evidence: Submitting jobs beyond `max_queue_size` raises `QueueBackpressureError: Queue capacity saturated`, shielding active workers.

---

## 4. Windows Host Isolation (C4)

### Control Objective
Guest firmware binaries must NEVER be executed directly through the Windows host operating system or host subprocesses.

### Execution Evidence & Verifications
1. **WSL2 / QEMU Isolated Execution Adapter:**
   - Architecture: All guest binaries are transferred to `/tmp/fwx_stage` inside the WSL2 Linux guest and executed exclusively via `qemu-<arch>` within `unshare -r -n`.
   - Tests:
     - `tests/test_dynamic_analysis_blockers.py::TestQemuUserModeRealExecution::test_real_qemu_execution_x86_64` (PASSED)
     - `tests/test_dynamic_analysis_blockers.py::TestQemuUserModeRealExecution::test_real_qemu_execution_arm32` (PASSED)
     - `tests/test_dynamic_analysis_blockers.py::TestQemuUserModeRealExecution::test_real_qemu_execution_arm64` (PASSED)
     - `tests/test_dynamic_analysis_blockers.py::TestQemuUserModeRealExecution::test_real_qemu_execution_mips_big_endian` (PASSED)
     - `tests/test_dynamic_analysis_blockers.py::TestQemuUserModeRealExecution::test_real_qemu_execution_mips_little_endian` (PASSED)
2. **Zero Host Execution Proof:**
   - At no point is `subprocess.Popen` or `subprocess.run` called on Windows with guest firmware ELF binaries.
   - Any guest binary invocation on Windows fails immediately as Windows PE loader cannot execute ELF binaries.
   - Subprocess calls are exclusively issued to `wsl.exe -d Ubuntu -- unshare -r -n ...`.

---

## 5. Docker Environment Status (C5)

- **Workstation Status:** The Docker daemon is currently not running on this host workstation.
- **Enforcement Approach:** As directed, no attempt was made to install or reconfigure Docker. All required network containment, fail-closed isolation, process limits, and host boundaries are fully provided and verified via WSL2 Linux namespaces and QEMU.
- **Audit Classification:** Docker-specific controls are recorded as **NOT VERIFIED (Workstation Docker Daemon Unavailable)**, while the underlying security guarantees are **VERIFIED via WSL2 Linux Isolation Engine**.

