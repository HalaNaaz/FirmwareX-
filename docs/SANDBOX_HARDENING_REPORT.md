# FirmwareX — Sandbox Hardening & Resource Enforcement Report

**Assessment Date:** 2026-10-30  
**PRD Clauses Addressed:** SC-1.1, SC-1.2, SC-1.3, SC-2.1, SC-2.2, NFR-SEC-1, NFR-PERF-1, NFR-PERF-2  
**Implementation Status:** **FULLY HARDENED & OPERATIONAL**

---

## 1. Hardened Containment Architecture

FirmwareX executes untrusted firmware binaries exclusively within an isolated, multi-layered Linux containment boundary powered by WSL2, Linux network namespaces, and cgroup v2 controllers:

```
[ Windows Host OS (Analysis Controller) ]
                   │
                   ▼ (Zero direct Windows ELF execution)
[ WSL2 Linux Boundary (wsl -d Ubuntu) ]
   ├── Layer 1: Linux cgroup v2 Resource Controller
   │     ├── MemoryMax = {budget}M
   │     ├── MemorySwapMax = 0 (No swap paging bypass)
   │     ├── CPUQuota = {quota}%
   │     └── NoNewPrivileges = yes (Prevents setuid escalation)
   │
   ├── Layer 2: Network Namespace Isolation (`unshare -r -n`)
   │     ├── User Namespace (Rootless mapping)
   │     ├── Network Namespace (Zero external NICs, lo down)
   │     └── Packet/Socket Egress: 100% BLOCKED
   │
   └── Layer 3: Bounded Process Execution
         ├── timeout -s KILL <seconds> (Hard process boundary)
         └── qemu-<arch> -d cpu /opt/angr-env (Isolated emulator/symbolic engine)
```

---

## 2. Hardening Verifications & Execution Telemetry

### 2.1 Linux cgroup v2 Kernel Memory Limit Enforcement
- **Mechanism:** Transient systemd service scope with `MemoryMax` and `MemorySwapMax=0`.
- **Workload Test:** 80 MB allocation requested within a 32 MB cgroup budget:
  ```bash
  wsl -d Ubuntu -- systemd-run --user --pipe --wait -p MemoryMax=32M -p MemorySwapMax=0 unshare -r -n python3 -c "x = bytearray(80*1024*1024)"
  ```
- **Observed Result:** Process killed by Linux kernel OOM killer.
- **Exit Status:** `Exit 1`
- **Captured Telemetry:**
  ```text
  Running as unit: run-p454-i1383.service; invocation ID: a38ca4f5edcc4c62827cd8eb5c549ac3
            Finished with result: oom-kill
  Main processes terminated with: code=killed, status=9/KILL
                 Service runtime: 100ms
               CPU time consumed: 71ms
                     Memory peak: 32M (swap: 0B)
  ```
- **Cleanup Verification:** systemd automatically purges transient unit and cgroup directory upon termination. Parent application remains completely unaffected.

### 2.2 Linux cgroup v2 CPU Quota Enforcement
- **Mechanism:** `CPUQuota=25%` throttles CPU allocation across the entire process tree.
- **Workload Test:** Tight CPU burn loop executed under cgroup quota:
  ```bash
  wsl -d Ubuntu -- systemd-run --user --pipe --wait -p CPUQuota=25% python3 -c "import time; t=time.time()+0.2; [None for _ in iter(lambda: time.time() > t, True)]"
  ```
- **Observed Result:** Workload completed within allotted quota. Telemetry confirms active CPU accounting (`CPU time consumed: 51ms`).
- **Status:** **PASS**

### 2.3 Network Egress Blocking (`unshare -r -n`)
- **Interface Enumeration:**
  ```text
  1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
  ```
- **External ICMP:** `ping -c 1 -W 2 8.8.8.8` -> `ping: connect: Network is unreachable` (Exit 1).
- **External TCP:** `curl --connect-timeout 2 http://1.1.1.1` -> `curl: (7) Failed to connect...` (Exit 7).
- **QEMU Full System:** Executed with `-net none` parameter.
- **Status:** **PASS**

### 2.4 Hard Execution Timeout & Zero Orphaned Processes
- **Mechanism:** Linux `timeout -s KILL <seconds>` coupled with systemd process slice cleanup.
- **Workload Test:** Forking bomb spawning background child processes and sleeping for 10 seconds:
  ```bash
  wsl -d Ubuntu -- systemd-run --user --pipe --wait unshare -r -n timeout -s KILL 1 python3 -c "import os, time; [os.fork() for _ in range(2)]; time.sleep(10)"
  ```
- **Observed Result:** Entire process tree terminated in exactly 1.04s with Exit Code `124`.
- **Orphan Check:** `pgrep -f sleep` confirmed **0 orphaned processes** remaining in WSL.
- **Status:** **PASS**

### 2.5 Fail-Closed Containment
- **Mechanism:** Any namespace creation failure or permission denial raises `SecurityBoundaryViolation` and immediately records `status="isolation_blocked"`.
- **Verification:** `tests/test_dynamic_analysis_blockers.py::TestNamespaceIsolationAndFailClosed::test_namespace_creation_failure_fails_closed` passed with zero fallback to host execution.
- **Status:** **PASS**

### 2.6 Windows Host Isolation
- **Mechanism:** Untrusted firmware ELF binaries are NEVER executed directly through Windows subprocesses.
- **Verification:** Windows PE loader rejects ELF binaries (`WinError 193: %1 is not a valid Win32 application`). All executions are channeled through `WSLExecutionEngine` to isolated QEMU user binaries.
- **Status:** **PASS**

---

## 3. Test Coverage Summary

All sandbox security controls are verified by automated tests in [`tests/test_sandbox_security_hardening.py`](file:///c:/Users/Hala/Downloads/Project%20Files/FirmwareX/tests/test_sandbox_security_hardening.py):
- `test_network_namespace_isolation_egress_blocked`: **PASSED**
- `test_cgroup_v2_memory_quota_oom_termination`: **PASSED**
- `test_cgroup_v2_cpu_quota_and_resource_accounting`: **PASSED**
- `test_hard_timeout_and_process_tree_termination_no_orphans`: **PASSED**
- `test_windows_host_isolation_fails_closed`: **PASSED**
- `test_least_privilege_no_new_privileges`: **PASSED**

