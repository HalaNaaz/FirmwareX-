# FirmwareX — Engineering Limitations & Research Boundaries

In accordance with PRD Sections 4.2, 6, 11, and 14, this document outlines explicit known limitations, boundary conditions, and implemented capabilities for FirmwareX.

---

## 1. Modular Firmware Filesystem Extraction (Phase 5 Status)

### Implemented & Tested Extractors:
FirmwareX provides a modular extractor registry (`ExtractorRegistry`) with native and container-isolated extractors:
* **Standard Archives:** ZIP, TAR, GZIP, BZIP2, XZ with Zip Slip traversal protection, symlink validation, special device node blocks, and cumulative quotas.
* **CramFS (Pure Python):** Complete native decompressor (`CramfsExtractor`) supporting little-endian (`0x28cd3d45`) and big-endian (`0x453dcd28`) variants, recursive directory trees, zlib decompression, and path containment.
* **Broadcom TRX:** Native partition splitter (`TrxExtractor`) parsing `HDR0` headers, validating CRC32, slicing kernel/rootfs partitions, and recursing into embedded filesystem layers.
* **U-Boot uImage:** Native legacy OS image parser (`UImageExtractor`) validating 64-byte `IH_MAGIC` (`0x27051956`), header/data CRCs, and automatically decompressing gzip and bzip2 payloads.
* **JFFS2 Flash Filesystem (Pure Python):** Complete native decompressor (`Jffs2Extractor`) parsing little-endian (`0x1985`) and big-endian (`0x8519`) node headers, traversing `DIRENT` structures, reassembling multi-chunk `INODE` contents (uncompressed and zlib compressed), and strictly enforcing directory traversal and quota boundaries.
* **Offset-Based Extraction:** Scans payload offsets up to 10 MB to discover and unpack embedded filesystems located behind proprietary bootloader padding.

### Explicit Operational Boundaries (SquashFS, UBIFS):
* **SquashFS:** FirmwareX parses SquashFS 4.0/3.0 superblocks (verifying block size, inode counts, and compression algorithms). Full extraction requires external binaries (`unsquashfs` or `sasquatch`). When external utilities are absent from the host or container, FirmwareX honestly returns **`UNSUPPORTED`** with detailed superblock diagnostics and recommended tools. It **never falsely claims extraction** based merely on signature detection.
* **UBIFS:** Eraseblock delimiters (`UBI#`) and node headers (`0x06101831`) are validated. Full node reconstruction requires `ubireader`. In its absence, FirmwareX returns structured diagnostic failure states.

---

## 2. Containment & Dynamic Execution Boundaries

### Implemented Controls:
* **Zero Host Execution:** Untrusted firmware ELF binaries are **never executed directly on the Windows 11 host operating system**.
* **Live Disposable Container Execution (`DisposableSandbox`):** Hardened Docker execution enforcing:
  - `--network none` (strict network egress denial, proven live via `Network unreachable` probes to external IPs).
  - `--read-only` root filesystem (proven live via touch permission errors).
  - `--cap-drop=ALL` (drops all Linux capabilities).
  - `--security-opt=no-new-privileges:true` (blocks privilege escalation).
  - `--user=1000:1000` (non-root unprivileged execution).
  - Bounded memory (`256m`), CPU (`1.0`), PIDs (`64`), tmpfs scratch, and wall-clock timeouts.
* **Path Scoping:** Volume mounts are restricted strictly to disposable subdirectories under `data/sandboxes/`. Mounts of host root drives, user profiles, or `docker.sock` are blocked fail-closed.
* **Live Containment Telemetry:** Verified by `ContainmentPreflight.verify_live_containment()`, running an innocuous internal probe to confirm network isolation, non-root execution, and read-only rootfs live.

### Explicit Deferral (Full-System Firmware Emulation):
* **User-Mode vs. Full-System Emulation:** FirmwareX provides a modular **QEMU User-Mode Adapter** (`QemuEmulationAdapter`) mapping MIPS, ARM, AArch64, and x86_64. If a guest QEMU binary is absent, it returns **`tool_unavailable`** with exact missing binary names rather than fabricating a fake execution trace.
* **Hardware & NVRAM Virtualization:** Full-system emulation (running an entire router OS with kernel, hardware peripherals, and NVRAM emulation via tools like Firmadyne or FirmAE) is **safely deferred**. Hardware peripheral stubbing cannot be guaranteed reliable across arbitrary IoT architectures within a rapid evaluation schedule.

---

## 3. Static Taint Analysis Engine & Platform Compatibility

### Platform Compatibility Note (Python 3.14 on Windows 11):
* The `angr` binary analysis framework relies on native C extensions (`pyvex`, `unicorn`, `z3-solver`, `claripy`). As of Python 3.14 on Windows, prebuilt wheels are not available on PyPI, and building from source requires complex MSVC toolchains that introduce host build fragility.
* **Implemented Clean Fallback:** FirmwareX implements `BoundedSymbolicAnalyzer` using `pyelftools` symbol inspection and relocation resolution.
* **Review Leads, Not Exploits:** All data-flow paths connecting input sources (e.g., `recv`, `read`, `getenv`) to dangerous sinks (e.g., `system`, `strcpy`, `popen`) are explicitly tagged as **`REVIEW_LEAD`** with `confidence: "candidate"`, analysis method `"static_symbol_reachability"`, and explicit limitations documentation. FirmwareX never fabricates symbolic execution traces, SAT solver solutions, or crash findings.

---

## 4. Defensive Protocol Fuzzing Foundation (Phase 5)

### Implemented Capabilities:
* **Loopback Safety Enforcement:** Fuzzing targets must strictly resolve to `127.0.0.1` or `localhost`. Any request targeting external networks or non-local IP addresses is rejected fail-closed with `PermissionError`.
* **Multi-Protocol Support:** Modular support for HTTP, UPnP (SSDP M-SEARCH), and MQTT (3.1.1 CONNECT and PUBLISH packets).
* **Deterministic Mutations:** Seeded pseudo-random mutations covering oversized headers, format string specifiers (`%s%n`), integer boundary numbers (`2147483647`, `-1`), path traversals, null-bytes, and malformed delimiters.
* **Synthetic In-Process Test Harness (`SyntheticLocalTestServer`):** In-process loopback server for testing fuzzer detection of 500 errors, connection drops, and anomaly classification end-to-end.
* **Connection Error & Timeout Resilience:** Fully verified handling of closed/unresponsive ports without unhandled exceptions.

---

## 5. PRD Feature Status & Compliance Matrix

| Feature | PRD Reference | Implementation Status | Technical Rationale & Evidence |
| :--- | :--- | :--- | :--- |
| **Raw Firmware Signature Detection** | PRD Section 6.1 | **Implemented & Tested** | Multi-offset scanning for SquashFS, CramFS, JFFS2, UBIFS, TRX, uImage, DTB. |
| **Modular Filesystem Extractors** | PRD Section 6.1 | **Implemented & Tested** | Pure-Python CramFS, TRX, uImage, and JFFS2 extractors; tested with synthetic images. |
| **Nested Archive Ingestion** | PRD Section 6.1 | **Implemented & Tested** | Recursive extraction up to 3 layers with cumulative quotas and provenance. |
| **Containment Preflight & Isolation** | PRD Section 11 | **Implemented & Tested** | Live Docker verification enforcing `--network none`, `--read-only`, zero host execution. |
| **Disposable Container Execution** | PRD Section 11 | **Implemented & Tested** | `DisposableSandbox.execute_isolated_command` with argument lists and timeout bounds. |
| **QEMU User-Mode Adapter** | PRD Section 6.2 | **Implemented & Tested** | Architecture mapping, preflight gating, and honest `tool_unavailable` states. |
| **Full-System Emulation** | PRD Section 6.2 | **Safely Deferred** | Requires NVRAM virtualization and hardware peripheral mocking. |
| **Bounded Data-Flow / Taint Analysis** | PRD Section 6.3 | **Implemented & Tested** | Static source-to-sink reachability tagged as `REVIEW_LEAD` with candidate confidence. |
| **Full `angr` Dynamic Symbolic Execution**| PRD Section 6.3 | **Blocked on Platform** | Missing Python 3.14 Windows binary wheels; clean fallback active and documented. |
| **Protocol-Aware Defensive Fuzzing** | PRD Section 6.4 | **Implemented & Tested** | Bounded HTTP, UPnP, and MQTT fuzzing engine tested against synthetic loopback server. |
| **SOC Command Center Dashboard** | PRD Section 7 | **Implemented & Tested** | Premium dark glassmorphism dashboard verified across 1440×900, 1280×800, and 390×844. |
| **JSON Security Report Export** | PRD Section 9 | **Implemented & Tested** | PRD Appendix A compliant with telemetry and redaction. |
