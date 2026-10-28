# FirmwareX — Engineering Limitations & Research Boundaries

In accordance with PRD Sections 4.2, 11, and 14, this document outlines explicit known limitations, boundary conditions, and deferred features for FirmwareX.

---

## 1. Raw Firmware Detection vs. Standalone Extraction

### Implemented Capabilities (Phase 3):
FirmwareX features a dedicated **Raw Firmware Signature Detector** (`RawFirmwareDetector`) capable of discovering embedded filesystem markers and container headers across the first 10 MB of any uploaded payload:
* **SquashFS:** Little-endian (`hsqs`), big-endian (`sqsh`), and non-standard swapped variants (`qshs`, `shsq`).
* **CramFS:** Little-endian (`0x28cd3d45`) and big-endian (`0x453dcd28`).
* **JFFS2:** Little-endian (`0x8519`) and big-endian (`0x1985`) bitmasks.
* **UBIFS:** Node magic (`0x06101831`) and UBI physical eraseblock markers (`UBI#`).
* **U-Boot uImage:** Legacy OS kernel header (`IH_MAGIC` `0x27051956`).
* **Broadcom TRX:** Multi-partition header (`HDR0`).
* **D-Link SHRS / Netgear CHK:** Proprietary vendor header containers.
* **Device Tree Blobs (DTB):** Compiled Open Firmware hardware trees (`0xd00dfeed`).
* **Nested Archives:** Recursive decompression of supported archives (ZIP, TAR, GZ, BZ2, XZ) up to 3 nesting levels with cumulative quotas and provenance metadata.

### Explicit Operational Boundary:
* **Signature Detection is NOT Extraction:** FirmwareX strictly distinguishes detection from extraction. When an image contains raw flash filesystems (e.g., raw SquashFS or JFFS2), FirmwareX detects the format, offset, and endianness, and returns **HTTP 422 (`unsupported_format`)** with specific recommended extractor tools (`unsquashfs`, `cramfsck`, `jffs2dump`, `ubireader`).
* FirmwareX never labels signature detection as successful extraction.
* Raw proprietary extraction without container sandboxing is prohibited to maintain host containment.

---

## 2. Containment & Dynamic Execution Boundaries

### Implemented Controls:
* **Host Execution Prohibition:** Untrusted firmware ELF binaries are **never executed directly on the Windows 11 host operating system**.
* **Preflight Verification (`ContainmentPreflight`):** Dynamic emulation cannot start unless Docker daemon responsiveness, `--network none` network egress denial, `--read-only` rootfs, and dropped capabilities (`--cap-drop=ALL`) are verified.
* **Path Scoping:** Volume mounts are restricted strictly to disposable subdirectories under `data/sandboxes/`. Mounts of host root drives, user profiles, or `docker.sock` are blocked fail-closed.

### Explicit Deferral (Full-System Firmware Emulation):
* **User-Mode vs. Full-System Emulation:** FirmwareX provides a modular **QEMU User-Mode Adapter** (`QemuEmulationAdapter`) mapping MIPS, ARM, AArch64, and x86_64, tested via a verified mock execution harness.
* **Hardware & NVRAM Virtualization:** Full-system emulation (running an entire router OS with kernel, hardware peripherals, and NVRAM emulation via tools like Firmadyne or FirmAE) is **safely deferred**. Hardware peripheral stubbing cannot be guaranteed reliable across arbitrary IoT architectures within a rapid evaluation schedule.

---

## 3. Symbolic Analysis Engine & Platform Compatibility

### Platform Compatibility Note (Python 3.14 on Windows 11):
* The `angr` binary analysis framework relies on native C extensions (`pyvex`, `unicorn`, `z3-solver`, `claripy`). As of Python 3.14 on Windows, prebuilt wheels are not available on PyPI, and building from source requires complex MSVC toolchains that introduce host build fragility.
* **Implemented Clean Fallback:** FirmwareX implements `BoundedSymbolicAnalyzer` using `pyelftools` symbol inspection and relocation resolution.
* **Review Leads, Not Exploits:** All data-flow paths connecting input sources (e.g., `recv`, `read`, `getenv`) to dangerous sinks (e.g., `system`, `strcpy`, `popen`) are explicitly tagged as **`REVIEW_LEAD`**. FirmwareX never fabricates symbolic execution traces, SAT solver solutions, or crash findings.

---

## 4. PRD Feature Status & Deferral Summary

| Feature | PRD Reference | Implementation Status | Technical Rationale |
| :--- | :--- | :--- | :--- |
| **Raw Firmware Signature Detection** | PRD Section 6.1 | **Implemented & Tested** | Multi-offset scanning for SquashFS, CramFS, JFFS2, UBIFS, TRX, uImage, DTB. |
| **Nested Archive Ingestion** | PRD Section 6.1 | **Implemented & Tested** | Recursive extraction up to 3 layers with cumulative quotas and provenance. |
| **Containment Preflight & Isolation** | PRD Section 11 | **Implemented & Tested** | Enforces `--network none`, zero host execution, and scoped sandbox mounts. |
| **QEMU User-Mode Adapter** | PRD Section 6.2 | **Implemented & Tested** | Architecture mapping, preflight gating, and mock diagnostic harness. |
| **Full-System Emulation** | PRD Section 6.2 | **Safely Deferred** | Requires NVRAM virtualization and hardware peripheral mocking. |
| **Bounded Data-Flow / Taint Analysis** | PRD Section 6.3 | **Implemented & Tested** | Static source-to-sink reachability tagged as `REVIEW_LEAD`. |
| **Full `angr` Dynamic Symbolic Execution**| PRD Section 6.3 | **Blocked on Platform** | Missing Python 3.14 Windows binary wheels; clean fallback active. |
| **Protocol-Aware Fuzzing** | PRD Section 6.4 | **Deferred** | Requires running emulated network services with live socket bindings. |
| **SOC Command Center Dashboard** | PRD Section 7 | **Implemented & Tested** | Graphite theme, 7 workspaces, active target selector, slide-over drawer. |
| **JSON Security Report Export** | PRD Section 9 | **Implemented & Tested** | PRD Appendix A compliant with telemetry and redaction. |
