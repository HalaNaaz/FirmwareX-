# FirmwareX — Engineering Limitations & Research Boundaries

In accordance with PRD Sections 4.2, 11, and 14, this document outlines explicit known limitations, boundary conditions, and deferred features.

---

## 1. Unsupported Firmware Formats in Phase 1

### Current Capabilities:
FirmwareX currently extracts and inspects standard archive containers:
* `.zip`
* `.tar`, `.tar.gz`, `.tgz`
* `.tar.bz2`, `.tbz2`
* `.tar.xz`, `.txz`

### Explicit Limitation (Raw Proprietary Flash Images):
* **SquashFS (`hsqs`, `sqsh`), CramFS, UBIFS, JFFS2, and TRX/uImage containers:**
  * Raw proprietary binary images cannot be parsed in the Windows 11 host environment without Binwalk and Linux kernel decompression tools (`sasquatch`, `jefferson`, `ubi_reader`).
  * When such an image is submitted, the API returns HTTP 422 with an explicit status (`unsupported_format`) detailing the exact missing decompressor rather than attempting unsafe carving or reporting false completion.

---

## 2. ELF Parser Boundaries

* **Stripped & Statically Linked Binaries:**
  * If a binary is stripped and statically linked (lacking `.symtab` and `.dynsym`), stack canary status cannot be reliably verified through symbol inspection and is reported as `unknown`.
* **Static Sink Detection is Not Exploit Proof:**
  * Discovering imported symbols such as `strcpy` or `system` indicates hazardous API usage (review leads), but does not prove reachability or exploitable memory corruption without verified call-site disassembly or dynamic symbolic execution.
* **Complex Non-Standard ELF Architectures:**
  * Architectures outside standard MIPS, ARM, and x86 (e.g. Xtensa, SuperH, ARC) fall back to generic ELF header inspection.

---

## 3. Secret Scanner False-Positive Boundaries

* **Shannon Entropy Limitations:**
  * High-entropy strings ($H > 4.6$) can flag compressed binary headers, base64-encoded static images, or UUIDs. All entropy matches are strictly marked as `confidence: heuristic`.
* **Pre-compiled Binary Strings:**
  * Scanning binary executables for plaintext strings without control-flow context may flag internal debug messages or non-secret format strings.

---

## 4. Honestly Deferred Advanced Features (PRD Phase 2)

| Feature | PRD Reference | Deferral Rationale |
| :--- | :--- | :--- |
| **QEMU Cross-Architecture Emulation** | PRD Section 6.2 | Requires peripheral hardware mocking, NVRAM virtualization, and architecture-specific Linux kernels. Cannot be deployed safely and reliably on a Windows host within a two-day build without container isolation verified. |
| **angr Symbolic Execution & Taint** | PRD Section 6.3 | Python 3.14 lacks prebuilt binary wheels for angr/unicorn on Windows. In unbounded execution, symbolic exploration suffers from catastrophic path explosion. |
| **Protocol-Aware Fuzzing** | PRD Section 6.4 | Fuzzing requires live emulated network sockets (HTTP/UPnP/MQTT). Marked as "(Should)" in PRD. |
| **Interactive CFG Visualisation** | PRD Section 6.6 | Complex graph rendering in the web browser requires heavy client-side graph engines (e.g., Cytoscape/D3) which would introduce unnecessary failure modes during an MVP build. |
| **Distributed Celery / Redis Queue** | PRD Section 5.1 | The native FastAPI + SQLite job queue fulfills throughput targets (< 30 min per image) with zero external daemon dependencies. |
