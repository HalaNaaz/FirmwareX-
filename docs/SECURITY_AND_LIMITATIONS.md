# FirmwareX — Security Architecture, Sandbox Containment & Research Limitations

> **Document Status:** Authoritative Security Specification  
> **PRD Compliance:** PRD Sections 4.2, 6, 11, and 14  
> **Notice:** FirmwareX is an independent firmware security research project designed to audit embedded firmware without endangering analyst systems.

---

## 1. Safe Handling of Untrusted Firmware & Zero Host Execution

IoT and embedded firmware images frequently contain untrusted, unknown, or hostile binaries, scripts, and embedded filesystems. To guarantee host integrity:

1. **Zero Host Execution Policy:** FirmwareX **never executes uploaded firmware binaries or extracted Linux ELF executables directly on the Windows 11 host operating system**.
2. **Deterministic Static Analysis:** All ELF hardening audits, secret scanning, format detection, and call-graph reachability analyses are performed statically in Python without invoking binary execution.
3. **Fail-Closed Emulation Gating:** Dynamic emulation via QEMU is strictly containerized. If the container runtime or network isolation preflight fails, dynamic analysis is blocked immediately (`status: "isolation_blocked"`).

---

## 2. Containerized Containment Design (`DisposableSandbox`)

When containerized execution is invoked (e.g. for dynamic testing or containerized tools), FirmwareX constructs an ephemeral Docker sandbox with the following verified security parameters:

```text
docker run --rm \
  --network=none \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --read-only \
  --user=1000:1000 \
  --memory=256m \
  --cpus=1.0 \
  --pids-limit=64 \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v "C:\...\data\sandboxes\<uuid>:/workspace:ro" \
  <isolated_image> <command>
```

### Verified Sandbox Controls:
* **Strict Network Egress Denial (`--network=none`):** Prevents external callback connections, command-and-control beaconing, or inadvertent scanning of local networks.
* **Immutable Root Filesystem (`--read-only`):** Prevents modification of container operating system files, persistence mechanisms, or unauthorized package installation.
* **Complete Capability Dropping (`--cap-drop=ALL`):** Strips all root capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_CHOWN`, etc.).
* **Privilege Escalation Prevention (`--security-opt=no-new-privileges:true`):** Blocks `setuid` / `setgid` binaries from escalating privileges.
* **Non-Root Execution (`--user=1000:1000`):** Enforces unprivileged execution within the guest environment.
* **Strict Mount Scoping:** Volume mounts are restricted strictly to disposable subdirectories inside `data/sandboxes/`. Mounts of root drives, user profiles, or `docker.sock` are rejected fail-closed.
* **Scratch Space Isolation:** Temporary memory is allocated strictly via an in-memory `tmpfs` mounted with `noexec` and `nosuid` flags.
* **Guaranteed Teardown:** Python context managers (`__enter__` and `__exit__`) ensure complete deletion of all scratch files upon process termination.

---

## 3. Ingestion & Archive Traversal Defenses

Firmware archives are untrusted input vectors vulnerable to path traversal attacks:

* **Zip-Slip & Canonical Path Verification:** Before writing any extracted file, its canonical destination path is resolved and validated:
  $$\text{resolved\_path} \in \text{sandbox\_dir}$$
  Attempts to unpack files with relative traversal (`../../`) or absolute paths (`/etc/passwd`) immediately trigger `SecurityException` and terminate extraction.
* **Symlink Escapes:** Symbolic and hard links are inspected to ensure they resolve within the sandbox boundaries. Dangling symlinks pointing to host directories are rejected.
* **Special Device Blocking:** Archives containing FIFO named pipes, character devices, or block special files are immediately rejected to prevent process hanging or host device file corruption.
* **Quota Management:** Cumulative file counts (5,000 files max) and uncompressed byte limits (250 MB max) are enforced to protect against decompression bombs.

---

## 4. Cryptographic Redaction & Privacy

FirmwareX incorporates automated data sanitization into its core pipeline:

* **Zero Plaintext Persistence:** When secret tokens, AWS credentials, JWTs, or private keys are identified, their values are masked before storage or display (e.g. `AKIA****************`).
* **Cryptographic Fingerprinting:** A one-way salted SHA-256 digest is generated for each secret (`sha256:...`) to enable deduplication and finding tracking without exposing the underlying credential.
* **Shadow Database Protection:** Unix password hashes in `/etc/shadow` are flagged for weak algorithms without persisting password hashes in finding exports.

---

## 5. Explicit Technical Limitations & Platform Boundaries

### 5.1 Python 3.14 on Windows 11 (`angr` Symbolic Execution)
* **Status:** `BLOCKED` (Clean static fallback active).
* **Technical Reason:** The `angr` binary analysis engine depends on C extensions (`pyvex`, `unicorn`, `z3-solver`, `claripy`). Precompiled wheels for Windows Python 3.14 are not available on PyPI, and building from source on Windows requires an extensive MSVC build harness that introduces platform fragility.
* **Implemented Mitigation:** FirmwareX provides `BoundedSymbolicAnalyzer`, a deterministic static symbol reachability engine that extracts imported input sources (`recv`, `read`, `getenv`) and dangerous sinks (`system`, `popen`, `strcpy`, `sprintf`). All findings are strictly classified as **`REVIEW_LEAD`** with `confidence: "candidate"`. FirmwareX **never fabricates execution traces or SAT solver proofs**.

### 5.2 External Tool Dependencies (SquashFS & UBIFS)
* **Status:** `PARTIAL` (Superblock metadata parsed; decompression tool-dependent).
* **Technical Reason:** SquashFS and UBIFS utilize specialized block-level compression and wear-leveling structures.
* **Implemented Mitigation:** Full superblock headers (inode counts, compression algorithms, block size, erase counters) are validated. If external binaries (`unsquashfs`, `ubireader`) are missing, FirmwareX returns an honest **`UNSUPPORTED`** status with diagnostic remediation advice. It **never falsely claims extraction** based merely on signature detection.

### 5.3 Full-System Firmware Emulation
* **Status:** `NOT IMPLEMENTED` (Safely Deferred).
* **Technical Reason:** Full-system emulation (booting an entire router Linux kernel with custom hardware peripherals, NVRAM virtualization, and device-tree emulation) requires tailored manual configuration per device model (e.g., FirmAE/Firmadyne).
* **Implemented Mitigation:** FirmwareX implements cross-architecture **QEMU User-Mode Emulation** for isolated ELF binaries. Full-system OS emulation is safely deferred as out of scope for automated rapid evaluation.

---

## 6. Responsible Research & Ethics Statement

FirmwareX is developed strictly as a defensive security research platform to assist IoT manufacturers, security auditors, and firmware analysts in identifying and remediating vulnerabilities before product deployment.

* **Independent Project:** FirmwareX is an independent research project inspired by industry threat research. It is not affiliated with, sponsored by, or endorsed by Palo Alto Networks or Unit 42.
* **Defensive Tooling:** Protocol fuzzing capabilities are strictly loopback-gated (`127.0.0.1`) and must never be directed against unauthorized third-party devices or public networks.

