# FirmwareX — Automated IoT Firmware Attack Surface & Vulnerability Analysis Engine

> [!NOTE]
> **Project Scope Notice:** FirmwareX is an independent cybersecurity research and engineering project designed according to the technical requirements in the `Project Unit42-FirmwareX` Product Requirements Document (PRD). It is not officially affiliated with or endorsed by Palo Alto Networks or Unit 42.

FirmwareX delivers an automated security analysis pipeline designed to audit IoT and embedded device firmware images. It performs safe multi-layer extraction, raw signature scanning, modular filesystem extraction (CramFS, Broadcom TRX, U-Boot uImage, JFFS2 flash filesystem, SquashFS), rootfs file inventory, cross-architecture ELF binary hardening audits, secret scanning with mandatory cryptographic redaction, bounded static taint analysis, live containerized isolation preflights, defensive protocol fuzzing, and normalised finding exports conforming to PRD Appendix A.

* **Repository:** [https://github.com/HalaNaaz/FirmwareX-.git](https://github.com/HalaNaaz/FirmwareX-.git)

---

## 1. Quickstart & Local Runbook

### Prerequisites
* **Operating System:** Windows 11 (or Linux/macOS)
* **Python:** Python 3.12+ (tested on Python 3.14.6 64-bit)
* **Container Engine:** Docker Desktop (WSL2 backend, verified for dynamic isolation preflight and `--network none` execution)
* **Dependencies:** FastAPI, Uvicorn, Pydantic, Pyelftools, Jinja2, Cryptography, Pytest, Pytest-Cov

### Installation & Launch
Navigate to the project root directory:
```powershell
cd "C:\Users\Hala\Downloads\Project Files\FirmwareX"
```

Activate the virtual environment and launch the FastAPI server bound to loopback `127.0.0.1`:
```powershell
.\.venv\Scripts\python.exe -m uvicorn firmwarex.api.server:app --host 127.0.0.1 --port 8080 --reload
```

Access the platform:
* **SOC Command Center Dashboard:** [http://127.0.0.1:8080/](http://127.0.0.1:8080/)
* **Interactive OpenAPI (Swagger) Docs:** [http://127.0.0.1:8080/docs](http://127.0.0.1:8080/docs)
* **Health Check Endpoints:** [http://127.0.0.1:8080/healthz](http://127.0.0.1:8080/healthz) and [http://127.0.0.1:8080/health](http://127.0.0.1:8080/health)
* **Extractor Capabilities:** [http://127.0.0.1:8080/api/v1/extractors/capabilities](http://127.0.0.1:8080/api/v1/extractors/capabilities)
* **Live Containment Verification:** [http://127.0.0.1:8080/api/v1/containment/verify](http://127.0.0.1:8080/api/v1/containment/verify)

---

## 2. Generating & Uploading a Test Sample

FirmwareX includes standalone synthetic firmware sample generators:
```powershell
# Generate standard tarball router sample
.\.venv\Scripts\python.exe samples/generate_sample_firmware.py
```
This generates `samples/sample_iot_router.tar.gz` containing synthetic MIPS and ARM ELF executables, configuration files with test credentials, and Unix shadow structures.

### Option A: Upload via SOC Command Center
1. Navigate to `http://127.0.0.1:8080/`.
2. Select **Firmware Ingestion** from the navigation tabs.
3. Drag and drop `samples/sample_iot_router.tar.gz` (or a supported CramFS, JFFS2, or TRX image) into the upload dropzone.
4. Click **Ingest & Run Pipeline**. The real-time terminal feed displays streaming progress: format validation, safe decompression, binary audits, and finding triage.

### Option B: Upload via cURL / PowerShell
```powershell
curl -X POST "http://127.0.0.1:8080/api/v1/firmware/upload" `
  -H "accept: application/json" `
  -F "file=@samples/sample_iot_router.tar.gz"
```

---

## 3. Core REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/firmware/upload` | Streams firmware archive/raw image, enforces Zip-Slip safety, extracts inventory, runs audits. |
| `GET` | `/api/v1/firmware` | Lists all ingested firmware images with SHA-256 digests and processing status. |
| `GET` | `/api/v1/firmware/{id}` | Returns firmware ingest metadata, digest, and status. |
| `GET` | `/api/v1/firmware/{id}/filesystem` | Returns rootfs file inventory with relative paths, sizes, and SHA-256 digests. |
| `GET` | `/api/v1/firmware/{id}/binary-audit` | Returns per-binary mitigation matrix (NX, PIE, RELRO, Canaries, FORTIFY, Sinks). |
| `GET` | `/api/v1/firmware/{id}/vulnerabilities`| Returns Appendix A normalized findings with category and severity filters. |
| `GET` | `/api/v1/firmware/{id}/signatures` | Returns detected container format headers and embedded filesystem signatures. |
| `GET` | `/api/v1/firmware/{id}/symbolic` | Returns bounded static taint reachability review leads for an analyzed image. |
| `GET` | `/api/v1/firmware/{id}/report` | Generates a full downloadable JSON report with audit telemetry and containment info. |
| `GET` | `/api/v1/containment/preflight` | Returns static containment preflight status, Docker daemon health, and network isolation. |
| `GET` | `/api/v1/containment/verify` | Executes project-controlled live probe in disposable container to verify `--network none` and `--read-only`. |
| `GET` | `/api/v1/extractors/capabilities`| Returns registered modular filesystem extractors and tool availability. |
| `POST` | `/api/v1/fuzzing/test` | Runs bounded defensive protocol fuzzing session against loopback test service (HTTP/UPnP/MQTT). |
| `GET` | `/api/v1/jobs/{jobId}` | Returns execution progress and stage for an analysis job. |

---

## 4. Running the Automated Test Suite

Run the full automated test suite with coverage measurement across all modules:
```powershell
.\.venv\Scripts\python.exe -m pytest -v --cov=firmwarex
```

### Verified Test Suite Breakdown (94 Tests Total):
* **Modular Filesystem Extractors (`test_extractors.py` & `test_phase8_analysis_integrity.py` — 18 tests):**
  - Pure-Python CramFS: LE/BE superblock parsing, zlib decompression, directory trees, corrupted header handling, quota enforcement.
  - Broadcom TRX: `HDR0` validation, partition slicing, CRC32 checks, corrupted container handling.
  - U-Boot uImage: `0x27051956` magic validation, header/data CRCs, gzip decompression, corrupted payload handling.
  - Pure-Python JFFS2: Little/Big Endian node parsing, DIRENT traversal, INODE chunk reassembly (zlib and raw), corrupted node recovery, quota enforcement.
  - SquashFS & UBIFS: Superblock inspection, PySquashfsImage and ubireader tool discovery, safe execution bounds, and corrupted stream recovery.
* **Disposable Containment & Isolation (`test_live_containment.py` & `test_containment_isolation.py` — 10 tests):**
  - Command argument-list enforcement (rejects shell string interpolation).
  - Strict host mount path isolation (rejection of system root, `.ssh`, `docker.sock`).
  - Disposable sandbox scratch directory guaranteed cleanup.
  - Live Docker container execution with `--network none` (verified network unreachable), `--read-only` rootfs, and non-root execution (`UID 1000`).
* **Defensive Protocol Fuzzing (`test_fuzzing.py` — 8 tests):**
  - Loopback safety enforcement: strictly rejects external and private non-loopback IPs (`192.168.1.1`, `10.0.0.1`, `8.8.8.8`).
  - Protocol mutator: HTTP, UPnP SSDP, and MQTT 3.1.1 packet generation with size bounding.
  - `SyntheticLocalTestServer`: loopback in-process server verifying anomaly classification (500 errors, connection drops).
  - Connection error and service shutdown handling: verifies graceful handling of closed/unresponsive ports without unhandled exceptions.
  - API endpoint verification for `/api/v1/extractors/capabilities` and `/api/v1/fuzzing/test`.
* **Bounded Static Taint Analysis (`test_symbolic_extended.py` & `test_symbolic_analyzer.py` — 8 tests):**
  - Deduplicated `REVIEW_LEAD` generation linking input sources to dangerous sinks.
  - Candidate confidence tagging, static call-graph evidence, and limitations documentation.
  - Graceful handling of stripped, truncated, and corrupt ELF executables.
* **Raw Signature Detection (`test_raw_detector.py` — 8 tests):**
  - SquashFS LE/BE/swapped, CramFS LE/BE, JFFS2, UBIFS/UBI#, U-Boot uImage, Broadcom TRX, DTB device tree blobs, and multi-offset composite scanning.
* **Nested Archive Unpacking (`test_nested_unpacker.py` — 3 tests):**
  - Recursive archive unpacking up to depth 3 with cumulative file count quotas and provenance metadata.
* **Security & Sandboxing (`test_unpacker_safety.py` — 9 tests):**
  - Zip Slip path traversal rejection, TAR traversal rejection, symlink escape rejection, FIFO/special device node blocking, file count quotas, uncompressed size ceilings.
* **ELF Hardening Audit (`test_elf_auditor.py` — 9 tests):**
  - NX/DEP detection (`PT_GNU_STACK`), Full & Partial RELRO (`PT_GNU_RELRO` & `BIND_NOW`), PIE detection (`ET_DYN` vs `ET_EXEC`), MIPS big-endian, ARM little-endian, ARM64/AArch64, x86_64, relocatable object files (`ET_REL`), truncated headers, and non-ELF handling.
* **Secret & Crypto Redaction (`test_secret_redactor.py` — 4 tests):**
  - AWS key masking, Shannon entropy calculations ($H > 4.5$), password assignment detection, shadow database matching, zero plaintext persistence.
* **API, Persistence & Dashboard (`test_api_integration.py` — 12 tests):**
  - End-to-end ingestion pipeline, report retrieval, SQLite transactions, audit logging (`audit_log.jsonl`), HTML5 SOC Command Center rendering, CramFS firmware upload, and JFFS2 firmware upload.
* **QEMU Emulation Adapter (`test_qemu_adapter.py` — 5 tests):**
  - Architecture mapping (MIPS-BE, MIPS-LE, ARM, ARMEB, AArch64, x86_64), fail-closed isolation checks (`isolation_blocked`), unavailable tool handling (`tool_unavailable`), and mock diagnostic scenarios.

---

## 5. Automated Browser QA & Viewport Verification

Run the automated headless Chrome testing suite:
```powershell
.\.venv\Scripts\python.exe tests/browser_qa_runner.py
```
This suite verifies:
1. Server launch on loopback `127.0.0.1:8080`.
2. Live DOM elements, table bodies, navigation, and branding rendered in headless Chrome.
3. Desktop 1440×900 screenshot captured (`docs/dashboard_desktop_1440.png`).
4. Desktop 1280×800 screenshot captured (`docs/dashboard_desktop_1280.png` / `docs/dashboard_desktop.png`).
5. Mobile 390×844 screenshot captured (`docs/dashboard_mobile_390.png` / `docs/dashboard_mobile.png`).
6. Live end-to-end multipart firmware archive upload and report export.

---

## 6. Teardown & Clean Up

To delete transient uploaded firmware, extracted files, and test artifacts:
```powershell
Remove-Item -Recurse -Force data\uploads\*, data\extracted\*, data\reports\*, data\sandboxes\*, data\*.db, data\*.jsonl -ErrorAction SilentlyContinue
```
