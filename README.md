# FirmwareX — Automated IoT Firmware Attack Surface & Vulnerability Analysis Engine

> [!NOTE]
> **Project Scope Notice:** FirmwareX is an independent cybersecurity research and engineering project designed according to the technical requirements in the `Project Unit42-FirmwareX` Product Requirements Document (PRD). It is not officially affiliated with or endorsed by Palo Alto Networks or Unit 42.

FirmwareX delivers an automated security analysis pipeline designed to audit IoT and embedded device firmware images. It performs safe multi-layer extraction, raw signature scanning, rootfs file inventory, cross-architecture ELF binary hardening audits, secret scanning with mandatory cryptographic redaction, bounded static taint analysis, containerized isolation preflights, and normalised finding exports conforming to PRD Appendix A.

---

## 1. Quickstart & Local Runbook

### Prerequisites
* **Operating System:** Windows 11 (or Linux/macOS)
* **Python:** Python 3.12+ (tested on Python 3.14.6 64-bit)
* **Container Engine:** Docker Desktop (WSL2 backend, optional but audited for dynamic isolation preflight)
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
* **Containment Preflight Status:** [http://127.0.0.1:8080/api/v1/containment/preflight](http://127.0.0.1:8080/api/v1/containment/preflight)

---

## 2. Generating & Uploading a Test Sample

FirmwareX includes a standalone synthetic IoT firmware sample generator:
```powershell
.\.venv\Scripts\python.exe samples/generate_sample_firmware.py
```
This generates `samples/sample_iot_router.tar.gz` containing synthetic MIPS and ARM ELF executables, configuration files with test credentials, and Unix shadow structures.

### Option A: Upload via SOC Command Center
1. Navigate to `http://127.0.0.1:8080/`.
2. Select **Firmware Ingestion** from the left navigation sidebar.
3. Drag and drop `samples/sample_iot_router.tar.gz` into the upload dropzone.
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
| `POST` | `/api/v1/firmware/upload` | Streams firmware archive, enforces Zip-Slip safety, extracts inventory, runs audits. |
| `GET` | `/api/v1/firmware` | Lists all ingested firmware images with SHA-256 digests and processing status. |
| `GET` | `/api/v1/firmware/{id}` | Returns firmware ingest metadata, digest, and status. |
| `GET` | `/api/v1/firmware/{id}/filesystem` | Returns rootfs file inventory with relative paths, sizes, and SHA-256 digests. |
| `GET` | `/api/v1/firmware/{id}/binary-audit` | Returns per-binary mitigation matrix (NX, PIE, RELRO, Canaries, FORTIFY, Sinks). |
| `GET` | `/api/v1/firmware/{id}/vulnerabilities`| Returns Appendix A normalized findings with category and severity filters. |
| `GET` | `/api/v1/firmware/{id}/signatures` | Returns detected container format headers and embedded filesystem signatures. |
| `GET` | `/api/v1/firmware/{id}/symbolic` | Returns bounded static taint reachability review leads for an analyzed image. |
| `GET` | `/api/v1/firmware/{id}/report` | Generates a full downloadable JSON report with audit telemetry and containment info. |
| `GET` | `/api/v1/containment/preflight` | Returns live containment preflight status, Docker daemon health, and network isolation. |
| `GET` | `/api/v1/jobs/{jobId}` | Returns execution progress and stage for an analysis job. |

---

## 4. Running the Automated Test Suite

Run the full automated test suite with coverage measurement across all 17 modules:
```powershell
.\.venv\Scripts\python.exe -m pytest -v --cov=firmwarex
```

### Verified Test Suite Breakdown (57 Tests Total — 83% Coverage):
* **Raw Signature Detection (`test_raw_detector.py` — 8 tests):** SquashFS LE/BE/swapped (`hsqs`, `sqsh`), CramFS LE/BE, JFFS2, UBIFS/UBI#, U-Boot uImage, Broadcom TRX, DTB device tree blobs, and multi-offset composite firmware scanning.
* **Nested Archive Unpacking (`test_nested_unpacker.py` — 3 tests):** Recursive archive unpacking, `MAX_NESTING_DEPTH = 3` ceiling enforcement, and cumulative file count quotas across nested layers.
* **Containment & Isolation (`test_containment_isolation.py` — 5 tests):** Docker daemon responsiveness, fail-closed handling on missing container runtime, volume mount path scoping to `data/sandboxes/`, rejection of system root / `.ssh` / `docker.sock`, and disposable sandbox lifecycle cleanup.
* **QEMU Emulation Adapter (`test_qemu_adapter.py` — 5 tests):** Cross-architecture mapping (MIPS-BE, MIPS-LE, ARM, ARMEB, AArch64, x86_64), unavailable tool handling, and mock diagnostic scenarios (`timeout`, `missing_libraries`, `crashed`, `completed`).
* **Bounded Symbolic Analysis (`test_symbolic_analyzer.py` — 4 tests):** Call-graph reachability connecting input sources (`recv`, `read`) to dangerous sinks (`system`, `strcpy`), `REVIEW_LEAD` tagging, and REST API telemetry endpoints.
* **Security & Sandboxing (`test_unpacker_safety.py` — 9 tests):** Zip Slip path traversal rejection, TAR traversal rejection, symlink escape rejection, FIFO/special device node blocking, file count quotas, uncompressed size ceilings.
* **ELF Hardening Audit (`test_elf_auditor.py` — 9 tests):** NX/DEP detection (`PT_GNU_STACK`), Full & Partial RELRO detection (`PT_GNU_RELRO` & `BIND_NOW`), PIE detection (`ET_DYN` vs `ET_EXEC`), MIPS big-endian, ARM little-endian, ARM64/AArch64, x86_64, relocatable object files (`ET_REL`), truncated headers, and non-ELF graceful handling.
* **Secret & Crypto Redaction (`test_secret_redactor.py` — 4 tests):** AWS key masking, Shannon entropy calculations ($H > 4.5$), password assignment detection, shadow database matching, zero plaintext persistence in database or exports.
* **API, Persistence & Dashboard (`test_api_integration.py` — 10 tests):** End-to-end ingestion pipeline, report retrieval, SQLite transactions, append-only audit logging (`audit_log.jsonl`), HTML5 SOC Command Center rendering.

---

## 5. Automated Browser QA & Viewport Verification

Run the automated headless Chrome testing suite:
```powershell
.\.venv\Scripts\python.exe tests/browser_qa_runner.py
```
This suite verifies:
1. Server launch on loopback `127.0.0.1:8080`.
2. Live DOM elements, table bodies, navigation, and branding rendered in headless Chrome.
3. Desktop layout screenshot captured at 1280x800 (`docs/dashboard_desktop.png`).
4. Mobile layout screenshot captured at 375x812 (`docs/dashboard_mobile.png`).
5. Live end-to-end multipart firmware archive upload and report export.

---

## 6. Teardown & Clean Up

To delete transient uploaded firmware, extracted files, and test artifacts:
```powershell
Remove-Item -Recurse -Force data\uploads\*, data\extracted\*, data\reports\*, data\sandboxes\*, data\*.db, data\*.jsonl -ErrorAction SilentlyContinue
```
