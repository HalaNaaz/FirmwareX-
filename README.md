# FirmwareX — Automated IoT Firmware Attack Surface & Vulnerability Analysis Engine

Project Unit42-FirmwareX delivers an automated security analysis pipeline designed to audit IoT and embedded device firmware images. It performs safe extraction, rootfs file inventory, cross-architecture ELF binary hardening audits, secret scanning with mandatory cryptographic redaction, and normalised finding exports conforming to PRD Appendix A.

---

## 1. Quickstart & Local Runbook

### Prerequisites
* **Operating System:** Windows 11 (or Linux/macOS)
* **Python:** Python 3.12+ (tested on Python 3.14.6)
* **Dependencies:** FastAPI, Uvicorn, Pydantic, Pyelftools, Jinja2, Cryptography, Pytest

### Installation
Clone or navigate to the workspace directory:
```powershell
cd "C:\Users\Hala\Downloads\Project Files\FirmwareX"
```

Activate the project-local virtual environment:
```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# Or invoke Python directly (bound safely to loopback 127.0.0.1)
.\.venv\Scripts\python.exe -m uvicorn firmwarex.api.server:app --host 127.0.0.1 --port 8080 --reload
```

Open your browser at:
* **Interactive Dashboard:** [http://127.0.0.1:8080/](http://127.0.0.1:8080/)
* **Interactive API Documentation (Swagger):** [http://127.0.0.1:8080/docs](http://127.0.0.1:8080/docs)
* **Health Check Endpoints:** [http://127.0.0.1:8080/healthz](http://127.0.0.1:8080/healthz) and [http://127.0.0.1:8080/health](http://127.0.0.1:8080/health)

---

## 2. Generating & Uploading a Test Sample

FirmwareX includes a standalone synthetic IoT firmware sample generator:
```powershell
.\.venv\Scripts\python.exe samples/generate_sample_firmware.py
```
This generates `samples/sample_iot_router.tar.gz` containing synthetic MIPS and ARM ELF executables, configuration files with test credentials, and Unix shadow structures.

### Option A: Upload via Dashboard
1. Navigate to `http://localhost:8080/`.
2. Drag and drop `samples/sample_iot_router.tar.gz` into the upload zone.
3. Click **Ingest & Analyse**. The dashboard dynamically updates with file inventories, the per-binary hardening matrix, and CWE-classified findings.

### Option B: Upload via cURL / PowerShell
```powershell
curl -X POST "http://localhost:8080/api/v1/firmware/upload" `
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
| `GET` | `/api/v1/firmware/{id}/filesystem` | Returns rootfs file inventory with relative paths and SHA-256 digests. |
| `GET` | `/api/v1/firmware/{id}/binary-audit` | Returns per-binary mitigation matrix (NX, PIE, RELRO, Canaries, Sinks). |
| `GET` | `/api/v1/firmware/{id}/vulnerabilities`| Returns Appendix A normalized findings with category and severity filters. |
| `GET` | `/api/v1/firmware/{id}/report` | Generates a full downloadable JSON report with audit telemetry. |
| `GET` | `/api/v1/jobs/{jobId}` | Returns execution progress and stage for an analysis job. |

---

## 4. Running the Automated Test Suite

Run all automated unit, integration, and security tests with coverage measurement:
```powershell
.\.venv\Scripts\python.exe -m pytest -v --cov=firmwarex
```

### Verified Test Suite Breakdown (32 Tests Total — 83% Coverage):
* **Security & Containment:** Zip Slip path traversal rejection, TAR traversal rejection, symlink escape rejection, FIFO/special device node blocking, file count quotas, uncompressed size ceilings.
* **Input Validation & Error Handling:** 0-byte upload rejection (HTTP 400), oversized upload rejection (HTTP 413), corrupted archive handling (HTTP 400), unsupported format detection (HTTP 422), non-existent resource handling (HTTP 404).
* **ELF Hardening Audit:** NX/DEP detection (`PT_GNU_STACK`), Full & Partial RELRO detection (`PT_GNU_RELRO` & `BIND_NOW`), PIE detection (`ET_DYN` vs `ET_EXEC`), MIPS big-endian, ARM little-endian, ARM64/AArch64, x86_64, relocatable object files (`ET_REL` with `not_applicable`), truncated/corrupted ELF headers, and non-ELF graceful handling.
* **Secret & Crypto Redaction:** AWS key masking, Shannon entropy calculations ($H > 4.5$), password assignment detection, shadow database matching, zero plaintext persistence in database or exports.
* **Schema Compliance:** Strict PRD Appendix A field structure, CWE mapping, and null safety verification.
* **API, Persistence & Dashboard:** End-to-end ingestion pipeline, all-firmwares enumeration endpoint (`GET /api/v1/firmware`), report retrieval, SQLite transactions, append-only audit logging (`audit_log.jsonl`), HTML5 SOC Command Center dashboard rendering.

---

## 5. Automated Browser QA & Viewport Verification

Run the automated headless Chrome testing suite:
```powershell
.\.venv\Scripts\python.exe tests/browser_qa_runner.py
```
This suite verifies:
1. Server launch on loopback `127.0.0.1:8080`.
2. Live DOM elements, table bodies, and branding rendered in headless Chrome.
3. Desktop layout screenshot captured at 1280x800 (`docs/dashboard_desktop.png`).
4. Mobile layout screenshot captured at 375x812 (`docs/dashboard_mobile.png`).
5. Live end-to-end multipart firmware archive upload and report export.

---

## 6. Teardown & Clean Up

To delete transient uploaded firmware, extracted files, and test artifacts:
```powershell
Remove-Item -Recurse -Force data\uploads\*, data\extracted\*, data\reports\*, data\*.db, data\*.jsonl -ErrorAction SilentlyContinue
```

