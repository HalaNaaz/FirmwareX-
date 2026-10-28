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
# Or invoke Python directly
.\.venv\Scripts\python.exe -m uvicorn firmwarex.api.server:app --host 0.0.0.0 --port 8080 --reload
```

Open your browser at:
* **Interactive Dashboard:** [http://localhost:8080/](http://localhost:8080/)
* **Interactive API Documentation (Swagger):** [http://localhost:8080/docs](http://localhost:8080/docs)

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

### Verified Test Suite Breakdown (22 Tests Total):
* **Security & Containment:** Zip Slip path traversal rejection, TAR traversal rejection, symlink escape rejection, FIFO/special device node blocking, file count quotas, uncompressed size ceilings.
* **ELF Hardening Audit:** NX/DEP detection (`PT_GNU_STACK`), RELRO detection (`PT_GNU_RELRO` & `BIND_NOW`), PIE detection (`ET_DYN` vs `ET_EXEC`), MIPS big-endian parsing, ARM little-endian parsing, x86_64 parsing, non-ELF graceful handling.
* **Secret & Crypto Redaction:** AWS key masking, Shannon entropy calculations ($H > 4.5$), password assignment detection, shadow database matching, zero plaintext persistence.
* **Schema Compliance:** Strict PRD Appendix A field structure and null safety verification.
* **API & Dashboard:** End-to-end ingestion pipeline, report retrieval, unsupported format error reporting, HTML5 dashboard rendering.

---

## 5. Teardown & Clean Up

To delete transient uploaded firmware, extracted files, and test artifacts:
```powershell
Remove-Item -Recurse -Force data\uploads\*, data\extracted\*, data\reports\*, data\*.db, data\*.jsonl -ErrorAction SilentlyContinue
```

