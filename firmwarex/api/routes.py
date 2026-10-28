"""FastAPI route definitions for FirmwareX control plane and analysis pipeline."""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse

from firmwarex.api.audit_log import AuditLogger
from firmwarex.api.storage import StorageManager
from firmwarex.config import (
    EXTRACTED_DIR,
    MAX_UPLOAD_SIZE_BYTES,
    UPLOADS_DIR,
    ensure_directories,
)
from firmwarex.core.elf_auditor import ELFAuditor
from firmwarex.core.normaliser import FindingNormaliser
from firmwarex.core.secret_scanner import SecretScanner
from firmwarex.core.symbolic_analyzer import BoundedSymbolicAnalyzer
from firmwarex.core.unpacker import (
    SafeExtractor,
    SecurityException,
    compute_sha256,
    detect_format_detailed,
)
from firmwarex.isolation.sandbox_manager import ContainmentPreflight

api_router = APIRouter(prefix="/api/v1")
storage = StorageManager()
audit_log = AuditLogger()
extractor = SafeExtractor()
elf_auditor = ELFAuditor()
secret_scanner = SecretScanner()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@api_router.get("/health")
async def api_health():
    """Health check endpoint for API consumers."""
    return {"status": "healthy"}


@api_router.get("/firmware")
async def list_all_firmware():
    """List all uploaded and analyzed firmware records for the SOC Command Center overview."""
    firmwares = storage.list_firmwares()
    return {"total": len(firmwares), "firmwares": firmwares}


@api_router.post("/firmware/upload")
async def upload_firmware(file: UploadFile = File(...)):
    """Upload a firmware image, validate format, safely extract, and run core security audits."""
    ensure_directories()
    firmware_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    filename = file.filename or "unknown_firmware"

    upload_path = UPLOADS_DIR / f"{firmware_id}_{filename}"
    extract_target = EXTRACTED_DIR / firmware_id

    # 1. Stream upload enforcing size bounds
    bytes_read = 0
    try:
        with open(upload_path, "wb") as f:
            while chunk := await file.read(65536):
                bytes_read += len(chunk)
                if bytes_read > MAX_UPLOAD_SIZE_BYTES:
                    upload_path.unlink(missing_ok=True)
                    audit_log.record_event("UPLOAD_REJECTED_OVERSIZED", {
                        "firmware_id": firmware_id,
                        "filename": filename,
                        "bytes_read": bytes_read,
                    })
                    raise HTTPException(
                        status_code=413,
                        detail=f"Uploaded file exceeds maximum permitted size ({MAX_UPLOAD_SIZE_BYTES} bytes).",
                    )
                f.write(chunk)

        # Enforce non-empty upload
        if bytes_read == 0:
            upload_path.unlink(missing_ok=True)
            audit_log.record_event("UPLOAD_REJECTED_EMPTY", {
                "firmware_id": firmware_id,
                "filename": filename,
            })
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty (0 bytes).",
            )
    except HTTPException:
        raise
    except Exception as e:
        upload_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Failed to stream upload: {e!s}")

    # 2. Compute digest, detect format, and scan embedded signatures
    sha256_digest = compute_sha256(upload_path)
    fmt, is_supported, signatures = detect_format_detailed(upload_path)
    sig_dicts = [s.to_dict() for s in signatures]

    # Initialize firmware record
    fw_record = {
        "id": firmware_id,
        "filename": filename,
        "sha256": sha256_digest,
        "size_bytes": bytes_read,
        "format": fmt,
        "is_supported": is_supported,
        "status": "uploaded",
        "created_at": _utc_now(),
        "extraction_dir": None,
        "error_message": None,
        "signatures": sig_dicts,
    }
    storage.save_firmware(fw_record)

    # Initialize job record
    job_record = {
        "job_id": job_id,
        "firmware_id": firmware_id,
        "status": "processing",
        "progress": 10,
        "stage": "format_validation",
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
        "error_message": None,
    }
    storage.save_job(job_record)
    audit_log.record_event("FIRMWARE_INGESTED", {
        "firmware_id": firmware_id,
        "job_id": job_id,
        "filename": filename,
        "format": fmt,
        "sha256": sha256_digest,
    })

    # If unsupported format, record clear limitation state and abort analysis gracefully
    if not is_supported:
        tool_advice = "Raw proprietary containers (SquashFS, TRX, uImage) require external extraction modules (Binwalk), which are currently deferred in this environment."
        if signatures:
            primary_sig = signatures[0]
            tool_advice = f"Detected: {primary_sig.name} at offset {primary_sig.offset}. Recommended tool: {primary_sig.recommended_tool}."

        err_msg = (
            f"Unsupported format '{fmt}'. Safe automated extraction in Phase 1 supports "
            "standard archive formats (.zip, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz). "
            f"{tool_advice}"
        )
        fw_record["status"] = "unsupported_format"
        fw_record["error_message"] = err_msg
        storage.save_firmware(fw_record)

        job_record["status"] = "failed"
        job_record["stage"] = "extraction_halted"
        job_record["error_message"] = err_msg
        job_record["updated_at"] = _utc_now()
        storage.save_job(job_record)

        audit_log.record_event("EXTRACTION_UNSUPPORTED_FORMAT", {
            "firmware_id": firmware_id,
            "format": fmt,
        })

        return JSONResponse(
            status_code=422,
            content={
                "firmware_id": firmware_id,
                "job_id": job_id,
                "status": "unsupported_format",
                "message": err_msg,
                "format": fmt,
                "sha256": sha256_digest,
                "signatures": sig_dicts,
            },
        )

    # 3. Perform Safe Extraction
    try:
        job_record["stage"] = "safe_extraction"
        job_record["progress"] = 30
        job_record["updated_at"] = _utc_now()
        storage.save_job(job_record)

        extraction_result = extractor.extract(upload_path, extract_target)
        if not extraction_result.success:
            err_msg = f"Archive extraction failed: {extraction_result.message}" if extraction_result.message else "Corrupted archive file."
            fw_record["status"] = "extraction_failed"
            fw_record["error_message"] = err_msg
            storage.save_firmware(fw_record)

            job_record["status"] = "failed"
            job_record["stage"] = "extraction_failed"
            job_record["error_message"] = err_msg
            job_record["updated_at"] = _utc_now()
            storage.save_job(job_record)
            raise HTTPException(status_code=400, detail=err_msg)

        fw_record["extraction_dir"] = str(extract_target)
        fw_record["status"] = "extracted"
        storage.save_firmware(fw_record)

        # Save File Inventory
        storage.save_inventory(firmware_id, extraction_result.inventory)
        audit_log.record_event("EXTRACTION_COMPLETED", {
            "firmware_id": firmware_id,
            "file_count": extraction_result.file_count,
            "total_size": extraction_result.total_size_bytes,
        })

    except SecurityException as sec_err:
        err_msg = f"Security Boundary Violation: {sec_err!s}"
        fw_record["status"] = "security_violation"
        fw_record["error_message"] = err_msg
        storage.save_firmware(fw_record)

        job_record["status"] = "failed"
        job_record["stage"] = "containment_trip"
        job_record["error_message"] = err_msg
        job_record["updated_at"] = _utc_now()
        storage.save_job(job_record)

        audit_log.record_event("SECURITY_BOUNDARY_VIOLATION", {
            "firmware_id": firmware_id,
            "error": str(sec_err),
        })
        raise HTTPException(status_code=400, detail=err_msg)

    except HTTPException:
        # Re-raise standard HTTPExceptions (such as 400 validation failures) without re-wrapping as 500
        raise

    except Exception as exc:
        err_msg = f"Extraction failure: {exc!s}"
        fw_record["status"] = "extraction_failed"
        fw_record["error_message"] = err_msg
        storage.save_firmware(fw_record)

        job_record["status"] = "failed"
        job_record["stage"] = "extraction_failed"
        job_record["error_message"] = err_msg
        job_record["updated_at"] = _utc_now()
        storage.save_job(job_record)
        raise HTTPException(status_code=500, detail=err_msg)

    # 4. Run ELF Binary Hardening Audit
    job_record["stage"] = "elf_binary_audit"
    job_record["progress"] = 60
    job_record["updated_at"] = _utc_now()
    storage.save_job(job_record)

    binary_audits = elf_auditor.audit_all_in_directory(extract_target)
    storage.save_binary_audits(firmware_id, binary_audits)

    # 5. Run Secret & Weak Crypto Scanner
    job_record["stage"] = "secret_crypto_scan"
    job_record["progress"] = 80
    job_record["updated_at"] = _utc_now()
    storage.save_job(job_record)

    secret_findings = secret_scanner.scan_directory(extract_target)

    # 6. Normalize Findings into PRD Appendix A Schema
    normalized_findings: list[dict[str, Any]] = []

    # Map secret findings
    for sf in secret_findings:
        normalized_findings.append(FindingNormaliser.from_secret_finding(sf, firmware_id))

    # Map ELF hardening & suspicious sink findings
    for ba in binary_audits:
        normalized_findings.extend(FindingNormaliser.from_binary_mitigations(ba, firmware_id))

    storage.save_findings(firmware_id, normalized_findings)

    # 7. Complete Job
    fw_record["status"] = "analysis_completed"
    storage.save_firmware(fw_record)

    job_record["status"] = "completed"
    job_record["stage"] = "done"
    job_record["progress"] = 100
    job_record["updated_at"] = _utc_now()
    storage.save_job(job_record)

    audit_log.record_event("ANALYSIS_COMPLETED", {
        "firmware_id": firmware_id,
        "job_id": job_id,
        "binaries_audited": len(binary_audits),
        "total_findings": len(normalized_findings),
    })

    return {
        "firmware_id": firmware_id,
        "job_id": job_id,
        "status": "completed",
        "filename": filename,
        "sha256": sha256_digest,
        "file_count": extraction_result.file_count,
        "binaries_audited": len(binary_audits),
        "findings_count": len(normalized_findings),
    }


@api_router.get("/firmware/{firmware_id}")
async def get_firmware(firmware_id: str):
    """Retrieve metadata, upload details, and status for a firmware image."""
    fw = storage.get_firmware(firmware_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware ID not found.")
    return fw


@api_router.get("/firmware/{firmware_id}/filesystem")
async def get_filesystem(firmware_id: str):
    """Retrieve complete file tree inventory for an extracted firmware image."""
    fw = storage.get_firmware(firmware_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware ID not found.")
    inventory = storage.get_inventory(firmware_id)
    return {
        "firmware_id": firmware_id,
        "total_files": len(inventory),
        "files": inventory,
    }


@api_router.get("/firmware/{firmware_id}/binary-audit")
async def get_binary_audit(firmware_id: str):
    """Retrieve per-binary ELF hardening audit reports and summary metrics."""
    fw = storage.get_firmware(firmware_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware ID not found.")
    audits = storage.get_binary_audits(firmware_id)
    # Reconstruct summary
    summary = {
        "total_binaries": len(audits),
        "nx_enabled": sum(1 for a in audits if a.get("nx", {}).get("status") == "enabled"),
        "pie_enabled": sum(1 for a in audits if a.get("pie", {}).get("status") == "enabled"),
        "relro_full": sum(1 for a in audits if a.get("relro", {}).get("status") == "enabled" and a.get("relro", {}).get("details") != "partial_relro"),
        "relro_partial": sum(1 for a in audits if a.get("relro", {}).get("status") == "enabled" and a.get("relro", {}).get("details") == "partial_relro"),
        "canary_enabled": sum(1 for a in audits if a.get("canary", {}).get("status") == "enabled"),
        "fortify_enabled": sum(1 for a in audits if a.get("fortify", {}).get("status") == "enabled"),
        "total_suspicious_sinks": sum(len(a.get("suspicious_sinks", [])) for a in audits),
    }
    return {
        "firmware_id": firmware_id,
        "summary": summary,
        "binaries": audits,
    }


@api_router.get("/firmware/{firmware_id}/vulnerabilities")
async def get_vulnerabilities(
    firmware_id: str,
    category: str | None = Query(None),
    risk: str | None = Query(None),
):
    """Retrieve normalized findings conforming to PRD Appendix A."""
    fw = storage.get_firmware(firmware_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware ID not found.")
    findings = storage.get_findings(firmware_id)

    if category:
        findings = [f for f in findings if f.get("category") == category]
    if risk:
        findings = [f for f in findings if f.get("risk_rating") == risk]

    return {
        "firmware_id": firmware_id,
        "total_findings": len(findings),
        "findings": findings,
    }


@api_router.get("/containment/preflight")
async def get_containment_preflight():
    """Retrieve live containment preflight status, Docker daemon health, and network isolation."""
    return ContainmentPreflight.run_preflight().to_dict()


@api_router.get("/firmware/{firmware_id}/signatures")
async def get_firmware_signatures(firmware_id: str):
    """Retrieve detected container format headers and embedded filesystem signatures."""
    fw = storage.get_firmware(firmware_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware ID not found.")
    return {
        "firmware_id": firmware_id,
        "signatures": fw.get("signatures", []),
    }


@api_router.get("/firmware/{firmware_id}/symbolic")
async def get_firmware_symbolic(firmware_id: str):
    """Retrieve bounded symbolic analysis leads for an analyzed firmware image."""
    fw = storage.get_firmware(firmware_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware ID not found.")
    ext_dir = fw.get("extraction_dir")
    if not ext_dir or not Path(ext_dir).exists():
        return {
            "firmware_id": firmware_id,
            "status": "no_extracted_files",
            "review_leads": [],
            "limitations": ["No extracted files present for analysis."],
        }
    report = BoundedSymbolicAnalyzer().analyze_workspace(Path(ext_dir))
    return report.to_dict()


@api_router.get("/firmware/{firmware_id}/report")
async def get_report(firmware_id: str):
    """Export complete, verifiable JSON security report for compliance and audit."""
    fw = storage.get_firmware(firmware_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware ID not found.")

    inventory = storage.get_inventory(firmware_id)
    audits = storage.get_binary_audits(firmware_id)
    findings = storage.get_findings(firmware_id)

    # Telemetry and bounded symbolic analysis
    preflight = ContainmentPreflight.run_preflight().to_dict()
    symbolic_summary = None
    ext_dir = fw.get("extraction_dir")
    if ext_dir and Path(ext_dir).exists():
        symbolic_summary = BoundedSymbolicAnalyzer().analyze_workspace(Path(ext_dir)).to_dict()

    return {
        "schema_version": "1.0",
        "generated_at": _utc_now(),
        "engine": "FirmwareX v0.1.0",
        "firmware_metadata": fw,
        "filesystem_inventory_summary": {
            "total_items": len(inventory),
            "elf_count": sum(1 for item in inventory if item.get("is_elf")),
        },
        "mitigation_matrix": {
            "total_binaries": len(audits),
            "reports": audits,
        },
        "containment_telemetry": preflight,
        "symbolic_analysis": symbolic_summary,
        "findings_appendix_a": findings,
    }


@api_router.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Retrieve progress and current stage of an asynchronous or running analysis job."""
    job = storage.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job ID not found.")
    return job

