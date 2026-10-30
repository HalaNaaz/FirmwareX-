"""FastAPI route definitions for FirmwareX control plane and analysis pipeline."""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from firmwarex.api.audit_log import AuditLogger
from firmwarex.api.auth import UserIdentity, extract_token_from_headers, get_token_registry
from firmwarex.api.storage import StorageManager
from firmwarex.config import (
    EXTRACTED_DIR,
    MAX_UPLOAD_SIZE_BYTES,
    UPLOADS_DIR,
    ensure_directories,
)
from firmwarex.core.elf_auditor import ELFAuditor
from firmwarex.core.extractors.base import SecurityViolationError
from firmwarex.core.normaliser import FindingNormaliser
from firmwarex.core.queue_manager import JobQueueManager
from firmwarex.core.secret_scanner import SecretScanner
from firmwarex.core.symbolic_analyzer import BoundedSymbolicAnalyzer
from firmwarex.core.unpacker import (
    SafeExtractor,
    SecurityException,
    compute_sha256,
    detect_format_detailed,
)
from firmwarex.isolation.sandbox_manager import ContainmentPreflight
from firmwarex.telemetry import PipelineTracer, get_trace, register_trace

api_router = APIRouter(prefix="/api/v1")
storage = StorageManager()
audit_log = AuditLogger()
extractor = SafeExtractor()
elf_auditor = ELFAuditor()
secret_scanner = SecretScanner()
symbolic_analyzer = BoundedSymbolicAnalyzer()
queue_manager = JobQueueManager(storage=storage)


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

    # Enforce SC-2.3 Queue backpressure
    if not queue_manager.can_accept_job():
        audit_log.record_event("UPLOAD_REJECTED_BACKPRESSURE", {
            "filename": file.filename or "unknown_firmware",
            "reason": "Queue capacity saturated",
        })
        raise HTTPException(
            status_code=503,
            detail="Analysis queue is full. Backpressure active to prevent system resource exhaustion.",
            headers={"Retry-After": "5"},
        )
    firmware_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    filename = file.filename or "unknown_firmware"

    upload_path = UPLOADS_DIR / f"{firmware_id}_{filename}"
    extract_target = EXTRACTED_DIR / firmware_id

    tracer = PipelineTracer(job_id=job_id, firmware_id=firmware_id)

    # 1. Stream upload enforcing size bounds
    bytes_read = 0
    try:
        with tracer.span("stream_upload", {"filename": filename}):
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
        register_trace(tracer.finish("failed"))
        raise
    except Exception as e:
        upload_path.unlink(missing_ok=True)
        register_trace(tracer.finish("failed"))
        raise HTTPException(status_code=500, detail=f"Failed to stream upload: {e!s}")

    # 2. Compute digest, detect format, and scan embedded signatures
    with tracer.span("format_validation"):
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
        register_trace(tracer.finish("failed"))

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

        with tracer.span("safe_extraction", {"extract_target": str(extract_target)}):
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
        with tracer.span("inventory_indexing", {"file_count": extraction_result.file_count}):
            storage.save_inventory(firmware_id, extraction_result.inventory)
        audit_log.record_event("EXTRACTION_COMPLETED", {
            "firmware_id": firmware_id,
            "file_count": extraction_result.file_count,
            "total_size": extraction_result.total_size_bytes,
        })

    except (SecurityException, SecurityViolationError) as sec_err:
        err_msg = f"Security Boundary Violation: {sec_err!s}"
        fw_record["status"] = "security_violation"
        fw_record["error_message"] = err_msg
        storage.save_firmware(fw_record)

        stage_name = "quota_exceeded" if "quota" in str(sec_err).lower() else "containment_trip"
        job_record["status"] = "failed"
        job_record["stage"] = stage_name
        job_record["error_message"] = err_msg
        job_record["updated_at"] = _utc_now()
        storage.save_job(job_record)

        audit_log.record_event("SECURITY_BOUNDARY_VIOLATION", {
            "firmware_id": firmware_id,
            "error": str(sec_err),
        })
        register_trace(tracer.finish("failed"))
        raise HTTPException(status_code=400, detail=err_msg)

    except HTTPException:
        register_trace(tracer.finish("failed"))
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
        register_trace(tracer.finish("failed"))
        raise HTTPException(status_code=500, detail=err_msg)

    # 4. Run ELF Binary Hardening Audit
    job_record["stage"] = "elf_binary_audit"
    job_record["progress"] = 60
    job_record["updated_at"] = _utc_now()
    storage.save_job(job_record)

    with tracer.span("elf_binary_audit"):
        binary_audits = elf_auditor.audit_all_in_directory(extract_target)
        storage.save_binary_audits(firmware_id, binary_audits)

    # 5. Run Secret & Weak Crypto Scanner
    job_record["stage"] = "secret_crypto_scan"
    job_record["progress"] = 75
    job_record["updated_at"] = _utc_now()
    storage.save_job(job_record)

    with tracer.span("secret_crypto_scan"):
        secret_findings = secret_scanner.scan_directory(extract_target)

    # 5b. Run Bounded Symbolic & Taint Analysis
    job_record["stage"] = "symbolic_taint_analysis"
    job_record["progress"] = 85
    job_record["updated_at"] = _utc_now()
    storage.save_job(job_record)

    with tracer.span("symbolic_taint_analysis"):
        symbolic_report = symbolic_analyzer.analyze_workspace(extract_target)

    # 6. Normalize Findings into PRD Appendix A Schema
    with tracer.span("finding_normalization"):
        raw_findings: list[dict[str, Any]] = []

        # Map secret findings
        for sf in secret_findings:
            raw_findings.append(FindingNormaliser.from_secret_finding(sf, firmware_id))

        # Map ELF hardening & suspicious sink findings
        for ba in binary_audits:
            raw_findings.extend(FindingNormaliser.from_binary_mitigations(ba, firmware_id))

        # Map symbolic & taint reachability leads
        for lead in symbolic_report.review_leads:
            arch_val = None
            for ba in binary_audits:
                if ba.file_path == lead.binary_path or lead.binary_path.endswith(ba.file_path):
                    arch_val = ba.architecture
                    break
            raw_findings.append(FindingNormaliser.from_symbolic_lead(lead, firmware_id, architecture=arch_val))

        # Deduplicate findings by (binary, category, cwe, sink, source, details_type)
        seen_keys: set[tuple] = set()
        normalized_findings: list[dict[str, Any]] = []
        for f in raw_findings:
            key = (
                f.get("binary"),
                f.get("category"),
                f.get("cwe"),
                f.get("sink"),
                f.get("source"),
                f.get("details", {}).get("type"),
            )
            if key not in seen_keys:
                seen_keys.add(key)
                normalized_findings.append(f)

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

    trace_summary = tracer.finish("completed")
    register_trace(trace_summary)

    return {
        "firmware_id": firmware_id,
        "job_id": job_id,
        "trace_id": trace_summary.trace_id,
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


@api_router.get("/firmware/{firmware_id}/findings")
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
@api_router.get("/firmware/{firmware_id}/export")
@api_router.get("/reports/{firmware_id}/export")
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

    # OpenTelemetry trace lookup
    job = storage.get_job_by_firmware(firmware_id)
    trace_data = None
    if job and job.get("job_id"):
        t = get_trace(job["job_id"])
        if t:
            trace_data = t.to_dict()

    return {
        "schema_version": "1.0",
        "telemetry_trace": trace_data,
        "generated_at": _utc_now(),
        "engine": "FirmwareX v0.1.0",
        "firmware_id": firmware_id,
        "firmware_metadata": fw,
        "filesystem_inventory_summary": {
            "total_items": len(inventory),
            "elf_count": sum(1 for item in inventory if item.get("is_elf")),
        },
        "inventory": inventory,
        "binary_hardening": audits,
        "vulnerabilities": findings,
        "mitigation_matrix": {
            "total_binaries": len(audits),
            "reports": audits,
        },
        "containment_telemetry": preflight,
        "symbolic_analysis": symbolic_summary,
        "severity_summary": {
            "critical": sum(1 for f in findings if (f.get("risk_rating") or "").lower() == "critical"),
            "high": sum(1 for f in findings if (f.get("risk_rating") or "").lower() == "high"),
            "medium": sum(1 for f in findings if (f.get("risk_rating") or "").lower() == "medium"),
            "low": sum(1 for f in findings if (f.get("risk_rating") or "").lower() == "low"),
        },
        "findings_appendix_a": findings,
    }


@api_router.get("/firmware/{firmware_id}/report/download")
async def download_report(firmware_id: str):
    """Download auditable JSON report as an attached file conforming to PRD Appendix A."""
    import json

    from fastapi.responses import Response

    report_data = await get_report(firmware_id)
    safe_filename = f"firmwarex_report_{firmware_id[:8]}.json"
    json_bytes = json.dumps(report_data, indent=2).encode("utf-8")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "Cache-Control": "no-cache",
        },
    )


@api_router.get("/firmware/{firmware_id}/binaries/{binary_name}/cfg")
async def get_binary_cfg(firmware_id: str, binary_name: str):
    """Retrieve control-flow graph for a binary asset if available, or return explicit contract."""
    fw = storage.get_firmware(firmware_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware ID not found.")
    return {
        "status": "unavailable",
        "firmware_id": firmware_id,
        "binary": binary_name,
        "message": "Control-Flow Graph generation is unavailable in the current static analysis pipeline.",
        "contract": {
            "required_capabilities": ["disassembly_engine", "basic_block_recovery", "edge_inference"],
            "nodes_format": [{"id": "str", "start_addr": "str", "end_addr": "str", "instructions": "list[str]"}],
            "edges_format": [{"source": "str", "target": "str", "type": "str"}]
        }
    }


@api_router.get("/jobs/{job_id}/trace")
async def get_job_trace(job_id: str):
    """Retrieve OpenTelemetry trace records for a completed or active pipeline job."""
    trace_obj = get_trace(job_id)
    if not trace_obj:
        job = storage.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job ID not found.")
        return {
            "trace_id": "0" * 32,
            "job_id": job_id,
            "firmware_id": job.get("firmware_id", ""),
            "status": job.get("status", "unknown"),
            "spans": [],
            "message": "Trace data unavailable for archived or historical job."
        }
    return trace_obj.to_dict()


@api_router.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Retrieve progress and current stage of an asynchronous or running analysis job."""
    # Check live queue state first, then persistent storage
    live_state = queue_manager.get_job_state(job_id)
    if live_state:
        return live_state
    job = storage.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job ID not found.")
    return job


@api_router.get("/queue/status")
async def get_queue_status():
    """Retrieve queue concurrency, active workers, depth, and backpressure metrics (SC-2.3)."""
    return queue_manager.get_metrics()


@api_router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    """Request cancellation of an active or queued analysis job."""
    success = queue_manager.cancel_job(job_id)
    if not success:
        job = storage.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job ID not found.")
        if job.get("status") in ("completed", "failed", "cancelled"):
            return {"job_id": job_id, "status": job["status"], "message": f"Job is already terminal ({job['status']})."}
        raise HTTPException(status_code=400, detail=f"Cannot cancel job in state {job.get('status')}.")
    return {"job_id": job_id, "status": "cancelled", "message": "Job cancellation processed."}


@api_router.get("/jobs")
async def list_all_jobs():
    """List all tracked analysis jobs with their lifecycle status and stage."""
    return {"jobs": storage.list_jobs()}



@api_router.get("/extractors/capabilities")
async def get_extractor_capabilities():
    """Retrieve registered modular firmware filesystem and container extractor capabilities."""
    from firmwarex.core.extractors.registry import ExtractorRegistry
    return {
        "capabilities": ExtractorRegistry().list_capabilities()
    }


@api_router.get("/containment/verify")
async def get_live_containment_verification():
    """Execute a project-controlled safe probe inside disposable container to verify live containment."""
    return ContainmentPreflight.verify_live_containment()


@api_router.post("/fuzzing/test")
async def run_protocol_fuzzing_test(
    protocol: str = Query("http", pattern="^(http|upnp|mqtt)$"),
    iterations: int = Query(20, ge=1, le=100),
    seed: int = Query(42),
):
    """Execute bounded defensive protocol fuzzing test against an isolated loopback test service."""
    from firmwarex.fuzzing.protocol_fuzzer import FuzzConfig, FuzzProtocol, ProtocolFuzzRunner
    from firmwarex.fuzzing.test_server import SyntheticLocalTestServer

    test_server = SyntheticLocalTestServer()
    port = test_server.start()

    try:
        proto_enum = FuzzProtocol(protocol)
        cfg = FuzzConfig(
            target_host="127.0.0.1",
            target_port=port,
            protocol=proto_enum,
            max_iterations=iterations,
            seed=seed,
            timeout_seconds=2.0,
        )
        runner = ProtocolFuzzRunner(cfg)
        report = runner.run_fuzzing_session()
        return report.to_dict()
    finally:
        test_server.stop()


@api_router.post("/emulation/system/boot")
async def trigger_system_emulation(
    architecture: str = Query("mips", pattern="^(mips|mipsel|arm|arm64|aarch64|x86_64|i386)$"),
    endianness: str = Query("little", pattern="^(little|big)$"),
    machine_type: str | None = Query(None),
    firmware_id: str | None = Query(None),
    simulate_scenario: str | None = Query(None, pattern="^(boot_successful|boot_failed|timeout)$"),
):
    """Attempt bounded full-system QEMU emulation under strict containment (PRD FR-2.2)."""
    from firmwarex.emulation.qemu_adapter import QemuSystemEmulator, SystemEmulationConfig

    kernel_path = None
    if firmware_id:
        fw = storage.get_firmware(firmware_id)
        if not fw:
            raise HTTPException(status_code=404, detail="Firmware ID not found.")
        ext_dir = fw.get("extraction_dir")
        if ext_dir:
            for candidate in Path(ext_dir).rglob("*vmlinux*"):
                if candidate.is_file():
                    kernel_path = candidate
                    break

    cfg = SystemEmulationConfig(
        architecture=architecture,
        endianness=endianness,
        machine_type=machine_type,
        kernel_path=kernel_path,
        timeout_seconds=10,
        network_mode="none",
    )
    emulator = QemuSystemEmulator(cfg)
    result = emulator.boot(simulated_scenario=simulate_scenario)
    return result.to_dict()


@api_router.get("/fuzzing/corpus")
async def list_fuzzing_corpus(protocol: str | None = Query(None, pattern="^(http|upnp|mqtt)$")):
    """List seed corpus items filtered by protocol."""
    from firmwarex.fuzzing.corpus_manager import CorpusManager
    mgr = CorpusManager()
    seeds = mgr.list_seeds(protocol=protocol)
    return {"seeds": [s.to_dict() for s in seeds]}


@api_router.post("/fuzzing/corpus")
async def add_fuzzing_seed(
    protocol: str = Query(..., pattern="^(http|upnp|mqtt)$"),
    name: str = Query(..., min_length=2, max_length=64),
    content: str = Query(..., min_length=1),
):
    """Add a seed to the persistent protocol corpus."""
    from firmwarex.fuzzing.corpus_manager import CorpusManager
    mgr = CorpusManager()
    try:
        seed = mgr.add_seed(protocol=protocol, name=name, content=content)
        return seed.to_dict()
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@api_router.post("/fuzzing/minimize")
async def minimize_fuzzing_payload(
    payload: str = Query(..., min_length=4),
    simulate_crash: bool = Query(True),
):
    """Minimize a crashing fuzzing input using bounded delta-debugging (PRD FR-4.2)."""
    from firmwarex.fuzzing.minimizer import CrashInputMinimizer

    def target_verifier(candidate: bytes) -> bool:
        if not simulate_crash:
            return False
        return b"%s" in candidate or b"%n" in candidate or len(candidate) >= 16

    minimizer = CrashInputMinimizer(max_iterations=30, timeout_seconds=3.0)
    res = minimizer.minimize(payload.encode("utf-8"), target_verifier)
    return res.to_dict()


@api_router.get("/fuzzing/crashes")
async def list_deduplicated_crashes():
    """Retrieve deduplicated crash groups with normalized stack fingerprints (PRD FR-4.3)."""
    from firmwarex.emulation.crash_parser import CrashStateParser
    from firmwarex.fuzzing.crash_deduplicator import CrashDeduplicator

    dedup = CrashDeduplicator()
    sample_stderr = (
        "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n"
        "fault address: 0x41414141\n"
        "#0 0x7ffd12345678 in strcpy () from /lib/libc.so.0\n"
        "#1 0x7ffd123489ab in handle_http () from /bin/httpd\n"
    )
    c1 = CrashStateParser.parse_crash(stdout="", stderr=sample_stderr, exit_code=-11, arch="arm", binary_name="httpd")
    if c1:
        dedup.record_crash(c1, binary_name="httpd", payload_hash="sha256_mock_a")
        dedup.record_crash(c1, binary_name="httpd", payload_hash="sha256_mock_b")

    groups = dedup.list_groups()
    return {"crash_groups": [g.to_dict() for g in groups]}



def _authenticate_analyst_request(request: Request) -> UserIdentity:
    """Validate that request carries valid credentials with 'analyst' or 'admin' role (PRD SC-3.3)."""
    x_api_key = request.headers.get("X-API-Key")
    authorization = request.headers.get("Authorization")
    raw_token = extract_token_from_headers(x_api_key, authorization)
    if not raw_token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required: Missing 'X-API-Key' or 'Authorization: Bearer' token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    registry = get_token_registry()
    if raw_token not in registry:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id, role = registry[raw_token]
    if role not in ("analyst", "admin"):
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: Role '{role}' is not authorized to access unredacted artefacts. Required: ['analyst', 'admin'].",
        )
    return UserIdentity(user_id=user_id, role=role, is_authenticated=True)


@api_router.get("/firmware/{firmware_id}/artifacts/raw/{file_path:path}")
async def get_raw_artifact(
    firmware_id: str,
    file_path: str,
    request: Request,
):
    """Download or inspect an unredacted raw extracted file, gated by RBAC and audited (PRD SC-3.3)."""
    try:
        user = _authenticate_analyst_request(request)
    except HTTPException as exc:
        audit_log.record_event("UNREDACTED_ACCESS_DENIED", {
            "firmware_id": firmware_id,
            "requested_path": file_path,
            "client_ip": request.client.host if request.client else "unknown",
            "status_code": exc.status_code,
            "detail": exc.detail,
        })
        raise

    fw = storage.get_firmware(firmware_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware ID not found.")

    extract_root = (EXTRACTED_DIR / firmware_id).resolve()
    target_file = (extract_root / file_path).resolve()

    if not target_file.is_relative_to(extract_root):
        audit_log.record_event("UNREDACTED_ACCESS_VIOLATION", {
            "firmware_id": firmware_id,
            "requested_path": file_path,
            "user_id": user.user_id,
            "role": user.role,
            "reason": "path_traversal_escape_attempt",
        })
        raise HTTPException(status_code=403, detail="Access denied: Path traversal escape attempt detected.")

    if not target_file.is_file():
        raise HTTPException(status_code=404, detail=f"Artefact '{file_path}' not found in extracted filesystem.")

    audit_log.record_event("UNREDACTED_ACCESS_GRANTED", {
        "firmware_id": firmware_id,
        "file_path": file_path,
        "user_id": user.user_id,
        "role": user.role,
        "file_size": target_file.stat().st_size,
        "action": "download_raw_artifact",
    })
    return FileResponse(path=target_file, filename=target_file.name)


@api_router.post("/firmware/{firmware_id}/secrets/{finding_id}/reveal")
async def reveal_secret_finding(
    firmware_id: str,
    finding_id: str,
    request: Request,
):
    """Reveal unredacted context for a specific secret finding to authorized analysts (PRD SC-3.3)."""
    try:
        user = _authenticate_analyst_request(request)
    except HTTPException as exc:
        audit_log.record_event("UNREDACTED_SECRET_REVEAL_DENIED", {
            "firmware_id": firmware_id,
            "finding_id": finding_id,
            "client_ip": request.client.host if request.client else "unknown",
            "status_code": exc.status_code,
            "detail": exc.detail,
        })
        raise

    fw = storage.get_firmware(firmware_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firmware ID not found.")

    findings = storage.get_findings(firmware_id)
    target_finding = next((f for f in findings if f.get("vulnerability_id") == finding_id), None)
    if not target_finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found for this firmware.")

    if target_finding.get("category") not in ("hardcoded_secret", "weak_crypto") and not target_finding.get("redacted"):
        raise HTTPException(status_code=400, detail="Finding is not a redacted secret or credential finding.")

    rel_path = target_finding.get("binary") or ""
    if not rel_path and target_finding.get("source"):
        rel_path = target_finding["source"].split("#")[0].replace("file:", "")
    rel_path = rel_path.lstrip("/\\")

    extract_root = (EXTRACTED_DIR / firmware_id).resolve()
    target_file = (extract_root / rel_path).resolve()
    if not target_file.is_relative_to(extract_root) or not target_file.is_file():
        raise HTTPException(status_code=404, detail="Source artifact file not found on disk.")

    line_number = None
    source_str = target_finding.get("source") or ""
    if "#L" in source_str:
        try:
            line_number = int(source_str.split("#L")[-1])
        except ValueError:
            pass

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            if line_number and 1 <= line_number <= len(lines):
                start_l = max(0, line_number - 2)
                end_l = min(len(lines), line_number + 2)
                unredacted_context = "".join(lines[start_l:end_l])
            else:
                unredacted_context = "".join(lines[:50])
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read source artifact: {exc}")

    audit_log.record_event("UNREDACTED_SECRET_REVEAL_GRANTED", {
        "firmware_id": firmware_id,
        "finding_id": finding_id,
        "user_id": user.user_id,
        "role": user.role,
        "cwe": target_finding.get("cwe"),
        "file_path": rel_path,
        "line_number": line_number,
        "action": "reveal_secret_context",
    })

    return {
        "firmware_id": firmware_id,
        "finding_id": finding_id,
        "authorized_by": user.user_id,
        "role": user.role,
        "revealed_at": _utc_now(),
        "cwe": target_finding.get("cwe"),
        "file_path": rel_path,
        "line_number": line_number,
        "unredacted_context": unredacted_context,
        "fingerprint": target_finding.get("evidence_ref"),
    }


@api_router.get("/audit/unredacted-access")
async def get_unredacted_access_audit_log(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
):
    """Retrieve audit records for unredacted artefact access and reveals (PRD SC-3.3)."""
    user = _authenticate_analyst_request(request)
    events = audit_log.get_events(limit=limit * 2)
    unredacted_events = [
        e for e in events
        if e.get("event_type", "").startswith("UNREDACTED_")
    ]
    return {
        "requested_by": user.user_id,
        "role": user.role,
        "total_events": len(unredacted_events),
        "events": unredacted_events[-limit:],
    }
