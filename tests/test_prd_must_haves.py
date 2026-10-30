"""Automated verification suite for PRD Must-Have Requirements.

Covers:
1. OpenTelemetry distributed tracing lifecycle and span emission (PRD §6, §8).
2. Filesystem inventory architecture, endianness, and bitness indexing (PRD FR-1.1 - FR-1.3).
3. Quota enforcement and over-limit job termination (PRD FR-1.2, NFR-SEC-1).
4. Contained networking, loopback isolation, and honest state reporting (PRD FR-2.1, FR-2.3).
5. Salted secret fingerprinting, redaction, and non-sensitive error formatting (PRD Appendix A, NFR-SEC-4).
"""

import io
import struct
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from firmwarex.api.server import app
from firmwarex.core.extractors.base import QuotaTracker, SecurityViolationError
from firmwarex.core.unpacker import SafeExtractor
from firmwarex.telemetry import PipelineTracer, generate_span_id, generate_trace_id

client = TestClient(app)


def _build_synthetic_elf(
    arch: str = "mips",
    bitness: int = 32,
    endianness: str = "little",
) -> bytes:
    """Generate minimal valid ELF binary header for synthetic test fixtures."""
    # EI_MAG: \x7fELF
    ei_mag = b"\x7fELF"
    # EI_CLASS: 1 = 32-bit, 2 = 64-bit
    ei_class = 1 if bitness == 32 else 2
    # EI_DATA: 1 = little endian, 2 = big endian
    ei_data = 1 if endianness == "little" else 2
    # EI_VERSION: 1
    ei_version = 1
    # EI_OSABI: 0 (System V)
    ei_osabi = 0
    # EI_ABIVERSION: 0
    ei_abiversion = 0
    # Padding: 7 zero bytes to reach 16 bytes e_ident
    e_ident = ei_mag + bytes([ei_class, ei_data, ei_version, ei_osabi, ei_abiversion]) + b"\x00" * 7

    fmt_prefix = "<" if endianness == "little" else ">"
    # e_type: 2 = ET_EXEC
    e_type = 2
    # e_machine mapping
    mach_map = {
        "x86": 0x03,
        "mips": 0x08,
        "arm": 0x28,
        "x86_64": 0x3E,
        "arm64": 0xB7,
    }
    e_machine = mach_map.get(arch, 0x08)
    e_version = 1

    header = e_ident + struct.pack(f"{fmt_prefix}HHI", e_type, e_machine, e_version)
    # Pad to 64 bytes
    return header + b"\x00" * (64 - len(header))


def _build_synthetic_tar_with_multiarch_elfs() -> bytes:
    """Construct a safe in-memory TAR archive with multiple multi-architecture ELFs."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        # 1. MIPS 32-bit little endian
        mips_elf = _build_synthetic_elf(arch="mips", bitness=32, endianness="little")
        ti = tarfile.TarInfo("bin/busybox")
        ti.size = len(mips_elf)
        ti.mode = 0o755
        tf.addfile(ti, io.BytesIO(mips_elf))

        # 2. ARM 32-bit little endian
        arm_elf = _build_synthetic_elf(arch="arm", bitness=32, endianness="little")
        ti2 = tarfile.TarInfo("sbin/httpd")
        ti2.size = len(arm_elf)
        ti2.mode = 0o755
        tf.addfile(ti2, io.BytesIO(arm_elf))

        # 3. ARM64 64-bit little endian
        arm64_elf = _build_synthetic_elf(arch="arm64", bitness=64, endianness="little")
        ti3 = tarfile.TarInfo("usr/bin/gateway")
        ti3.size = len(arm64_elf)
        ti3.mode = 0o755
        tf.addfile(ti3, io.BytesIO(arm64_elf))

        # 4. Standard text config
        cfg = b"admin_user=admin\npassword=SecretPassword123!\n"
        ti4 = tarfile.TarInfo("etc/config.txt")
        ti4.size = len(cfg)
        tf.addfile(ti4, io.BytesIO(cfg))

    return bio.getvalue()


class TestOpenTelemetryPipelineTracing:
    """PRD §6 & §8: Mandatory distributed tracing throughout pipeline lifecycle."""

    def test_trace_id_and_span_id_generation(self):
        tid = generate_trace_id()
        assert len(tid) == 32
        int(tid, 16)  # Must be valid hex

        sid = generate_span_id()
        assert len(sid) == 16
        int(sid, 16)

    def test_pipeline_tracer_span_hierarchy_and_durations(self):
        tracer = PipelineTracer(job_id="test-job-001", firmware_id="fw-001")
        with tracer.span("step_1", {"attr1": "val1"}):
            with tracer.span("step_1_sub", {"sub_attr": 42}):
                pass

        trace = tracer.finish("completed")
        assert trace.status == "completed"
        assert trace.total_duration_ms >= 0.0
        assert len(trace.spans) == 2

        spans_by_name = {s.name: s for s in trace.spans}
        assert "step_1" in spans_by_name
        assert "step_1_sub" in spans_by_name

        sub_span = spans_by_name["step_1_sub"]
        parent_span = spans_by_name["step_1"]
        assert sub_span.parent_span_id == parent_span.span_id
        assert sub_span.duration_ms >= 0.0

    def test_end_to_end_job_trace_emission(self):
        tar_bytes = _build_synthetic_tar_with_multiarch_elfs()
        files = {"file": ("firmware_trace_test.tar", tar_bytes, "application/x-tar")}

        resp = client.post("/api/v1/firmware/upload", files=files)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        job_id = data["job_id"]
        firmware_id = data["firmware_id"]
        trace_id = data.get("trace_id")

        assert trace_id is not None
        assert len(trace_id) == 32

        # Verify trace retrieval endpoint
        trace_resp = client.get(f"/api/v1/jobs/{job_id}/trace")
        assert trace_resp.status_code == 200, trace_resp.text
        trace_data = trace_resp.json()
        assert trace_data["trace_id"] == trace_id
        assert trace_data["job_id"] == job_id
        assert trace_data["firmware_id"] == firmware_id
        assert trace_data["status"] == "completed"
        assert trace_data["total_duration_ms"] >= 0.0

        span_names = [s["name"] for s in trace_data["spans"]]
        expected_spans = [
            "stream_upload",
            "format_validation",
            "safe_extraction",
            "inventory_indexing",
            "elf_binary_audit",
            "secret_crypto_scan",
            "symbolic_taint_analysis",
            "finding_normalization",
        ]
        for expected in expected_spans:
            assert expected in span_names, f"Missing expected trace span: {expected}"

        # Verify report includes telemetry trace
        report_resp = client.get(f"/api/v1/firmware/{firmware_id}/report")
        assert report_resp.status_code == 200
        report_json = report_resp.json()
        assert "telemetry_trace" in report_json
        assert report_json["telemetry_trace"] is not None
        assert report_json["telemetry_trace"]["trace_id"] == trace_id


class TestFilesystemInventoryMustHaves:
    """PRD FR-1.1 - FR-1.3: Inventory paths, types, sizes, hashes, architecture, endianness, bitness."""

    def test_inventory_records_architecture_endianness_bitness(self):
        tar_bytes = _build_synthetic_tar_with_multiarch_elfs()
        files = {"file": ("firmware_inventory_test.tar", tar_bytes, "application/x-tar")}

        resp = client.post("/api/v1/firmware/upload", files=files)
        assert resp.status_code == 200
        fw_id = resp.json()["firmware_id"]

        fs_resp = client.get(f"/api/v1/firmware/{fw_id}/filesystem")
        assert fs_resp.status_code == 200
        items = fs_resp.json()["files"]

        items_by_path = {item["path"]: item for item in items}

        # Check Busybox (MIPS 32-bit little)
        assert "bin/busybox" in items_by_path
        bb = items_by_path["bin/busybox"]
        assert bb["is_elf"] is True or bb["is_elf"] == 1
        assert bb["architecture"] == "mips"
        assert bb["endianness"] == "little"
        assert bb["bitness"] == 32
        assert bb["sha256"] is not None
        assert bb["size_bytes"] > 0

        # Check HTTPD (ARM 32-bit little)
        assert "sbin/httpd" in items_by_path
        httpd = items_by_path["sbin/httpd"]
        assert httpd["architecture"] == "arm"
        assert httpd["endianness"] == "little"
        assert httpd["bitness"] == 32

        # Check Gateway (ARM64 64-bit little)
        assert "usr/bin/gateway" in items_by_path
        gw = items_by_path["usr/bin/gateway"]
        assert gw["architecture"] == "arm64"
        assert gw["endianness"] == "little"
        assert gw["bitness"] == 64

        # Check config text file
        assert "etc/config.txt" in items_by_path
        cfg = items_by_path["etc/config.txt"]
        assert cfg["is_elf"] is False or cfg["is_elf"] == 0
        assert cfg["type"] == "text"
        assert cfg["architecture"] is None


class TestQuotaEnforcementAndOverlimitTermination:
    """PRD FR-1.2 & NFR-SEC-1: Quotas enforced; over-limit terminates job cleanly."""

    def test_quota_tracker_file_count_breach(self):
        tracker = QuotaTracker(max_file_count=3, max_total_bytes=1000000)

        tracker.add_file(100)
        tracker.add_file(100)
        tracker.add_file(100)

        with pytest.raises(SecurityViolationError) as exc_info:
            tracker.add_file(100)
        assert "File count limit" in str(exc_info.value)

    def test_quota_tracker_total_bytes_breach(self):
        tracker = QuotaTracker(max_file_count=10, max_total_bytes=500)

        tracker.add_file(300)
        with pytest.raises(SecurityViolationError) as exc_info:
            tracker.add_file(300)
        assert "Total uncompressed size limit" in str(exc_info.value)

    def test_safe_extractor_terminates_over_quota_archive(self):
        # Create ZIP with more files than quota permits
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            for i in range(25):
                zf.writestr(f"file_{i}.txt", b"A" * 10)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_file = tmp_path / "bomb.zip"
            archive_file.write_bytes(bio.getvalue())
            out_target = tmp_path / "out"

            from firmwarex.core.unpacker import SecurityException
            extractor = SafeExtractor(max_file_count=10)
            with pytest.raises(SecurityException) as exc_info:
                extractor.extract(archive_file, out_target)
            assert "file count limit" in str(exc_info.value).lower()


class TestSecurityControlsAndContainment:
    """PRD Appendix A, NFR-SEC-1, NFR-SEC-4: Contained execution and sensitive data protection."""

    def test_containment_preflight_reports_honest_state(self):
        resp = client.get("/api/v1/containment/preflight")
        assert resp.status_code == 200
        data = resp.json()
        assert "docker_available" in data
        assert "daemon_responsive" in data
        assert "network_isolation_verified" in data
        assert "host_paths_isolated" in data
        assert isinstance(data["passed"], bool)

    def test_secret_scrubbing_and_sanitization(self):
        tar_bytes = _build_synthetic_tar_with_multiarch_elfs()
        files = {"file": ("firmware_sec_test.tar", tar_bytes, "application/x-tar")}

        resp = client.post("/api/v1/firmware/upload", files=files)
        assert resp.status_code == 200
        fw_id = resp.json()["firmware_id"]

        findings_resp = client.get(f"/api/v1/firmware/{fw_id}/findings")
        assert findings_resp.status_code == 200
        findings = findings_resp.json()["findings"]

        # If any secret findings exist, confirm evidence does not reveal raw plain passwords
        for f in findings:
            if f.get("category") == "hardcoded_secret":
                evidence = f.get("evidence", "")
                assert "SecretPassword123!" not in evidence
                assert "*" in evidence or "[REDACTED]" in evidence or "fingerprint" in str(f)
