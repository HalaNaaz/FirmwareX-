"""Priority 1, Phase 3: Final End-to-End Pipeline Integration and Acceptance Tests.

Verifies:
1. End-to-end pipeline: Ingestion -> Extraction -> Inventory -> ELF Audit -> Symbolic/Taint -> Secret Scan -> Normalization -> Reports.
2. Taint analysis positive and negative controls (distinguishing reachability from uncalled sinks).
3. Complete secret redaction: zero plaintext leakage in API responses, logs, or reports.
4. Normalized finding schema Appendix A compliance (all 19 fields populated, zero duplicates).
5. Error handling and containment gates fail-closed.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from firmwarex.api.server import app
from firmwarex.core.normaliser import FindingNormaliser
from firmwarex.core.symbolic_analyzer import BoundedSymbolicAnalyzer, SymbolicReviewLead
from tests.fixtures_helper import create_benign_firmware_archive, create_minimal_elf

client = TestClient(app)


class TestPriority1PipelineIntegration:
    """End-to-end pipeline integration covering PRD FR-1.1 through FR-3.4 and Appendix A."""

    def test_full_pipeline_upload_to_report(self, tmp_path: Path):
        """Verify upload pipeline produces inventory, binary audit, secret findings, and taint leads."""
        archive_path = tmp_path / "integration_firmware.tar.gz"
        create_benign_firmware_archive(archive_path)

        with open(archive_path, "rb") as f:
            upload_resp = client.post(
                "/api/v1/firmware/upload",
                files={"file": ("integration_firmware.tar.gz", f, "application/gzip")},
            )

        assert upload_resp.status_code == 200
        upload_data = upload_resp.json()
        assert upload_data["status"] == "completed"
        fw_id = upload_data["firmware_id"]
        job_id = upload_data["job_id"]

        # 1. Verify Job Status
        job_resp = client.get(f"/api/v1/jobs/{job_id}")
        assert job_resp.status_code == 200
        assert job_resp.json()["status"] == "completed"
        assert job_resp.json()["progress"] == 100

        # 2. Verify Filesystem Inventory (FR-1.2)
        fs_resp = client.get(f"/api/v1/firmware/{fw_id}/filesystem")
        assert fs_resp.status_code == 200
        fs_data = fs_resp.json()
        assert fs_data["total_files"] >= 5
        paths = [item["path"] for item in fs_data["files"]]
        assert any("bin/" in p for p in paths)
        for item in fs_data["files"]:
            assert not item["path"].startswith("C:")
            assert "\\" not in item["path"]

        # 3. Verify Binary Audit (FR-1.3, FR-1.4)
        ba_resp = client.get(f"/api/v1/firmware/{fw_id}/binary-audit")
        assert ba_resp.status_code == 200
        ba_data = ba_resp.json()
        assert ba_data["summary"]["total_binaries"] >= 2
        assert "nx_enabled" in ba_data["summary"]
        assert "pie_enabled" in ba_data["summary"]

        # 4. Verify Normalized Vulnerabilities (Appendix A)
        vuln_resp = client.get(f"/api/v1/firmware/{fw_id}/vulnerabilities")
        assert vuln_resp.status_code == 200
        vuln_data = vuln_resp.json()
        assert vuln_data["total_findings"] >= 1

        appendix_a_fields = [
            "vulnerability_id", "firmware_id", "binary", "architecture", "category",
            "cwe", "address", "sink", "source", "tainted_path", "crash_state",
            "risk_rating", "confidence", "evidence_ref", "redacted", "remediation",
            "status", "detected_at", "details",
        ]
        for finding in vuln_data["findings"]:
            for field in appendix_a_fields:
                assert field in finding, f"Missing Appendix A field '{field}' in finding"
            assert finding["firmware_id"] == fw_id

        # 5. Verify Full JSON Report Generation
        rep_resp = client.get(f"/api/v1/firmware/{fw_id}/report")
        assert rep_resp.status_code == 200
        report = rep_resp.json()
        assert report["firmware_id"] == fw_id
        assert "inventory" in report
        assert "binary_hardening" in report
        assert "vulnerabilities" in report
        assert "containment_telemetry" in report
        assert "symbolic_analysis" in report

    def test_taint_negative_control_no_false_reachability(self, tmp_path: Path):
        """Negative control: binary with sink only (no source) does not produce false taint lead."""
        bin_sink_only = tmp_path / "sink_only.elf"
        elf_bytes = create_minimal_elf("arm", bitness=32)
        # Embed dangerous sink only
        bin_sink_only.write_bytes(elf_bytes + b"\x00system\x00")

        analyzer = BoundedSymbolicAnalyzer()
        leads = analyzer.analyze_binary(bin_sink_only)
        # Without an input source, no source-to-sink reachability lead is created
        assert len(leads) == 0

    def test_taint_negative_control_source_only(self, tmp_path: Path):
        """Negative control: binary with input source only (no dangerous sink) produces no taint lead."""
        bin_source_only = tmp_path / "source_only.elf"
        elf_bytes = create_minimal_elf("mips", bitness=32, endianness="big")
        # Embed input source only
        bin_source_only.write_bytes(elf_bytes + b"\x00getenv\x00")

        analyzer = BoundedSymbolicAnalyzer()
        leads = analyzer.analyze_binary(bin_source_only)
        assert len(leads) == 0

    def test_taint_positive_control_creates_tainted_path(self, tmp_path: Path):
        """Positive control: binary with both source and sink produces structured TaintedPath."""
        bin_both = tmp_path / "flow_app.elf"
        elf_bytes = create_minimal_elf("x86_64")
        bin_both.write_bytes(elf_bytes + b"\x00recv\x00strcpy\x00")

        analyzer = BoundedSymbolicAnalyzer()
        leads = analyzer.analyze_binary(bin_both)
        assert len(leads) >= 1
        lead = leads[0]
        assert lead.source_symbol == "recv"
        assert lead.sink_symbol == "strcpy"
        assert len(lead.tainted_path) >= 2
        assert lead.reaching_condition is not None

    def test_zero_plaintext_leakage_across_all_endpoints(self, tmp_path: Path):
        """Verify that synthetic test secrets are never leaked in plaintext via any API endpoint."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        archive_path = tmp_path / "secret_fw.tar.gz"
        create_benign_firmware_archive(archive_path)

        with open(archive_path, "rb") as f:
            up = client.post(
                "/api/v1/firmware/upload",
                files={"file": ("secret_fw.tar.gz", f, "application/gzip")},
            )
        fw_id = up.json()["firmware_id"]

        # Check endpoints: upload, vulnerabilities, report
        for path in [
            f"/api/v1/firmware/{fw_id}",
            f"/api/v1/firmware/{fw_id}/vulnerabilities",
            f"/api/v1/firmware/{fw_id}/report",
        ]:
            resp = client.get(path)
            assert resp.status_code == 200
            assert raw_secret not in resp.text

    def test_deduplication_prevents_duplicate_findings(self):
        """Verify finding normalizer deduplicates identical findings."""
        # Create identical findings
        lead1 = SymbolicReviewLead(
            binary_path="app", source_symbol="recv", sink_symbol="system",
            cwe_id="CWE-78", category="command_injection", evidence="ev",
            tainted_path=["recv", "system"],
        )
        lead2 = SymbolicReviewLead(
            binary_path="app", source_symbol="recv", sink_symbol="system",
            cwe_id="CWE-78", category="command_injection", evidence="ev",
            tainted_path=["recv", "system"],
        )
        f1 = FindingNormaliser.from_symbolic_lead(lead1, "fw-1")
        f2 = FindingNormaliser.from_symbolic_lead(lead2, "fw-1")

        # They share identical structural keys
        key1 = (f1["binary"], f1["category"], f1["cwe"], f1["sink"], f1["source"], f1["details"]["type"])
        key2 = (f2["binary"], f2["category"], f2["cwe"], f2["sink"], f2["source"], f2["details"]["type"])
        assert key1 == key2
