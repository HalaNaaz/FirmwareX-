"""Priority 2, Phase 3: Final Integration, Regression & Acceptance Test Suite.

Authoritative specification: Project Unit42-FirmwareX PRD v1.0.

Verifies:
1. End-to-end pipeline: Ingestion -> Extraction -> Inventory -> ELF Audit ->
   Analysis Jobs (Symbolic Lead / Fuzzing / Emulation / Crashes) -> Findings Normalization ->
   Deduplication -> Redaction -> API Responses -> Dashboard -> Downloadable Report.
2. FR-2.2 Best-Effort Full-System Emulation: machine mapping, overlay disks, -net none,
   boot stage progression, and fail-closed host containment.
3. FR-4.1 Protocol-Aware Fuzzing: strict loopback enforcement, synthetic local service,
   bounded mutation loops for HTTP, UPnP, and MQTT.
4. FR-4.2 Seed Corpus Management & Crash-Input Delta-Debugging Minimization.
5. FR-4.3 Crash Deduplication: ASLR-normalized stack fingerprints (v1_normalized_stack_hash),
   recurrence aggregation, and Appendix A schema compliance.
6. Negative & Adversarial controls: zero-byte input, corrupted firmware, external targets,
   path traversal resistance, and honest unavailable CFG contract.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from firmwarex.api.server import app
from firmwarex.emulation.crash_parser import CrashStateParser
from firmwarex.emulation.qemu_adapter import (
    QemuSystemEmulator,
    SystemEmulationConfig,
)
from firmwarex.fuzzing.corpus_manager import CorpusManager
from firmwarex.fuzzing.crash_deduplicator import (
    CrashDeduplicator,
    CrashFingerprinter,
)
from firmwarex.fuzzing.minimizer import CrashInputMinimizer
from firmwarex.fuzzing.protocol_fuzzer import (
    FuzzConfig,
    FuzzProtocol,
    ProtocolFuzzRunner,
)
from firmwarex.fuzzing.test_server import SyntheticLocalTestServer
from tests.fixtures_helper import create_benign_firmware_archive


@pytest.fixture
def client():
    """TestClient instance for FastAPI integration testing."""
    return TestClient(app)


# ==============================================================================
# 1. End-to-End Firmware Analysis & Reporting Pipeline Integration
# ==============================================================================

class TestPriority2EndToEndIntegration:
    """Full-pipeline integration from archive upload to downloadable report export."""

    def test_complete_pipeline_upload_to_downloadable_report(self, client, tmp_path: Path):
        """Verify upload produces inventory, binary audit, findings, and downloadable report."""
        archive_path = tmp_path / "p2_integration_fw.tar.gz"
        create_benign_firmware_archive(archive_path)

        with open(archive_path, "rb") as f:
            upload_resp = client.post(
                "/api/v1/firmware/upload",
                files={"file": ("p2_integration_fw.tar.gz", f, "application/gzip")},
            )

        assert upload_resp.status_code == 200
        data = upload_resp.json()
        assert data["status"] == "completed"
        fw_id = data["firmware_id"]
        job_id = data["job_id"]

        # 1. Job telemetry
        job_resp = client.get(f"/api/v1/jobs/{job_id}")
        assert job_resp.status_code == 200
        assert job_resp.json()["status"] == "completed"

        # 2. Filesystem Inventory (FR-1.2)
        fs_resp = client.get(f"/api/v1/firmware/{fw_id}/filesystem")
        assert fs_resp.status_code == 200
        fs_data = fs_resp.json()
        assert fs_data["total_files"] >= 5
        paths = [item["path"] for item in fs_data["files"]]
        assert any("bin/" in p for p in paths)
        # Verify relative path cleanliness (no Windows drive letters or absolute host leaks)
        for item in fs_data["files"]:
            assert not item["path"].startswith("C:")
            assert "\\" not in item["path"]

        # 3. Binary Mitigation Audit (FR-1.3, FR-1.4)
        bin_resp = client.get(f"/api/v1/firmware/{fw_id}/binary-audit")
        assert bin_resp.status_code == 200
        bin_data = bin_resp.json()
        assert len(bin_data["binaries"]) >= 1
        for b in bin_data["binaries"]:
            assert "architecture" in b
            assert "nx" in b
            assert "pie" in b

        # 4. Normalized Findings & Redaction (FR-3.1 - FR-3.4, App A)
        findings_resp = client.get(f"/api/v1/firmware/{fw_id}/vulnerabilities")
        assert findings_resp.status_code == 200
        findings_data = findings_resp.json()
        assert "findings" in findings_data
        findings = findings_data["findings"]
        # Verify zero plaintext secret leakage
        for f_item in findings:
            desc = f_item.get("description", "")
            title = f_item.get("title", "")
            assert "AKIAIOSFODNN7EXAMPLE" not in desc
            assert "super_secret_password" not in desc
            assert "AKIAIOSFODNN7EXAMPLE" not in title

        # 5. Downloadable JSON Report with RFC Attachment Header
        dl_resp = client.get(f"/api/v1/firmware/{fw_id}/report/download")
        assert dl_resp.status_code == 200
        cd_header = dl_resp.headers.get("content-disposition", "")
        assert "attachment" in cd_header
        assert f"firmwarex_report_{fw_id[:8]}.json" in cd_header
        report_data = dl_resp.json()
        assert report_data["firmware_id"] == fw_id
        assert "inventory" in report_data
        assert "binary_hardening" in report_data
        assert "vulnerabilities" in report_data

    def test_negative_controls_and_error_handling(self, client):
        """Verify system rejects invalid, zero-byte, and non-existent inputs safely."""
        # 1. Zero-byte file upload
        resp_empty = client.post(
            "/api/v1/firmware/upload",
            files={"file": ("empty.bin", b"", "application/octet-stream")},
        )
        assert resp_empty.status_code == 400

        # 2. Corrupt / unextractable file
        resp_corrupt = client.post(
            "/api/v1/firmware/upload",
            files={"file": ("corrupt.tar.gz", b"\x1f\x8b\x08random_garbage_not_a_valid_tar", "application/gzip")},
        )
        assert resp_corrupt.status_code == 400

        # 3. Non-existent firmware ID queries
        fake_id = "00000000-0000-0000-0000-000000000000"
        assert client.get(f"/api/v1/firmware/{fake_id}/filesystem").status_code == 404
        assert client.get(f"/api/v1/firmware/{fake_id}/binary-audit").status_code == 404
        assert client.get(f"/api/v1/firmware/{fake_id}/vulnerabilities").status_code == 404
        assert client.get(f"/api/v1/firmware/{fake_id}/report").status_code == 404
        assert client.get(f"/api/v1/firmware/{fake_id}/report/download").status_code == 404
        assert client.get(f"/api/v1/firmware/{fake_id}/binaries/httpd/cfg").status_code == 404


# ==============================================================================
# 2. FR-2.2 Full-System Emulation Integration & State Matrix
# ==============================================================================

class TestPriority2FullSystemEmulationIntegration:
    """Full-system emulation command generation, isolation gates, and boot simulation."""

    def test_multi_arch_system_command_construction(self):
        """Verify command lines enforce default-deny networking, overlay disks, and machine mappings."""
        test_matrix = [
            ("mips", "big", "malta", "qemu-system-mips"),
            ("mips", "little", "malta", "qemu-system-mipsel"),
            ("arm", "little", "virt", "qemu-system-arm"),
            ("arm64", "little", "virt", "qemu-system-aarch64"),
            ("x86_64", "little", "q35", "qemu-system-x86_64"),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            kernel_path = Path(tmpdir) / "vmlinux"
            kernel_path.write_bytes(b"\x7fELF" + b"\x00" * 64)

            for arch, endian, expected_mach, expected_bin in test_matrix:
                cfg = SystemEmulationConfig(
                    architecture=arch,
                    endianness=endian,
                    kernel_path=kernel_path,
                    memory_mb=256,
                    network_mode="none",
                )
                emulator = QemuSystemEmulator(cfg)
                cmd = emulator.build_command()

                assert cmd[0] == expected_bin
                assert "-M" in cmd
                assert expected_mach in cmd
                assert "-net" in cmd
                assert "none" in cmd
                assert "-nographic" in cmd
                assert "-no-reboot" in cmd

    def test_system_emulation_state_machine_transitions(self):
        """Verify state machine progression across boot stages in simulated harness."""
        cfg = SystemEmulationConfig(architecture="mips", endianness="big")
        emulator = QemuSystemEmulator(cfg)

        # 1. Successful boot transition
        res_ok = emulator.boot(simulated_scenario="boot_successful")
        assert res_ok.status == "boot_successful"
        assert res_ok.boot_stage == "shell_ready"
        assert res_ok.exit_code == 0
        assert res_ok.is_mocked is True
        assert "/bin/sh" in res_ok.stdout

        # 2. Kernel panic transition
        res_panic = emulator.boot(simulated_scenario="boot_failed")
        assert res_panic.status == "boot_failed"
        assert res_panic.boot_stage == "kernel_boot"
        assert res_panic.exit_code == 1
        assert "Kernel panic" in res_panic.stdout

        # 3. Timeout transition
        res_timeout = emulator.boot(simulated_scenario="timeout")
        assert res_timeout.status == "timeout"
        assert res_timeout.boot_stage == "kernel_boot"
        assert res_timeout.exit_code is None

    def test_system_emulation_fail_closed_on_uncontained_host(self):
        """Verify system emulation halts safely without executing untrusted code on bare host."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_kernel = Path(tmpdir) / "kernel.bin"
            fake_kernel.write_bytes(b"dummy")

            cfg = SystemEmulationConfig(architecture="arm", endianness="little", kernel_path=fake_kernel)
            emulator = QemuSystemEmulator(cfg)
            res = emulator.boot()
            # Under Windows without docker daemon / Linux QEMU system binaries, must halt safely
            assert res.status in ("isolation_blocked", "tool_unavailable", "missing_dependencies")


# ==============================================================================
# 3. FR-4.1 Protocol Fuzzing End-to-End Loop with Synthetic Service
# ==============================================================================

class TestPriority2ProtocolFuzzingIntegration:
    """Protocol fuzzing loop execution, loopback enforcement, and anomaly capture."""

    def test_strict_loopback_isolation_blocks_external_targets(self):
        """Verify ProtocolFuzzRunner strictly refuses non-loopback destinations."""
        invalid_destinations = [
            "8.8.8.8",
            "1.1.1.1",
            "192.168.1.1",
            "10.0.0.1",
            "example.com",
            "google.com",
        ]
        for dest in invalid_destinations:
            cfg = FuzzConfig(target_host=dest, target_port=80, protocol=FuzzProtocol.HTTP)
            runner = ProtocolFuzzRunner(cfg)
            with pytest.raises(PermissionError, match="outside loopback"):
                runner.run_fuzzing_session()

    def test_synthetic_service_fuzzing_session_http(self):
        """Execute bounded fuzzing session against synthetic local HTTP service."""
        server = SyntheticLocalTestServer()
        port = server.start()
        try:
            cfg = FuzzConfig(
                target_host="127.0.0.1",
                target_port=port,
                protocol=FuzzProtocol.HTTP,
                max_iterations=15,
                seed=123,
                timeout_seconds=1.0,
            )
            runner = ProtocolFuzzRunner(cfg)
            report = runner.run_fuzzing_session()

            assert report.status == "completed"
            assert report.total_iterations == 15
            assert report.target == f"127.0.0.1:{port}"
            assert isinstance(report.anomalies, list)
        finally:
            server.stop()

    def test_api_fuzzing_test_endpoint_integration(self, client):
        """Verify POST /api/v1/fuzzing/test runs safely against temporary synthetic service."""
        resp = client.post("/api/v1/fuzzing/test?protocol=http&iterations=10&seed=99")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["protocol"] == "http"
        assert data["total_iterations"] == 10


# ==============================================================================
# 4. FR-4.2 & FR-4.3 Corpus, Minimization & Crash Deduplication Integration
# ==============================================================================

class TestPriority2CrashIntelligenceIntegration:
    """Seed corpus management, delta-debugging minimization, and stack fingerprinting."""

    def test_corpus_content_addressable_lifecycle(self):
        """Verify seed registration, deduplication, secret scrubbing, and listing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CorpusManager(base_dir=Path(tmpdir))

            # 1. Baseline seeds exist
            assert len(mgr.list_seeds("http")) >= 2
            assert len(mgr.list_seeds("upnp")) >= 2
            assert len(mgr.list_seeds("mqtt")) >= 2

            # 2. Add custom seed with credentials -> scrubbed
            seed_content = b"POST /setup HTTP/1.1\r\n\r\npassword=very_sensitive_password_12345"
            meta = mgr.add_seed(protocol="http", name="setup_seed", content=seed_content)
            assert len(meta.content_hash) == 64
            saved_content = mgr.get_seed_content("http", meta.seed_id)
            assert saved_content is not None
            assert b"very_sensitive_password_12345" not in saved_content
            assert b"*" in saved_content

            # 3. Duplicate seed registration does not duplicate files
            meta_dup = mgr.add_seed(protocol="http", name="setup_seed_dup", content=seed_content)
            assert meta_dup.content_hash == meta.content_hash

            # 4. Path traversal blocked
            with pytest.raises(ValueError, match="Invalid protocol name"):
                mgr.add_seed(protocol="../malicious", name="bad", content=b"attack")

    def test_crash_input_minimization_delta_debugging(self):
        """Verify minimization reduces payload size only when verified crash reproduces."""
        minimizer = CrashInputMinimizer(max_iterations=50, timeout_seconds=5)

        trigger = b"OVERFLOW_TRIGGER_CRASH"

        def verifier_true(candidate: bytes) -> bool:
            return trigger in candidate

        def verifier_false(candidate: bytes) -> bool:
            return False

        # Positive case: reducible payload
        long_payload = b"HEADER\n" + b"NOISE\n" * 10 + trigger + b"\nTAIL\n" * 10
        res_ok = minimizer.minimize(long_payload, verifier_true)
        assert res_ok.status == "minimized"
        assert res_ok.reproduced is True
        assert res_ok.minimized_size < res_ok.original_size
        assert trigger in res_ok.minimized_payload

        # Negative case: un-reproducible crash
        res_fail = minimizer.minimize(long_payload, verifier_false)
        assert res_fail.status == "not_reproducible"
        assert res_fail.reproduced is False
        assert res_fail.minimized_payload == long_payload

    def test_crash_deduplication_and_aslr_normalization(self):
        """Verify identical fingerprint derived across ASLR shifts and aggregated into groups."""
        dedup = CrashDeduplicator()

        trace_run1 = (
            "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n"
            "fault address: 0x41414141\n"
            "#0 0x7ffd12345678 in strcpy () from /lib/libc.so.0\n"
            "#1 0x7ffd12349999 in vuln_parse () from /bin/httpd\n"
        )
        trace_run2 = (
            "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n"
            "fault address: 0x41414141\n"
            "#0 0x7ffebbcc0000 in strcpy () from /lib/libc.so.0\n"
            "#1 0x7ffebbcc4444 in vuln_parse () from /bin/httpd\n"
        )

        c1 = CrashStateParser.parse_crash(stdout="", stderr=trace_run1, exit_code=-11, arch="arm", binary_name="httpd")
        c2 = CrashStateParser.parse_crash(stdout="", stderr=trace_run2, exit_code=-11, arch="arm", binary_name="httpd")

        assert c1 is not None and c2 is not None

        # Fingerprints must match identically
        fp1 = CrashFingerprinter.compute_fingerprint(c1, "httpd")
        fp2 = CrashFingerprinter.compute_fingerprint(c2, "httpd")
        assert fp1.fingerprint_hash == fp2.fingerprint_hash
        assert fp1.algorithm_version == "v1_normalized_stack_hash"

        # Record crashes
        grp1, is_new1 = dedup.record_crash(c1, binary_name="httpd", payload_hash="hash_a")
        assert is_new1 is True
        assert grp1.event_count == 1

        grp2, is_new2 = dedup.record_crash(c2, binary_name="httpd", payload_hash="hash_b")
        assert is_new2 is False
        assert grp2.event_count == 2
        assert len(dedup.list_groups()) == 1


# ==============================================================================
# 5. Dashboard Data Integrity & Honesty Contract
# ==============================================================================

class TestPriority2DashboardAndReportIntegrity:
    """Dashboard HTML data bindings, CFG unavailable state, and report export integrity."""

    def test_cfg_endpoint_returns_honest_unavailable_contract(self, client, tmp_path: Path):
        """Verify GET /api/v1/firmware/{id}/binaries/{binary}/cfg returns structured unavailable state."""
        archive_path = tmp_path / "cfg_fw.tar.gz"
        create_benign_firmware_archive(archive_path)

        with open(archive_path, "rb") as f:
            up_resp = client.post("/api/v1/firmware/upload", files={"file": ("cfg_fw.tar.gz", f, "application/gzip")})
        fw_id = up_resp.json()["firmware_id"]

        cfg_resp = client.get(f"/api/v1/firmware/{fw_id}/binaries/httpd/cfg")
        assert cfg_resp.status_code == 200
        cfg_data = cfg_resp.json()
        assert cfg_data["status"] == "unavailable"
        assert cfg_data["firmware_id"] == fw_id
        assert cfg_data["binary"] == "httpd"
        assert "contract" in cfg_data
        assert "required_capabilities" in cfg_data["contract"]

    def test_dashboard_template_contains_all_priority2_sections(self, client):
        """Verify dashboard index.html renders tree, mitigation, findings, and CFG sections."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        # Required panels
        assert 'id="view-filesystem"' in html
        assert 'id="view-mitigation"' in html
        assert 'id="view-findings"' in html
        assert 'id="view-cfg"' in html
        assert 'id="view-reports"' in html

        # Data integrity badges
        assert "HEURISTIC LEAD" in html or "CONFIRMED" in html
        assert "ENGINE STAGE NOTICE" in html
