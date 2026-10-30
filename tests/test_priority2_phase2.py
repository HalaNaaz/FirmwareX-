"""Tests for Priority 2, Phase 2: Advanced Emulation, Protocol Fuzzing & Crash Intelligence.

Covers:
- FR-2.2: Best-effort full-system emulation (machine mapper, overlay disk, -net none, boot stages).
- FR-4.1: Protocol-aware fuzzing & strict loopback validation.
- FR-4.2: Content-addressable seed corpus management & crash-input delta-debugging minimization.
- FR-4.3: Crash deduplication with ASLR-normalized stack hashing & Appendix A finding generation.
- FastAPI REST API endpoints for emulation, corpus, minimization, and crash intelligence.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from firmwarex.api.server import app
from firmwarex.emulation.crash_parser import CrashStateParser
from firmwarex.emulation.qemu_adapter import (
    QemuSystemArchitectureMapper,
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


@pytest.fixture
def client():
    """Test client for FastAPI API endpoints."""
    return TestClient(app)


# ==============================================================================
# FR-2.2: Full-System Emulation Tests
# ==============================================================================

class TestFullSystemEmulation:
    """Test best-effort full-system emulation configuration and isolation."""

    def test_qemu_system_architecture_mapper(self):
        """Verify standard embedded architectures map to correct QEMU machine & binary."""
        # MIPS big endian -> malta
        mips_p = QemuSystemArchitectureMapper.get_system_profile("mips", "big")
        assert mips_p is not None
        assert mips_p["binary"] == "qemu-system-mips"
        assert mips_p["machine"] == "malta"

        # MIPS little endian -> malta
        mipsel_p = QemuSystemArchitectureMapper.get_system_profile("mips", "little")
        assert mipsel_p is not None
        assert mipsel_p["binary"] == "qemu-system-mipsel"
        assert mipsel_p["machine"] == "malta"

        # ARM little endian -> virt
        arm_p = QemuSystemArchitectureMapper.get_system_profile("arm", "little")
        assert arm_p is not None
        assert arm_p["binary"] == "qemu-system-arm"
        assert arm_p["machine"] == "virt"

        # ARM64 little endian -> virt
        arm64_p = QemuSystemArchitectureMapper.get_system_profile("arm64", "little")
        assert arm64_p is not None
        assert arm64_p["binary"] == "qemu-system-aarch64"
        assert arm64_p["machine"] == "virt"

        # x86_64 little endian -> q35
        x64_p = QemuSystemArchitectureMapper.get_system_profile("x86_64", "little")
        assert x64_p is not None
        assert x64_p["binary"] == "qemu-system-x86_64"
        assert x64_p["machine"] == "q35"

        # Unsupported
        unknown_p = QemuSystemArchitectureMapper.get_system_profile("sparc", "big")
        assert unknown_p is None

    def test_system_emulation_config_and_cmd_builder(self):
        """Verify command construction enforces -net none, memory sizing, and overlay disks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kernel_path = Path(tmpdir) / "vmlinux"
            drive_path = Path(tmpdir) / "rootfs.ext4"
            kernel_path.write_bytes(b"\x7fELF" + b"\x00" * 100)
            drive_path.write_bytes(b"\x00" * 4096)

            config = SystemEmulationConfig(
                architecture="mips",
                endianness="big",
                kernel_path=kernel_path,
                drive_image_path=drive_path,
                memory_mb=256,
                use_disposable_overlay=True,
                network_mode="none",
            )

            emulator = QemuSystemEmulator(config)
            cmd = emulator.build_command()

            assert "-M" in cmd
            assert "malta" in cmd
            assert "-m" in cmd
            assert "256M" in cmd
            assert "-kernel" in cmd
            assert str(kernel_path) in cmd
            assert "-net" in cmd
            assert "none" in cmd
            assert "-nographic" in cmd
            assert "-no-reboot" in cmd

    def test_system_emulator_fail_closed_without_runtime(self):
        """Verify system emulator fails closed if host execution environment is uncontained."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kernel = Path(tmpdir) / "kernel.bin"
            kernel.write_bytes(b"dummy")

            config = SystemEmulationConfig(
                architecture="arm",
                endianness="little",
                kernel_path=kernel,
            )
            emulator = QemuSystemEmulator(config)
            result = emulator.boot()
            # Under Windows without docker or Linux qemu-system-arm, must halt safely
            assert result.status in ("isolation_blocked", "tool_unavailable", "missing_dependencies")

    def test_system_emulator_simulation_boot_stages(self):
        """Verify boot stage parsing and state transitions in simulated harness."""
        config = SystemEmulationConfig(architecture="mips", endianness="big")
        emulator = QemuSystemEmulator(config)

        # Successful boot scenario
        res_ok = emulator.boot(simulated_scenario="boot_successful")
        assert res_ok.status == "boot_successful"
        assert res_ok.boot_stage == "shell_ready"
        assert res_ok.exit_code == 0
        assert res_ok.is_mocked is True
        assert "/bin/sh" in res_ok.stdout

        # Kernel panic scenario
        res_fail = emulator.boot(simulated_scenario="boot_failed")
        assert res_fail.status == "boot_failed"
        assert res_fail.boot_stage == "kernel_boot"
        assert "Kernel panic" in res_fail.stdout

        # Timeout scenario
        res_to = emulator.boot(simulated_scenario="timeout")
        assert res_to.status == "timeout"
        assert res_to.boot_stage == "kernel_boot"


# ==============================================================================
# FR-4.1: Defensive Fuzzer Loopback Guard Tests
# ==============================================================================

class TestDefensiveFuzzerLoopback:
    """Test strict loopback target enforcement in protocol fuzzer."""

    def test_rejects_external_ip_addresses(self):
        """Verify external IPv4 addresses are immediately rejected with PermissionError."""
        cfg = FuzzConfig(
            target_host="8.8.8.8",
            target_port=80,
            protocol=FuzzProtocol.HTTP,
        )
        runner = ProtocolFuzzRunner(cfg)
        with pytest.raises(PermissionError, match="outside loopback"):
            runner.run_fuzzing_session()

    def test_rejects_external_hostnames(self):
        """Verify non-localhost hostnames are resolved and blocked."""
        cfg = FuzzConfig(
            target_host="example.com",
            target_port=80,
            protocol=FuzzProtocol.HTTP,
        )
        runner = ProtocolFuzzRunner(cfg)
        with pytest.raises(PermissionError, match="outside loopback"):
            runner.run_fuzzing_session()

    def test_allows_valid_loopback_addresses(self):
        """Verify 127.0.0.1 passes destination isolation preflight check."""
        cfg = FuzzConfig(
            target_host="127.0.0.1",
            target_port=65432,
            protocol=FuzzProtocol.HTTP,
            max_iterations=1,
        )
        runner = ProtocolFuzzRunner(cfg)
        # Does not raise PermissionError; may catch connection error if nothing listens
        report = runner.run_fuzzing_session()
        assert report.status == "completed"
        assert report.target == "127.0.0.1:65432"


# ==============================================================================
# FR-4.2: Seed Corpus Management Tests
# ==============================================================================

class TestSeedCorpusManagement:
    """Test content-addressable seed corpus storage, deduplication, and sanitization."""

    def test_corpus_seed_storage_and_deduplication(self):
        """Verify SHA-256 content addressable storage and duplicate suppression."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CorpusManager(base_dir=Path(tmpdir))

            payload = b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            meta1 = mgr.add_seed(protocol="http", name="benign_http_get", content=payload)
            assert meta1.protocol == "http"
            assert meta1.size_bytes == len(payload)
            assert len(meta1.content_hash) == 64

            # Verify saved file exists
            seed_file = Path(tmpdir) / "http" / f"{meta1.seed_id}.bin"
            assert seed_file.is_file()

            # Re-adding same payload returns existing entry without creating duplicate file
            meta2 = mgr.add_seed(protocol="http", name="duplicate_get", content=payload)
            assert meta2.content_hash == meta1.content_hash

            # Retrieve content
            retrieved = mgr.get_seed_content("http", meta1.seed_id)
            assert retrieved == payload

            # Verify list
            seeds = mgr.list_seeds(protocol="http")
            # Baseline + newly added seed
            assert any(s.content_hash == meta1.content_hash for s in seeds)

    def test_corpus_path_traversal_prevention(self):
        """Verify malicious protocol strings and hash lookups fail safely."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CorpusManager(base_dir=Path(tmpdir))

            with pytest.raises(ValueError, match="Invalid protocol name"):
                mgr.add_seed(protocol="../../../etc", name="malicious", content=b"payload")

    def test_corpus_secret_scrubbing(self):
        """Verify credentials in seeds are scrubbed from stored payload."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CorpusManager(base_dir=Path(tmpdir))
            sensitive_payload = b"POST /login HTTP/1.1\r\n\r\npassword=super_secret_password_123!"
            meta = mgr.add_seed(protocol="http", name="login_seed", content=sensitive_payload)
            content = mgr.get_seed_content("http", meta.seed_id)
            assert content is not None
            assert b"super_secret_password_123!" not in content
            assert b"*" in content

    def test_default_baseline_seeds(self):
        """Verify built-in baseline seeds exist for HTTP, UPnP, and MQTT."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CorpusManager(base_dir=Path(tmpdir))
            http_seeds = mgr.list_seeds(protocol="http")
            upnp_seeds = mgr.list_seeds(protocol="upnp")
            mqtt_seeds = mgr.list_seeds(protocol="mqtt")

            assert len(http_seeds) >= 2
            assert len(upnp_seeds) >= 2
            assert len(mqtt_seeds) >= 2


# ==============================================================================
# FR-4.2: Crash-Input Minimization Tests
# ==============================================================================

class TestCrashInputMinimization:
    """Test delta-debugging minimization of crashing inputs."""

    def test_line_based_delta_debugging_minimization(self):
        """Verify large payload with crash trigger is reduced to minimal crashing form."""
        minimizer = CrashInputMinimizer(max_iterations=100, timeout_seconds=10)

        # Bug triggers only if token "VULN_TRIGGER" is present
        def mock_reproduce(candidate: bytes) -> bool:
            return b"VULN_TRIGGER" in candidate

        original_payload = (
            b"Line 1: unnecessary header\n"
            b"Line 2: useless padding\n"
            b"Line 3: VULN_TRIGGER\n"
            b"Line 4: trailing noise\n"
            b"Line 5: even more noise\n"
        )

        res = minimizer.minimize(original_payload, mock_reproduce)
        assert res.reproduced is True
        assert res.status == "minimized"
        assert res.minimized_size < res.original_size
        assert b"VULN_TRIGGER" in res.minimized_payload
        assert res.reduction_percentage > 40.0

    def test_binary_chunk_bisection_minimization(self):
        """Verify binary data without newlines is minimized via binary chunk bisection."""
        minimizer = CrashInputMinimizer(max_iterations=50, timeout_seconds=5)

        trigger_pattern = b"\xde\xad\xbe\xef" * 4

        def mock_binary_reproduce(candidate: bytes) -> bool:
            return trigger_pattern in candidate

        # 512 bytes with the trigger pattern buried in the middle
        padded_payload = b"A" * 200 + trigger_pattern + b"B" * 200
        res = minimizer.minimize(padded_payload, mock_binary_reproduce)

        assert res.reproduced is True
        assert res.status == "minimized"
        assert trigger_pattern in res.minimized_payload
        assert res.minimized_size < res.original_size

    def test_minimizer_handles_non_reproducing_input(self):
        """Verify inputs that do not reproduce return original payload intact."""
        minimizer = CrashInputMinimizer()

        def never_reproduces(candidate: bytes) -> bool:
            return False

        payload = b"Clean benign input without flaws"
        res = minimizer.minimize(payload, never_reproduces)
        assert res.reproduced is False
        assert res.status == "not_reproducible"
        assert res.minimized_payload == payload


# ==============================================================================
# FR-4.3: Crash Deduplication & Fingerprinting Tests
# ==============================================================================

class TestCrashDeduplication:
    """Test ASLR-normalized stack fingerprinting and duplicate aggregation."""

    def test_aslr_stack_normalization(self):
        """Verify varying ASLR load addresses yield the exact same fingerprint."""
        raw_stderr_run1 = (
            "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n"
            "fault address: 0x41414141\n"
            "#0 0x7ffd12345678 in strcpy () from /lib/libc.so.0\n"
            "#1 0x7ffd123489ab in handle_http () from /bin/httpd\n"
            "#2 0x55aa00123400 in main () from /bin/httpd\n"
        )

        raw_stderr_run2 = (
            "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n"
            "fault address: 0x41414141\n"
            "#0 0x7ffebcde1234 in strcpy () from /lib/libc.so.0\n"
            "#1 0x7ffebcde4567 in handle_http () from /bin/httpd\n"
            "#2 0x55bb99887766 in main () from /bin/httpd\n"
        )

        c1 = CrashStateParser.parse_crash(
            stdout="", stderr=raw_stderr_run1, exit_code=-11, arch="arm", binary_name="httpd"
        )
        c2 = CrashStateParser.parse_crash(
            stdout="", stderr=raw_stderr_run2, exit_code=-11, arch="arm", binary_name="httpd"
        )

        assert c1 is not None and c2 is not None

        fp1 = CrashFingerprinter.compute_fingerprint(c1, "httpd")
        fp2 = CrashFingerprinter.compute_fingerprint(c2, "httpd")

        # Hashes must match despite randomized ASLR base addresses
        assert fp1.fingerprint_hash == fp2.fingerprint_hash
        assert fp1.signal == "SIGSEGV"
        assert fp1.completeness == "complete"

    def test_distinct_crashes_yield_distinct_fingerprints(self):
        """Verify different crash causes produce different hashes."""
        stderr_segv = (
            "qemu: uncaught target signal 11 (Segmentation fault)\n"
            "fault address: 0x0\n"
            "#0 0x1000 in null_deref () from /app/binary\n"
        )
        stderr_ill = (
            "qemu: uncaught target signal 4 (Illegal instruction)\n"
            "fault address: 0x1000\n"
            "#0 0x1000 in illegal_instr () from /app/binary\n"
        )

        c_segv = CrashStateParser.parse_crash(stdout="", stderr=stderr_segv, exit_code=-11, arch="arm", binary_name="app")
        c_ill = CrashStateParser.parse_crash(stdout="", stderr=stderr_ill, exit_code=-4, arch="arm", binary_name="app")

        assert c_segv is not None and c_ill is not None
        fp_segv = CrashFingerprinter.compute_fingerprint(c_segv, "app")
        fp_ill = CrashFingerprinter.compute_fingerprint(c_ill, "app")

        assert fp_segv.fingerprint_hash != fp_ill.fingerprint_hash

    def test_crash_deduplicator_aggregation(self):
        """Verify crash deduplicator aggregates counts and tracks occurrences."""
        dedup = CrashDeduplicator()

        raw_stderr = (
            "qemu: uncaught target signal 11 (Segmentation fault)\n"
            "fault address: 0x41414141\n"
            "#0 0x7fff00001000 in strcpy () from /lib/libc.so.0\n"
            "#1 0x555500002000 in vuln_handler () from /bin/vuln\n"
        )
        c = CrashStateParser.parse_crash(stdout="", stderr=raw_stderr, exit_code=-11, arch="arm", binary_name="vuln")
        assert c is not None

        # Register same crash 3 times
        group1, is_new1 = dedup.record_crash(c, binary_name="vuln", payload_hash="hash1")
        assert is_new1 is True
        assert group1.event_count == 1

        group2, is_new2 = dedup.record_crash(c, binary_name="vuln", payload_hash="hash2")
        assert is_new2 is False
        assert group2.event_count == 2

        group3, is_new3 = dedup.record_crash(c, binary_name="vuln", payload_hash="hash3")
        assert is_new3 is False
        assert group3.event_count == 3

        assert len(dedup.list_groups()) == 1


# ==============================================================================
# REST API Integration Tests
# ==============================================================================

class TestPriority2Phase2APIEndpoints:
    """Test newly added Priority 2, Phase 2 REST API endpoints."""

    def test_api_system_emulation_boot_simulated(self, client):
        """Test POST /api/v1/emulation/system/boot with simulated execution."""
        resp = client.post(
            "/api/v1/emulation/system/boot",
            params={
                "architecture": "mips",
                "endianness": "big",
                "simulate_scenario": "boot_successful",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "boot_successful"
        assert data["boot_stage"] == "shell_ready"
        assert data["is_mocked"] is True

    def test_api_corpus_list_and_add(self, client):
        """Test GET /api/v1/fuzzing/corpus and POST /api/v1/fuzzing/corpus."""
        # List default baseline seeds
        resp = client.get("/api/v1/fuzzing/corpus", params={"protocol": "http"})
        assert resp.status_code == 200
        data = resp.json()
        assert "seeds" in data
        assert len(data["seeds"]) >= 2

        # Add a custom seed
        add_resp = client.post(
            "/api/v1/fuzzing/corpus",
            params={
                "protocol": "http",
                "name": "api_test_seed",
                "content": "OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            },
        )
        assert add_resp.status_code == 200
        meta = add_resp.json()
        assert meta["protocol"] == "http"
        assert len(meta["content_hash"]) == 64

    def test_api_minimization_endpoint(self, client):
        """Test POST /api/v1/fuzzing/minimize."""
        resp = client.post(
            "/api/v1/fuzzing/minimize",
            params={
                "payload": "Line 1: benign\nLine 2: CRASH_TEST_KEYWORD_WITH_OVERSIZED_INPUT\nLine 3: noise\n",
                "simulate_crash": True,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "minimized_payload" in data
        assert "reduction_percentage" in data

    def test_api_crashes_list_endpoint(self, client):
        """Test GET /api/v1/fuzzing/crashes."""
        resp = client.get("/api/v1/fuzzing/crashes")
        assert resp.status_code == 200
        data = resp.json()
        assert "crash_groups" in data
        assert isinstance(data["crash_groups"], list)
        assert len(data["crash_groups"]) >= 1
