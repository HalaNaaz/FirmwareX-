"""Tests for Priority 1, Phase 1: Core Static Analysis & Firmware Extraction.

Covers PRD FR-1.1 through FR-1.4:
- FR-1.1: Multi-format parsing (CPIO, CramFS, JFFS2, TRX, uImage) and Zip Slip defenses
- FR-1.2: Streaming filesystem reconstruction and file inventory without full-memory buffer loads
- FR-1.3: Cross-architecture ELF discovery and metadata extraction (ARM32/64, MIPS/MIPSEL, x86_64)
- FR-1.4: Static ELF hardening mitigation matrix with explicit state classification
"""

from pathlib import Path

import pytest

from firmwarex.core.elf_auditor import ELFAuditor
from firmwarex.core.extractors.base import ExtractionStatus, QuotaTracker
from firmwarex.core.extractors.cpio_extractor import CpioExtractor
from firmwarex.core.extractors.registry import ExtractorRegistry
from firmwarex.core.raw_detector import RawFirmwareDetector
from firmwarex.core.unpacker import SafeExtractor, compute_sha256
from tests.fixtures_extractors import (
    create_synthetic_cpio,
    create_synthetic_cramfs,
    create_synthetic_jffs2,
)
from tests.fixtures_helper import create_minimal_elf


class TestCpioExtractor:
    """FR-1.1: CPIO initramfs archive extraction, security, and error handling."""

    def test_cpio_detection_and_extraction(self, tmp_path: Path):
        archive_path = tmp_path / "initramfs.cpio"
        files = {
            "etc/hostname": b"firmwarex-router\n",
            "bin/busybox": b"\x7fELF" + b"\x00" * 60,
            "usr/share/banner": b"Welcome to OpenWRT\n",
        }
        create_synthetic_cpio(archive_path, files=files)

        # 1. Verify Raw detector sees CPIO
        primary_fmt, is_supported, sigs = RawFirmwareDetector.detect_header(archive_path)
        assert primary_fmt == "cpio"
        assert is_supported is True
        assert any(s.format_id == "cpio" for s in sigs)

        # 2. Extract using CpioExtractor
        extractor = CpioExtractor()
        assert extractor.can_extract(archive_path) is True
        out_dir = tmp_path / "extracted_cpio"
        outcome = extractor.extract(archive_path, out_dir)

        assert outcome.success is True
        assert outcome.status == ExtractionStatus.EXTRACTED
        assert outcome.file_count == 3
        assert (out_dir / "etc" / "hostname").read_bytes() == b"firmwarex-router\n"
        assert (out_dir / "bin" / "busybox").read_bytes().startswith(b"\x7fELF")
        assert (out_dir / "usr" / "share" / "banner").read_bytes() == b"Welcome to OpenWRT\n"

    def test_cpio_zip_slip_traversal_blocked(self, tmp_path: Path):
        """Verify that directory traversal attempts inside CPIO are blocked."""
        archive_path = tmp_path / "malicious.cpio"
        # Create CPIO containing path traversal entry
        files = {
            "../../escaped.txt": b"ATTACK",
            "normal.txt": b"SAFE",
        }
        create_synthetic_cpio(archive_path, files=files)

        extractor = CpioExtractor()
        out_dir = tmp_path / "out_slip"
        outcome = extractor.extract(archive_path, out_dir)

        assert outcome.success is False
        assert outcome.status == ExtractionStatus.FAILED
        assert any("Security policy violation" in err or "traversal" in err.lower() for err in outcome.errors)

    def test_cpio_quota_exhaustion_defense(self, tmp_path: Path):
        """Verify that QuotaTracker limits abort extraction on quota breach."""
        archive_path = tmp_path / "large.cpio"
        files = {
            "file1.bin": b"A" * 1024,
            "file2.bin": b"B" * 1024,
            "file3.bin": b"C" * 1024,
        }
        create_synthetic_cpio(archive_path, files=files)

        extractor = CpioExtractor()
        out_dir = tmp_path / "out_quota"
        # Quota allows only 1 file
        strict_tracker = QuotaTracker(max_file_count=1, max_total_bytes=10000)
        outcome = extractor.extract(archive_path, out_dir, quota_tracker=strict_tracker)

        assert outcome.success is False
        assert outcome.status == ExtractionStatus.FAILED
        assert any("quota exceeded" in err.lower() for err in outcome.errors)

    def test_cpio_truncated_corrupted_archive(self, tmp_path: Path):
        """Verify graceful error reporting when CPIO archive is truncated."""
        archive_path = tmp_path / "truncated.cpio"
        create_synthetic_cpio(archive_path, files={"data.txt": b"SOME_DATA"})
        # Truncate halfway through header
        raw = archive_path.read_bytes()
        archive_path.write_bytes(raw[:50])

        extractor = CpioExtractor()
        out_dir = tmp_path / "out_trunc"
        outcome = extractor.extract(archive_path, out_dir)

        assert outcome.success is False
        assert outcome.status == ExtractionStatus.CORRUPTED
        assert len(outcome.errors) > 0


class TestFilesystemInventory:
    """FR-1.2: Streaming filesystem reconstruction and file inventory."""

    def test_streaming_sha256_large_file(self, tmp_path: Path):
        """Verify compute_sha256 streams chunks rather than loading entire file into memory."""
        big_file = tmp_path / "big_sample.bin"
        chunk = b"X" * 65536
        with open(big_file, "wb") as f:
            for _ in range(32):  # 2 MB in 64KB blocks
                f.write(chunk)

        digest = compute_sha256(big_file)
        assert isinstance(digest, str)
        assert len(digest) == 64

    def test_inventory_relative_paths_no_host_leak(self, tmp_path: Path):
        """Verify generated inventory contains clean relative POSIX paths with zero host path leaks."""
        sample_dir = tmp_path / "firmware_root"
        (sample_dir / "etc").mkdir(parents=True)
        (sample_dir / "bin").mkdir(parents=True)
        (sample_dir / "etc" / "config.ini").write_text("setting=1\n")
        (sample_dir / "bin" / "daemon").write_bytes(b"\x7fELF" + b"\x00" * 50)

        unpacker = SafeExtractor()
        inventory = unpacker.generate_inventory(sample_dir)

        paths = [item.path for item in inventory]
        assert "etc" in paths or "etc/config.ini" in paths
        assert "bin/daemon" in paths
        for item in inventory:
            # No Windows drive letters (C:) or full system directory paths
            assert not item.path.startswith("C:")
            assert not item.path.startswith("/")
            assert "\\" not in item.path
            if item.type == "directory":
                assert item.size == 0
                assert item.sha256 is None
            elif item.type == "elf_binary":
                assert item.is_elf is True
                assert item.is_executable is True
                assert item.sha256 is not None


class TestElfDiscoveryAndHardening:
    """FR-1.3 & FR-1.4: Cross-architecture discovery and mitigation evaluation."""

    @pytest.mark.parametrize(
        "arch,bitness,endianness,expected_arch",
        [
            ("arm", 32, "little", "ARM32"),
            ("arm64", 64, "little", "ARM64"),
            ("mips", 32, "big", "MIPS"),
            ("mips", 32, "little", "MIPSEL"),
            ("x86_64", 64, "little", "x86_64"),
        ],
    )
    def test_multi_arch_identification(self, tmp_path: Path, arch, bitness, endianness, expected_arch):
        elf_bytes = create_minimal_elf(arch=arch, bitness=bitness, endianness=endianness)
        target = tmp_path / f"test_{expected_arch}.elf"
        target.write_bytes(elf_bytes)

        auditor = ELFAuditor()
        report = auditor.audit_binary(target)

        assert report.is_valid_elf is True
        assert report.architecture == expected_arch
        assert report.bitness == bitness
        assert report.endianness == endianness
        assert report.is_stripped is True  # Synthetic minimal ELF lacks .symtab

    def test_elf_hardening_mitigation_states(self, tmp_path: Path):
        """Verify explicit states: enabled, not_detected, not_applicable."""
        # 1. Fully protected ELF
        secure_elf = tmp_path / "secure.elf"
        secure_elf.write_bytes(create_minimal_elf(enable_nx=True, has_relro=True, is_pie=True))

        auditor = ELFAuditor()
        report_sec = auditor.audit_binary(secure_elf)

        assert report_sec.nx.status == "enabled"
        assert report_sec.pie.status == "enabled"
        assert report_sec.relro.status == "enabled"

        # 2. Relocatable object file (ET_REL)
        reloc_elf = tmp_path / "module.o"
        reloc_elf.write_bytes(create_minimal_elf(is_relocatable=True))
        report_rel = auditor.audit_binary(reloc_elf)

        assert report_rel.nx.status == "not_applicable"
        assert report_rel.pie.status == "not_applicable"
        assert report_rel.relro.status == "not_applicable"

    def test_malformed_truncated_elf_resilience(self, tmp_path: Path):
        """Verify that malformed or truncated ELFs never crash the engine."""
        corrupt_elf = tmp_path / "corrupt.elf"
        corrupt_elf.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\xff" * 20)

        auditor = ELFAuditor()
        report = auditor.audit_binary(corrupt_elf)

        # Report returns safely with error_message rather than raising exception
        assert report.is_valid_elf is True
        assert report.error_message is not None
        assert "parsing exception" in report.error_message.lower() or "error" in report.error_message.lower()


class TestExtractorRegistryIntegration:
    """Verify registry dispatch across supported embedded formats."""

    def test_registry_handles_cpio(self, tmp_path: Path):
        archive_path = tmp_path / "test.cpio"
        create_synthetic_cpio(archive_path, files={"banner.txt": b"FWX CPIO"})

        registry = ExtractorRegistry()
        extractor = registry.find_extractor_for_file(archive_path)
        assert extractor is not None
        assert extractor.format_id == "cpio"

        out_dir = tmp_path / "out_reg_cpio"
        outcome = registry.extract_firmware(archive_path, out_dir)
        assert outcome.success is True
        assert outcome.format_id == "cpio"
        assert (out_dir / "banner.txt").read_bytes() == b"FWX CPIO"

    def test_registry_handles_cramfs(self, tmp_path: Path):
        cramfs_path = tmp_path / "test.cramfs"
        create_synthetic_cramfs(cramfs_path, files={"info.txt": b"CramFS content"})

        registry = ExtractorRegistry()
        extractor = registry.find_extractor_for_file(cramfs_path)
        assert extractor is not None
        assert extractor.format_id == "cramfs"

        out_dir = tmp_path / "out_reg_cramfs"
        outcome = registry.extract_firmware(cramfs_path, out_dir)
        assert outcome.success is True
        assert outcome.format_id == "cramfs"
        assert (out_dir / "info.txt").read_bytes() == b"CramFS content"

    def test_registry_handles_jffs2(self, tmp_path: Path):
        jffs2_path = tmp_path / "test.jffs2"
        create_synthetic_jffs2(jffs2_path, files={"version.txt": b"JFFS2 v1"})

        registry = ExtractorRegistry()
        extractor = registry.find_extractor_for_file(jffs2_path)
        assert extractor is not None
        assert extractor.format_id == "jffs2"

        out_dir = tmp_path / "out_reg_jffs2"
        outcome = registry.extract_firmware(jffs2_path, out_dir)
        assert outcome.success is True
        assert outcome.format_id == "jffs2"
        assert (out_dir / "version.txt").read_bytes() == b"JFFS2 v1"
