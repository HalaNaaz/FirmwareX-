"""Tests for Phase 8: Analysis Integrity, Modular Extractor Integrations, and Dashboard Data Correctness.

Verifies:
1. SquashFS extractor discovers PySquashfsImage and executes or reports honest corruption/unsupported.
2. UBIFS extractor discovers ubireader and validates bounded execution and safe path checks.
3. Containment preflight endpoint reports genuine Docker daemon status (evidence-grounded).
4. Dashboard contracts ensure dynamic data binding and empty-state presentation without fabricated findings.
"""

import struct
from pathlib import Path

from firmwarex.core.extractors.base import ExtractionStatus, QuotaTracker
from firmwarex.core.extractors.jffs2_ubifs_extractor import UbifsExtractor
from firmwarex.core.extractors.squashfs_extractor import SquashfsExtractor
from firmwarex.isolation.sandbox_manager import ContainmentPreflight


def test_squashfs_tool_availability_and_pysquashfs_discovery():
    """Verify SquashFS extractor detects PySquashfsImage or external tooling."""
    extractor = SquashfsExtractor()
    available, tool_info = extractor.check_tool_availability()
    assert available is True
    assert tool_info is not None
    assert any(name in tool_info.lower() for name in ("pysquashfsimage", "unsquashfs", "sasquatch"))


def test_squashfs_extractor_with_corrupt_stream(tmp_path):
    """Verify SquashFS extractor handles corrupt/truncated data safely without unhandled exceptions."""
    corrupt_sqsh = tmp_path / "corrupt.squashfs"
    # Write a valid 96-byte header with non-existent data blocks
    hdr = struct.pack("<4sIIII", b"hsqs", 10, 1700000000, 4096, 0)
    hdr += struct.pack("<HHHHHH", 1, 12, 0, 1, 4, 0)
    hdr += struct.pack("<QQ", 0, 2048)
    hdr = hdr.ljust(96, b"\x00")
    corrupt_sqsh.write_bytes(hdr)

    extractor = SquashfsExtractor()
    out_dir = tmp_path / "out_corrupt_sqsh"
    outcome = extractor.extract(corrupt_sqsh, out_dir)

    # Must report failure/corruption honestly without crashing
    assert outcome.success is False
    assert outcome.status in (ExtractionStatus.CORRUPTED, ExtractionStatus.FAILED, ExtractionStatus.UNSUPPORTED)
    assert len(outcome.diagnostics) > 0


def test_ubifs_tool_availability_and_ubireader_discovery():
    """Verify UBIFS extractor detects ubireader installation."""
    extractor = UbifsExtractor()
    available, tool_info = extractor.check_tool_availability()
    assert available is True
    assert tool_info is not None
    assert "ubireader" in tool_info.lower()


def test_ubifs_extractor_with_minimal_header(tmp_path):
    """Verify UBIFS extractor validates UBI eraseblock header and handles partial stream safely."""
    ubi_file = tmp_path / "test.ubi"
    # UBI Erase Counter Header (64 bytes)
    hdr = b"UBI#" + b"\x01" + b"\x00" * 11 + struct.pack(">I", 4096) + b"\x00" * 44
    ubi_file.write_bytes(hdr)

    extractor = UbifsExtractor()
    assert extractor.can_extract(ubi_file) is True

    out_dir = tmp_path / "out_ubi_test"
    tracker = QuotaTracker(max_file_count=50)
    outcome = extractor.extract(ubi_file, out_dir, quota_tracker=tracker)

    # Minimal header without physical eraseblock image reports partial/corrupted honestly
    assert outcome.success is False
    assert outcome.status in (ExtractionStatus.PARTIAL, ExtractionStatus.CORRUPTED, ExtractionStatus.FAILED)
    assert len(outcome.diagnostics) > 0


def test_containment_preflight_evidence_grounded():
    """Verify containment preflight reports truthful Docker status without fabrication."""
    result = ContainmentPreflight.run_preflight()
    as_dict = result.to_dict()

    assert "passed" in as_dict
    assert "docker_available" in as_dict
    assert "daemon_responsive" in as_dict
    assert "network_isolation_verified" in as_dict
    assert "read_only_rootfs_supported" in as_dict
    assert "diagnostics" in as_dict

    # If daemon is unresponsive, passed MUST be False (fail-closed)
    if not result.daemon_responsive:
        assert result.passed is False
        assert any("offline" in d.lower() or "not responsive" in d.lower() or "failed" in d.lower() for d in result.diagnostics)


def test_dashboard_template_contains_integrity_data_bindings():
    """Verify dashboard template includes required elements for dynamic data binding and empty state."""
    template_path = Path("firmwarex/web/templates/index.html")
    assert template_path.exists()
    content = template_path.read_text(encoding="utf-8")

    # Dynamic containment hooks
    assert 'id="card-containment"' in content
    assert 'id="containment-badge"' in content
    assert 'id="containment-metric"' in content
    assert 'updateContainmentStatus' in content

    # Dynamic secrets breakdown hooks
    assert 'id="bar-passwords"' in content
    assert 'id="bar-aws"' in content
    assert 'id="bar-shadow"' in content
    assert 'id="secrets-items-container"' in content

    # Dynamic mitigations pill bar hooks
    assert 'id="bar-nx"' in content
    assert 'id="bar-pie"' in content
    assert 'id="bar-rel"' in content
    assert 'id="bar-can"' in content
    assert 'id="bar-all"' in content

    # Empty overview rendering function
    assert 'function renderEmptyOverview()' in content
    assert "renderEmptyOverview();" in content
