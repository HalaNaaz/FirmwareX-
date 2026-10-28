"""Unit tests for safe extraction, Zip Slip defense, symlink restrictions, and quotas."""

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from firmwarex.core.unpacker import (
    SafeExtractor,
    SecurityException,
    UnsupportedFormatException,
    compute_sha256,
    detect_format,
)
from tests.fixtures_helper import create_benign_firmware_archive


def test_benign_zip_extraction(tmp_path):
    """Test valid extraction of a benign ZIP archive and inventory creation."""
    zip_path = tmp_path / "firmware.zip"
    create_benign_firmware_archive(zip_path, archive_type="zip")

    extractor = SafeExtractor()
    out_dir = tmp_path / "extracted_zip"
    res = extractor.extract(zip_path, out_dir)

    assert res.success is True
    assert res.status == "extracted"
    assert res.file_count >= 5
    assert len(res.inventory) >= 5

    # Check inventory entries
    paths = [item.path for item in res.inventory]
    assert any("etc/shadow" in p for p in paths)
    assert any("bin/service_mips" in p for p in paths)

    # Check file classifications
    mips_item = next(item for item in res.inventory if "service_mips" in item.path)
    assert mips_item.is_elf is True
    assert mips_item.type == "elf_binary"


def test_benign_tar_extraction(tmp_path):
    """Test valid extraction of a benign tar.gz archive."""
    tar_path = tmp_path / "firmware.tar.gz"
    create_benign_firmware_archive(tar_path, archive_type="tar.gz")

    extractor = SafeExtractor()
    out_dir = tmp_path / "extracted_tar"
    res = extractor.extract(tar_path, out_dir)

    assert res.success is True
    assert res.status == "extracted"
    assert res.file_count >= 5


def test_zip_slip_traversal_rejection(tmp_path):
    """Verify that a ZIP archive containing path traversal (../../evil.txt) is blocked."""
    evil_zip = tmp_path / "malicious_slip.zip"
    with zipfile.ZipFile(evil_zip, "w") as zf:
        zf.writestr("../../evil_slip.txt", b"malicious content outside sandbox")

    extractor = SafeExtractor()
    out_dir = tmp_path / "extracted_slip"

    with pytest.raises(SecurityException) as exc:
        extractor.extract(evil_zip, out_dir)

    assert "Zip Slip" in str(exc.value)
    # Ensure no file was written outside sandbox
    assert not (tmp_path / "evil_slip.txt").exists()


def test_tar_path_traversal_rejection(tmp_path):
    """Verify that a TAR archive containing path traversal is blocked."""
    evil_tar = tmp_path / "malicious_slip.tar"
    with tarfile.open(evil_tar, "w") as tf:
        ti = tarfile.TarInfo(name="../../outside_tar.txt")
        content = b"evil tar content"
        ti.size = len(content)
        tf.addfile(ti, io.BytesIO(content))

    extractor = SafeExtractor()
    out_dir = tmp_path / "extracted_tar_slip"

    with pytest.raises(SecurityException) as exc:
        extractor.extract(evil_tar, out_dir)

    assert "traversal attempt blocked" in str(exc.value)


def test_tar_malicious_symlink_rejection(tmp_path):
    """Verify that a symlink pointing outside the sandbox root is blocked."""
    evil_tar = tmp_path / "evil_symlink.tar"
    with tarfile.open(evil_tar, "w") as tf:
        ti = tarfile.TarInfo(name="symlink_to_root")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "../../../../../../../../../Windows/System32/cmd.exe"
        tf.addfile(ti)

    extractor = SafeExtractor()
    out_dir = tmp_path / "extracted_symlink"

    with pytest.raises(SecurityException) as exc:
        extractor.extract(evil_tar, out_dir)

    assert "symlink" in str(exc.value).lower()


def test_tar_fifo_device_rejection(tmp_path):
    """Verify that device/FIFO nodes inside archives are blocked."""
    evil_tar = tmp_path / "evil_fifo.tar"
    with tarfile.open(evil_tar, "w") as tf:
        ti = tarfile.TarInfo(name="evil_fifo")
        ti.type = tarfile.FIFOTYPE
        tf.addfile(ti)

    extractor = SafeExtractor()
    out_dir = tmp_path / "extracted_fifo"

    with pytest.raises(SecurityException) as exc:
        extractor.extract(evil_tar, out_dir)

    assert "device/FIFO node creation blocked" in str(exc.value)


def test_quota_max_file_count_enforcement(tmp_path):
    """Verify that archive exceeding maximum file count quota is terminated."""
    big_zip = tmp_path / "bomb_files.zip"
    with zipfile.ZipFile(big_zip, "w") as zf:
        for i in range(15):
            zf.writestr(f"file_{i}.txt", b"x")

    # Set artificial quota of 10 files
    extractor = SafeExtractor(max_file_count=10)
    out_dir = tmp_path / "extracted_bomb"

    with pytest.raises(SecurityException) as exc:
        extractor.extract(big_zip, out_dir)

    assert "max file count limit" in str(exc.value)


def test_quota_max_uncompressed_size_enforcement(tmp_path):
    """Verify that archive exceeding uncompressed size limit is terminated."""
    big_zip = tmp_path / "bomb_size.zip"
    with zipfile.ZipFile(big_zip, "w") as zf:
        zf.writestr("huge.txt", b"A" * 10000)

    # Set artificial quota of 5000 bytes
    extractor = SafeExtractor(max_uncompressed_size=5000)
    out_dir = tmp_path / "extracted_size_bomb"

    with pytest.raises(SecurityException) as exc:
        extractor.extract(big_zip, out_dir)

    assert "uncompressed size exceeds limit" in str(exc.value)


def test_unsupported_format_detection(tmp_path):
    """Verify that raw SquashFS / TRX binaries are identified and rejected with clear reason."""
    squashfs_file = tmp_path / "firmware.bin"
    with open(squashfs_file, "wb") as f:
        f.write(b"hsqs\x00\x00\x00\x01raw_squashfs_superblock_data")

    fmt, is_supported = detect_format(squashfs_file)
    assert fmt == "squashfs"
    assert is_supported is False

    extractor = SafeExtractor()
    with pytest.raises(UnsupportedFormatException) as exc:
        extractor.extract(squashfs_file, tmp_path / "out")

    assert "Unsupported firmware format 'squashfs'" in str(exc.value)
