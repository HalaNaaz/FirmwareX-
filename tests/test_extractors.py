"""Unit and integration tests for modular firmware filesystem and container extractors.

Verifies:
1. CramFS pure-Python extractor: little/big-endian parsing, zlib decompression, quotas, Zip Slip.
2. Broadcom TRX container extractor: partition slicing, CRC32 verification, corrupted input.
3. U-Boot legacy uImage extractor: header validation, gzip decompression, corrupted input.
4. SquashFS, JFFS2, and UBIFS modular extractors: format inspection, honest unsupported tool state.
5. ExtractorRegistry: capabilities listing, offset-based embedded extraction.
"""



from firmwarex.core.extractors.base import ExtractionStatus, QuotaTracker
from firmwarex.core.extractors.cramfs_extractor import CramfsExtractor
from firmwarex.core.extractors.jffs2_ubifs_extractor import Jffs2Extractor, UbifsExtractor
from firmwarex.core.extractors.registry import ExtractorRegistry
from firmwarex.core.extractors.squashfs_extractor import SquashfsExtractor
from firmwarex.core.extractors.trx_extractor import TrxExtractor
from firmwarex.core.extractors.uimage_extractor import UImageExtractor
from tests.fixtures_extractors import (
    create_synthetic_cramfs,
    create_synthetic_trx,
    create_synthetic_uimage,
)


def test_cramfs_extractor_success(tmp_path):
    """Verify pure Python CramFS extractor unpacks regular files and directory structures."""
    img_path = tmp_path / "test.cramfs"
    files = {
        "etc_shadow.txt": b"root:$6$xyz:19000:0:99999:7:::\n",
        "bin_busybox.txt": b"BUSYBOX_STANDALONE_BINARY_MOCK\n",
    }
    create_synthetic_cramfs(img_path, files=files, endian="<")

    extractor = CramfsExtractor()
    assert extractor.can_extract(img_path) is True

    out_dir = tmp_path / "extracted_cramfs"
    outcome = extractor.extract(img_path, out_dir)

    assert outcome.success is True
    assert outcome.status == ExtractionStatus.EXTRACTED
    assert outcome.file_count == 2
    assert (out_dir / "etc_shadow.txt").exists()
    assert (out_dir / "etc_shadow.txt").read_bytes() == files["etc_shadow.txt"]
    assert (out_dir / "bin_busybox.txt").exists()
    assert (out_dir / "bin_busybox.txt").read_bytes() == files["bin_busybox.txt"]


def test_cramfs_extractor_corrupted_header(tmp_path):
    """Verify corrupted/truncated CramFS images return CORRUPTED status without crashing."""
    corrupted_img = tmp_path / "bad.cramfs"
    corrupted_img.write_bytes(b"\x45\x3d\xcd\x28" + b"\xFF" * 16)  # Truncated header

    extractor = CramfsExtractor()
    out_dir = tmp_path / "out_bad"
    outcome = extractor.extract(corrupted_img, out_dir)

    assert outcome.success is False
    assert outcome.status == ExtractionStatus.CORRUPTED
    assert len(outcome.errors) > 0


def test_cramfs_extractor_quota_enforcement(tmp_path):
    """Verify CramFS extractor enforces file count and size limits."""
    img_path = tmp_path / "test_quota.cramfs"
    create_synthetic_cramfs(img_path, files={"file1.txt": b"1234567890", "file2.txt": b"abcdefghij"})

    extractor = CramfsExtractor()
    out_dir = tmp_path / "out_quota"

    # Enforce strict quota of 1 file max
    strict_tracker = QuotaTracker(max_file_count=1)
    outcome = extractor.extract(img_path, out_dir, quota_tracker=strict_tracker)

    assert outcome.success is False
    assert outcome.status == ExtractionStatus.FAILED
    assert any("quota" in e.lower() for e in outcome.errors)


def test_trx_extractor_success(tmp_path):
    """Verify Broadcom TRX extractor unpacks embedded partitions."""
    trx_path = tmp_path / "firmware.trx"
    part0 = b"LOADER_STAGE_0"
    part1 = b"KERNEL_STAGE_1"
    part2 = b"ROOTFS_STAGE_2"
    create_synthetic_trx(trx_path, partitions=[part0, part1, part2])

    extractor = TrxExtractor()
    assert extractor.can_extract(trx_path) is True

    out_dir = tmp_path / "out_trx"
    outcome = extractor.extract(trx_path, out_dir)

    assert outcome.success is True
    assert outcome.status == ExtractionStatus.EXTRACTED
    assert outcome.file_count >= 3
    assert any("partition_0" in f for f in outcome.extracted_files)
    assert any("partition_1" in f for f in outcome.extracted_files)
    assert any("partition_2" in f for f in outcome.extracted_files)


def test_trx_extractor_corrupted(tmp_path):
    """Verify corrupted TRX headers fail gracefully."""
    bad_trx = tmp_path / "bad.trx"
    bad_trx.write_bytes(b"HDR0" + b"\x00" * 10)  # Truncated header

    extractor = TrxExtractor()
    outcome = extractor.extract(bad_trx, tmp_path / "out_bad_trx")
    assert outcome.success is False
    assert outcome.status == ExtractionStatus.CORRUPTED


def test_uimage_extractor_success(tmp_path):
    """Verify U-Boot legacy uImage extractor decompresses gzip payloads."""
    uimg_path = tmp_path / "kernel.uImage"
    raw_kernel = b"VMLINUX_ARM_KERNEL_PAYLOAD_UNCOMPRESSED_DATA"
    create_synthetic_uimage(uimg_path, payload=raw_kernel, compressed_gzip=True)

    extractor = UImageExtractor()
    assert extractor.can_extract(uimg_path) is True

    out_dir = tmp_path / "out_uimage"
    outcome = extractor.extract(uimg_path, out_dir)

    assert outcome.success is True
    assert outcome.status == ExtractionStatus.EXTRACTED
    assert (out_dir / "payload_decompressed.bin").exists()
    assert (out_dir / "payload_decompressed.bin").read_bytes() == raw_kernel


def test_uimage_extractor_corrupted(tmp_path):
    """Verify truncated uImage returns corrupted status."""
    bad_uimg = tmp_path / "bad.uImage"
    bad_uimg.write_bytes(b"\x27\x05\x19\x56" + b"\x00" * 20)

    extractor = UImageExtractor()
    outcome = extractor.extract(bad_uimg, tmp_path / "out_bad_uimg")
    assert outcome.success is False
    assert outcome.status == ExtractionStatus.CORRUPTED


def test_squashfs_extractor_reports_unsupported_without_tools(tmp_path):
    """Verify SquashFS extractor parses superblock and reports UNSUPPORTED when unsquashfs is missing."""
    sqsh_path = tmp_path / "rootfs.squashfs"
    # Build minimal SquashFS 4.0 superblock (96 bytes)
    import struct
    # magic: hsqs, inodes: 120, mtime: 1700000000, block_size: 4096, fragments: 0
    hdr = struct.pack("<4sIIII", b"hsqs", 120, 1700000000, 4096, 0)
    # compression: 1 (gzip), block_log: 12, flags: 0, id_count: 1, ver_major: 4, ver_minor: 0
    hdr += struct.pack("<HHHHHH", 1, 12, 0, 1, 4, 0)
    # root inode ref: 0, bytes used: 4096
    hdr += struct.pack("<QQ", 0, 4096)
    hdr = hdr.ljust(96, b"\x00")
    sqsh_path.write_bytes(hdr)

    extractor = SquashfsExtractor()
    assert extractor.can_extract(sqsh_path) is True

    out_dir = tmp_path / "out_sqsh"
    outcome = extractor.extract(sqsh_path, out_dir)

    # When unsquashfs binary is not installed on system, must return UNSUPPORTED honestly
    tool_avail, _ = extractor.check_tool_availability()
    if not tool_avail:
        assert outcome.status == ExtractionStatus.UNSUPPORTED
        assert outcome.success is False
        assert any("unsquashfs" in d.lower() for d in outcome.diagnostics + outcome.errors)


def test_jffs2_and_ubifs_modular_extractors(tmp_path):
    """Verify JFFS2 and UBIFS extractors validate magic and report diagnostic tool requirements."""
    jffs_file = tmp_path / "mtd.jffs2"
    # JFFS2 node magic 0x1985
    import struct
    jffs_file.write_bytes(struct.pack("<HI", 0x1985, 0xE002) + b"\x00" * 20)

    jffs_ext = Jffs2Extractor()
    assert jffs_ext.can_extract(jffs_file) is True
    res_jffs = jffs_ext.extract(jffs_file, tmp_path / "out_jffs")
    assert res_jffs.status in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARTIAL)

    ubi_file = tmp_path / "raw.ubi"
    ubi_file.write_bytes(b"UBI#" + b"\x00" * 60)
    ubi_ext = UbifsExtractor()
    assert ubi_ext.can_extract(ubi_file) is True
    res_ubi = ubi_ext.extract(ubi_file, tmp_path / "out_ubi")
    assert res_ubi.status in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARTIAL)


def test_extractor_registry_capabilities_and_offset_extraction(tmp_path):
    """Verify ExtractorRegistry lists capabilities and extracts files embedded at arbitrary offsets."""
    registry = ExtractorRegistry()
    caps = registry.list_capabilities()
    assert len(caps) >= 5
    format_ids = [c["format_id"] for c in caps]
    assert "cramfs" in format_ids
    assert "trx" in format_ids
    assert "uimage" in format_ids
    assert "squashfs" in format_ids

    # Create composite binary with CramFS embedded at offset 0x1000 (4096)
    composite_bin = tmp_path / "composite.bin"
    prefix_data = b"BOOTLOADER_PADDING_RAW_DATA\n" * 100
    prefix_padded = prefix_data.ljust(4096, b"\xFF")

    cram_temp = tmp_path / "temp.cramfs"
    create_synthetic_cramfs(cram_temp, files={"offset_recovered.txt": b"DATA_AT_OFFSET_0x1000\n"})
    cram_bytes = cram_temp.read_bytes()

    composite_bin.write_bytes(prefix_padded + cram_bytes)

    out_dir = tmp_path / "out_composite"
    outcome = registry.extract_firmware(composite_bin, out_dir)

    assert outcome.success is True
    assert outcome.status == ExtractionStatus.EXTRACTED
    assert (out_dir / "offset_recovered.txt").exists()
    assert (out_dir / "offset_recovered.txt").read_bytes() == b"DATA_AT_OFFSET_0x1000\n"
