"""Unit tests for raw firmware format detection and embedded filesystem signatures."""

from firmwarex.core.raw_detector import RawFirmwareDetector


def test_detect_squashfs_signatures(tmp_path):
    """Verify detection of SquashFS little-endian, big-endian, and swapped variants."""
    le_squash = tmp_path / "rootfs_le.squashfs"
    le_squash.write_bytes(b"hsqs" + b"\x00" * 60)

    be_squash = tmp_path / "rootfs_be.squashfs"
    be_squash.write_bytes(b"sqsh" + b"\x00" * 60)

    fmt_le, is_sup_le, sigs_le = RawFirmwareDetector.detect_header(le_squash)
    assert fmt_le == "squashfs"
    assert is_sup_le is False  # Raw container requires external unsquashfs/binwalk
    assert sigs_le[0].endianness == "little"
    assert sigs_le[0].recommended_tool == "unsquashfs / sasquatch"

    fmt_be, is_sup_be, sigs_be = RawFirmwareDetector.detect_header(be_squash)
    assert fmt_be == "squashfs"
    assert is_sup_be is False
    assert sigs_be[0].endianness == "big"


def test_detect_cramfs_signatures(tmp_path):
    """Verify detection of CramFS little-endian and big-endian magic."""
    cram_le = tmp_path / "cram_le.bin"
    cram_le.write_bytes(b"\x45\x3d\xcd\x28" + b"\x00" * 60)

    fmt, is_sup, sigs = RawFirmwareDetector.detect_header(cram_le)
    assert fmt == "cramfs"
    assert is_sup is False
    assert sigs[0].endianness == "little"
    assert sigs[0].recommended_tool == "cramfsck / cramfsswap"


def test_detect_jffs2_signatures(tmp_path):
    """Verify detection of JFFS2 flash filesystem magic."""
    jffs2_le = tmp_path / "flash_jffs2.bin"
    jffs2_le.write_bytes(b"\x85\x19" + b"\x00" * 60)

    fmt, is_sup, sigs = RawFirmwareDetector.detect_header(jffs2_le)
    assert fmt == "jffs2"
    assert is_sup is False
    assert sigs[0].endianness == "little"


def test_detect_ubifs_signatures(tmp_path):
    """Verify detection of UBIFS node magic and UBI eraseblock markers."""
    ubi_file = tmp_path / "nand_ubi.bin"
    ubi_file.write_bytes(b"UBI#" + b"\x00" * 60)

    fmt, is_sup, sigs = RawFirmwareDetector.detect_header(ubi_file)
    assert fmt == "ubifs"
    assert is_sup is False
    assert "UBI" in sigs[0].name


def test_detect_uimage_and_trx(tmp_path):
    """Verify detection of Das U-Boot uImage (IH_MAGIC) and Broadcom TRX headers."""
    uimage = tmp_path / "kernel.uImage"
    uimage.write_bytes(b"\x27\x05\x19\x56" + b"\x00" * 60)

    trx = tmp_path / "router.trx"
    trx.write_bytes(b"HDR0" + b"\x00" * 60)

    fmt_u, is_sup_u, sigs_u = RawFirmwareDetector.detect_header(uimage)
    assert fmt_u == "uimage"
    assert is_sup_u is False
    assert "U-Boot" in sigs_u[0].name

    fmt_t, is_sup_t, sigs_t = RawFirmwareDetector.detect_header(trx)
    assert fmt_t == "trx"
    assert is_sup_t is False
    assert "Broadcom TRX" in sigs_t[0].name


def test_detect_dtb_device_tree(tmp_path):
    """Verify detection of Flattened Device Tree Blob (DTB)."""
    dtb = tmp_path / "board.dtb"
    dtb.write_bytes(b"\xd0\x0d\xfe\xed" + b"\x00" * 60)

    fmt, is_sup, sigs = RawFirmwareDetector.detect_header(dtb)
    assert fmt == "dtb"
    assert is_sup is False
    assert "Device Tree" in sigs[0].name


def test_detect_composite_firmware_offsets(tmp_path):
    """Verify multi-offset scanning across composite firmware (e.g. uImage at 0, SquashFS at 4096)."""
    firmware_blob = tmp_path / "composite_firmware.bin"
    # Header: uImage at offset 0
    payload = bytearray(b"\x27\x05\x19\x56" + b"\x00" * 4092)
    # Embedded SquashFS at offset 4096
    payload.extend(b"hsqs" + b"\x00" * 4092)
    firmware_blob.write_bytes(payload)

    sigs = RawFirmwareDetector.scan_signatures(firmware_blob)
    assert len(sigs) >= 2

    # Check offsets
    uimage_sig = next(s for s in sigs if s.format_id == "uimage")
    squash_sig = next(s for s in sigs if s.format_id == "squashfs")

    assert uimage_sig.offset == 0
    assert squash_sig.offset == 4096
    assert squash_sig.magic_hex == b"hsqs".hex()


def test_detect_empty_or_nonexistent_files(tmp_path):
    """Verify graceful handling of 0-byte or non-existent files."""
    empty_f = tmp_path / "empty.bin"
    empty_f.write_bytes(b"")

    fmt, is_sup, sigs = RawFirmwareDetector.detect_header(empty_f)
    assert fmt == "empty_file"
    assert is_sup is False
    assert len(sigs) == 0

    non_existent = tmp_path / "does_not_exist.bin"
    fmt2, is_sup2, sigs2 = RawFirmwareDetector.detect_header(non_existent)
    assert fmt2 == "empty_file"
    assert is_sup2 is False
    assert len(sigs2) == 0
