"""Synthetic firmware test fixture builders for CramFS, TRX, and uImage.

Builds deterministic, minimal, valid binary containers conforming strictly
to file format specifications without external binaries or network dependencies.
"""

import binascii
import gzip
import struct
import zlib
from pathlib import Path


def create_synthetic_cramfs(
    output_path: Path,
    files: dict[str, bytes] | None = None,
    endian: str = "<",
    volume_name: str = "TestCramFS",
) -> Path:
    """Create a minimal, valid, spec-compliant CramFS filesystem image.

    Superblock (76 bytes):
    - magic (4 bytes): 0x28cd3d45 (LE) or 0x453dcd28 (BE)
    - size (4 bytes)
    - flags (4 bytes)
    - future (4 bytes)
    - signature (16 bytes): "Compressed ROMFS"
    - fsid (16 bytes)
    - name (16 bytes)
    - root inode (12 bytes)
    Followed by:
    - Root directory entries (cramfs_inode + padded name)
    - Block pointer tables + zlib-compressed data blocks
    """
    if files is None:
        files = {"hello.txt": b"Hello from FirmwareX CramFS!", "version.cfg": b"VERSION=1.0.0\n"}

    magic = 0x28CD3D45 if endian == "<" else 0x453DCD28
    sig = b"Compressed ROMFS".ljust(16, b"\x00")
    fsid = b"\x00" * 16
    vname = volume_name.encode("utf-8")[:16].ljust(16, b"\x00")

    # Inode offset constants
    # Superblock is 76 bytes. We align root directory at offset 76 (or 80)
    root_dir_offset = 80
    sb_padding = root_dir_offset - 76

    # We will build:
    # 1. Directory entries table
    # 2. File data area (block pointers + zlib compressed blocks)
    dir_entries_bytes = bytearray()
    file_data_bytes = bytearray()

    # Pre-calculate file records
    file_records = []
    # Start of file data area is after root_dir_offset + directory table size
    # Calculate dir table size first
    dir_table_size = 0
    for name, content in files.items():
        name_bytes = name.encode("utf-8")
        namelen = len(name_bytes)
        padded_namelen = ((namelen + 3) // 4) * 4
        entry_size = 12 + padded_namelen
        dir_table_size += entry_size
        file_records.append((name, name_bytes, namelen, padded_namelen, content))

    # Pad directory table to 4-byte boundary
    dir_table_padded_size = ((dir_table_size + 3) // 4) * 4
    file_data_start_offset = root_dir_offset + dir_table_padded_size

    current_file_offset = file_data_start_offset

    for name, name_bytes, namelen, padded_namelen, content in file_records:
        file_size = len(content)
        # Compress with zlib
        compressed = zlib.compress(content)
        # Block count: (file_size + 4095) // 4096
        block_count = (file_size + 4095) // 4096 if file_size > 0 else 0

        # Build inode
        # mode: regular file 0o100644
        mode = 0o100644
        uid = 1000
        gid = 1000

        # Offset to file data (in 4-byte words!)
        offset_words = current_file_offset // 4

        if endian == "<":
            size_gid = (file_size & 0xFFFFFF) | ((gid & 0xFF) << 24)
            namelen_offset = (namelen & 0x3F) | ((offset_words & 0x3FFFFFF) << 6)
        else:
            size_gid = ((file_size & 0xFFFFFF) << 8) | (gid & 0xFF)
            namelen_offset = ((namelen & 0x3F) << 26) | (offset_words & 0x3FFFFFF)

        inode_bytes = struct.pack(f"{endian}HHI I", mode, uid, size_gid, namelen_offset)
        dir_entries_bytes.extend(inode_bytes)
        dir_entries_bytes.extend(name_bytes.ljust(padded_namelen, b"\x00"))

        # Build file data: block pointers + compressed data
        if file_size > 0:
            block_data_start = current_file_offset + block_count * 4
            end_ptr = block_data_start + len(compressed)
            ptr_bytes = struct.pack(f"{endian}I", end_ptr)
            file_data_bytes.extend(ptr_bytes)
            file_data_bytes.extend(compressed)
            # Align next file to 4-byte boundary
            file_data_len = block_count * 4 + len(compressed)
            pad_needed = ((file_data_len + 3) // 4) * 4 - file_data_len
            file_data_bytes.extend(b"\x00" * pad_needed)
            current_file_offset += file_data_len + pad_needed

    total_fs_size = root_dir_offset + dir_table_padded_size + len(file_data_bytes)

    # Root directory inode
    # Directory mode 0o040755
    root_mode = 0o040755
    root_uid = 0
    root_gid = 0
    root_size = dir_table_size
    root_offset_words = root_dir_offset // 4

    if endian == "<":
        root_size_gid = (root_size & 0xFFFFFF) | ((root_gid & 0xFF) << 24)
        root_namelen_offset = (0 & 0x3F) | ((root_offset_words & 0x3FFFFFF) << 6)
    else:
        root_size_gid = ((root_size & 0xFFFFFF) << 8) | (root_gid & 0xFF)
        root_namelen_offset = ((0 & 0x3F) << 26) | (root_offset_words & 0x3FFFFFF)

    root_inode = struct.pack(f"{endian}HHI I", root_mode, root_uid, root_size_gid, root_namelen_offset)

    # Assemble Superblock
    sb = bytearray()
    sb.extend(struct.pack(f"{endian}I", magic))
    sb.extend(struct.pack(f"{endian}I", total_fs_size))
    sb.extend(struct.pack(f"{endian}I", 0))  # flags
    sb.extend(struct.pack(f"{endian}I", 0))  # future
    sb.extend(sig)
    sb.extend(fsid)
    sb.extend(vname)
    sb.extend(root_inode)
    sb.extend(b"\x00" * sb_padding)

    full_image = sb + dir_entries_bytes + (b"\x00" * (dir_table_padded_size - dir_table_size)) + file_data_bytes
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(full_image)
    return output_path


def create_synthetic_trx(
    output_path: Path,
    partitions: list[bytes] | None = None,
) -> Path:
    """Create a valid Broadcom TRX container image wrapping partition payloads."""
    if partitions is None:
        partitions = [b"BOOTLOADER_PAYLOAD_DATA\n", b"KERNEL_GZIP_MIPS_PAYLOAD\n", b"ROOTFS_FILESYSTEM_PAYLOAD\n"]

    hdr_len = 28
    offsets = []
    current_off = hdr_len
    for part in partitions:
        offsets.append(current_off)
        current_off += len(part)

    total_len = current_off
    # Pad offsets to at least 3
    while len(offsets) < 3:
        offsets.append(total_len)

    # Compute CRC32 from offset 12 to end of container
    # Build partial container without CRC first
    flags = 0
    version = 1
    flags_ver = flags | (version << 16)

    part_data = b"".join(partitions)
    body_for_crc = struct.pack("<IIII", flags_ver, offsets[0], offsets[1], offsets[2]) + part_data
    crc32_val = binascii.crc32(body_for_crc) & 0xFFFFFFFF

    hdr = struct.pack("<4sIII", b"HDR0", total_len, crc32_val, flags_ver)
    hdr += struct.pack("<III", offsets[0], offsets[1], offsets[2])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(hdr + part_data)
    return output_path


def create_synthetic_uimage(
    output_path: Path,
    payload: bytes = b"LINUX_KERNEL_TEST_IMAGE",
    compressed_gzip: bool = True,
    image_name: str = "Test Linux Kernel",
) -> Path:
    """Create a valid U-Boot legacy uImage with CRC checksums."""
    magic = 0x27051956
    itime = 1700000000
    load_addr = 0x80000000
    entry_point = 0x80000000
    os_code = 5      # Linux
    arch_code = 1    # ARM
    type_code = 2    # Kernel
    comp_code = 1 if compressed_gzip else 0

    if compressed_gzip:
        payload_bytes = gzip.compress(payload)
    else:
        payload_bytes = payload

    size = len(payload_bytes)
    dcrc = binascii.crc32(payload_bytes) & 0xFFFFFFFF
    name_bytes = image_name.encode("utf-8")[:32].ljust(32, b"\x00")

    # Header without hcrc (hcrc set to 0)
    hdr_zero = struct.pack(
        ">IIIIIIIBBBB32s",
        magic,
        0,  # hcrc = 0
        itime,
        size,
        load_addr,
        entry_point,
        dcrc,
        os_code,
        arch_code,
        type_code,
        comp_code,
        name_bytes,
    )
    hcrc = binascii.crc32(hdr_zero) & 0xFFFFFFFF

    hdr_final = struct.pack(
        ">IIIIIIIBBBB32s",
        magic,
        hcrc,
        itime,
        size,
        load_addr,
        entry_point,
        dcrc,
        os_code,
        arch_code,
        type_code,
        comp_code,
        name_bytes,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(hdr_final + payload_bytes)
    return output_path
