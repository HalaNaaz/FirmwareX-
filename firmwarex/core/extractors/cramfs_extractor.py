"""Pure Python CramFS (Compressed ROM File System) parser and safe extractor.

Compliant with Linux CramFS filesystem specifications. Supports little-endian
and big-endian variants, handles zlib compression, directory trees, file symlinks,
and enforces strict Zip Slip path containment and cumulative quota controls.
"""

import os
import struct
import zlib
from pathlib import Path

from firmwarex.core.extractors.base import (
    BaseExtractor,
    ExtractionOutcome,
    ExtractionStatus,
    QuotaTracker,
    SecurityViolationError,
    is_safe_extraction_path,
)

CRAMFS_MAGIC_LE = 0x28CD3D45
CRAMFS_MAGIC_BE = 0x453DCD28


class CramfsExtractor(BaseExtractor):
    """Pure-Python extractor for CramFS embedded filesystems."""

    format_id = "cramfs"
    name = "CramFS Extractor (Pure Python)"

    def check_tool_availability(self) -> tuple[bool, str | None]:
        """CramFS extractor is pure Python (zlib/struct) and requires no external binaries."""
        return True, "Pure Python built-in"

    def can_extract(self, file_path: Path, offset: int = 0) -> bool:
        """Inspect bytes at offset for CramFS magic markers."""
        if not file_path.exists():
            return False
        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                magic_bytes = f.read(4)
                if len(magic_bytes) < 4:
                    return False
                magic_le = struct.unpack("<I", magic_bytes)[0]
                magic_be = struct.unpack(">I", magic_bytes)[0]
                return magic_le == CRAMFS_MAGIC_LE or magic_be == CRAMFS_MAGIC_BE
        except Exception:
            return False

    def extract(
        self,
        file_path: Path,
        output_dir: Path,
        offset: int = 0,
        quota_tracker: QuotaTracker | None = None,
    ) -> ExtractionOutcome:
        """Parse CramFS filesystem at specified offset and safely extract into output_dir."""
        tracker = quota_tracker or QuotaTracker()
        diagnostics: list[str] = []
        errors: list[str] = []
        extracted_files: list[str] = []

        if not file_path.exists():
            return ExtractionOutcome(
                status=ExtractionStatus.FAILED,
                success=False,
                format_id=self.format_id,
                offset=offset,
                tool_name=self.name,
                errors=["Source firmware file does not exist."],
            )

        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                # Read Superblock (76 bytes)
                sb_bytes = f.read(76)
                if len(sb_bytes) < 76:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=["Truncated CramFS superblock header."],
                    )

                magic_le = struct.unpack("<I", sb_bytes[0:4])[0]
                magic_be = struct.unpack(">I", sb_bytes[0:4])[0]

                if magic_le == CRAMFS_MAGIC_LE:
                    endian = "<"
                    endian_name = "little-endian"
                elif magic_be == CRAMFS_MAGIC_BE:
                    endian = ">"
                    endian_name = "big-endian"
                else:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=[f"Invalid CramFS magic: 0x{sb_bytes[0:4].hex()}"],
                    )

                size, flags, future = struct.unpack(f"{endian}III", sb_bytes[4:16])
                signature = sb_bytes[16:32].rstrip(b"\x00").decode("utf-8", errors="replace")
                fs_name = sb_bytes[48:64].rstrip(b"\x00").decode("utf-8", errors="replace")

                diagnostics.append(
                    f"CramFS {endian_name} identified at offset {offset}. "
                    f"Size: {size} bytes, Volume: '{fs_name}', Signature: '{signature}'."
                )

                # Read remaining image payload up to reported size
                f.seek(offset)
                fs_data = f.read(size)
                if len(fs_data) < size:
                    diagnostics.append(
                        f"Warning: File size ({len(fs_data)}) is less than superblock size ({size}). "
                        "Attempting best-effort extraction."
                    )

                # Parse Root Inode (offset 64 to 76 in superblock)
                root_inode = self._parse_inode(sb_bytes[64:76], endian)

                # Extract directory tree recursively
                output_dir.mkdir(parents=True, exist_ok=True)
                self._extract_directory(
                    fs_data=fs_data,
                    dir_offset=root_inode["offset"],
                    dir_size=root_inode["size"],
                    current_path=output_dir,
                    base_dir=output_dir,
                    endian=endian,
                    tracker=tracker,
                    extracted_files=extracted_files,
                    diagnostics=diagnostics,
                )

                return ExtractionOutcome(
                    status=ExtractionStatus.EXTRACTED,
                    success=True,
                    format_id=self.format_id,
                    offset=offset,
                    tool_name=self.name,
                    tool_version="1.0-purepy",
                    file_count=len(extracted_files),
                    total_size_bytes=tracker.current_total_bytes,
                    extracted_files=extracted_files,
                    diagnostics=diagnostics,
                    errors=errors,
                )

        except SecurityViolationError as sec_err:
            return ExtractionOutcome(
                status=ExtractionStatus.FAILED,
                success=False,
                format_id=self.format_id,
                offset=offset,
                tool_name=self.name,
                errors=[f"Security boundary violation: {sec_err!s}"],
                diagnostics=diagnostics,
            )
        except Exception as e:
            return ExtractionOutcome(
                status=ExtractionStatus.CORRUPTED,
                success=False,
                format_id=self.format_id,
                offset=offset,
                tool_name=self.name,
                errors=[f"CramFS parsing failed: {e!s}"],
                diagnostics=diagnostics,
            )

    @classmethod
    def _parse_inode(cls, raw_12: bytes, endian: str) -> dict:
        """Unpack a 12-byte CramFS inode record."""
        mode, uid = struct.unpack(f"{endian}HH", raw_12[0:4])
        size_gid = struct.unpack(f"{endian}I", raw_12[4:8])[0]
        namelen_offset = struct.unpack(f"{endian}I", raw_12[8:12])[0]

        if endian == "<":
            size = size_gid & 0xFFFFFF
            gid = (size_gid >> 24) & 0xFF
            namelen = namelen_offset & 0x3F
            offset = (namelen_offset >> 6) << 2
        else:
            size = (size_gid >> 8) & 0xFFFFFF
            gid = size_gid & 0xFF
            namelen = (namelen_offset >> 26) & 0x3F
            offset = (namelen_offset & 0x3FFFFFF) << 2

        return {
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "size": size,
            "namelen": namelen,
            "offset": offset,
        }

    def _extract_directory(
        self,
        fs_data: bytes,
        dir_offset: int,
        dir_size: int,
        current_path: Path,
        base_dir: Path,
        endian: str,
        tracker: QuotaTracker,
        extracted_files: list[str],
        diagnostics: list[str],
    ):
        """Walk entries inside a CramFS directory and unpack files/subdirectories."""
        pos = dir_offset
        end_pos = dir_offset + dir_size

        while pos < end_pos and pos + 12 <= len(fs_data):
            inode = self._parse_inode(fs_data[pos:pos + 12], endian)
            pos += 12

            namelen = inode["namelen"]
            if namelen == 0:
                continue

            # In CramFS, name length is padded to a 4-byte word boundary
            padded_namelen = ((namelen + 3) // 4) * 4
            if pos + padded_namelen > len(fs_data):
                break

            name_raw = fs_data[pos:pos + namelen]
            pos += padded_namelen
            name = name_raw.decode("utf-8", errors="replace").rstrip("\x00")

            if not name or name in (".", ".."):
                continue

            target_file = (current_path / name).resolve()
            if not is_safe_extraction_path(base_dir, target_file):
                raise SecurityViolationError(
                    f"Path traversal attempted in CramFS entry '{name}' -> '{target_file}'"
                )

            mode = inode["mode"]
            file_type = mode & 0o170000

            if file_type == 0o040000:  # Directory
                target_file.mkdir(parents=True, exist_ok=True)
                tracker.add_file(0)
                extracted_files.append(str(target_file.relative_to(base_dir)).replace("\\", "/"))
                # Recurse into child directory
                self._extract_directory(
                    fs_data=fs_data,
                    dir_offset=inode["offset"],
                    dir_size=inode["size"],
                    current_path=target_file,
                    base_dir=base_dir,
                    endian=endian,
                    tracker=tracker,
                    extracted_files=extracted_files,
                    diagnostics=diagnostics,
                )

            elif file_type == 0o100000:  # Regular file
                target_file.parent.mkdir(parents=True, exist_ok=True)
                file_bytes = self._extract_file_data(fs_data, inode, endian)
                tracker.add_file(len(file_bytes))
                with open(target_file, "wb") as f_out:
                    f_out.write(file_bytes)
                extracted_files.append(str(target_file.relative_to(base_dir)).replace("\\", "/"))

            elif file_type == 0o120000:  # Symlink
                target_file.parent.mkdir(parents=True, exist_ok=True)
                link_bytes = self._extract_file_data(fs_data, inode, endian)
                link_target = link_bytes.decode("utf-8", errors="replace").rstrip("\x00")
                tracker.add_file(len(link_bytes))

                # Verify symlink target does not escape sandbox
                target_dest = (target_file.parent / link_target).resolve()
                if not is_safe_extraction_path(base_dir, target_dest):
                    raise SecurityViolationError(
                        f"Malicious symlink in CramFS: '{target_file}' -> '{link_target}' escapes analysis workspace."
                    )

                try:
                    if hasattr(os, "symlink"):
                        os.symlink(link_target, target_file)
                except OSError:
                    with open(target_file, "w", encoding="utf-8") as f_out:
                        f_out.write(f"SYMLINK: {link_target}\n")
                extracted_files.append(str(target_file.relative_to(base_dir)).replace("\\", "/"))

    @classmethod
    def _extract_file_data(cls, fs_data: bytes, inode: dict, endian: str) -> bytes:
        """Decompress zlib blocks of a regular CramFS file."""
        size = inode["size"]
        if size == 0:
            return b""

        offset = inode["offset"]
        block_count = (size + 4095) // 4096
        ptr_table_size = block_count * 4

        if offset + ptr_table_size > len(fs_data):
            return b""

        # Read block pointer table
        ptrs = [
            struct.unpack(f"{endian}I", fs_data[offset + i * 4:offset + (i + 1) * 4])[0]
            for i in range(block_count)
        ]

        unpacked_chunks = []
        cur_offset = offset + ptr_table_size

        for i in range(block_count):
            end_ptr = ptrs[i]
            if end_ptr > len(fs_data) or end_ptr < cur_offset:
                break

            compressed_chunk = fs_data[cur_offset:end_ptr]
            cur_offset = end_ptr

            expected_size = min(4096, size - (i * 4096))
            # If length equals expected uncompressed size, chunk is uncompressed
            if len(compressed_chunk) == expected_size:
                unpacked_chunks.append(compressed_chunk)
            else:
                try:
                    decompressed = zlib.decompress(compressed_chunk)
                    unpacked_chunks.append(decompressed)
                except Exception:
                    # Best effort uncompressed fallback
                    unpacked_chunks.append(compressed_chunk[:expected_size])

        return b"".join(unpacked_chunks)[:size]

