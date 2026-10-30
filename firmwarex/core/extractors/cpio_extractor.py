"""Pure Python safe CPIO archive extractor.

Supports standard Linux initramfs / initrd CPIO formats:
- SVR4 Portable Format without CRC ("newc", magic "070701")
- SVR4 Portable Format with CRC ("crc", magic "070702")
- Old Portable ASCII format (magic "070707")
- Old Binary format (magic 0x71c7 little/big endian)

Features:
- Enforces strict Zip Slip path traversal defenses via is_safe_extraction_path
- Respects cumulative QuotaTracker limits (file count and uncompressed bytes)
- Safely handles regular files, directories, and symlinks
- Pure Python with no external subprocess or system utility requirements
"""

import os
import struct
from pathlib import Path

from firmwarex.core.extractors.base import (
    BaseExtractor,
    ExtractionOutcome,
    ExtractionStatus,
    QuotaTracker,
    SecurityViolationError,
    is_safe_extraction_path,
)

CPIO_NEWC_MAGIC = b"070701"
CPIO_CRC_MAGIC = b"070702"
CPIO_OLD_ASCII_MAGIC = b"070707"
CPIO_BIN_LE_MAGIC = b"\xc7\x71"
CPIO_BIN_BE_MAGIC = b"\x71\xc7"


class CpioExtractor(BaseExtractor):
    """Pure-Python safe extractor for CPIO archives and embedded initramfs images."""

    format_id = "cpio"
    name = "CPIO Archive Safe Extractor (Pure Python)"

    def check_tool_availability(self) -> tuple[bool, str | None]:
        """CPIO extractor is pure Python and requires no external binaries."""
        return True, "Pure Python built-in (SVR4 newc/crc & binary)"

    def can_extract(self, file_path: Path, offset: int = 0) -> bool:
        """Inspect bytes at offset for CPIO magic markers."""
        if not file_path.exists():
            return False
        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                magic6 = f.read(6)
                if magic6 in (CPIO_NEWC_MAGIC, CPIO_CRC_MAGIC, CPIO_OLD_ASCII_MAGIC):
                    return True
                if magic6[:2] in (CPIO_BIN_LE_MAGIC, CPIO_BIN_BE_MAGIC):
                    return True
            return False
        except Exception:
            return False

    def extract(
        self,
        file_path: Path,
        output_dir: Path,
        offset: int = 0,
        quota_tracker: QuotaTracker | None = None,
    ) -> ExtractionOutcome:
        """Safely extract all entries in the CPIO archive."""
        if quota_tracker is None:
            quota_tracker = QuotaTracker()

        output_dir.mkdir(parents=True, exist_ok=True)
        extracted_files: list[str] = []
        diagnostics: list[str] = []
        errors: list[str] = []

        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                head_magic = f.read(6)
                f.seek(offset)

                if head_magic in (CPIO_NEWC_MAGIC, CPIO_CRC_MAGIC):
                    status = self._extract_svr4(f, output_dir, quota_tracker, extracted_files, diagnostics, errors)
                elif head_magic[:2] in (CPIO_BIN_LE_MAGIC, CPIO_BIN_BE_MAGIC):
                    endian = "<" if head_magic[:2] == CPIO_BIN_LE_MAGIC else ">"
                    status = self._extract_binary(f, endian, output_dir, quota_tracker, extracted_files, diagnostics, errors)
                elif head_magic == CPIO_OLD_ASCII_MAGIC:
                    status = self._extract_old_ascii(f, output_dir, quota_tracker, extracted_files, diagnostics, errors)
                else:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name="builtin_cpio",
                        errors=["Unrecognized CPIO header signature"],
                    )

            total_bytes = sum(
                (output_dir / rel).stat().st_size
                for rel in extracted_files
                if (output_dir / rel).is_file()
            )

            is_success = status == ExtractionStatus.EXTRACTED and len(extracted_files) > 0
            return ExtractionOutcome(
                status=status if is_success else (ExtractionStatus.CORRUPTED if errors else ExtractionStatus.PARTIAL),
                success=is_success,
                format_id=self.format_id,
                offset=offset,
                tool_name="builtin_cpio",
                tool_version="pure-python-1.0",
                file_count=len(extracted_files),
                total_size_bytes=total_bytes,
                extracted_files=extracted_files,
                diagnostics=diagnostics,
                errors=errors,
            )

        except SecurityViolationError as e:
            return ExtractionOutcome(
                status=ExtractionStatus.FAILED,
                success=False,
                format_id=self.format_id,
                offset=offset,
                tool_name="builtin_cpio",
                errors=[f"Security policy violation: {e}"],
            )
        except Exception as e:
            return ExtractionOutcome(
                status=ExtractionStatus.FAILED,
                success=False,
                format_id=self.format_id,
                offset=offset,
                tool_name="builtin_cpio",
                errors=[f"Unexpected CPIO extraction error: {e}"],
            )

    def _extract_svr4(
        self,
        f,
        output_dir: Path,
        quota_tracker: QuotaTracker,
        extracted_files: list[str],
        diagnostics: list[str],
        errors: list[str],
    ) -> ExtractionStatus:
        """Parse SVR4 newc/crc format (110-byte ASCII header)."""
        while True:
            hdr_bytes = f.read(110)
            if len(hdr_bytes) < 110:
                if len(extracted_files) > 0:
                    diagnostics.append("CPIO archive ended without trailer")
                    return ExtractionStatus.EXTRACTED
                errors.append("Truncated CPIO SVR4 header")
                return ExtractionStatus.CORRUPTED

            magic = hdr_bytes[0:6]
            if magic not in (CPIO_NEWC_MAGIC, CPIO_CRC_MAGIC):
                errors.append(f"Invalid CPIO header magic: {magic!r}")
                return ExtractionStatus.CORRUPTED

            try:
                mode = int(hdr_bytes[14:22], 16)
                filesize = int(hdr_bytes[54:62], 16)
                namesize = int(hdr_bytes[94:102], 16)
            except ValueError as e:
                errors.append(f"Malformed hexadecimal fields in CPIO header: {e}")
                return ExtractionStatus.CORRUPTED

            name_bytes = f.read(namesize)
            if len(name_bytes) < namesize:
                errors.append("Premature EOF while reading filename")
                return ExtractionStatus.CORRUPTED

            filename = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")

            # Align header + filename to 4-byte boundary
            header_and_name_len = 110 + namesize
            header_pad = (4 - (header_and_name_len % 4)) % 4
            if header_pad:
                f.read(header_pad)

            if filename == "TRAILER!!!":
                break

            # Parse file type
            file_type = mode & 0o170000

            # Safe destination path calculation
            clean_rel = os.path.normpath(filename.lstrip("/\\"))
            if clean_rel in (".", ""):
                # Root directory entry
                file_pad = (4 - (filesize % 4)) % 4
                if filesize > 0:
                    f.seek(filesize + file_pad, os.SEEK_CUR)
                continue

            dest_path = output_dir / clean_rel
            if not is_safe_extraction_path(output_dir, dest_path):
                raise SecurityViolationError(f"Directory traversal detected in CPIO member: {filename}")

            if file_type == 0o040000:  # Directory
                dest_path.mkdir(parents=True, exist_ok=True)
                quota_tracker.add_file(0)
                extracted_files.append(str(Path(clean_rel).as_posix()))
                file_pad = (4 - (filesize % 4)) % 4
                if filesize > 0:
                    f.seek(filesize + file_pad, os.SEEK_CUR)

            elif file_type == 0o120000:  # Symlink
                link_target_bytes = f.read(filesize)
                file_pad = (4 - (filesize % 4)) % 4
                if file_pad:
                    f.read(file_pad)

                dest_path.parent.mkdir(parents=True, exist_ok=True)
                link_target = link_target_bytes.decode("utf-8", errors="replace")
                # On Windows or safe platforms, record symlink target in a text marker or relative link
                try:
                    if dest_path.exists() or dest_path.is_symlink():
                        dest_path.unlink()
                    dest_path.symlink_to(link_target)
                except (OSError, NotImplementedError):
                    # Fallback for Windows without SeCreateSymbolicLinkPrivilege: write .symlink file
                    dest_path.write_text(f"SYMLINK: {link_target}", encoding="utf-8")

                quota_tracker.add_file(len(link_target_bytes))
                extracted_files.append(str(Path(clean_rel).as_posix()))

            elif file_type in (0o100000, 0):  # Regular file (or generic)
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                quota_tracker.add_file(filesize)

                with open(dest_path, "wb") as out_f:
                    remaining = filesize
                    while remaining > 0:
                        chunk_size = min(65536, remaining)
                        chunk = f.read(chunk_size)
                        if not chunk:
                            errors.append(f"Premature EOF while reading file content: {filename}")
                            return ExtractionStatus.CORRUPTED
                        out_f.write(chunk)
                        remaining -= len(chunk)

                file_pad = (4 - (filesize % 4)) % 4
                if file_pad:
                    f.read(file_pad)

                extracted_files.append(str(Path(clean_rel).as_posix()))

            else:
                # Device, FIFO, socket, etc. Skip content safely
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                dest_path.write_text(f"SPECIAL_NODE mode={oct(mode)}", encoding="utf-8")
                quota_tracker.add_file(0)
                extracted_files.append(str(Path(clean_rel).as_posix()))
                file_pad = (4 - (filesize % 4)) % 4
                if filesize > 0:
                    f.seek(filesize + file_pad, os.SEEK_CUR)

        return ExtractionStatus.EXTRACTED

    def _extract_binary(
        self,
        f,
        endian: str,
        output_dir: Path,
        quota_tracker: QuotaTracker,
        extracted_files: list[str],
        diagnostics: list[str],
        errors: list[str],
    ) -> ExtractionStatus:
        """Parse old binary CPIO format (26-byte struct)."""
        hdr_fmt = f"{endian}6H2HIH"
        while True:
            hdr_bytes = f.read(26)
            if len(hdr_bytes) < 26:
                if len(extracted_files) > 0:
                    return ExtractionStatus.EXTRACTED
                errors.append("Truncated binary CPIO header")
                return ExtractionStatus.CORRUPTED

            magic, _dev, _ino, mode, _uid, _gid, _nlink, _rdev, _mtime, namesize, filesize = struct.unpack(
                hdr_fmt, hdr_bytes
            )

            if magic not in (0x71C7, 0xC771):
                errors.append(f"Invalid binary CPIO magic: {hex(magic)}")
                return ExtractionStatus.CORRUPTED

            name_bytes = f.read(namesize)
            if len(name_bytes) < namesize:
                errors.append("Premature EOF while reading filename")
                return ExtractionStatus.CORRUPTED

            filename = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")

            # Align header + filename to 2-byte boundary
            if (26 + namesize) % 2 != 0:
                f.read(1)

            if filename == "TRAILER!!!":
                break

            clean_rel = os.path.normpath(filename.lstrip("/\\"))
            if clean_rel in (".", ""):
                if filesize % 2 != 0:
                    filesize += 1
                f.seek(filesize, os.SEEK_CUR)
                continue

            dest_path = output_dir / clean_rel
            if not is_safe_extraction_path(output_dir, dest_path):
                raise SecurityViolationError(f"Directory traversal detected in CPIO member: {filename}")

            file_type = mode & 0o170000
            if file_type == 0o040000:
                dest_path.mkdir(parents=True, exist_ok=True)
                quota_tracker.add_file(0)
                extracted_files.append(str(Path(clean_rel).as_posix()))
                if filesize > 0:
                    if filesize % 2 != 0:
                        filesize += 1
                    f.seek(filesize, os.SEEK_CUR)
            else:
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                quota_tracker.add_file(filesize)
                with open(dest_path, "wb") as out_f:
                    remaining = filesize
                    while remaining > 0:
                        chunk_size = min(65536, remaining)
                        chunk = f.read(chunk_size)
                        if not chunk:
                            errors.append(f"Premature EOF in binary CPIO file: {filename}")
                            return ExtractionStatus.CORRUPTED
                        out_f.write(chunk)
                        remaining -= len(chunk)

                if filesize % 2 != 0:
                    f.read(1)
                extracted_files.append(str(Path(clean_rel).as_posix()))

        return ExtractionStatus.EXTRACTED

    def _extract_old_ascii(
        self,
        f,
        output_dir: Path,
        quota_tracker: QuotaTracker,
        extracted_files: list[str],
        diagnostics: list[str],
        errors: list[str],
    ) -> ExtractionStatus:
        """Parse old portable ASCII CPIO format (76-byte octal header)."""
        while True:
            hdr_bytes = f.read(76)
            if len(hdr_bytes) < 76:
                if len(extracted_files) > 0:
                    return ExtractionStatus.EXTRACTED
                errors.append("Truncated old ASCII CPIO header")
                return ExtractionStatus.CORRUPTED

            magic = hdr_bytes[0:6]
            if magic != CPIO_OLD_ASCII_MAGIC:
                errors.append(f"Invalid old ASCII magic: {magic!r}")
                return ExtractionStatus.CORRUPTED

            try:
                _mode = int(hdr_bytes[18:24], 8)
                filesize = int(hdr_bytes[55:66], 8)
                namesize = int(hdr_bytes[66:72], 8)
            except ValueError as e:
                errors.append(f"Malformed octal in old ASCII CPIO header: {e}")
                return ExtractionStatus.CORRUPTED

            name_bytes = f.read(namesize)
            filename = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")

            if filename == "TRAILER!!!":
                break

            clean_rel = os.path.normpath(filename.lstrip("/\\"))
            if clean_rel in (".", ""):
                f.seek(filesize, os.SEEK_CUR)
                continue

            dest_path = output_dir / clean_rel
            if not is_safe_extraction_path(output_dir, dest_path):
                raise SecurityViolationError(f"Directory traversal detected in CPIO member: {filename}")

            dest_path.parent.mkdir(parents=True, exist_ok=True)
            quota_tracker.add_file(filesize)
            with open(dest_path, "wb") as out_f:
                remaining = filesize
                while remaining > 0:
                    chunk = f.read(min(65536, remaining))
                    if not chunk:
                        break
                    out_f.write(chunk)
                    remaining -= len(chunk)

            extracted_files.append(str(Path(clean_rel).as_posix()))

        return ExtractionStatus.EXTRACTED

