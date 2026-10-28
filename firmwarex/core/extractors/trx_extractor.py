"""Broadcom TRX firmware container parser and partition extractor.

TRX headers wrap bootloader, kernel, and rootfs partitions commonly used
in embedded routers (e.g., Linksys, Asus, Netgear, OpenWrt).
"""

import binascii
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

TRX_MAGIC = b"HDR0"


class TrxExtractor(BaseExtractor):
    """Parses Broadcom TRX headers and unpacks embedded kernel and rootfs partitions."""

    format_id = "trx"
    name = "Broadcom TRX Container Extractor"

    def check_tool_availability(self) -> tuple[bool, str | None]:
        """Built-in pure Python container parser."""
        return True, "Pure Python built-in"

    def can_extract(self, file_path: Path, offset: int = 0) -> bool:
        if not file_path.exists():
            return False
        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                magic = f.read(4)
                return magic == TRX_MAGIC
        except Exception:
            return False

    def extract(
        self,
        file_path: Path,
        output_dir: Path,
        offset: int = 0,
        quota_tracker: QuotaTracker | None = None,
    ) -> ExtractionOutcome:
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
                hdr = f.read(28)
                if len(hdr) < 28 or hdr[0:4] != TRX_MAGIC:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=["Truncated or invalid TRX header."],
                    )

                magic, total_len, stored_crc, flags_ver = struct.unpack("<4sIII", hdr[0:16])
                flags = flags_ver & 0xFFFF
                version = (flags_ver >> 16) & 0xFFFF

                # Offsets to partitions
                off0, off1, off2 = struct.unpack("<III", hdr[16:28])
                partition_offsets = [off0, off1, off2]

                # If version >= 2, there is an offset 3
                if version >= 2:
                    off3_bytes = f.read(4)
                    if len(off3_bytes) == 4:
                        off3 = struct.unpack("<I", off3_bytes)[0]
                        partition_offsets.append(off3)

                diagnostics.append(
                    f"TRX v{version} container identified at offset {offset}. "
                    f"Total length: {total_len} bytes, Flags: 0x{flags:04x}."
                )

                # Validate partition offsets are ordered and within total_len
                valid_offsets = [p for p in partition_offsets if 0 < p < total_len]
                if not valid_offsets:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=["TRX container has no valid partition offsets."],
                    )

                # Read container data
                f.seek(offset)
                container_data = f.read(total_len)
                if len(container_data) < total_len:
                    diagnostics.append(
                        f"Warning: File contains {len(container_data)} bytes; TRX claims {total_len} bytes."
                    )

                # Verify CRC32
                if len(container_data) >= 12:
                    computed_crc = binascii.crc32(container_data[12:]) & 0xFFFFFFFF
                    if computed_crc != stored_crc:
                        diagnostics.append(
                            f"CRC32 mismatch (stored: 0x{stored_crc:08x}, computed: 0x{computed_crc:08x}). Continuing extraction."
                        )

                # Extract each partition
                output_dir.mkdir(parents=True, exist_ok=True)
                offsets_sorted = sorted(set(valid_offsets))
                offsets_sorted.append(min(len(container_data), total_len))

                for idx in range(len(offsets_sorted) - 1):
                    p_start = offsets_sorted[idx]
                    p_end = offsets_sorted[idx + 1]
                    p_data = container_data[p_start:p_end]

                    part_name = f"partition_{idx}_offset_0x{p_start:x}.bin"
                    target_file = (output_dir / part_name).resolve()

                    if not is_safe_extraction_path(output_dir, target_file):
                        raise SecurityViolationError(f"Path traversal in partition name '{part_name}'")

                    tracker.add_file(len(p_data))
                    with open(target_file, "wb") as f_part:
                        f_part.write(p_data)

                    extracted_files.append(str(target_file.relative_to(output_dir)).replace("\\", "/"))
                    diagnostics.append(
                        f"Extracted partition {idx} ({len(p_data)} bytes) from offset 0x{p_start:x} to '{part_name}'."
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
                errors=[f"TRX parsing failed: {e!s}"],
                diagnostics=diagnostics,
            )
