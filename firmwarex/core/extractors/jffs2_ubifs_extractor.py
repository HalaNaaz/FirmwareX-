"""JFFS2 and UBIFS filesystem parsers and modular extractor interfaces.

Inspects JFFS2 node headers (magic 0x8519 / 0x1985) and UBI physical eraseblock
headers (magic 'UBI#', 0x06101831). Evaluates tool availability (jffs2dump,
ubireader) and provides structured diagnostic validation.
"""

import shutil
import struct
from pathlib import Path

from firmwarex.core.extractors.base import (
    BaseExtractor,
    ExtractionOutcome,
    ExtractionStatus,
    QuotaTracker,
)

JFFS2_MAGIC_LE = 0x1985
JFFS2_MAGIC_BE = 0x8519
UBIFS_NODE_MAGIC = 0x06101831
UBI_EC_HDR_MAGIC = b"UBI#"


class Jffs2Extractor(BaseExtractor):
    """Modular extractor for JFFS2 (Journalling Flash File System v2)."""

    format_id = "jffs2"
    name = "JFFS2 Flash Filesystem Extractor"

    def check_tool_availability(self) -> tuple[bool, str | None]:
        tool = shutil.which("jffs2dump") or shutil.which("jffs2extract")
        if tool:
            return True, tool
        return False, "jffs2dump / jffs2extract not installed in environment"

    def can_extract(self, file_path: Path, offset: int = 0) -> bool:
        if not file_path.exists():
            return False
        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                hdr = f.read(2)
                if len(hdr) < 2:
                    return False
                val = struct.unpack("<H", hdr)[0]
                return val in (JFFS2_MAGIC_LE, JFFS2_MAGIC_BE)
        except Exception:
            return False

    def extract(
        self,
        file_path: Path,
        output_dir: Path,
        offset: int = 0,
        quota_tracker: QuotaTracker | None = None,
    ) -> ExtractionOutcome:
        diagnostics: list[str] = []

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
                hdr = f.read(12)
                if len(hdr) < 12:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=["Truncated JFFS2 node header."],
                    )

                magic_le = struct.unpack("<H", hdr[0:2])[0]
                endian = "<" if magic_le == JFFS2_MAGIC_LE else ">"
                nodetype, totlen = struct.unpack(f"{endian}HI", hdr[2:8])

                diagnostics.append(
                    f"JFFS2 node validated at offset {offset}. "
                    f"Endianness: {'little' if endian == '<' else 'big'}, "
                    f"NodeType: 0x{nodetype:04x}, NodeLength: {totlen} bytes."
                )

                tool_avail, tool_info = self.check_tool_availability()
                if not tool_avail:
                    return ExtractionOutcome(
                        status=ExtractionStatus.UNSUPPORTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name="jffs2dump / jffs2extract",
                        tool_version=None,
                        diagnostics=diagnostics,
                        errors=[
                            "JFFS2 header verified, but extraction requires 'jffs2dump' which is not installed. "
                            "Extraction deferred."
                        ],
                    )

                return ExtractionOutcome(
                    status=ExtractionStatus.PARTIAL,
                    success=False,
                    format_id=self.format_id,
                    offset=offset,
                    tool_name=self.name,
                    diagnostics=diagnostics,
                )

        except Exception as e:
            return ExtractionOutcome(
                status=ExtractionStatus.CORRUPTED,
                success=False,
                format_id=self.format_id,
                offset=offset,
                tool_name=self.name,
                errors=[f"JFFS2 parse error: {e!s}"],
                diagnostics=diagnostics,
            )


class UbifsExtractor(BaseExtractor):
    """Modular extractor for UBIFS and UBI volumes."""

    format_id = "ubifs"
    name = "UBIFS / UBI Volume Extractor"

    def check_tool_availability(self) -> tuple[bool, str | None]:
        tool = shutil.which("ubireader_extract_files") or shutil.which("ubireader_extract_images")
        if tool:
            return True, tool
        return False, "ubireader not installed in environment"

    def can_extract(self, file_path: Path, offset: int = 0) -> bool:
        if not file_path.exists():
            return False
        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                hdr = f.read(4)
                if len(hdr) < 4:
                    return False
                if hdr == UBI_EC_HDR_MAGIC:
                    return True
                val = struct.unpack("<I", hdr)[0]
                return val == UBIFS_NODE_MAGIC
        except Exception:
            return False

    def extract(
        self,
        file_path: Path,
        output_dir: Path,
        offset: int = 0,
        quota_tracker: QuotaTracker | None = None,
    ) -> ExtractionOutcome:
        diagnostics: list[str] = []

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
                hdr = f.read(64)
                if len(hdr) < 4:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=["Truncated UBI/UBIFS header."],
                    )

                if hdr.startswith(UBI_EC_HDR_MAGIC):
                    diagnostics.append(f"UBI Eraseblock Header (UBI#) identified at offset {offset}.")
                else:
                    diagnostics.append(f"UBIFS Node magic (0x06101831) identified at offset {offset}.")

                tool_avail, tool_info = self.check_tool_availability()
                if not tool_avail:
                    return ExtractionOutcome(
                        status=ExtractionStatus.UNSUPPORTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name="ubireader",
                        tool_version=None,
                        diagnostics=diagnostics,
                        errors=[
                            "UBI/UBIFS format verified, but extraction requires 'ubireader' which is not installed. "
                            "Extraction deferred."
                        ],
                    )

                return ExtractionOutcome(
                    status=ExtractionStatus.PARTIAL,
                    success=False,
                    format_id=self.format_id,
                    offset=offset,
                    tool_name=self.name,
                    diagnostics=diagnostics,
                )

        except Exception as e:
            return ExtractionOutcome(
                status=ExtractionStatus.CORRUPTED,
                success=False,
                format_id=self.format_id,
                offset=offset,
                tool_name=self.name,
                errors=[f"UBIFS parse error: {e!s}"],
                diagnostics=diagnostics,
            )
