"""SquashFS filesystem parser and modular extractor interface.

Validates SquashFS 4.0/3.0 superblocks (little-endian 'hsqs', big-endian 'sqsh',
and non-standard swapped variants 'qshs', 'shsq'). Discovers external extraction
tools (unsquashfs, sasquatch) and falls back honestly to structured diagnostic reporting
when native decompression binaries are unavailable.
"""

import shutil
import struct
import subprocess
from pathlib import Path

from firmwarex.core.extractors.base import (
    BaseExtractor,
    ExtractionOutcome,
    ExtractionStatus,
    QuotaTracker,
    SecurityViolationError,
    is_safe_extraction_path,
)

SQUASHFS_MAGICS = {
    b"hsqs": ("little", "SquashFS 4.0 (Little-Endian)"),
    b"sqsh": ("big", "SquashFS 4.0 (Big-Endian)"),
    b"qshs": ("little", "SquashFS Non-Standard Swapped Variant"),
    b"shsq": ("big", "SquashFS Non-Standard Swapped Variant"),
}

COMPRESSION_NAMES = {
    1: "gzip",
    2: "lzma",
    3: "lzo",
    4: "xz",
    5: "lz4",
    6: "zstd",
}


class SquashfsExtractor(BaseExtractor):
    """Modular extractor for SquashFS filesystems."""

    format_id = "squashfs"
    name = "SquashFS Extractor"

    def check_tool_availability(self) -> tuple[bool, str | None]:
        """Check for unsquashfs or sasquatch on system PATH."""
        for tool in ["unsquashfs", "sasquatch"]:
            tool_path = shutil.which(tool)
            if tool_path:
                try:
                    ver_proc = subprocess.run([tool_path, "-v"], capture_output=True, text=True, timeout=3)
                    version = ver_proc.stdout.strip().split("\n")[0] or "detected"
                    return True, f"{tool} ({version})"
                except Exception:
                    return True, tool
        return False, "unsquashfs / sasquatch not installed in environment"

    def can_extract(self, file_path: Path, offset: int = 0) -> bool:
        if not file_path.exists():
            return False
        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                magic = f.read(4)
                return magic in SQUASHFS_MAGICS
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
                hdr = f.read(96)
                if len(hdr) < 96:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=["Truncated SquashFS superblock."],
                    )

                magic = hdr[0:4]
                if magic not in SQUASHFS_MAGICS:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=[f"Invalid SquashFS magic: 0x{magic.hex()}"],
                    )

                endian_code, desc = SQUASHFS_MAGICS[magic]
                endian = "<" if endian_code == "little" else ">"

                # Parse SquashFS 4.0 Superblock layout
                inodes, mtime, block_size, fragments = struct.unpack(f"{endian}IIII", hdr[4:20])
                compression_id, block_log, flags, id_count, ver_major, ver_minor = struct.unpack(
                    f"{endian}HHHHHH", hdr[20:32]
                )
                bytes_used = struct.unpack(f"{endian}Q", hdr[40:48])[0]

                comp_name = COMPRESSION_NAMES.get(compression_id, f"unknown_comp_{compression_id}")
                diagnostics.append(
                    f"SquashFS v{ver_major}.{ver_minor} [{endian_code}] validated at offset {offset}. "
                    f"Compression: {comp_name}, Block Size: {block_size} bytes, "
                    f"Inodes: {inodes}, Bytes Used: {bytes_used}."
                )

                # Check tool availability
                tool_available, tool_info = self.check_tool_availability()

                if not tool_available:
                    diagnostics.append(
                        "External extraction tool (unsquashfs/sasquatch) not found. "
                        "Failing closed to prevent corrupted partial extraction."
                    )
                    return ExtractionOutcome(
                        status=ExtractionStatus.UNSUPPORTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name="unsquashfs / sasquatch",
                        tool_version=None,
                        diagnostics=diagnostics,
                        errors=[
                            "SquashFS superblock successfully validated, but host/container lacks 'unsquashfs'. "
                            "Extraction requires external tooling."
                        ],
                    )

                # Execute unsquashfs safely if available
                tool_bin = shutil.which("unsquashfs") or shutil.which("sasquatch")
                output_dir.mkdir(parents=True, exist_ok=True)
                cmd = [tool_bin, "-d", str(output_dir.resolve()), "-f"]
                if offset > 0:
                    cmd.extend(["-o", str(offset)])
                cmd.append(str(file_path.resolve()))

                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if proc.returncode == 0:
                    # Collect extracted items and enforce quotas
                    extracted_files = []
                    for root, _, files in Path(output_dir).walk():
                        for f_name in files:
                            p = root / f_name
                            if not is_safe_extraction_path(output_dir, p):
                                raise SecurityViolationError(f"Path traversal detected in extracted file '{p}'")
                            tracker.add_file(p.stat().st_size)
                            extracted_files.append(str(p.relative_to(output_dir)).replace("\\", "/"))

                    return ExtractionOutcome(
                        status=ExtractionStatus.EXTRACTED,
                        success=True,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=tool_bin,
                        tool_version=tool_info,
                        file_count=len(extracted_files),
                        total_size_bytes=tracker.current_total_bytes,
                        extracted_files=extracted_files,
                        diagnostics=diagnostics,
                    )
                else:
                    return ExtractionOutcome(
                        status=ExtractionStatus.FAILED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=tool_bin,
                        errors=[f"unsquashfs failed with code {proc.returncode}: {proc.stderr.strip()}"],
                        diagnostics=diagnostics,
                    )

        except Exception as e:
            return ExtractionOutcome(
                status=ExtractionStatus.CORRUPTED,
                success=False,
                format_id=self.format_id,
                offset=offset,
                tool_name=self.name,
                errors=[f"SquashFS parsing failed: {e!s}"],
                diagnostics=diagnostics,
            )
