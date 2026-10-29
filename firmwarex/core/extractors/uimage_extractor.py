"""U-Boot legacy uImage firmware parser and payload extractor.

Parses 64-byte U-Boot legacy headers (IH_MAGIC 0x27051956), validates header
and data CRC checksums, decompresses compressed payloads (gzip/bzip2/none),
and unpacks kernel or ramdisk/rootfs payloads into the designated workspace.
"""

import binascii
import bz2
import gzip
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

UIMAGE_MAGIC = 0x27051956

OS_NAMES = {
    0: "invalid",
    1: "openbsd",
    2: "netbsd",
    3: "freebsd",
    4: "4_4bsd",
    5: "linux",
    6: "svr4",
    7: "esix",
    8: "solaris",
    9: "irix",
    10: "sco",
    11: "dell",
    12: "ncr",
    13: "lynxos",
    14: "vxworks",
    15: "psos",
    16: "qnx",
    17: "u_boot",
    18: "rtems",
    19: "artos",
    20: "unity",
    21: "integrity",
    22: "ose",
    23: "plan9",
    24: "openrtos",
    25: "arm_trusted_firmware",
    26: "tee",
    27: "opensbi",
    28: "efi",
}

ARCH_NAMES = {
    0: "invalid",
    1: "arm",
    2: "arm64",
    3: "mips",
    4: "mips64",
    5: "ppc",
    6: "s390",
    7: "sh",
    8: "sparc",
    9: "sparc64",
    10: "m68k",
    11: "microblaze",
    12: "nios2",
    13: "blackfin",
    14: "avr32",
    15: "stm8",
    16: "riscv",
    17: "sandbox",
    18: "x86",
    19: "x86_64",
    20: "xtensa",
}

TYPE_NAMES = {
    0: "invalid",
    1: "standalone",
    2: "kernel",
    3: "ramdisk",
    4: "multi",
    5: "firmware",
    6: "script",
    7: "filesystem",
    8: "fdt",
}

COMP_NAMES = {
    0: "none",
    1: "gzip",
    2: "bzip2",
    3: "lzma",
    4: "lzo",
    5: "lz4",
    6: "zstd",
}


class UImageExtractor(BaseExtractor):
    """Parses and extracts U-Boot legacy uImage payloads."""

    format_id = "uimage"
    name = "U-Boot Legacy uImage Extractor"

    def check_tool_availability(self) -> tuple[bool, str | None]:
        """Pure Python parsing with built-in gzip and bz2 decompression."""
        return True, "Pure Python built-in"

    def can_extract(self, file_path: Path, offset: int = 0) -> bool:
        if not file_path.exists():
            return False
        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                hdr = f.read(4)
                if len(hdr) < 4:
                    return False
                magic = struct.unpack(">I", hdr)[0]
                return magic == UIMAGE_MAGIC
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
                hdr_bytes = f.read(64)
                if len(hdr_bytes) < 64:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=["Truncated uImage header (less than 64 bytes)."],
                    )

                magic, hcrc, itime, size, load, ep, dcrc = struct.unpack(">IIIIIII", hdr_bytes[0:28])
                os_code, arch_code, type_code, comp_code = struct.unpack("BBBB", hdr_bytes[28:32])
                name = hdr_bytes[32:64].rstrip(b"\x00").decode("utf-8", errors="replace")

                if magic != UIMAGE_MAGIC:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=[f"Invalid uImage magic: 0x{magic:08x}"],
                    )

                # Verify header CRC (hcrc computed with hcrc field set to zero)
                zeroed_hdr = hdr_bytes[:4] + b"\x00\x00\x00\x00" + hdr_bytes[8:]
                computed_hcrc = binascii.crc32(zeroed_hdr) & 0xFFFFFFFF
                if computed_hcrc != hcrc:
                    diagnostics.append(
                        f"Header CRC mismatch (header: 0x{hcrc:08x}, computed: 0x{computed_hcrc:08x})."
                    )

                os_str = OS_NAMES.get(os_code, f"os_{os_code}")
                arch_str = ARCH_NAMES.get(arch_code, f"arch_{arch_code}")
                type_str = TYPE_NAMES.get(type_code, f"type_{type_code}")
                comp_str = COMP_NAMES.get(comp_code, f"comp_{comp_code}")

                diagnostics.append(
                    f"uImage identified: '{name}' (OS: {os_str}, Arch: {arch_str}, "
                    f"Type: {type_str}, Compression: {comp_str}, Size: {size} bytes)."
                )

                # Read payload
                payload = f.read(size)
                if len(payload) < size:
                    diagnostics.append(
                        f"Warning: File contains {len(payload)} bytes; uImage header claims {size} bytes."
                    )

                # Verify data CRC
                if len(payload) == size:
                    computed_dcrc = binascii.crc32(payload) & 0xFFFFFFFF
                    if computed_dcrc != dcrc:
                        diagnostics.append(
                            f"Data CRC mismatch (header: 0x{dcrc:08x}, computed: 0x{computed_dcrc:08x})."
                        )

                # Decompress payload if needed
                uncompressed_data = payload
                decomp_name = "payload_raw.bin"

                if comp_code == 1:  # gzip
                    try:
                        uncompressed_data = gzip.decompress(payload)
                        decomp_name = "payload_decompressed.bin"
                        diagnostics.append(
                            f"Gzip payload decompressed: {len(payload)} bytes -> {len(uncompressed_data)} bytes."
                        )
                    except Exception as gz_err:
                        diagnostics.append(f"Gzip decompression failed: {gz_err!s}; using raw bytes.")
                elif comp_code == 2:  # bzip2
                    try:
                        uncompressed_data = bz2.decompress(payload)
                        decomp_name = "payload_decompressed.bin"
                        diagnostics.append(
                            f"Bzip2 payload decompressed: {len(payload)} bytes -> {len(uncompressed_data)} bytes."
                        )
                    except Exception as bz_err:
                        diagnostics.append(f"Bzip2 decompression failed: {bz_err!s}; using raw bytes.")
                elif comp_code in (3, 4, 5, 6):
                    diagnostics.append(
                        f"Compression type '{comp_str}' requires external tool; writing raw payload."
                    )

                output_dir.mkdir(parents=True, exist_ok=True)
                target_file = (output_dir / decomp_name).resolve()

                if not is_safe_extraction_path(output_dir, target_file):
                    raise SecurityViolationError(f"Path traversal in uImage payload name '{decomp_name}'")

                tracker.add_file(len(uncompressed_data))
                with open(target_file, "wb") as f_out:
                    f_out.write(uncompressed_data)

                extracted_files.append(str(target_file.relative_to(output_dir)).replace("\\", "/"))

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
                errors=[f"uImage parsing failed: {e!s}"],
                diagnostics=diagnostics,
            )

