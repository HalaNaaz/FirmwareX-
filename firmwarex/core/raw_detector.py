"""Raw firmware format and filesystem magic signature detection engine.

Detects proprietary and embedded container formats (SquashFS, CramFS, JFFS2,
UBIFS, U-Boot uImage, Broadcom TRX, D-Link SHRS, Netgear chk, Device Tree Blobs,
and standard archives) with offset tracking and tool compatibility reporting.
"""

from dataclasses import asdict, dataclass
from pathlib import Path

# Maximum byte offset to scan inside raw binary images to prevent CPU exhaustion
MAX_SIGNATURE_SCAN_BYTES = 10 * 1024 * 1024  # 10 MB


@dataclass
class DetectedSignature:
    """Detailed record of a detected firmware format or embedded filesystem layer."""
    format_id: str
    name: str
    offset: int
    magic_hex: str
    endianness: str
    description: str
    is_supported_natively: bool
    recommended_tool: str
    extraction_state: str  # "supported", "unsupported", "partial", "corrupted", "failed"

    def to_dict(self) -> dict:
        return asdict(self)


# Magic byte specifications for embedded container formats
KNOWN_SIGNATURES: list[dict] = [
    # SquashFS 4.0 / 3.0 / 2.0 signatures
    {
        "format_id": "squashfs",
        "name": "SquashFS Filesystem (Little-Endian)",
        "magic": b"hsqs",
        "endianness": "little",
        "description": "Compressed read-only filesystem commonly used for Linux embedded rootfs.",
        "is_supported_natively": False,
        "recommended_tool": "unsquashfs / sasquatch",
    },
    {
        "format_id": "squashfs",
        "name": "SquashFS Filesystem (Big-Endian)",
        "magic": b"sqsh",
        "endianness": "big",
        "description": "Compressed read-only filesystem (Big-Endian, e.g. MIPS/PowerPC).",
        "is_supported_natively": False,
        "recommended_tool": "unsquashfs / sasquatch",
    },
    {
        "format_id": "squashfs",
        "name": "SquashFS Filesystem (Swapped Variant)",
        "magic": b"qshs",
        "endianness": "unknown",
        "description": "Non-standard swapped SquashFS header variant.",
        "is_supported_natively": False,
        "recommended_tool": "sasquatch",
    },
    {
        "format_id": "squashfs",
        "name": "SquashFS Filesystem (Swapped Variant)",
        "magic": b"shsq",
        "endianness": "unknown",
        "description": "Non-standard swapped SquashFS header variant.",
        "is_supported_natively": False,
        "recommended_tool": "sasquatch",
    },
    # CramFS signatures
    {
        "format_id": "cramfs",
        "name": "CramFS Filesystem (Little-Endian)",
        "magic": b"\x45\x3d\xcd\x28",
        "endianness": "little",
        "description": "Compressed ROM filesystem for embedded Linux.",
        "is_supported_natively": False,
        "recommended_tool": "cramfsck / cramfsswap",
    },
    {
        "format_id": "cramfs",
        "name": "CramFS Filesystem (Big-Endian)",
        "magic": b"\x28\xcd\x3d\x45",
        "endianness": "big",
        "description": "Compressed ROM filesystem (Big-Endian).",
        "is_supported_natively": False,
        "recommended_tool": "cramfsck / cramfsswap",
    },
    # JFFS2 signatures
    {
        "format_id": "jffs2",
        "name": "JFFS2 Filesystem (Little-Endian)",
        "magic": b"\x85\x19",
        "endianness": "little",
        "description": "Journalling Flash File System v2 for NOR/NAND flash memory.",
        "is_supported_natively": False,
        "recommended_tool": "jffs2dump / jffs2extract",
    },
    {
        "format_id": "jffs2",
        "name": "JFFS2 Filesystem (Big-Endian)",
        "magic": b"\x19\x85",
        "endianness": "big",
        "description": "Journalling Flash File System v2 (Big-Endian).",
        "is_supported_natively": False,
        "recommended_tool": "jffs2dump / jffs2extract",
    },
    # UBIFS / UBI eraseblock
    {
        "format_id": "ubifs",
        "name": "UBIFS Node Magic",
        "magic": b"\x31\x18\x10\x06",
        "endianness": "little",
        "description": "Unsorted Block Image File System (raw NAND flash).",
        "is_supported_natively": False,
        "recommended_tool": "ubireader_extract_files",
    },
    {
        "format_id": "ubifs",
        "name": "UBI Eraseblock Header",
        "magic": b"UBI#",
        "endianness": "big",
        "description": "UBI physical eraseblock magic delimiter.",
        "is_supported_natively": False,
        "recommended_tool": "ubireader_extract_images",
    },
    # U-Boot uImage
    {
        "format_id": "uimage",
        "name": "U-Boot Legacy uImage",
        "magic": b"\x27\x05\x19\x56",
        "endianness": "big",
        "description": "Das U-Boot OS kernel/ramdisk image header (IH_MAGIC).",
        "is_supported_natively": False,
        "recommended_tool": "dumpimage / ubi_reader",
    },
    # Broadcom TRX firmware container
    {
        "format_id": "trx",
        "name": "Broadcom TRX Firmware Header",
        "magic": b"HDR0",
        "endianness": "little",
        "description": "Broadcom TRX header container wrapping kernel and rootfs partitions.",
        "is_supported_natively": False,
        "recommended_tool": "trx-extract / binwalk",
    },
    # D-Link SHRS
    {
        "format_id": "dlink_shrs",
        "name": "D-Link SHRS Firmware Header",
        "magic": b"SHRS",
        "endianness": "big",
        "description": "D-Link proprietary firmware capsule header.",
        "is_supported_natively": False,
        "recommended_tool": "binwalk -e",
    },
    # Netgear chk
    {
        "format_id": "netgear_chk",
        "name": "Netgear CHK Firmware Container",
        "magic": b"\x2a\x23\x24\x5e",  # *#$^
        "endianness": "big",
        "description": "Netgear encrypted/checksummed firmware container.",
        "is_supported_natively": False,
        "recommended_tool": "packet-chk / netgear-chk-parser",
    },
    # Device Tree Blob (DTB / FDT)
    {
        "format_id": "dtb",
        "name": "Flattened Device Tree (DTB)",
        "magic": b"\xd0\x0d\xfe\xed",
        "endianness": "big",
        "description": "Compiled hardware description tree for ARM/MIPS/PPC kernels.",
        "is_supported_natively": False,
        "recommended_tool": "fdtdump / dtc",
    },
    # Android Boot Image
    {
        "format_id": "android_boot",
        "name": "Android Boot Image",
        "magic": b"ANDROID!",
        "endianness": "little",
        "description": "Standard Android/AOSP boot or recovery image.",
        "is_supported_natively": False,
        "recommended_tool": "abootimg / unpack_bootimg",
    },
    # Standard archives natively supported by FirmwareX
    {
        "format_id": "zip",
        "name": "ZIP Archive",
        "magic": b"PK\x03\x04",
        "endianness": "little",
        "description": "Standard ZIP compressed container.",
        "is_supported_natively": True,
        "recommended_tool": "builtin_zip_extractor",
    },
    {
        "format_id": "gzip",
        "name": "GZIP Compressed Stream / Tarball",
        "magic": b"\x1f\x8b",
        "endianness": "little",
        "description": "GNU Gzip stream or tar.gz archive.",
        "is_supported_natively": True,
        "recommended_tool": "builtin_tar_extractor",
    },
    {
        "format_id": "bzip2",
        "name": "BZIP2 Compressed Archive",
        "magic": b"BZh",
        "endianness": "big",
        "description": "Burrows-Wheeler bzip2 compressed archive.",
        "is_supported_natively": True,
        "recommended_tool": "builtin_tar_extractor",
    },
    {
        "format_id": "xz",
        "name": "XZ / LZMA2 Compressed Archive",
        "magic": b"\xfd7zXZ\x00",
        "endianness": "little",
        "description": "XZ compressed tarball or container.",
        "is_supported_natively": True,
        "recommended_tool": "builtin_tar_extractor",
    },
    # Standalone ELF
    {
        "format_id": "elf",
        "name": "Executable and Linkable Format (ELF)",
        "magic": b"\x7fELF",
        "endianness": "variable",
        "description": "Standalone binary executable or shared object.",
        "is_supported_natively": False,
        "recommended_tool": "firmwarex_elf_auditor",
    },
]


class RawFirmwareDetector:
    """Scans firmware payloads for container headers and embedded filesystem signatures."""

    @classmethod
    def detect_header(cls, file_path: Path) -> tuple[str, bool, list[DetectedSignature]]:
        """Fast header check at offset 0 plus initial scan.

        Returns:
            (primary_format_id, is_supported_natively, list_of_signatures)
        """
        if not file_path.exists() or file_path.stat().st_size == 0:
            return "empty_file", False, []

        signatures = cls.scan_signatures(file_path, max_bytes=65536)
        if not signatures:
            # Check tar ustar magic at offset 257
            try:
                with open(file_path, "rb") as f:
                    f.seek(257)
                    tar_magic = f.read(5)
                    if tar_magic == b"ustar":
                        sig = DetectedSignature(
                            format_id="tar",
                            name="POSIX TAR Archive",
                            offset=257,
                            magic_hex=tar_magic.hex(),
                            endianness="not_applicable",
                            description="Standard POSIX tape archive.",
                            is_supported_natively=True,
                            recommended_tool="builtin_tar_extractor",
                            extraction_state="supported",
                        )
                        return "tar", True, [sig]
            except Exception:
                pass

            return "raw_or_unknown_binary", False, []

        primary = signatures[0]
        # Offset 0 match takes precedence
        zero_offset = [s for s in signatures if s.offset == 0]
        if zero_offset:
            primary = zero_offset[0]

        return primary.format_id, primary.is_supported_natively, signatures

    @classmethod
    def scan_signatures(
        cls, file_path: Path, max_bytes: int = MAX_SIGNATURE_SCAN_BYTES
    ) -> list[DetectedSignature]:
        """Scan file up to max_bytes for all occurrences of known magic signatures."""
        detected: list[DetectedSignature] = []
        if not file_path.exists():
            return detected

        try:
            file_size = file_path.stat().st_size
            read_limit = min(file_size, max_bytes)

            with open(file_path, "rb") as f:
                content = f.read(read_limit)

            # Check tar ustar explicitly if content >= 512
            if len(content) >= 262 and content[257:262] == b"ustar":
                detected.append(
                    DetectedSignature(
                        format_id="tar",
                        name="POSIX TAR Archive",
                        offset=257,
                        magic_hex="7573746172",
                        endianness="not_applicable",
                        description="POSIX standard tarball container.",
                        is_supported_natively=True,
                        recommended_tool="builtin_tar_extractor",
                        extraction_state="supported",
                    )
                )

            for sig_def in KNOWN_SIGNATURES:
                magic = sig_def["magic"]
                start = 0
                while True:
                    idx = content.find(magic, start)
                    if idx == -1:
                        break

                    # Avoid redundant false positives for short 2-byte magics like JFFS2
                    # except at 4-byte boundaries or offset 0
                    if len(magic) < 4 and (idx % 4 != 0 and idx != 0):
                        start = idx + 1
                        continue

                    extraction_state = "supported" if sig_def["is_supported_natively"] else "unsupported"
                    detected.append(
                        DetectedSignature(
                            format_id=sig_def["format_id"],
                            name=sig_def["name"],
                            offset=idx,
                            magic_hex=magic.hex(),
                            endianness=sig_def["endianness"],
                            description=sig_def["description"],
                            is_supported_natively=sig_def["is_supported_natively"],
                            recommended_tool=sig_def["recommended_tool"],
                            extraction_state=extraction_state,
                        )
                    )
                    start = idx + len(magic)
                    # Limit duplicate hits of same signature to 10
                    if sum(1 for d in detected if d.format_id == sig_def["format_id"]) >= 10:
                        break

        except Exception:
            pass

        # Sort signatures strictly by ascending byte offset
        detected.sort(key=lambda x: x.offset)
        return detected
