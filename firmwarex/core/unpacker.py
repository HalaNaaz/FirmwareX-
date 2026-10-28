"""Safe firmware unpacking and archive extraction engine with Zip Slip prevention."""

import hashlib
import os
import shutil
import tarfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from firmwarex.config import (
    MAX_FILE_COUNT,
    MAX_UNCOMPRESSED_SIZE_BYTES,
    SUPPORTED_ARCHIVE_EXTENSIONS,
)


class SecurityException(Exception):
    """Raised when an extraction security control or safety boundary is violated."""
    pass


class UnsupportedFormatException(Exception):
    """Raised when an uploaded file format is not supported for safe extraction."""
    pass


@dataclass
class FileInventoryItem:
    """Metadata record for a single extracted file or directory."""
    path: str
    type: str
    size: int
    sha256: Optional[str]
    is_elf: bool = False
    is_executable: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ExtractionResult:
    """Outcome of a firmware extraction attempt."""
    success: bool
    status: str
    message: str
    extraction_dir: Optional[str] = None
    file_count: int = 0
    total_size_bytes: int = 0
    inventory: List[FileInventoryItem] = None
    errors: List[str] = None

    def __post_init__(self):
        if self.inventory is None:
            self.inventory = []
        if self.errors is None:
            self.errors = []

    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "status": self.status,
            "message": self.message,
            "extraction_dir": self.extraction_dir,
            "file_count": self.file_count,
            "total_size_bytes": self.total_size_bytes,
            "inventory": [item.to_dict() for item in self.inventory],
            "errors": self.errors,
        }


def detect_format(file_path: Path) -> Tuple[str, bool]:
    """Inspect magic bytes and extension to determine file format and extraction support.

    Returns:
        (format_name, is_supported)
    """
    file_name = file_path.name.lower()
    magic = b""
    try:
        with open(file_path, "rb") as f:
            magic = f.read(32)
    except Exception as e:
        return f"unreadable ({e})", False

    # Check magic bytes first
    if magic.startswith(b"PK\x03\x04") or magic.startswith(b"PK\x05\x06") or magic.startswith(b"PK\x07\x08"):
        return "zip", True

    if magic.startswith(b"\x1f\x8b"):
        return "gzip_tar" if any(file_name.endswith(ext) for ext in [".tar.gz", ".tgz"]) else "gzip", True

    if magic.startswith(b"BZh"):
        return "bzip2_tar" if any(file_name.endswith(ext) for ext in [".tar.bz2", ".tbz2"]) else "bzip2", True

    if magic.startswith(b"\xfd7zXZ\x00"):
        return "xz_tar" if any(file_name.endswith(ext) for ext in [".tar.xz", ".txz"]) else "xz", True

    if len(magic) >= 262 and magic[257:262] == b"ustar":
        return "tar", True

    # Common raw firmware headers (unsupported without Binwalk/specialised unpackers)
    if magic.startswith(b"hsqs") or magic.startswith(b"sqsh"):
        return "squashfs", False
    if magic.startswith(b"HDR0") or magic.startswith(b"TRX"):
        return "trx_firmware", False
    if magic.startswith(b"\x27\x05\x19\x56"):
        return "uimage", False
    if magic.startswith(b"\x7fELF"):
        return "standalone_elf", False

    # Fallback to extension check
    for ext in SUPPORTED_ARCHIVE_EXTENSIONS:
        if file_name.endswith(ext):
            return ext.lstrip("."), True

    return "raw_or_unknown_binary", False


def compute_sha256(file_path: Path) -> str:
    """Calculate the SHA-256 digest of a file in streaming chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """Verify that target_path resolves strictly inside base_dir (Zip Slip defense)."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return resolved_base == resolved_target or resolved_base in resolved_target.parents
    except Exception:
        return False


def _classify_file(file_path: Path) -> Tuple[str, bool, bool]:
    """Classify file type, ELF status, and executable flags."""
    if file_path.is_dir():
        return "directory", False, False

    is_elf = False
    is_exec = False
    file_type = "binary"

    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
            if header == b"\x7fELF":
                is_elf = True
                is_exec = True
                file_type = "elf_binary"
    except Exception:
        pass

    if not is_elf:
        name_lower = file_path.name.lower()
        if any(name_lower.endswith(ext) for ext in [".sh", ".py", ".pl", ".cgi"]):
            file_type = "script"
            is_exec = True
        elif any(name_lower.endswith(ext) for ext in [".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml", ".env"]):
            file_type = "configuration"
        elif any(name_lower.endswith(ext) for ext in [".pem", ".crt", ".key", ".pub", ".der", ".cer"]):
            file_type = "certificate_or_key"
        elif any(name_lower.endswith(ext) for ext in [".txt", ".md", ".log", ".html", ".htm"]):
            file_type = "text"

    return file_type, is_elf, is_exec


class SafeExtractor:
    """Hardened extractor providing Zip Slip defense and quota enforcement."""

    def __init__(
        self,
        max_file_count: int = MAX_FILE_COUNT,
        max_uncompressed_size: int = MAX_UNCOMPRESSED_SIZE_BYTES,
    ):
        self.max_file_count = max_file_count
        self.max_uncompressed_size = max_uncompressed_size

    def extract(self, archive_path: Path, output_dir: Path) -> ExtractionResult:
        """Safely extract an archive file into output_dir.

        Raises:
            UnsupportedFormatException: If file cannot be unpacked by supported safe unpackers.
            SecurityException: If path traversal or quota breach is detected.
        """
        fmt, supported = detect_format(archive_path)
        if not supported:
            raise UnsupportedFormatException(
                f"Unsupported firmware format '{fmt}'. Safe automated extraction in Phase 1 "
                "supports standard archives (.zip, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz). "
                "Raw proprietary firmware containers (SquashFS, TRX, uImage) require Binwalk/firmware-mod-kit "
                "which is currently deferred or requires external container tooling."
            )

        output_dir.mkdir(parents=True, exist_ok=True)
        resolved_out = output_dir.resolve()

        if fmt == "zip":
            return self._extract_zip(archive_path, resolved_out)
        elif fmt in ("tar", "gzip_tar", "bzip2_tar", "xz_tar", "gzip", "bzip2", "xz"):
            return self._extract_tar(archive_path, resolved_out)
        else:
            raise UnsupportedFormatException(f"No extraction handler available for '{fmt}'.")

    def _extract_zip(self, zip_path: Path, output_dir: Path) -> ExtractionResult:
        """Extract a ZIP archive enforcing Zip Slip defense and quotas."""
        file_count = 0
        total_size = 0
        errors: List[str] = []

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # 1. Pre-flight check: validate paths and size quotas
                for member in zf.infolist():
                    file_count += 1
                    total_size += member.file_size

                    if file_count > self.max_file_count:
                        raise SecurityException(
                            f"Extraction aborted: Archive exceeds max file count limit ({self.max_file_count})."
                        )
                    if total_size > self.max_uncompressed_size:
                        raise SecurityException(
                            f"Extraction aborted: Archive uncompressed size exceeds limit ({self.max_uncompressed_size} bytes)."
                        )

                    # Validate path traversal (Zip Slip)
                    target_dest = (output_dir / member.filename).resolve()
                    if not _is_safe_path(output_dir, target_dest):
                        raise SecurityException(
                            f"Zip Slip path traversal attempt blocked: '{member.filename}' resolves outside target directory."
                        )

                # 2. Extract safely
                for member in zf.infolist():
                    target_dest = (output_dir / member.filename).resolve()
                    if member.is_dir():
                        target_dest.mkdir(parents=True, exist_ok=True)
                        continue

                    target_dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member, "r") as src, open(target_dest, "wb") as dst:
                        shutil.copyfileobj(src, dst)

            inventory = self.generate_inventory(output_dir)
            return ExtractionResult(
                success=True,
                status="extracted",
                message=f"Successfully extracted {file_count} items ({total_size} bytes).",
                extraction_dir=str(output_dir),
                file_count=file_count,
                total_size_bytes=total_size,
                inventory=inventory,
                errors=errors,
            )

        except (SecurityException, UnsupportedFormatException):
            # Clean up partial extraction on security violation
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)
            raise
        except Exception as e:
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)
            return ExtractionResult(
                success=False,
                status="failed",
                message=f"ZIP extraction failed: {str(e)}",
                extraction_dir=str(output_dir),
                errors=[str(e)],
            )

    def _extract_tar(self, tar_path: Path, output_dir: Path) -> ExtractionResult:
        """Extract a TAR-family archive enforcing containment and symlink safety."""
        file_count = 0
        total_size = 0
        errors: List[str] = []

        try:
            with tarfile.open(tar_path, "r:*") as tf:
                # 1. Pre-flight quota and safety check
                for member in tf.getmembers():
                    file_count += 1
                    total_size += member.size

                    if file_count > self.max_file_count:
                        raise SecurityException(
                            f"Extraction aborted: Archive exceeds max file count limit ({self.max_file_count})."
                        )
                    if total_size > self.max_uncompressed_size:
                        raise SecurityException(
                            f"Extraction aborted: Archive uncompressed size exceeds limit ({self.max_uncompressed_size} bytes)."
                        )

                    # Path traversal check
                    target_dest = (output_dir / member.name).resolve()
                    if not _is_safe_path(output_dir, target_dest):
                        raise SecurityException(
                            f"Tar path traversal attempt blocked: '{member.name}' resolves outside target directory."
                        )

                    # Symlink / Hardlink safety check
                    if member.issym() or member.islnk():
                        link_target = (output_dir / member.linkname).resolve()
                        if not _is_safe_path(output_dir, link_target):
                            raise SecurityException(
                                f"Malicious symlink/hardlink blocked: '{member.name}' -> '{member.linkname}' points outside sandbox."
                            )

                    # Special-file defense (FIFO, Character / Block device nodes)
                    if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                        raise SecurityException(
                            f"Special device/FIFO node creation blocked in archive: '{member.name}'."
                        )

                # 2. Safe extraction using data filter or explicit safe write
                for member in tf.getmembers():
                    target_dest = (output_dir / member.name).resolve()
                    if member.isdir():
                        target_dest.mkdir(parents=True, exist_ok=True)
                        continue

                    # If symlink, only create if on platform that supports it and inside sandbox
                    if member.issym():
                        # On Windows or restricted environments, write a placeholder or skip
                        try:
                            target_dest.parent.mkdir(parents=True, exist_ok=True)
                            if hasattr(os, "symlink"):
                                os.symlink(member.linkname, target_dest)
                        except OSError:
                            # Fallback: record as symlink metadata placeholder
                            with open(target_dest, "w", encoding="utf-8") as f:
                                f.write(f"SYMLINK: {member.linkname}\n")
                        continue

                    target_dest.parent.mkdir(parents=True, exist_ok=True)
                    extracted_file = tf.extractfile(member)
                    if extracted_file:
                        with extracted_file as src, open(target_dest, "wb") as dst:
                            shutil.copyfileobj(src, dst)

            inventory = self.generate_inventory(output_dir)
            return ExtractionResult(
                success=True,
                status="extracted",
                message=f"Successfully extracted {file_count} items ({total_size} bytes).",
                extraction_dir=str(output_dir),
                file_count=file_count,
                total_size_bytes=total_size,
                inventory=inventory,
                errors=errors,
            )

        except (SecurityException, UnsupportedFormatException):
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)
            raise
        except Exception as e:
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)
            return ExtractionResult(
                success=False,
                status="failed",
                message=f"TAR extraction failed: {str(e)}",
                extraction_dir=str(output_dir),
                errors=[str(e)],
            )

    @staticmethod
    def generate_inventory(root_dir: Path) -> List[FileInventoryItem]:
        """Walk root_dir and build complete file inventory with hashes and types."""
        inventory: List[FileInventoryItem] = []
        resolved_root = root_dir.resolve()

        for dirpath, dirnames, filenames in os.walk(resolved_root):
            rel_dir = os.path.relpath(dirpath, resolved_root)
            if rel_dir != ".":
                inventory.append(
                    FileInventoryItem(
                        path=rel_dir.replace("\\", "/"),
                        type="directory",
                        size=0,
                        sha256=None,
                        is_elf=False,
                        is_executable=False,
                    )
                )

            for filename in filenames:
                file_path = Path(dirpath) / filename
                rel_path = os.path.relpath(file_path, resolved_root).replace("\\", "/")
                try:
                    size = file_path.stat().st_size
                    file_type, is_elf, is_exec = _classify_file(file_path)
                    digest = compute_sha256(file_path) if not file_path.is_dir() else None
                    inventory.append(
                        FileInventoryItem(
                            path=rel_path,
                            type=file_type,
                            size=size,
                            sha256=digest,
                            is_elf=is_elf,
                            is_executable=is_exec,
                        )
                    )
                except Exception:
                    # Skip unreadable or broken files safely
                    pass

        # Sort inventory deterministically by path
        inventory.sort(key=lambda x: x.path)
        return inventory
