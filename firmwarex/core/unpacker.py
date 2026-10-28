"""Safe firmware unpacking and archive extraction engine with Zip Slip prevention.

Supports standard archives (ZIP, TAR, GZIP, BZIP2, XZ), nested archive recursion
with strict depth/quota limits, raw container format signature detection,
and provenance tracking.
"""

import hashlib
import os
import shutil
import tarfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

from firmwarex.config import (
    MAX_FILE_COUNT,
    MAX_UNCOMPRESSED_SIZE_BYTES,
    SUPPORTED_ARCHIVE_EXTENSIONS,
)
from firmwarex.core.raw_detector import (
    DetectedSignature,
    RawFirmwareDetector,
)

MAX_NESTING_DEPTH = 3


class SecurityException(Exception):
    """Raised when an extraction security control or safety boundary is violated."""


class UnsupportedFormatException(Exception):
    """Raised when an uploaded file format is not supported for safe extraction."""


@dataclass
class FileInventoryItem:
    """Metadata record for a single extracted file or directory."""
    path: str
    type: str
    size: int
    sha256: str | None
    is_elf: bool = False
    is_executable: bool = False
    parent_archive: str = "root"
    nesting_level: int = 0
    source_offset: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractionResult:
    """Outcome of a firmware extraction attempt."""
    success: bool
    status: str  # "supported", "extracted", "unsupported", "corrupted", "partial", "failed"
    message: str
    extraction_dir: str | None = None
    file_count: int = 0
    total_size_bytes: int = 0
    inventory: list[FileInventoryItem] = None
    errors: list[str] = None
    detected_signatures: list[dict] = None
    nesting_depth_reached: int = 0

    def __post_init__(self):
        if self.inventory is None:
            self.inventory = []
        if self.errors is None:
            self.errors = []
        if self.detected_signatures is None:
            self.detected_signatures = []

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "status": self.status,
            "message": self.message,
            "extraction_dir": self.extraction_dir,
            "file_count": self.file_count,
            "total_size_bytes": self.total_size_bytes,
            "inventory": [item.to_dict() for item in self.inventory],
            "errors": self.errors,
            "detected_signatures": self.detected_signatures,
            "nesting_depth_reached": self.nesting_depth_reached,
        }


def detect_format_detailed(file_path: Path) -> tuple[str, bool, list[DetectedSignature]]:
    """Inspect magic bytes, container headers, and extension to determine file format.

    Returns:
        (format_name, is_supported, list_of_signatures)
    """
    file_name = file_path.name.lower()

    # Use RawFirmwareDetector for deep magic scanning
    fmt_id, is_supported, signatures = RawFirmwareDetector.detect_header(file_path)

    # If raw detector identified format
    if fmt_id != "raw_or_unknown_binary" and fmt_id != "empty_file":
        # Check if gzip or bzip or xz is actually a tarball by extension
        if fmt_id == "gzip" and any(file_name.endswith(ext) for ext in [".tar.gz", ".tgz"]):
            return "gzip_tar", True, signatures
        if fmt_id == "bzip2" and any(file_name.endswith(ext) for ext in [".tar.bz2", ".tbz2"]):
            return "bzip2_tar", True, signatures
        if fmt_id == "xz" and any(file_name.endswith(ext) for ext in [".tar.xz", ".txz"]):
            return "xz_tar", True, signatures
        # CramFS, TRX, and uImage are supported by modular extractors in Phase 4
        if fmt_id in ("cramfs", "trx", "uimage"):
            return fmt_id, True, signatures
        return fmt_id, is_supported, signatures

    # Fallback to file extension checks for archives
    for ext in SUPPORTED_ARCHIVE_EXTENSIONS:
        if file_name.endswith(ext):
            ext_clean = ext.lstrip(".")
            return ext_clean, True, signatures

    return "raw_or_unknown_binary", False, signatures


def detect_format(file_path: Path) -> tuple[str, bool]:
    """Inspect magic bytes and extension to determine file format and extraction support.

    Returns:
        (format_name, is_supported)
    """
    fmt, supported, _ = detect_format_detailed(file_path)
    return fmt, supported


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


def _classify_file(file_path: Path) -> tuple[str, bool, bool]:
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
    """Hardened extractor providing Zip Slip defense, nested archive handling, and quotas."""

    def __init__(
        self,
        max_file_count: int = MAX_FILE_COUNT,
        max_uncompressed_size: int = MAX_UNCOMPRESSED_SIZE_BYTES,
        max_nesting_depth: int = MAX_NESTING_DEPTH,
    ):
        self.max_file_count = max_file_count
        self.max_uncompressed_size = max_uncompressed_size
        self.max_nesting_depth = max_nesting_depth
        self._cumulative_file_count = 0
        self._cumulative_uncompressed_size = 0

    def extract(self, archive_path: Path, output_dir: Path) -> ExtractionResult:
        """Safely extract an archive file into output_dir.

        Raises:
            UnsupportedFormatException: If file cannot be unpacked by supported safe unpackers.
            SecurityException: If path traversal or quota breach is detected.
        """
        fmt, supported, signatures = detect_format_detailed(archive_path)
        sig_dicts = [s.to_dict() for s in signatures]

        if not supported:
            # Build detailed diagnostic message with detected signature and tool advice
            tool_advice = "Requires external extractor tooling (e.g. unsquashfs, binwalk, ubireader) not available in native environment."
            if signatures:
                primary_sig = signatures[0]
                tool_advice = f"Detected: {primary_sig.name} at offset {primary_sig.offset}. Recommended tool: {primary_sig.recommended_tool}."

            raise UnsupportedFormatException(
                f"Unsupported firmware format '{fmt}'. {tool_advice} "
                "Safe automated extraction in Phase 3 supports standard archives "
                "(.zip, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz) and nested archive structures. "
                "Raw proprietary firmware containers are identified via signatures but cannot be extracted without verified sandbox isolation."
            )

        output_dir.mkdir(parents=True, exist_ok=True)
        resolved_out = output_dir.resolve()
        self._cumulative_file_count = 0
        self._cumulative_uncompressed_size = 0

        try:
            if fmt == "zip":
                result = self._extract_zip(archive_path, resolved_out, nesting_level=0, parent="root")
            elif fmt in ("tar", "gzip_tar", "bzip2_tar", "xz_tar", "gzip", "bzip2", "xz"):
                result = self._extract_tar(archive_path, resolved_out, nesting_level=0, parent="root")
            elif fmt in ("cramfs", "trx", "uimage"):
                from firmwarex.core.extractors.base import ExtractionStatus, SecurityViolationError
                from firmwarex.core.extractors.registry import ExtractorRegistry
                try:
                    outcome = ExtractorRegistry().extract_firmware(
                        archive_path,
                        resolved_out,
                        max_file_count=self.max_file_count,
                        max_uncompressed_size=self.max_uncompressed_size,
                    )
                    if not outcome.success:
                        if outcome.status == ExtractionStatus.UNSUPPORTED:
                            raise UnsupportedFormatException("; ".join(outcome.errors or outcome.diagnostics))
                        return ExtractionResult(
                            success=False,
                            status=outcome.status.value,
                            message="; ".join(outcome.errors) or "Extraction failed.",
                            extraction_dir=str(output_dir),
                            errors=outcome.errors,
                            detected_signatures=sig_dicts,
                        )
                    result = ExtractionResult(
                        success=True,
                        status="extracted",
                        message=f"Successfully extracted {outcome.file_count} items via {outcome.tool_name}.",
                        extraction_dir=str(output_dir),
                        file_count=outcome.file_count,
                        total_size_bytes=outcome.total_size_bytes,
                        errors=outcome.errors,
                    )
                except SecurityViolationError as sve:
                    raise SecurityException(str(sve))
            else:
                raise UnsupportedFormatException(f"No extraction handler available for '{fmt}'.")

            # Check and process nested archive layers
            max_depth_reached = self._unpack_nested_archives(resolved_out, current_depth=1)
            result.nesting_depth_reached = max_depth_reached

            # Regenerate full inventory covering all extracted and nested items
            result.inventory = self.generate_inventory(resolved_out)
            result.file_count = len(result.inventory)
            result.total_size_bytes = sum(i.size for i in result.inventory if i.type != "directory")
            result.detected_signatures = sig_dicts
            return result

        except (SecurityException, UnsupportedFormatException):
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)
            raise
        except Exception as e:
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)
            return ExtractionResult(
                success=False,
                status="corrupted" if "corrupt" in str(e).lower() or "bad" in str(e).lower() else "failed",
                message=f"Archive extraction failed: {e!s}",
                extraction_dir=str(output_dir),
                errors=[str(e)],
                detected_signatures=sig_dicts,
            )

    def _extract_zip(
        self, zip_path: Path, output_dir: Path, nesting_level: int = 0, parent: str = "root"
    ) -> ExtractionResult:
        """Extract a ZIP archive enforcing Zip Slip defense and quotas."""
        file_count = 0
        total_size = 0
        errors: list[str] = []

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # 1. Pre-flight check: validate paths and size quotas
                for member in zf.infolist():
                    file_count += 1
                    total_size += member.file_size
                    self._cumulative_file_count += 1
                    self._cumulative_uncompressed_size += member.file_size

                    if self._cumulative_file_count > self.max_file_count:
                        raise SecurityException(
                            f"Extraction aborted: Archive exceeds max file count limit ({self.max_file_count})."
                        )
                    if self._cumulative_uncompressed_size > self.max_uncompressed_size:
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

            inventory = self.generate_inventory(output_dir, parent=parent, nesting_level=nesting_level)
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
            raise
        except Exception as e:
            return ExtractionResult(
                success=False,
                status="corrupted" if "bad" in str(e).lower() or "crc" in str(e).lower() else "failed",
                message=f"ZIP extraction failed: {e!s}",
                extraction_dir=str(output_dir),
                errors=[str(e)],
            )

    def _extract_tar(
        self, tar_path: Path, output_dir: Path, nesting_level: int = 0, parent: str = "root"
    ) -> ExtractionResult:
        """Extract a TAR-family archive enforcing containment and symlink safety."""
        file_count = 0
        total_size = 0
        errors: list[str] = []

        try:
            with tarfile.open(tar_path, "r:*") as tf:
                # 1. Pre-flight quota and safety check
                for member in tf.getmembers():
                    file_count += 1
                    total_size += member.size
                    self._cumulative_file_count += 1
                    self._cumulative_uncompressed_size += member.size

                    if self._cumulative_file_count > self.max_file_count:
                        raise SecurityException(
                            f"Extraction aborted: Archive exceeds max file count limit ({self.max_file_count})."
                        )
                    if self._cumulative_uncompressed_size > self.max_uncompressed_size:
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

                # 2. Safe extraction
                for member in tf.getmembers():
                    target_dest = (output_dir / member.name).resolve()
                    if member.isdir():
                        target_dest.mkdir(parents=True, exist_ok=True)
                        continue

                    if member.issym():
                        try:
                            target_dest.parent.mkdir(parents=True, exist_ok=True)
                            if hasattr(os, "symlink"):
                                os.symlink(member.linkname, target_dest)
                        except OSError:
                            with open(target_dest, "w", encoding="utf-8") as f:
                                f.write(f"SYMLINK: {member.linkname}\n")
                        continue

                    target_dest.parent.mkdir(parents=True, exist_ok=True)
                    extracted_file = tf.extractfile(member)
                    if extracted_file:
                        with extracted_file as src, open(target_dest, "wb") as dst:
                            shutil.copyfileobj(src, dst)

            inventory = self.generate_inventory(output_dir, parent=parent, nesting_level=nesting_level)
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
            raise
        except Exception as e:
            return ExtractionResult(
                success=False,
                status="corrupted" if "corrupt" in str(e).lower() or "bad" in str(e).lower() else "failed",
                message=f"TAR extraction failed: {e!s}",
                extraction_dir=str(output_dir),
                errors=[str(e)],
            )

    def _unpack_nested_archives(self, base_dir: Path, current_depth: int) -> int:
        """Scan base_dir for nested supported archives and extract them up to max_nesting_depth."""
        if current_depth > self.max_nesting_depth:
            return current_depth - 1

        max_depth_seen = current_depth - 1

        # Collect nested archives first to avoid modifying directory while walking
        candidates: list[Path] = []
        for root, _, files in os.walk(base_dir):
            for file in files:
                p = Path(root) / file
                # Skip already created _nested_* extraction folders inside base_dir
                try:
                    rel_p = p.relative_to(base_dir)
                    if any(part.startswith("_nested_") for part in rel_p.parts):
                        continue
                except ValueError:
                    continue
                name_lower = file.lower()
                if any(name_lower.endswith(ext) for ext in SUPPORTED_ARCHIVE_EXTENSIONS):
                    candidates.append(p)

        for candidate in candidates:
            # Check format
            fmt, is_supported = detect_format(candidate)
            if not is_supported:
                continue

            nested_out = candidate.parent / f"_nested_{candidate.stem}"
            nested_out.mkdir(parents=True, exist_ok=True)

            try:
                if fmt == "zip":
                    self._extract_zip(candidate, nested_out, nesting_level=current_depth, parent=candidate.name)
                elif fmt in ("tar", "gzip_tar", "bzip2_tar", "xz_tar", "gzip", "bzip2", "xz"):
                    self._extract_tar(candidate, nested_out, nesting_level=current_depth, parent=candidate.name)

                max_depth_seen = max(max_depth_seen, current_depth)
                # Recursively unpack any deeper archives
                deeper_depth = self._unpack_nested_archives(nested_out, current_depth + 1)
                max_depth_seen = max(max_depth_seen, deeper_depth)

            except Exception:
                # Nested extraction error is contained; preserve what we have
                pass

        return max_depth_seen

    @staticmethod
    def generate_inventory(
        root_dir: Path, parent: str = "root", nesting_level: int = 0
    ) -> list[FileInventoryItem]:
        """Walk root_dir and build complete file inventory with hashes and types."""
        inventory: list[FileInventoryItem] = []
        resolved_root = root_dir.resolve()

        for dirpath, dirnames, filenames in os.walk(resolved_root):
            rel_dir = os.path.relpath(dirpath, resolved_root)

            # Record directories
            if rel_dir != ".":
                inventory.append(
                    FileInventoryItem(
                        path=rel_dir.replace("\\", "/"),
                        type="directory",
                        size=0,
                        sha256=None,
                        is_elf=False,
                        is_executable=False,
                        parent_archive=parent,
                        nesting_level=nesting_level,
                    )
                )

            # Record files
            for file in filenames:
                full_file_path = Path(dirpath) / file
                rel_file_path = os.path.relpath(full_file_path, resolved_root).replace("\\", "/")

                # Detect provenance and nesting level from path parts
                path_parts = rel_file_path.split("/")
                nested_parts = [p for p in path_parts if p.startswith("_nested_")]
                item_nesting_lvl = nesting_level + len(nested_parts)
                item_parent = parent
                if nested_parts:
                    raw_stem = nested_parts[-1].replace("_nested_", "")
                    item_parent = f"{raw_stem}.tar" if not any(raw_stem.endswith(e) for e in [".tar", ".zip", ".gz"]) else raw_stem

                try:
                    file_size = full_file_path.stat().st_size
                    file_sha = compute_sha256(full_file_path)
                    file_type, is_elf, is_exec = _classify_file(full_file_path)

                    inventory.append(
                        FileInventoryItem(
                            path=rel_file_path,
                            type=file_type,
                            size=file_size,
                            sha256=file_sha,
                            is_elf=is_elf,
                            is_executable=is_exec,
                            parent_archive=item_parent,
                            nesting_level=item_nesting_lvl,
                        )
                    )
                except Exception:
                    inventory.append(
                        FileInventoryItem(
                            path=rel_file_path,
                            type="unreadable",
                            size=0,
                            sha256=None,
                            is_elf=False,
                            is_executable=False,
                            parent_archive=item_parent,
                            nesting_level=item_nesting_lvl,
                        )
                    )

        return inventory
