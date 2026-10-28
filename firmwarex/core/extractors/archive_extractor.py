"""Archive extractor wrapping ZIP, TAR, GZIP, BZIP2, and XZ into modular interface."""

import os
import shutil
import tarfile
import zipfile
from pathlib import Path

from firmwarex.core.extractors.base import (
    BaseExtractor,
    ExtractionOutcome,
    ExtractionStatus,
    QuotaTracker,
    SecurityViolationError,
    is_safe_extraction_path,
)


class ArchiveExtractor(BaseExtractor):
    """Safe extractor for standard archives (ZIP, TAR, GZIP, BZIP2, XZ)."""

    format_id = "archive"
    name = "Standard Archive Safe Extractor"

    def check_tool_availability(self) -> tuple[bool, str | None]:
        return True, "Python standard library (zipfile, tarfile, gzip, bz2, lzma)"

    def can_extract(self, file_path: Path, offset: int = 0) -> bool:
        if not file_path.exists():
            return False
        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                magic = f.read(4)
                if magic.startswith(b"PK\x03\x04"):
                    return True
                if magic.startswith(b"\x1f\x8b"):  # GZIP
                    return True
                if magic.startswith(b"BZh"):  # BZIP2
                    return True
                if magic.startswith(b"\xfd7zX"):  # XZ
                    return True
                # Tar ustar check at offset + 257
                f.seek(offset + 257)
                if f.read(5) == b"ustar":
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
                errors=["Source archive does not exist."],
            )

        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Check if ZIP
            with open(file_path, "rb") as f:
                f.seek(offset)
                hdr = f.read(4)
                is_zip = hdr.startswith(b"PK\x03\x04")

            if is_zip:
                with zipfile.ZipFile(file_path, "r") as zf:
                    for member in zf.infolist():
                        target_dest = (output_dir / member.filename).resolve()
                        if not is_safe_extraction_path(output_dir, target_dest):
                            raise SecurityViolationError(f"Zip Slip path traversal blocked: '{member.filename}'")

                        if member.is_dir():
                            target_dest.mkdir(parents=True, exist_ok=True)
                            continue

                        tracker.add_file(member.file_size)
                        target_dest.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member, "r") as src, open(target_dest, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        extracted_files.append(str(target_dest.relative_to(output_dir)).replace("\\", "/"))

            else:
                # Open with tarfile
                with tarfile.open(file_path, "r:*") as tf:
                    for member in tf.getmembers():
                        target_dest = (output_dir / member.name).resolve()
                        if not is_safe_extraction_path(output_dir, target_dest):
                            raise SecurityViolationError(f"Tar path traversal blocked: '{member.name}'")

                        if member.issym() or member.islnk():
                            link_target = (output_dir / member.linkname).resolve()
                            if not is_safe_extraction_path(output_dir, link_target):
                                raise SecurityViolationError(f"Malicious link blocked: '{member.linkname}'")

                        if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                            raise SecurityViolationError(f"Special device node blocked: '{member.name}'")

                        if member.isdir():
                            target_dest.mkdir(parents=True, exist_ok=True)
                            continue

                        tracker.add_file(member.size)
                        target_dest.parent.mkdir(parents=True, exist_ok=True)
                        if member.issym():
                            try:
                                if hasattr(os, "symlink"):
                                    os.symlink(member.linkname, target_dest)
                            except OSError:
                                with open(target_dest, "w", encoding="utf-8") as f_link:
                                    f_link.write(f"SYMLINK: {member.linkname}\n")
                        else:
                            extracted_file = tf.extractfile(member)
                            if extracted_file:
                                with extracted_file as src, open(target_dest, "wb") as dst:
                                    shutil.copyfileobj(src, dst)

                        extracted_files.append(str(target_dest.relative_to(output_dir)).replace("\\", "/"))

            return ExtractionOutcome(
                status=ExtractionStatus.EXTRACTED,
                success=True,
                format_id=self.format_id,
                offset=offset,
                tool_name=self.name,
                tool_version="builtin",
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
                errors=[str(sec_err)],
                diagnostics=diagnostics,
            )
        except Exception as e:
            return ExtractionOutcome(
                status=ExtractionStatus.CORRUPTED,
                success=False,
                format_id=self.format_id,
                offset=offset,
                tool_name=self.name,
                errors=[f"Archive extraction failed: {e!s}"],
                diagnostics=diagnostics,
            )
