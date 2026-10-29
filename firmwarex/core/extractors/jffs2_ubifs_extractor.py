import binascii
import hashlib
import shutil
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
        tracker = quota_tracker or QuotaTracker()

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
                if magic_le not in (JFFS2_MAGIC_LE, JFFS2_MAGIC_BE):
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=[f"Invalid JFFS2 magic header: 0x{magic_le:04x}."],
                    )

                endian = "<" if magic_le == JFFS2_MAGIC_LE else ">"
                nodetype, totlen = struct.unpack(f"{endian}HI", hdr[2:8])

                diagnostics.append(
                    f"JFFS2 node validated at offset {offset}. "
                    f"Endianness: {'little' if endian == '<' else 'big'}, "
                    f"NodeType: 0x{nodetype:04x}, NodeLength: {totlen} bytes."
                )

            # Perform pure-Python JFFS2 node extraction
            return self._extract_pure_python(
                file_path=file_path,
                output_dir=output_dir,
                offset=offset,
                tracker=tracker,
                endian=endian,
                diagnostics=diagnostics,
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
                errors=[f"JFFS2 parse error: {e!s}"],
                diagnostics=diagnostics,
            )

    def _extract_pure_python(
        self,
        file_path: Path,
        output_dir: Path,
        offset: int,
        tracker: QuotaTracker,
        endian: str,
        diagnostics: list[str],
    ) -> ExtractionOutcome:
        extracted_files: list[str] = []
        hashes: dict[str, str] = {}
        file_size = file_path.stat().st_size

        # Inode tree structures:
        # dirents: (pino, name) -> (ino, ftype, version)
        # inode_chunks: ino -> list of (chunk_offset, data, version)
        # inode_isize: ino -> max isize
        dirents: dict[tuple[int, str], tuple[int, int, int]] = {}
        inode_chunks: dict[int, list[tuple[int, bytes, int]]] = {}
        inode_isize: dict[int, int] = {}
        corrupted_nodes = 0
        unsupported_nodes = 0

        with open(file_path, "rb") as f:
            curr_pos = offset
            while curr_pos + 12 <= file_size:
                f.seek(curr_pos)
                hdr = f.read(12)
                magic_val = struct.unpack(f"{endian}H", hdr[:2])[0]
                if magic_val not in (JFFS2_MAGIC_LE, JFFS2_MAGIC_BE):
                    curr_pos += 4
                    continue

                nodetype, totlen, hdr_crc = struct.unpack(f"{endian}HII", hdr[2:12])
                calc_hdr_crc = binascii.crc32(hdr[:8]) & 0xFFFFFFFF
                if calc_hdr_crc != hdr_crc:
                    corrupted_nodes += 1
                    curr_pos += 4
                    continue

                if totlen < 12 or curr_pos + totlen > file_size:
                    corrupted_nodes += 1
                    break

                base_type = nodetype & 0x00FF
                aligned_len = (totlen + 3) & ~3

                if base_type == 0x01:  # DIRENT
                    if totlen >= 40:
                        d_bytes = f.read(28)
                        pino, ver, f_ino, mctime, nsize, ftype, unused, node_crc, data_crc = struct.unpack(
                            f"{endian}IIIIBBHII", d_bytes
                        )
                        name_raw = f.read(nsize)
                        name_str = name_raw.decode("utf-8", errors="replace").strip("\x00")
                        if name_str:
                            key = (pino, name_str)
                            if key not in dirents or dirents[key][2] <= ver:
                                dirents[key] = (f_ino, ftype, ver)

                elif base_type == 0x02:  # INODE
                    if totlen >= 68:
                        i_bytes = f.read(56)
                        (
                            ino_num,
                            ver,
                            mode,
                            uid,
                            gid,
                            isize,
                            atime,
                            mtime,
                            ctime,
                            chk_off,
                            csize,
                            dsize,
                            compr,
                            usercompr,
                            flags,
                            data_crc,
                            node_crc,
                        ) = struct.unpack(f"{endian}IIIHHIIIIIIIBBHII", i_bytes)

                        cdata = f.read(csize)
                        decompressed: bytes | None = None
                        if compr == 0:  # NONE
                            decompressed = cdata[:dsize]
                        elif compr == 1:  # ZERO
                            decompressed = b"\x00" * dsize
                        elif compr == 6:  # ZLIB
                            try:
                                decompressed = zlib.decompress(cdata)
                            except Exception as e:
                                diagnostics.append(f"Zlib decompress error for inode {ino_num}: {e}")
                                corrupted_nodes += 1
                        else:
                            diagnostics.append(f"Unsupported compression {compr} in inode {ino_num}")
                            unsupported_nodes += 1

                        if decompressed is not None:
                            if ino_num not in inode_chunks:
                                inode_chunks[ino_num] = []
                            inode_chunks[ino_num].append((chk_off, decompressed, ver))
                            inode_isize[ino_num] = max(inode_isize.get(ino_num, 0), isize)

                curr_pos += aligned_len

        # Map each ino to relative path
        ino_to_path: dict[int, str] = {1: ""}
        resolved_any = True
        while resolved_any:
            resolved_any = False
            for (pino, name), (f_ino, ftype, _) in dirents.items():
                if f_ino == 0:
                    continue
                if pino in ino_to_path and f_ino not in ino_to_path:
                    parent_path = ino_to_path[pino]
                    rel = f"{parent_path}/{name}".lstrip("/") if parent_path else name
                    ino_to_path[f_ino] = rel
                    resolved_any = True

        total_extracted_bytes = 0
        output_dir.mkdir(parents=True, exist_ok=True)

        for (pino, name), (f_ino, ftype, _) in dirents.items():
            if f_ino == 0:
                continue
            rel_path_str = ino_to_path.get(f_ino, name)
            out_file = output_dir / rel_path_str
            if not is_safe_extraction_path(output_dir, out_file):
                raise SecurityViolationError(f"Path traversal detected in JFFS2 entry: {rel_path_str}")

            if ftype == 4:  # Directory
                out_file.mkdir(parents=True, exist_ok=True)
            else:  # Regular file
                out_file.parent.mkdir(parents=True, exist_ok=True)
                chunks = inode_chunks.get(f_ino, [])
                expected_size = inode_isize.get(f_ino, 0)

                if chunks:
                    chunks.sort(key=lambda x: (x[0], x[2]))
                    max_end = max((chk[0] + len(chk[1]) for chk in chunks), default=0)
                    file_buf = bytearray(max(expected_size, max_end))
                    for chk_off, data_chunk, _ in chunks:
                        file_buf[chk_off : chk_off + len(data_chunk)] = data_chunk
                    file_bytes = bytes(file_buf[:expected_size]) if expected_size > 0 else bytes(file_buf)
                else:
                    file_bytes = b""

                tracker.add_file(len(file_bytes))
                out_file.write_bytes(file_bytes)
                extracted_files.append(rel_path_str.replace("\\", "/"))
                total_extracted_bytes += len(file_bytes)
                hashes[rel_path_str.replace("\\", "/")] = hashlib.sha256(file_bytes).hexdigest()

        if not extracted_files:
            if corrupted_nodes > 0:
                return ExtractionOutcome(
                    status=ExtractionStatus.CORRUPTED,
                    success=False,
                    format_id=self.format_id,
                    offset=offset,
                    tool_name=self.name,
                    errors=["No valid files recovered; corrupted JFFS2 node stream."],
                    diagnostics=diagnostics,
                )
            if unsupported_nodes > 0:
                return ExtractionOutcome(
                    status=ExtractionStatus.UNSUPPORTED,
                    success=False,
                    format_id=self.format_id,
                    offset=offset,
                    tool_name=self.name,
                    errors=["JFFS2 filesystem uses unsupported compression algorithm."],
                    diagnostics=diagnostics,
                )
            return ExtractionOutcome(
                status=ExtractionStatus.PARTIAL,
                success=False,
                format_id=self.format_id,
                offset=offset,
                tool_name=self.name,
                diagnostics=diagnostics,
            )

        status = ExtractionStatus.PARTIAL if (corrupted_nodes > 0 or unsupported_nodes > 0) else ExtractionStatus.EXTRACTED
        diagnostics.append(f"Pure-Python JFFS2 extraction recovered {len(extracted_files)} files ({total_extracted_bytes} bytes).")

        return ExtractionOutcome(
            status=status,
            success=True,
            format_id=self.format_id,
            offset=offset,
            tool_name=self.name,
            tool_version="pure-python-v1.0",
            file_count=len(extracted_files),
            total_size_bytes=total_extracted_bytes,
            extracted_files=extracted_files,
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
                magic = f.read(4)
                if len(magic) < 4:
                    return ExtractionOutcome(
                        status=ExtractionStatus.CORRUPTED,
                        success=False,
                        format_id=self.format_id,
                        offset=offset,
                        tool_name=self.name,
                        errors=["Truncated UBI/UBIFS header."],
                    )

                if magic == UBI_EC_HDR_MAGIC:
                    ec_hdr = f.read(60)
                    if len(ec_hdr) < 60:
                        return ExtractionOutcome(
                            status=ExtractionStatus.CORRUPTED,
                            success=False,
                            format_id=self.format_id,
                            offset=offset,
                            tool_name=self.name,
                            errors=["Truncated UBI Erase Counter header."],
                        )
                    version = ec_hdr[0]
                    vid_hdr_offset = struct.unpack(">I", ec_hdr[12:16])[0]
                    diagnostics.append(
                        f"UBI Eraseblock header validated at offset {offset}. "
                        f"UBI Version: {version}, VID Header Offset: {vid_hdr_offset}."
                    )
                else:
                    node_magic = struct.unpack("<I", magic)[0]
                    if node_magic == UBIFS_NODE_MAGIC:
                        diagnostics.append(
                            f"UBIFS Node validated at offset {offset}. Magic: 0x{node_magic:08x}."
                        )
                    else:
                        return ExtractionOutcome(
                            status=ExtractionStatus.CORRUPTED,
                            success=False,
                            format_id=self.format_id,
                            offset=offset,
                            tool_name=self.name,
                            errors=[f"Invalid UBIFS magic: 0x{node_magic:08x}."],
                        )

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
                            "UBI/UBIFS headers verified, but extraction requires 'ubireader' which is not installed. "
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
