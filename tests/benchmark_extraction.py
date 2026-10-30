"""Extraction benchmark runner for Priority 1, Phase 1.

Measures extraction success rate against synthetic spec-compliant fixtures
across all supported firmware container and filesystem formats.
"""

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from firmwarex.core.extractors.registry import ExtractorRegistry
from firmwarex.core.unpacker import SafeExtractor
from tests.fixtures_extractors import (
    create_synthetic_cpio,
    create_synthetic_cramfs,
    create_synthetic_jffs2,
    create_synthetic_trx,
    create_synthetic_uimage,
)
from tests.fixtures_helper import create_benign_firmware_archive


def run_benchmark():
    registry = ExtractorRegistry()
    unpacker = SafeExtractor()

    benchmark_cases = []

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        # 1. CramFS Little-Endian
        cramfs_le = root / "image_cramfs_le.img"
        create_synthetic_cramfs(cramfs_le, endian="<", files={"etc/banner": b"CramFS LE Banner\n"})
        benchmark_cases.append(("CramFS (Little-Endian)", cramfs_le, "extractor"))

        # 2. CramFS Big-Endian
        cramfs_be = root / "image_cramfs_be.img"
        create_synthetic_cramfs(cramfs_be, endian=">", files={"etc/banner": b"CramFS BE Banner\n"})
        benchmark_cases.append(("CramFS (Big-Endian)", cramfs_be, "extractor"))

        # 3. TRX Container
        trx_img = root / "firmware.trx"
        create_synthetic_trx(trx_img, partitions=[b"\x7fELF" + b"\x00" * 200])
        benchmark_cases.append(("Broadcom TRX Container", trx_img, "extractor"))

        # 4. U-Boot uImage
        uimage_img = root / "uImage"
        create_synthetic_uimage(uimage_img, payload=b"\x7fELF" + b"\x00" * 300)
        benchmark_cases.append(("U-Boot uImage", uimage_img, "extractor"))

        # 5. JFFS2 Flash Filesystem
        jffs2_img = root / "rootfs.jffs2"
        create_synthetic_jffs2(jffs2_img, endian="<", files={"etc/passwd": b"root:x:0:0::/root:/bin/sh\n"})
        benchmark_cases.append(("JFFS2 Flash Filesystem", jffs2_img, "extractor"))

        # 6. CPIO Initramfs
        cpio_img = root / "initramfs.cpio"
        create_synthetic_cpio(cpio_img, files={"init": b"#!/bin/sh\necho 1\n", "dev/console": b""})
        benchmark_cases.append(("CPIO Initramfs (SVR4 newc)", cpio_img, "extractor"))

        # 7. Standard TAR.GZ
        tar_img = root / "archive.tar.gz"
        create_benign_firmware_archive(tar_img, archive_type="tar.gz")
        benchmark_cases.append(("Standard TAR.GZ Archive", tar_img, "unpacker"))

        # 8. Standard ZIP
        zip_img = root / "archive.zip"
        create_benign_firmware_archive(zip_img, archive_type="zip")
        benchmark_cases.append(("Standard ZIP Archive", zip_img, "unpacker"))

        # 9. Standard TAR
        plain_tar = root / "archive.tar"
        create_benign_firmware_archive(plain_tar, archive_type="tar")
        benchmark_cases.append(("Standard Uncompressed TAR", plain_tar, "unpacker"))

        print("=" * 70)
        print("FirmwareX — Priority 1 Phase 1 Extraction Benchmark")
        print("=" * 70)

        passed = 0
        total = len(benchmark_cases)

        for name, img_path, engine in benchmark_cases:
            t0 = time.perf_counter()
            out_dir = root / f"out_{img_path.stem}"
            try:
                if engine == "extractor":
                    outcome = registry.extract_firmware(img_path, out_dir)
                    success = outcome.success
                    items = outcome.file_count
                    tool = outcome.tool_name
                    errs = outcome.errors
                else:
                    res = unpacker.extract(img_path, out_dir)
                    success = res.success
                    items = res.file_count
                    tool = "unpacker_builtin"
                    errs = res.errors

                dt = (time.perf_counter() - t0) * 1000.0

                if success:
                    passed += 1
                    status_str = "PASS"
                else:
                    status_str = f"FAIL ({'; '.join(errs)})"

                print(f"[{status_str:<4}] {name:<36} | {items:>3} items | {dt:>6.2f} ms | tool: {tool}")

            except Exception as e:
                dt = (time.perf_counter() - t0) * 1000.0
                print(f"[FAIL] {name:<36} | ERR: {e!s} | {dt:>6.2f} ms")

        rate = (passed / total) * 100.0
        print("-" * 70)
        print(f"Total Test Cases: {total}")
        print(f"Successful Extractions: {passed}")
        print(f"Extraction Pass Rate: {rate:.1f}% (PRD Week 1 threshold: >90%)")
        print("=" * 70)

        assert rate >= 90.0, f"Extraction pass rate {rate}% is below 90% threshold"


if __name__ == "__main__":
    run_benchmark()
