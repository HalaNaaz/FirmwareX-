import os
import sys

sys.path.insert(0, os.path.abspath('.'))
import hashlib
import json
import os
import shutil
import tempfile
import time
import urllib.request
from pathlib import Path

from firmwarex.core.unpacker import SafeExtractor

# Load the candidates
with open("benchmark_candidates.json", "r", encoding="utf-8") as f:
    candidates = json.load(f)

# Select 12 distinct targets
selected_targets = [
    "x86/64",
    "x86/generic",
    "armsr/armv7",
    "armsr/armv8",
    "at91/sam9x",
    "at91/sama5",
    "at91/sama7",
    "imx/cortexa7",
    "imx/cortexa9",
    "malta/be",
    "mvebu/cortexa53",
    "mvebu/cortexa72",
]

selected = [c for c in candidates if c["target"] in selected_targets][:12]
assert len(selected) == 12, f"Expected 12, got {len(selected)}"

samples_dir = Path("samples") / "real"
samples_dir.mkdir(parents=True, exist_ok=True)

results = []
total_count = len(selected)
success_count = 0

print(f"Beginning Real Firmware Extraction Benchmark on {total_count} authentic images...")

for idx, item in enumerate(selected, 1):
    target = item["target"]
    fname = item["filename"]
    expected_sha = item["sha256"]
    url = item["url"]
    dest = samples_dir / fname

    print(f"\n[{idx}/{total_count}] Processing {target}: {fname}")

    # 1. Download if not present
    if not dest.exists():
        print(f"  Downloading from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "FirmwareX-Benchmark/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as out_f:
            shutil.copyfileobj(resp, out_f)

    size_bytes = dest.stat().st_size
    print(f"  Size: {size_bytes} bytes ({size_bytes / 1024 / 1024:.2f} MB)")

    # 2. Checksum verification
    h = hashlib.sha256()
    with open(dest, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    actual_sha = h.hexdigest()

    checksum_match = (actual_sha.lower() == expected_sha.lower())
    print(f"  SHA-256 match: {checksum_match} ({actual_sha[:16]}...)")
    if not checksum_match:
        results.append({
            "target": target,
            "filename": fname,
            "url": url,
            "size_bytes": size_bytes,
            "sha256": actual_sha,
            "expected_sha256": expected_sha,
            "checksum_verified": False,
            "extraction_success": False,
            "error": "Checksum mismatch",
            "duration_seconds": 0.0,
            "file_count": 0,
            "extracted_size_bytes": 0,
        })
        continue

    # 3. Extraction with SafeExtractor
    temp_extract = Path(tempfile.mkdtemp(prefix=f"fwx_bench_{idx}_"))
    extractor = SafeExtractor(max_file_count=20000, max_uncompressed_size=1024*1024*1024)
    t0 = time.perf_counter()
    try:
        ext_res = extractor.extract(archive_path=dest, output_dir=temp_extract)
        t1 = time.perf_counter()
        dur = round(t1 - t0, 3)

        # Verify inventory
        is_success = ext_res.success and ext_res.file_count > 0
        if is_success:
            success_count += 1
            print(f"  Extraction SUCCESS: {ext_res.file_count} files, {ext_res.total_size_bytes} bytes in {dur}s")
        else:
            print(f"  Extraction FAILED: {ext_res.message}")

        sample_paths = [item.path for item in ext_res.inventory[:5]] if ext_res.inventory else []

        results.append({
            "target": target,
            "filename": fname,
            "url": url,
            "size_bytes": size_bytes,
            "sha256": actual_sha,
            "expected_sha256": expected_sha,
            "checksum_verified": True,
            "extraction_success": is_success,
            "status": ext_res.status,
            "duration_seconds": dur,
            "file_count": ext_res.file_count,
            "extracted_size_bytes": ext_res.total_size_bytes,
            "sample_files": sample_paths,
            "error": ext_res.message if not is_success else None
        })
    except Exception as e:
        t1 = time.perf_counter()
        dur = round(t1 - t0, 3)
        print(f"  Extraction EXCEPTION: {e}")
        results.append({
            "target": target,
            "filename": fname,
            "url": url,
            "size_bytes": size_bytes,
            "sha256": actual_sha,
            "expected_sha256": expected_sha,
            "checksum_verified": True,
            "extraction_success": False,
            "status": "exception",
            "duration_seconds": dur,
            "file_count": 0,
            "extracted_size_bytes": 0,
            "sample_files": [],
            "error": str(e)
        })
    finally:
        # Clean up temporary extracted directory
        shutil.rmtree(temp_extract, ignore_errors=True)

success_rate = (success_count / total_count) * 100.0
print("\n" + "="*50)
print("BENCHMARK SUMMARY:")
print(f"Total Authentic Images: {total_count}")
print(f"Successful Extractions: {success_count}")
print(f"Failed Extractions:     {total_count - success_count}")
print(f"Success Rate:           {success_rate:.1f}%")
print("="*50)

summary_data = {
    "benchmark_type": "authentic_openwrt_firmware_set",
    "total_images": total_count,
    "successful_extractions": success_count,
    "failed_extractions": total_count - success_count,
    "success_rate_percent": success_rate,
    "acceptance_threshold_percent": 90.0,
    "meets_acceptance": success_rate >= 90.0,
    "images": results
}

with open("benchmark_results_real.json", "w", encoding="utf-8") as f:
    json.dump(summary_data, f, indent=2)

print("Saved benchmark_results_real.json successfully.")
