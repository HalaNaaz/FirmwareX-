"""CLI script to generate a benign synthetic IoT firmware sample archive."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.fixtures_helper import create_benign_firmware_archive

if __name__ == "__main__":
    samples_dir = Path(__file__).resolve().parent
    out_file = samples_dir / "sample_iot_router.tar.gz"
    create_benign_firmware_archive(out_file, archive_type="tar.gz")
    print(f"Sample firmware archive generated successfully at: {out_file}")

