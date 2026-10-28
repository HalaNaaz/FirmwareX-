"""Configuration settings and containment limits for FirmwareX."""

import os
from pathlib import Path

# Base Paths
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("FIRMWAREX_DATA_DIR", WORKSPACE_ROOT / "data"))
UPLOADS_DIR = DATA_DIR / "uploads"
EXTRACTED_DIR = DATA_DIR / "extracted"
REPORTS_DIR = DATA_DIR / "reports"
AUDIT_LOG_PATH = DATA_DIR / "audit_log.jsonl"
DB_PATH = DATA_DIR / "firmwarex.db"

# Server configuration (Defaults safely to loopback 127.0.0.1)
SERVER_HOST = os.getenv("FIRMWAREX_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("FIRMWAREX_PORT", "8080"))

# Safety and Quota Limits
# Maximum upload payload size (Default: 500 MB)
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("FIRMWAREX_MAX_UPLOAD_SIZE", 500 * 1024 * 1024))

# Maximum total uncompressed size across all extracted files (Default: 1 GB)
MAX_UNCOMPRESSED_SIZE_BYTES = int(os.getenv("FIRMWAREX_MAX_UNCOMPRESSED_SIZE", 1024 * 1024 * 1024))

# Maximum number of files permitted in an extracted archive (Default: 10,000 files)
MAX_FILE_COUNT = int(os.getenv("FIRMWAREX_MAX_FILE_COUNT", 10000))

# Maximum size per individual file inspected by secret/entropy scanner (Default: 10 MB)
MAX_SCAN_FILE_SIZE_BYTES = int(os.getenv("FIRMWAREX_MAX_SCAN_FILE_SIZE", 10 * 1024 * 1024))

# Analysis execution timeout per job in seconds (Default: 900s = 15 minutes)
JOB_TIMEOUT_SECONDS = int(os.getenv("FIRMWAREX_JOB_TIMEOUT", 900))

# Supported archive extraction formats
SUPPORTED_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
}

# Ensure base runtime directories exist
def ensure_directories():
    """Create data directories if they do not exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACTED_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

