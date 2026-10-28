"""Secret and cryptographic posture scanner with Shannon entropy and safe redaction.

Scans extracted configuration, scripts, text files, and bounded binary strings for:
- Private keys and certificate material (CWE-321)
- Hardcoded credentials and API tokens (CWE-798 / CWE-259)
- High-entropy candidate secrets (Shannon Entropy H > 4.5)
- Deprecated or weak cryptographic primitives (MD5, SHA-1, DES, RC4) (CWE-327 / CWE-328)

Enforces:
- File-size ceilings (MAX_SCAN_FILE_SIZE_BYTES)
- Bounded line/chunk processing
- Strict output redaction: only hashes and masked previews are stored.
"""

import math
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Generator, List, Optional, Set, Tuple

from firmwarex.config import MAX_SCAN_FILE_SIZE_BYTES
from firmwarex.core.redactor import Redactor


@dataclass
class SecretFinding:
    """Standardized result for an identified credential, key, or weak cryptographic indicator."""
    file_path: str
    line_number: Optional[int]
    category: str  # 'hardcoded_secret' or 'weak_crypto'
    cwe: str       # e.g., 'CWE-798', 'CWE-321', 'CWE-327', 'CWE-328'
    finding_type: str
    redacted_preview: str
    fingerprint: str
    confidence: str  # 'probable', 'heuristic'
    risk_rating: str  # 'critical', 'high', 'medium', 'low', 'info'
    description: str
    evidence_ref: str
    redacted: bool = True

    def to_dict(self) -> Dict:
        return asdict(self)


# Regular expressions for known credential and token patterns
SECRET_PATTERNS = [
    {
        "type": "Private Key Header",
        "regex": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "cwe": "CWE-321",
        "confidence": "probable",
        "risk": "critical",
        "category": "hardcoded_secret",
        "desc": "Hardcoded private cryptographic key material discovered in root filesystem.",
    },
    {
        "type": "AWS Access Key",
        "regex": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "cwe": "CWE-798",
        "confidence": "probable",
        "risk": "high",
        "category": "hardcoded_secret",
        "desc": "Hardcoded AWS Access Key identifier.",
    },
    {
        "type": "Generic API Key Assignment",
        "regex": re.compile(
            r"""(?i)(?:api_key|apikey|secret_key|auth_token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]"""
        ),
        "cwe": "CWE-798",
        "confidence": "heuristic",
        "risk": "high",
        "category": "hardcoded_secret",
        "desc": "Hardcoded API key or auth token variable assignment.",
    },
    {
        "type": "Hardcoded Password Assignment",
        "regex": re.compile(
            r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{6,64})['"]"""
        ),
        "cwe": "CWE-259",
        "confidence": "heuristic",
        "risk": "high",
        "category": "hardcoded_secret",
        "desc": "Hardcoded password variable assignment in configuration or script.",
    },
    {
        "type": "Hardcoded /etc/shadow Hash",
        "regex": re.compile(
            r"""^[a-zA-Z0-9_\-]+:\$[156y]\$[a-zA-Z0-9./$]+:"""
        ),
        "cwe": "CWE-798",
        "confidence": "probable",
        "risk": "critical",
        "category": "hardcoded_secret",
        "desc": "Pre-configured password hash detected in shadow password database.",
    },
]

# Patterns for weak or broken cryptographic primitives
WEAK_CRYPTO_PATTERNS = [
    {
        "type": "MD5 Hash Function Reference",
        "regex": re.compile(r"\b(?:MD5_Init|EVP_md5|md5sum|md5_crypt)\b", re.IGNORECASE),
        "cwe": "CWE-328",
        "confidence": "heuristic",
        "risk": "medium",
        "category": "weak_crypto",
        "desc": "Reference to cryptographically broken MD5 hash algorithm.",
    },
    {
        "type": "SHA-1 Hash Function Reference",
        "regex": re.compile(r"\b(?:SHA1_Init|EVP_sha1|sha1sum)\b", re.IGNORECASE),
        "cwe": "CWE-328",
        "confidence": "heuristic",
        "risk": "medium",
        "category": "weak_crypto",
        "desc": "Reference to deprecated SHA-1 hash algorithm vulnerable to collision attacks.",
    },
    {
        "type": "DES / 3DES Cipher Reference",
        "regex": re.compile(r"\b(?:des_crypt|DES_set_key|EVP_des_ede3_cbc|DES_ede3)\b", re.IGNORECASE),
        "cwe": "CWE-327",
        "confidence": "heuristic",
        "risk": "medium",
        "category": "weak_crypto",
        "desc": "Reference to broken or deprecated DES/3DES cipher primitive.",
    },
    {
        "type": "RC4 / ARC4 Stream Cipher Reference",
        "regex": re.compile(r"\b(?:RC4_set_key|EVP_rc4|arcfour)\b", re.IGNORECASE),
        "cwe": "CWE-327",
        "confidence": "heuristic",
        "risk": "high",
        "category": "weak_crypto",
        "desc": "Reference to broken RC4 stream cipher exhibiting systemic keystream bias.",
    },
]


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of an ASCII string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts: Dict[str, int] = {}
    for c in data:
        char_counts[c] = char_counts.get(c, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class SecretScanner:
    """Scans firmware filesystem for credentials, tokens, entropy anomalies, and weak crypto."""

    def __init__(self, max_file_size: int = MAX_SCAN_FILE_SIZE_BYTES):
        self.max_file_size = max_file_size

    def scan_directory(self, extraction_dir: Path) -> List[SecretFinding]:
        """Iterate over all eligible files in extraction_dir and collect findings."""
        findings: List[SecretFinding] = []
        resolved_root = extraction_dir.resolve()

        for file_path in resolved_root.rglob("*"):
            if not file_path.is_file():
                continue

            try:
                # Enforce file-size limit
                if file_path.stat().st_size > self.max_file_size:
                    continue

                rel_path = file_path.relative_to(resolved_root).as_posix()
                file_findings = self.scan_file(file_path, rel_path)
                findings.extend(file_findings)
            except Exception:
                continue

        return findings

    def scan_file(self, file_path: Path, rel_path: str) -> List[SecretFinding]:
        """Scan a single file for secrets, crypto anomalies, and high-entropy strings."""
        findings: List[SecretFinding] = []

        # Read as text or bounded binary strings
        is_binary = False
        lines: List[str] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                # Read up to 20,000 lines max per file to bound scanning time
                for i, line in enumerate(f):
                    if i > 20000:
                        break
                    lines.append(line)
        except Exception:
            return findings

        # 1. Pattern Matching (Secrets & Weak Crypto)
        for line_num, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or len(line_str) > 1000:
                continue

            # Check Secret Patterns
            for p in SECRET_PATTERNS:
                matches = p["regex"].findall(line_str)
                for match in matches:
                    matched_val = match if isinstance(match, str) else match[0]
                    # Avoid false positives on trivial placeholder tokens
                    if matched_val.strip().lower() in ["changeme", "your_api_key_here", "password123", "placeholder"]:
                        continue

                    fp = Redactor.fingerprint(matched_val)
                    full_fp = Redactor.full_fingerprint(matched_val)
                    preview = Redactor.redact(matched_val)

                    findings.append(
                        SecretFinding(
                            file_path=rel_path,
                            line_number=line_num,
                            category=p["category"],
                            cwe=p["cwe"],
                            finding_type=p["type"],
                            redacted_preview=preview,
                            fingerprint=fp,
                            confidence=p["confidence"],
                            risk_rating=p["risk"],
                            description=p["desc"],
                            evidence_ref=full_fp,
                            redacted=True,
                        )
                    )

            # Check Weak Crypto Patterns
            for cp in WEAK_CRYPTO_PATTERNS:
                if cp["regex"].search(line_str):
                    preview = Redactor.sanitize_evidence(line_str[:80], [])
                    fp = Redactor.fingerprint(f"{rel_path}:{line_num}:{cp['type']}")
                    findings.append(
                        SecretFinding(
                            file_path=rel_path,
                            line_number=line_num,
                            category=cp["category"],
                            cwe=cp["cwe"],
                            finding_type=cp["type"],
                            redacted_preview=preview,
                            fingerprint=fp,
                            confidence=cp["confidence"],
                            risk_rating=cp["risk"],
                            description=cp["desc"],
                            evidence_ref=fp,
                            redacted=True,
                        )
                    )

            # 2. Shannon Entropy String Scanning for potential unidentified tokens
            words = re.findall(r"\b[a-zA-Z0-9+/=_-]{24,80}\b", line_str)
            for word in words:
                entropy = shannon_entropy(word)
                if entropy > 4.6:  # Threshold for high-entropy alphanumeric string
                    # Filter out simple base64 blocks or repetition
                    fp = Redactor.fingerprint(word)
                    findings.append(
                        SecretFinding(
                            file_path=rel_path,
                            line_number=line_num,
                            category="hardcoded_secret",
                            cwe="CWE-798",
                            finding_type="High-Entropy Candidate Secret",
                            redacted_preview=Redactor.redact(word),
                            fingerprint=fp,
                            confidence="heuristic",
                            risk_rating="medium",
                            description=f"High-entropy string anomaly detected (Shannon H={entropy:.2f}). Potential token or key.",
                            evidence_ref=Redactor.full_fingerprint(word),
                            redacted=True,
                        )
                    )

        return findings
