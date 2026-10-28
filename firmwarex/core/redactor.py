"""Cryptographic redactor and fingerprinting engine for sensitive data protection."""

import hashlib
import re
from typing import Optional, Tuple


class Redactor:
    """Masks secret values and computes non-reversible cryptographic fingerprints."""

    @staticmethod
    def fingerprint(secret_value: str) -> str:
        """Generate a deterministic SHA-256 fingerprint for a secret value without storing the plaintext."""
        if not secret_value:
            return ""
        # Salted/prefixed hash representation for audit tracking
        h = hashlib.sha256(secret_value.encode("utf-8", errors="replace")).hexdigest()
        return f"sha256:{h[:16]}...{h[-8:]}"

    @staticmethod
    def full_fingerprint(secret_value: str) -> str:
        """Full 64-char SHA-256 hex digest for internal deduplication and evidence reference."""
        return hashlib.sha256(secret_value.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def redact(secret_value: str, prefix_len: int = 3, suffix_len: int = 3) -> str:
        """Redact a secret, preserving a minimal bounded preview for human triage.

        Example:
            'AKIAIOSFODNN7EXAMPLE' -> 'AKI**************PLE'
            'secret123' -> 'sec***123'
            'short' -> '*****'
        """
        if not secret_value:
            return ""

        clean = secret_value.strip()
        length = len(clean)

        if length <= 6:
            return "*" * length

        if length <= 12:
            return clean[:2] + ("*" * (length - 4)) + clean[-2:]

        p_len = min(prefix_len, 4)
        s_len = min(suffix_len, 4)
        mask_len = length - (p_len + s_len)
        return clean[:p_len] + ("*" * max(mask_len, 6)) + clean[-s_len:]

    @classmethod
    def sanitize_evidence(cls, evidence_text: str, secret_matches: list) -> str:
        """Replace all occurrences of detected secret values inside a surrounding context string."""
        sanitized = evidence_text
        for match in secret_matches:
            if match and len(match) > 3:
                masked = cls.redact(match)
                sanitized = sanitized.replace(match, masked)
        return sanitized
