"""Cryptographic redactor and fingerprinting engine for sensitive data protection."""

import hashlib


class Redactor:
    """Masks secret values and computes non-reversible cryptographic fingerprints."""

    @staticmethod
    def fingerprint(secret_value: str, salt: str = "fwx_salt_v1:") -> str:
        """Generate a deterministic salted SHA-256 fingerprint for a secret value without storing plaintext."""
        if not secret_value:
            return ""
        salted = f"{salt}{secret_value}".encode("utf-8", errors="replace")
        h = hashlib.sha256(salted).hexdigest()
        return f"sha256:{h[:16]}...{h[-8:]}"

    @staticmethod
    def full_fingerprint(secret_value: str, salt: str = "fwx_salt_v1:") -> str:
        """Full 64-char salted SHA-256 hex digest for internal deduplication and evidence reference."""
        if not secret_value:
            return ""
        salted = f"{salt}{secret_value}".encode("utf-8", errors="replace")
        return hashlib.sha256(salted).hexdigest()

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
    def sanitize_evidence(cls, evidence_text: str, secret_matches: list | None = None) -> str:
        """Replace all occurrences of detected secret values inside a surrounding context string."""
        if not evidence_text:
            return ""
        sanitized = evidence_text
        if secret_matches:
            for match in secret_matches:
                if match and len(match) > 3:
                    masked = cls.redact(match)
                    sanitized = sanitized.replace(match, masked)

        import re
        # Automated redaction pass for sensitive AWS tokens and key-value assignments
        sanitized = re.sub(r"\b(AKIA[0-9A-Z]{16})\b", lambda m: cls.redact(m.group(1)), sanitized)
        sanitized = re.sub(
            r"""(?i)\b(api_key|apikey|secret_key|auth_token|password|passwd)\s*[:=]\s*(?:['"]([^'"]{4,})['"]|([^\s&;'"\r\n]{4,}))""",
            lambda m: f"{m.group(1)}='{cls.redact(m.group(2) or m.group(3))}'",
            sanitized,
        )
        return sanitized

