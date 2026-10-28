"""Unit tests for secret scanning, Shannon entropy, redaction engine, and schema compliance."""

from pathlib import Path
import pytest

from firmwarex.core.redactor import Redactor
from firmwarex.core.secret_scanner import SecretScanner, shannon_entropy
from firmwarex.core.normaliser import FindingNormaliser


def test_redactor_masking():
    """Verify that credentials of various lengths are properly masked."""
    # Long AWS key
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    redacted = Redactor.redact(aws_key)
    assert aws_key not in redacted
    assert redacted.startswith("AKI")
    assert redacted.endswith("PLE")
    assert "*" in redacted

    # Short secret
    short = "secret"
    assert Redactor.redact(short) == "******"

    # Fingerprint check
    fp = Redactor.fingerprint(aws_key)
    assert fp.startswith("sha256:")
    assert aws_key not in fp


def test_shannon_entropy():
    """Verify entropy calculations for low-entropy vs high-entropy strings."""
    low_entropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    high_entropy = "4kL9#mP!2zQ8$vR5*tW1@yB7^cN3&"
    assert shannon_entropy(low_entropy) < 1.0
    assert shannon_entropy(high_entropy) > 4.5


def test_secret_scanner_detection(tmp_path):
    """Verify detection and mandatory redaction of secrets in text and config files."""
    config_file = tmp_path / "app_config.conf"
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    raw_pwd = "SuperSecretAdminPassword123"
    
    config_file.write_text(f"""
    # Embedded system configuration
    aws_key = "{raw_secret}"
    admin_password = "{raw_pwd}"
    crypto_hash = "MD5_Init"
    """)

    scanner = SecretScanner()
    findings = scanner.scan_file(config_file, "etc/app_config.conf")

    assert len(findings) >= 2

    # Verify no raw secret is stored in findings
    for f in findings:
        assert raw_secret not in f.redacted_preview
        assert raw_pwd not in f.redacted_preview
        assert f.redacted is True
        assert f.fingerprint.startswith("sha256:")

    # Check finding categories
    categories = [f.category for f in findings]
    assert "hardcoded_secret" in categories
    assert "weak_crypto" in categories


def test_normaliser_appendix_a_compliance(tmp_path):
    """Verify normalized output strictly adheres to PRD Appendix A schema keys and types."""
    scanner = SecretScanner()
    test_file = tmp_path / "shadow"
    test_file.write_text("root:$6$salt$encryptedhashvaluehere12345678901234567890:19000:0:99999:7:::\n")
    
    findings = scanner.scan_file(test_file, "etc/shadow")
    assert len(findings) > 0
    
    norm = FindingNormaliser.from_secret_finding(findings[0], firmware_id="fw-test-uuid-1234")

    # Check required Appendix A schema keys
    required_keys = [
        "vulnerability_id",
        "firmware_id",
        "binary",
        "architecture",
        "category",
        "cwe",
        "address",
        "sink",
        "source",
        "tainted_path",
        "crash_state",
        "risk_rating",
        "confidence",
        "evidence_ref",
        "redacted",
        "status",
        "detected_at",
    ]
    for key in required_keys:
        assert key in norm, f"Missing required Appendix A key: {key}"

    # Verify crash_state structure
    assert "fault_address" in norm["crash_state"]
    assert "registers" in norm["crash_state"]
    assert "overflow_offset" in norm["crash_state"]
    assert "stack_hash" in norm["crash_state"]
    # Ensure crash state is null for static findings (no invented dynamic data)
    assert norm["crash_state"]["fault_address"] is None

