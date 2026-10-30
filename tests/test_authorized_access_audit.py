"""Tests for PRD SC-3.3: Authorized Access & Auditing of Unredacted Artefacts.

Enforces:
- SC-3.3: Access to any unredacted artefact is gated and audited. [Target: Every reveal is authorised and logged.]
- Verification of positive access (analyst/admin roles).
- Verification of denial on anonymous, invalid token, or insufficient role (viewer/guest).
- Verification of anti-path traversal containment.
- Verification that audit events are logged for both granted and denied accesses.
- Verification that audit records NEVER leak plaintext secret values.
"""

from __future__ import annotations

import json
import uuid

import pytest
from starlette.testclient import TestClient

from firmwarex.api.routes import audit_log, storage
from firmwarex.api.server import app
from firmwarex.config import EXTRACTED_DIR, ensure_directories


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def test_firmware_with_artifact(tmp_path):
    """Set up an extracted firmware directory with an unredacted artifact and a secret finding."""
    ensure_directories()
    fw_id = f"test-fw-{uuid.uuid4().hex[:8]}"
    extract_dir = EXTRACTED_DIR / fw_id
    extract_dir.mkdir(parents=True, exist_ok=True)

    # 1. Create a simulated sensitive config file
    etc_dir = extract_dir / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = etc_dir / "app.conf"
    sensitive_token = "AKIAIOSFODNN7EXAMPLE"
    cfg_file.write_text(
        f"# System Config\nDEBUG=0\nAWS_SECRET_KEY={sensitive_token}\nTIMEOUT=30\n",
        encoding="utf-8",
    )

    # 2. Register firmware in storage
    storage.save_firmware({
        "id": fw_id,
        "filename": "fw.bin",
        "sha256": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        "size_bytes": 1024,
        "format": "trx",
        "is_supported": True,
        "status": "analysis_completed",
        "created_at": "2026-10-29T10:00:00Z",
        "extraction_dir": str(extract_dir),
    })

    # 3. Register normalized secret finding in storage (with redacted representation)
    finding_id = f"vuln-{uuid.uuid4().hex[:8]}"
    storage.save_findings(fw_id, [
        {
            "vulnerability_id": finding_id,
            "firmware_id": fw_id,
            "binary": "etc/app.conf",
            "architecture": None,
            "category": "hardcoded_secret",
            "cwe": "CWE-798",
            "address": None,
            "sink": None,
            "source": "file:etc/app.conf#L3",
            "tainted_path": [],
            "crash_state": None,
            "risk_rating": "high",
            "confidence": "probable",
            "evidence_ref": "hash:salted_sha256_mock_fp",
            "redacted": True,
            "remediation": "Revoke and remove hardcoded AWS credentials.",
            "status": "new",
            "detected_at": "2026-10-29T10:00:00Z",
            "details": {
                "type": "AWS Access Key",
                "preview": "AKIA***REDACTED***",
                "description": "Hardcoded AWS token discovered in configuration.",
            },
        }
    ])

    yield {
        "firmware_id": fw_id,
        "finding_id": finding_id,
        "extract_dir": extract_dir,
        "sensitive_token": sensitive_token,
    }

    # Cleanup
    import shutil
    shutil.rmtree(extract_dir, ignore_errors=True)


def test_positive_authorized_analyst_raw_artifact_download(client, test_firmware_with_artifact):
    """Verify that an authorized analyst can download raw unredacted artefacts and the access is audited."""
    fw_id = test_firmware_with_artifact["firmware_id"]
    headers = {"X-API-Key": "fwx-analyst-key-v1"}

    resp = client.get(f"/api/v1/firmware/{fw_id}/artifacts/raw/etc/app.conf", headers=headers)
    assert resp.status_code == 200
    assert "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE" in resp.text

    # Verify audit event was recorded
    events = audit_log.get_events(event_type="UNREDACTED_ACCESS_GRANTED", limit=20)
    matching = [
        e for e in events
        if e["details"].get("firmware_id") == fw_id and e["details"].get("file_path") == "etc/app.conf"
    ]
    assert len(matching) >= 1
    assert matching[-1]["details"]["role"] == "analyst"
    assert matching[-1]["details"]["user_id"] == "analyst-unit42"
    assert matching[-1]["details"]["action"] == "download_raw_artifact"


def test_positive_authorized_admin_secret_reveal(client, test_firmware_with_artifact):
    """Verify that an authorized admin can reveal secret context and reveal is logged without secret leakage."""
    fw_id = test_firmware_with_artifact["firmware_id"]
    finding_id = test_firmware_with_artifact["finding_id"]
    headers = {"Authorization": "Bearer fwx-admin-key-v1"}

    resp = client.post(
        f"/api/v1/firmware/{fw_id}/secrets/{finding_id}/reveal",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["firmware_id"] == fw_id
    assert data["finding_id"] == finding_id
    assert data["authorized_by"] == "admin-unit42"
    assert data["role"] == "admin"
    assert "AKIAIOSFODNN7EXAMPLE" in data["unredacted_context"]

    # Verify audit event was logged
    events = audit_log.get_events(event_type="UNREDACTED_SECRET_REVEAL_GRANTED", limit=20)
    matching = [
        e for e in events
        if e["details"].get("firmware_id") == fw_id and e["details"].get("finding_id") == finding_id
    ]
    assert len(matching) >= 1
    record = matching[-1]
    assert record["details"]["user_id"] == "admin-unit42"
    assert record["details"]["role"] == "admin"
    assert record["details"]["cwe"] == "CWE-798"

    # CRITICAL SECURITY CHECK: Audit log record must NEVER store plaintext secret
    raw_event_json = json.dumps(record)
    assert test_firmware_with_artifact["sensitive_token"] not in raw_event_json, (
        "Security Violation: Plaintext secret leaked into audit log!"
    )


def test_negative_anonymous_access_denied_and_audited(client, test_firmware_with_artifact):
    """Verify unauthenticated requests to unredacted artefacts are denied (401) and logged."""
    fw_id = test_firmware_with_artifact["firmware_id"]

    resp = client.get(f"/api/v1/firmware/{fw_id}/artifacts/raw/etc/app.conf")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]

    # Verify denial audit event
    events = audit_log.get_events(event_type="UNREDACTED_ACCESS_DENIED", limit=20)
    matching = [
        e for e in events
        if e["details"].get("firmware_id") == fw_id and e["details"].get("requested_path") == "etc/app.conf"
    ]
    assert len(matching) >= 1
    assert matching[-1]["details"]["status_code"] == 401


def test_negative_invalid_token_denied_and_audited(client, test_firmware_with_artifact):
    """Verify invalid token requests are rejected (401) and logged."""
    fw_id = test_firmware_with_artifact["firmware_id"]
    headers = {"X-API-Key": "forged-invalid-key-999"}

    resp = client.get(f"/api/v1/firmware/{fw_id}/artifacts/raw/etc/app.conf", headers=headers)
    assert resp.status_code == 401
    assert "Invalid or revoked authentication token" in resp.json()["detail"]

    events = audit_log.get_events(event_type="UNREDACTED_ACCESS_DENIED", limit=20)
    matching = [e for e in events if e["details"].get("firmware_id") == fw_id]
    assert len(matching) >= 1


def test_negative_insufficient_role_denied_and_audited(client, test_firmware_with_artifact):
    """Verify viewer/guest role cannot access unredacted artefacts (403 Forbidden)."""
    fw_id = test_firmware_with_artifact["firmware_id"]
    finding_id = test_firmware_with_artifact["finding_id"]
    headers = {"X-API-Key": "fwx-viewer-key-v1"}

    # Try raw file download
    resp1 = client.get(f"/api/v1/firmware/{fw_id}/artifacts/raw/etc/app.conf", headers=headers)
    assert resp1.status_code == 403
    assert "Forbidden" in resp1.json()["detail"]

    # Try secret reveal
    resp2 = client.post(f"/api/v1/firmware/{fw_id}/secrets/{finding_id}/reveal", headers=headers)
    assert resp2.status_code == 403
    assert "Forbidden" in resp2.json()["detail"]

    events = audit_log.get_events(event_type="UNREDACTED_ACCESS_DENIED", limit=20)
    viewer_events = [e for e in events if e["details"].get("firmware_id") == fw_id and e["details"].get("status_code") == 403]
    assert len(viewer_events) >= 1


def test_anti_path_traversal_containment_safeguard(client, test_firmware_with_artifact):
    """Verify that path traversal escape attempts outside the extraction root are rejected and flagged."""
    fw_id = test_firmware_with_artifact["firmware_id"]
    headers = {"X-API-Key": "fwx-analyst-key-v1"}

    # Attempt to traverse up out of the extracted directory
    resp = client.get(
        f"/api/v1/firmware/{fw_id}/artifacts/raw/../../etc/passwd",
        headers=headers,
    )
    assert resp.status_code in (403, 404)

    # If it reached containment check, verify UNREDACTED_ACCESS_VIOLATION event
    events = audit_log.get_events(limit=50)
    violations = [
        e for e in events
        if e.get("event_type") == "UNREDACTED_ACCESS_VIOLATION"
    ]
    if resp.status_code == 403:
        assert len(violations) >= 1


def test_audit_unredacted_access_endpoint(client):
    """Verify the /api/v1/audit/unredacted-access endpoint returns compliance events."""
    headers = {"X-API-Key": "fwx-analyst-key-v1"}
    resp = client.get("/api/v1/audit/unredacted-access", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert "total_events" in data
    assert data["role"] == "analyst"
