"""Integration tests for FirmwareX REST API endpoints and dashboard."""

from fastapi.testclient import TestClient

from firmwarex.api.server import app
from tests.fixtures_helper import create_benign_firmware_archive

client = TestClient(app)


def test_health_check():
    """Verify health endpoint."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_list_firmware_endpoint():
    """Verify listing all firmware records."""
    response = client.get("/api/v1/firmware")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert isinstance(data["firmwares"], list)


def test_dashboard_ui_html():
    """Verify dashboard index page serves valid HTML5 containing FirmwareX branding."""
    response = client.get("/")
    assert response.status_code == 200
    assert "FirmwareX" in response.text
    assert "Binary Hardening Matrix" in response.text


def test_end_to_end_upload_and_analysis_pipeline(tmp_path):
    """Test full pipeline flow: upload archive, extract, audit ELFs, scan secrets, query report."""
    archive_path = tmp_path / "test_fw.tar.gz"
    create_benign_firmware_archive(archive_path, archive_type="tar.gz")

    with open(archive_path, "rb") as f:
        response = client.post(
            "/api/v1/firmware/upload",
            files={"file": ("test_fw.tar.gz", f, "application/gzip")},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert "firmware_id" in data
    assert "job_id" in data
    assert data["file_count"] >= 5
    assert data["binaries_audited"] >= 2
    assert data["findings_count"] >= 1

    firmware_id = data["firmware_id"]
    job_id = data["job_id"]

    # 1. Check Job status
    job_res = client.get(f"/api/v1/jobs/{job_id}")
    assert job_res.status_code == 200
    assert job_res.json()["status"] == "completed"
    assert job_res.json()["progress"] == 100

    # 2. Check Filesystem inventory
    fs_res = client.get(f"/api/v1/firmware/{firmware_id}/filesystem")
    assert fs_res.status_code == 200
    assert fs_res.json()["total_files"] >= 5

    # 3. Check Binary Hardening Audit
    ba_res = client.get(f"/api/v1/firmware/{firmware_id}/binary-audit")
    assert ba_res.status_code == 200
    ba_data = ba_res.json()
    assert ba_data["summary"]["total_binaries"] >= 2
    assert len(ba_data["binaries"]) >= 2

    # 4. Check Vulnerabilities (Appendix A)
    vuln_res = client.get(f"/api/v1/firmware/{firmware_id}/vulnerabilities")
    assert vuln_res.status_code == 200
    vulns = vuln_res.json()
    assert vulns["total_findings"] >= 1
    # Verify redaction flag in all findings
    for finding in vulns["findings"]:
        if finding["category"] == "hardcoded_secret":
            assert finding["redacted"] is True
            assert "AKIAIOSFODNN7EXAMPLE" not in str(finding)

    # 5. Check Full JSON Report Export
    rep_res = client.get(f"/api/v1/firmware/{firmware_id}/report")
    assert rep_res.status_code == 200
    rep = rep_res.json()
    assert rep["schema_version"] == "1.0"
    assert "mitigation_matrix" in rep
    assert "findings_appendix_a" in rep


def test_upload_unsupported_format(tmp_path):
    """Verify that uploading an unsupported format returns status 422 with clear explanation."""
    bad_file = tmp_path / "firmware.bin"
    bad_file.write_bytes(b"hsqs\x00\x00\x00\x01raw_squashfs_data")

    with open(bad_file, "rb") as f:
        response = client.post(
            "/api/v1/firmware/upload",
            files={"file": ("firmware.bin", f, "application/octet-stream")},
        )

    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "unsupported_format"
    assert "Unsupported format 'squashfs'" in data["message"]


def test_upload_zero_byte_empty_file():
    """Verify that 0-byte file upload is rejected with HTTP 400."""
    response = client.post(
        "/api/v1/firmware/upload",
        files={"file": ("empty.tar.gz", b"", "application/gzip")},
    )
    assert response.status_code == 400
    assert "empty (0 bytes)" in response.json()["detail"]


def test_upload_corrupted_archive(tmp_path):
    """Verify that a corrupted archive payload is handled gracefully with HTTP 400."""
    bad_tar = tmp_path / "corrupted.tar.gz"
    # Write gzip header followed by random garbage
    bad_tar.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00" + b"\xff\x00\xaa\xbb" * 20)

    with open(bad_tar, "rb") as f:
        response = client.post(
            "/api/v1/firmware/upload",
            files={"file": ("corrupted.tar.gz", f, "application/gzip")},
        )

    assert response.status_code == 400
    assert "extraction failed" in response.json()["detail"].lower()


def test_get_nonexistent_resources():
    """Verify 404 responses for non-existent IDs."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/firmware/{fake_id}").status_code == 404
    assert client.get(f"/api/v1/firmware/{fake_id}/filesystem").status_code == 404
    assert client.get(f"/api/v1/firmware/{fake_id}/binary-audit").status_code == 404
    assert client.get(f"/api/v1/firmware/{fake_id}/vulnerabilities").status_code == 404
    assert client.get(f"/api/v1/firmware/{fake_id}/report").status_code == 404
    assert client.get(f"/api/v1/jobs/{fake_id}").status_code == 404


def test_audit_log_persists_events():
    """Verify that operations write append-only records to audit_log.jsonl."""
    import json

    from firmwarex.config import AUDIT_LOG_PATH

    assert AUDIT_LOG_PATH.exists()
    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) > 0

    # Parse last event
    last_event = json.loads(lines[-1])
    assert "timestamp" in last_event
    assert "event_type" in last_event
    assert "details" in last_event


def test_database_persistence():
    """Verify SQLite database stores firmware metadata and findings cleanly."""
    from firmwarex.api.storage import StorageManager
    storage = StorageManager()
    firmwares = storage.list_firmwares()
    assert isinstance(firmwares, list)
    if firmwares:
        fw = firmwares[0]
        assert "id" in fw
        assert "sha256" in fw
        assert "status" in fw

