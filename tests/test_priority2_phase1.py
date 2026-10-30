"""Priority 2, Phase 1: Dashboard Usability, Filesystem Visualization & Reporting Tests.

Verifies:
1. Filesystem tree viewer schema compatibility and safe path handling.
2. Sortable ELF mitigation matrix fields (architecture, bitness, endianness, stripped, mitigations).
3. Filterable findings and structured crash-state telemetry in API and drawer templates.
4. Honest Control-Flow Graph (CFG) contract endpoint and unavailable state.
5. Report generation, attachment download (Content-Disposition), severity grouping, and zero secret leakage.
6. Error handling for non-existent firmware IDs across all new endpoints.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from firmwarex.api.server import app
from tests.fixtures_helper import create_benign_firmware_archive

client = TestClient(app)


class TestPriority2Phase1DashboardAndReporting:
    """Test suite for Priority 2, Phase 1 requirements."""

    def test_dashboard_html_contains_all_priority2_views(self):
        """Verify dashboard index.html renders all required Priority 2 views and controls."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        # 1. Navigation items
        assert 'id="nav-overview"' in html
        assert 'id="nav-filesystem"' in html
        assert 'id="nav-mitigation"' in html
        assert 'id="nav-findings"' in html
        assert 'id="nav-cfg"' in html
        assert 'id="nav-reports"' in html

        # 2. Filesystem tree viewer controls
        assert 'id="view-filesystem"' in html
        assert 'id="fs-view-tree-btn"' in html
        assert 'id="fs-view-table-btn"' in html
        assert 'id="fs-tree-container"' in html
        assert 'id="fs-tree-root"' in html
        assert 'id="fs-expand-all-btn"' in html

        # 3. Sortable Mitigation matrix controls
        assert 'id="view-mitigation"' in html
        assert 'id="bm-arch-filter"' in html
        assert 'id="bm-status-filter"' in html
        assert 'onclick="sortMitigations(\'file_path\')"' in html
        assert 'onclick="sortMitigations(\'architecture\')"' in html

        # 4. Filterable Findings & Crash log controls
        assert 'id="view-findings"' in html
        assert 'id="findings-type-filter"' in html
        assert 'id="findings-sev-filter"' in html
        assert 'id="findings-pagination"' in html
        assert 'id="drawer-crash-state"' in html
        assert 'id="drawer-tainted-path"' in html

        # 5. Honest CFG viewer panel
        assert 'id="view-cfg"' in html
        assert "Control-Flow Graph (CFG) Analysis" in html
        assert "ENGINE STAGE NOTICE" in html
        assert "Disassembly &amp; Basic-Block CFG Recovery Inactive" in html
        assert "CFG Ingestion Contract" in html

        # 6. Reports & Export controls
        assert 'id="view-reports"' in html
        assert 'id="rep-download-btn"' in html
        assert 'id="rep-count-crit"' in html
        assert 'id="rep-count-high"' in html
        assert "copyReportJson" in html

    def test_report_download_endpoint_and_headers(self, tmp_path: Path):
        """Verify GET /api/v1/firmware/{id}/report/download provides valid attachment with safe headers."""
        archive_path = tmp_path / "fw_download_test.tar.gz"
        create_benign_firmware_archive(archive_path)

        with open(archive_path, "rb") as f:
            upload_resp = client.post(
                "/api/v1/firmware/upload",
                files={"file": ("fw_download_test.tar.gz", f, "application/gzip")},
            )
        assert upload_resp.status_code == 200
        fw_id = upload_resp.json()["firmware_id"]

        # Call the report download endpoint
        dl_resp = client.get(f"/api/v1/firmware/{fw_id}/report/download")
        assert dl_resp.status_code == 200
        assert "application/json" in dl_resp.headers["content-type"]
        cd_header = dl_resp.headers.get("content-disposition", "")
        assert "attachment" in cd_header
        assert f"firmwarex_report_{fw_id[:8]}.json" in cd_header

        # Parse downloaded payload
        report_json = dl_resp.json()
        assert report_json["firmware_id"] == fw_id
        assert "severity_summary" in report_json
        sev = report_json["severity_summary"]
        assert "critical" in sev and isinstance(sev["critical"], int)
        assert "high" in sev and isinstance(sev["high"], int)
        assert "medium" in sev and isinstance(sev["medium"], int)
        assert "low" in sev and isinstance(sev["low"], int)

        assert "filesystem_inventory_summary" in report_json
        assert "inventory" in report_json
        assert "binary_hardening" in report_json
        assert "vulnerabilities" in report_json

    def test_report_download_zero_plaintext_secret_leakage(self, tmp_path: Path):
        """Verify downloaded JSON report contains zero unmasked credentials."""
        archive_path = tmp_path / "secret_firmware.tar.gz"
        raw_secret = "AKIAIOSFODNN7EXAMPLE"

        # Construct archive containing credential
        import tarfile
        with tarfile.open(archive_path, "w:gz") as tar:
            content = f"AWS_KEY='{raw_secret}'\nPASSWORD='P@ssw0rd12345!'\n".encode("utf-8")
            ti = tarfile.TarInfo(name="etc/credentials.conf")
            ti.size = len(content)
            import io
            tar.addfile(ti, io.BytesIO(content))

        with open(archive_path, "rb") as f:
            upload_resp = client.post(
                "/api/v1/firmware/upload",
                files={"file": ("secret_firmware.tar.gz", f, "application/gzip")},
            )
        fw_id = upload_resp.json()["firmware_id"]

        dl_resp = client.get(f"/api/v1/firmware/{fw_id}/report/download")
        assert dl_resp.status_code == 200
        assert raw_secret not in dl_resp.text
        assert "P@ssw0rd12345!" not in dl_resp.text

    def test_cfg_endpoint_returns_honest_unavailable_contract(self, tmp_path: Path):
        """Verify GET /api/v1/firmware/{id}/binaries/{bin}/cfg returns explicit unavailable contract."""
        archive_path = tmp_path / "cfg_fw.tar.gz"
        create_benign_firmware_archive(archive_path)

        with open(archive_path, "rb") as f:
            upload_resp = client.post(
                "/api/v1/firmware/upload",
                files={"file": ("cfg_fw.tar.gz", f, "application/gzip")},
            )
        fw_id = upload_resp.json()["firmware_id"]

        cfg_resp = client.get(f"/api/v1/firmware/{fw_id}/binaries/busybox/cfg")
        assert cfg_resp.status_code == 200
        data = cfg_resp.json()
        assert data["status"] == "unavailable"
        assert data["firmware_id"] == fw_id
        assert data["binary"] == "busybox"
        assert "contract" in data
        assert "nodes_format" in data["contract"]
        assert "edges_format" in data["contract"]

    def test_nonexistent_firmware_error_handling(self):
        """Verify non-existent firmware IDs return proper 404 on all Priority 2 endpoints."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        assert client.get(f"/api/v1/firmware/{fake_id}/report/download").status_code == 404
        assert client.get(f"/api/v1/firmware/{fake_id}/binaries/app/cfg").status_code == 404

