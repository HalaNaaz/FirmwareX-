"""Unit tests for bounded symbolic analysis, static taint reachability, and review lead tagging."""

from fastapi.testclient import TestClient

from firmwarex.api.server import app
from firmwarex.core.symbolic_analyzer import (
    BoundedSymbolicAnalyzer,
    SymbolicBudget,
)

client = TestClient(app)


def test_symbolic_analyzer_detects_source_and_sink(tmp_path):
    """Verify BoundedSymbolicAnalyzer discovers source-to-sink reachability in ELF binaries."""
    from tests.fixtures_helper import create_minimal_elf
    test_elf = tmp_path / "daemon_sink.elf"
    test_elf.write_bytes(create_minimal_elf(arch="x86_64", bitness=64, enable_nx=True))

    analyzer = BoundedSymbolicAnalyzer(budget=SymbolicBudget(timeout_seconds=2.0))
    report = analyzer.analyze_workspace(tmp_path)

    assert report.status == "completed"
    assert report.binaries_analyzed >= 1
    assert isinstance(report.review_leads, list)
    assert report.engine in ("angr_symbolic", "firmwarex_static_taint_v1")


def test_symbolic_api_endpoint(tmp_path):
    """Verify GET /api/v1/firmware/{id}/symbolic endpoint returns analysis report."""
    from tests.fixtures_helper import create_benign_firmware_archive
    archive_path = tmp_path / "fw_sample.tar.gz"
    create_benign_firmware_archive(archive_path)

    with open(archive_path, "rb") as f:
        up_res = client.post(
            "/api/v1/firmware/upload",
            files={"file": ("fw_sample.tar.gz", f, "application/gzip")},
        )
    assert up_res.status_code == 200
    fw_id = up_res.json()["firmware_id"]

    # Test GET /api/v1/firmware/{fw_id}/symbolic
    sym_res = client.get(f"/api/v1/firmware/{fw_id}/symbolic")
    assert sym_res.status_code == 200
    data = sym_res.json()
    assert "status" in data
    assert "engine" in data
    assert "review_leads" in data
    assert isinstance(data["review_leads"], list)


def test_containment_preflight_api_endpoint():
    """Verify GET /api/v1/containment/preflight endpoint returns live containment status."""
    res = client.get("/api/v1/containment/preflight")
    assert res.status_code == 200
    data = res.json()
    assert "passed" in data
    assert "docker_available" in data
    assert "network_isolation_verified" in data
    assert "diagnostics" in data


def test_firmware_signatures_api_endpoint(tmp_path):
    """Verify GET /api/v1/firmware/{id}/signatures endpoint returns detected signatures."""
    from tests.fixtures_helper import create_benign_firmware_archive
    archive_path = tmp_path / "fw_sigs.tar.gz"
    create_benign_firmware_archive(archive_path)

    with open(archive_path, "rb") as f:
        up_res = client.post(
            "/api/v1/firmware/upload",
            files={"file": ("fw_sigs.tar.gz", f, "application/gzip")},
        )
    fw_id = up_res.json()["firmware_id"]

    sig_res = client.get(f"/api/v1/firmware/{fw_id}/signatures")
    assert sig_res.status_code == 200
    data = sig_res.json()
    assert "firmware_id" in data
    assert "signatures" in data
    assert isinstance(data["signatures"], list)
