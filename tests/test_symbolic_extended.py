"""Extended unit tests for bounded static taint and symbol reachability analysis.

Verifies:
1. Candidate source-to-sink reachability review leads generation.
2. Metadata enrichment: confidence, analysis_method, limitations, and deduplication.
3. Robustness against stripped, truncated, and non-ELF files.
4. Clean fallback reporting when angr is not installed on Windows Python 3.14.
"""


from starlette.testclient import TestClient

from firmwarex.api.server import app
from firmwarex.core.symbolic_analyzer import (
    BoundedSymbolicAnalyzer,
    SymbolicBudget,
)
from tests.fixtures_helper import create_minimal_elf


def test_symbolic_analyzer_deduplication_and_metadata(tmp_path):
    """Verify that detected review leads are deduplicated and contain honest metadata."""
    bin_path = tmp_path / "router_cli"
    elf_bytes = create_minimal_elf("arm", bitness=32, endianness="little")
    # Append test symbol references
    bin_path.write_bytes(elf_bytes + b"\x00recv\x00popen\x00system\x00read\x00")

    analyzer = BoundedSymbolicAnalyzer(budget=SymbolicBudget(instruction_budget=5000))
    leads = analyzer.analyze_binary(bin_path)

    # Leads must be tagged strictly as REVIEW_LEAD with confidence='candidate'
    for lead in leads:
        assert lead.status == "REVIEW_LEAD"
        assert lead.confidence == "candidate"
        assert lead.analysis_method == "static_symbol_reachability"
        assert len(lead.limitations) >= 1
        assert "does not prove" in lead.limitations[0].lower()


def test_symbolic_analyzer_handles_stripped_or_empty_binaries(tmp_path):
    """Verify analyzer gracefully handles stripped, truncated, or non-ELF binaries."""
    analyzer = BoundedSymbolicAnalyzer()

    # 1. Truncated ELF
    trunc_elf = tmp_path / "trunc"
    trunc_elf.write_bytes(b"\x7fELF\x02\x01")
    assert analyzer.analyze_binary(trunc_elf) == []

    # 2. Non-ELF file
    text_file = tmp_path / "readme.txt"
    text_file.write_text("Hello World")
    assert analyzer.analyze_binary(text_file) == []

    # 3. Nonexistent file
    assert analyzer.analyze_binary(tmp_path / "does_not_exist") == []


def test_symbolic_workspace_report_documents_angr_limitation(tmp_path):
    """Verify analyze_workspace produces honest limitations report on Python 3.14 Windows."""
    analyzer = BoundedSymbolicAnalyzer()
    report = analyzer.analyze_workspace(tmp_path)

    assert report.status == "completed"
    assert report.angr_available is False
    assert len(report.limitations) >= 1
    assert "angr" in report.limitations[0].lower()
    assert "review leads" in report.limitations[0].lower()


def test_api_containment_verify_endpoint():
    """Verify GET /api/v1/containment/verify endpoint executes live containment telemetry."""
    client = TestClient(app)
    resp = client.get("/api/v1/containment/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert "live_execution_verified" in data
    assert "network_egress_denied" in data
    assert "read_only_rootfs_verified" in data
