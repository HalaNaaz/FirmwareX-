"""Tests for defensive protocol fuzzing foundation, mutators, and synthetic loopback server.

Verifies:
1. Strict loopback constraint enforcement (rejecting non-local target IPs).
2. ProtocolMutator for HTTP, UPnP SSDP, and MQTT packet mutations.
3. SyntheticLocalTestServer boundary conditions (normal 200, header overflow 500).
4. ProtocolFuzzRunner anomaly classification and reproducible seed reporting.
5. FastAPI endpoints for fuzzing and extractor capabilities.
"""

import pytest
from starlette.testclient import TestClient

from firmwarex.api.server import app
from firmwarex.fuzzing.protocol_fuzzer import (
    FuzzConfig,
    FuzzProtocol,
    ProtocolFuzzRunner,
    ProtocolMutator,
)
from firmwarex.fuzzing.test_server import SyntheticLocalTestServer


def test_fuzzer_rejects_external_targets():
    """Verify safety boundary: fuzzer strictly rejects external target IPs."""
    cfg = FuzzConfig(target_host="192.168.1.1", protocol=FuzzProtocol.HTTP)
    runner = ProtocolFuzzRunner(cfg)
    with pytest.raises(PermissionError) as exc_info:
        runner.run_fuzzing_session()
    assert "safety boundary violation" in str(exc_info.value).lower()


def test_protocol_mutator_http_upnp_mqtt():
    """Verify ProtocolMutator generates valid, bounded mutation structures."""
    mutator = ProtocolMutator(seed=123)

    # HTTP mutation
    path, headers, body, m_type = mutator.mutate_http("/")
    assert isinstance(path, str)
    assert isinstance(headers, dict)
    assert isinstance(body, bytes)
    assert isinstance(m_type, str)

    # UPnP SSDP mutation
    upnp_payload, upnp_type = mutator.mutate_upnp_msearch()
    assert isinstance(upnp_payload, bytes)
    assert b"M-SEARCH" in upnp_payload

    # MQTT mutation
    mqtt_bytes, mqtt_type = mutator.mutate_mqtt_packet()
    assert isinstance(mqtt_bytes, bytes)
    assert len(mqtt_bytes) > 0


def test_synthetic_test_server_and_fuzz_runner_end_to_end():
    """Verify ProtocolFuzzRunner exercises SyntheticLocalTestServer and captures anomalies."""
    server = SyntheticLocalTestServer()
    port = server.start()

    try:
        cfg = FuzzConfig(
            target_host="127.0.0.1",
            target_port=port,
            protocol=FuzzProtocol.HTTP,
            max_iterations=15,
            seed=42,
            timeout_seconds=2.0,
        )
        runner = ProtocolFuzzRunner(cfg)
        report = runner.run_fuzzing_session()

        assert report.status == "completed"
        assert report.total_iterations == 15
        assert report.target == f"127.0.0.1:{port}"
        assert report.duration_ms > 0
        assert len(report.diagnostics) >= 2

        # Check that server_500 anomalies were detected when mutator hit oversized headers
        server_500_anomalies = [a for a in report.anomalies if a.anomaly_type == "server_500"]
        assert len(server_500_anomalies) > 0
        assert server_500_anomalies[0].status_code == 500

    finally:
        server.stop()


def test_api_extractor_capabilities():
    """Verify /api/v1/extractors/capabilities returns registered modular extractors."""
    client = TestClient(app)
    resp = client.get("/api/v1/extractors/capabilities")
    assert resp.status_code == 200
    data = resp.json()
    assert "capabilities" in data
    format_ids = [c["format_id"] for c in data["capabilities"]]
    assert "cramfs" in format_ids
    assert "trx" in format_ids
    assert "uimage" in format_ids
    assert "squashfs" in format_ids


def test_api_fuzzing_test_endpoint():
    """Verify POST /api/v1/fuzzing/test runs bounded loopback fuzzing session."""
    client = TestClient(app)
    resp = client.post("/api/v1/fuzzing/test?protocol=http&iterations=10&seed=99")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["protocol"] == "http"
    assert data["total_iterations"] == 10
    assert data["seed"] == 99
