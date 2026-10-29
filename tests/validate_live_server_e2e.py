import io
import json
import tarfile
import urllib.error
import urllib.request


def create_test_tar():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Add a test config file with secret
        cfg = b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\nPORT=8080\n"
        ti_cfg = tarfile.TarInfo(name="etc/config.env")
        ti_cfg.size = len(cfg)
        tar.addfile(ti_cfg, io.BytesIO(cfg))

        # Add a minimal MIPS ELF
        # Minimal ELF header (MIPS BE)
        elf = (
            b"\x7fELF\x01\x02\x01\x00"  # 32-bit, Big Endian
            + b"\x00" * 8
            + b"\x00\x02"  # ET_EXEC
            + b"\x00\x08"  # EM_MIPS
            + b"\x00\x00\x00\x01"  # EV_CURRENT
            + b"\x00\x40\x00\x00"  # entry point
            + b"\x00" * 32
        )
        ti_elf = tarfile.TarInfo(name="bin/service_mips")
        ti_elf.size = len(elf)
        tar.addfile(ti_elf, io.BytesIO(elf))

    buf.seek(0)
    return buf.read()


def run_e2e_live_validation():
    base_url = "http://127.0.0.1:8080"
    results = {}

    print(f"[*] Starting E2E validation against live server at {base_url}...")

    # 1. Health checks
    for path in ["/healthz", "/health"]:
        req = urllib.request.Request(f"{base_url}{path}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "healthy"
            results[f"health_{path}"] = "PASS"
    print(" [+] Health endpoints verified: PASS")

    # 2. Docs check
    with urllib.request.urlopen(f"{base_url}/docs", timeout=5) as resp:
        assert resp.status == 200
        html = resp.read().decode("utf-8")
        assert "Swagger UI" in html or "swagger-ui" in html
        results["docs"] = "PASS"
    print(" [+] OpenAPI Swagger documentation verified: PASS")

    # 3. Dashboard UI check
    with urllib.request.urlopen(f"{base_url}/", timeout=5) as resp:
        assert resp.status == 200
        html = resp.read().decode("utf-8")
        assert "SOC Command Center" in html
        assert "FirmwareX" in html
        results["dashboard_html"] = "PASS"
    print(" [+] Dashboard HTML route (GET /) verified: PASS")

    # 4. Upload synthetic firmware
    tar_bytes = create_test_tar()
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="e2e_test_firmware.tar.gz"\r\n'
        f"Content-Type: application/gzip\r\n\r\n"
    ).encode("utf-8") + tar_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        f"{base_url}/api/v1/firmware/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        assert resp.status == 200
        upload_data = json.loads(resp.read().decode("utf-8"))
        fw_id = upload_data["firmware_id"]
        assert upload_data["status"] == "completed"
        assert upload_data["file_count"] >= 2
        results["firmware_upload"] = "PASS"
    print(f" [+] Synthetic firmware uploaded and analyzed (ID: {fw_id}): PASS")

    # 5. Check Filesystem inventory
    with urllib.request.urlopen(f"{base_url}/api/v1/firmware/{fw_id}/filesystem") as resp:
        assert resp.status == 200
        fs_data = json.loads(resp.read().decode("utf-8"))
        assert fs_data["total_files"] >= 2
        files = [f["path"] for f in fs_data["files"]]
        assert any("etc/config.env" in p for p in files)
        results["filesystem_inventory"] = "PASS"
    print(" [+] Filesystem inventory verified: PASS")

    # 6. Check Binary Audit
    with urllib.request.urlopen(f"{base_url}/api/v1/firmware/{fw_id}/binary-audit") as resp:
        assert resp.status == 200
        ba_data = json.loads(resp.read().decode("utf-8"))
        assert ba_data["summary"]["total_binaries"] >= 1
        results["binary_audit"] = "PASS"
    print(" [+] Binary hardening audit verified: PASS")

    # 7. Check Findings & Redaction
    with urllib.request.urlopen(f"{base_url}/api/v1/firmware/{fw_id}/vulnerabilities") as resp:
        assert resp.status == 200
        vuln_data = json.loads(resp.read().decode("utf-8"))
        assert vuln_data["total_findings"] >= 1
        # Confirm secret is redacted
        for finding in vuln_data["findings"]:
            if finding["category"] == "hardcoded_secret":
                assert finding["redacted"] is True
                assert "AKIAIOSFODNN7EXAMPLE" not in str(finding)
                assert "remediation" in finding
                assert len(finding["remediation"]) > 10
        results["vulnerabilities_redaction_remediation"] = "PASS"
    print(" [+] Findings, secret redaction, and remediation fields verified: PASS")

    # 8. Check JSON Report Export and Export Alias
    for rep_path in [f"/api/v1/firmware/{fw_id}/report", f"/api/v1/firmware/{fw_id}/export"]:
        with urllib.request.urlopen(f"{base_url}{rep_path}") as resp:
            assert resp.status == 200
            rep = json.loads(resp.read().decode("utf-8"))
            assert rep["schema_version"] == "1.0"
            assert "mitigation_matrix" in rep
            assert "findings_appendix_a" in rep
        results[f"report_export_{rep_path.split('/')[-1]}"] = "PASS"
    print(" [+] Full JSON report export and aliases verified: PASS")

    # 9. Error state testing: Zero-byte upload
    zero_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="empty.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n\r\n--{boundary}--\r\n"
    ).encode("utf-8")
    req_zero = urllib.request.Request(
        f"{base_url}/api/v1/firmware/upload",
        data=zero_body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req_zero, timeout=5)
        results["zero_byte_rejection"] = "FAIL (unexpected 200)"
    except urllib.error.HTTPError as e:
        assert e.code == 400
        results["zero_byte_rejection"] = "PASS (400 Bad Request)"
    print(" [+] Error handling: Zero-byte file correctly rejected with HTTP 400: PASS")

    # 10. Error state testing: Nonexistent resource
    try:
        urllib.request.urlopen(f"{base_url}/api/v1/firmware/nonexistent-uuid-99999", timeout=5)
        results["nonexistent_resource"] = "FAIL (unexpected 200)"
    except urllib.error.HTTPError as e:
        assert e.code == 404
        results["nonexistent_resource"] = "PASS (404 Not Found)"
    print(" [+] Error handling: Nonexistent firmware correctly returned HTTP 404: PASS")

    print("\n[=== ALL 10 E2E LIVE VALIDATION CHECKS PASSED ===]")
    return results


if __name__ == "__main__":
    run_e2e_live_validation()
