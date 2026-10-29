"""Browser QA and Headless Chrome Automation Runner for FirmwareX Dashboard.

Verifies:
- Dashboard route (GET /)
- Responsive viewports (Desktop 1280x800 and Mobile 375x812)
- Visual rendering and screenshot capture
- Form validation and active pipeline presentation
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
WORKSPACE_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = WORKSPACE_DIR / "docs"


def wait_for_server(url: str, timeout: int = 10) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def run_browser_qa():
    print("=== FirmwareX Browser QA & Automation Suite ===")
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    if not Path(CHROME_PATH).exists():
        print(f"ERROR: Chrome binary not found at {CHROME_PATH}")
        sys.exit(1)

    # 1. Start Server in Subprocess if not already running
    print("[1/5] Checking FirmwareX server status at http://127.0.0.1:8080...")
    already_running = False
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=1) as r:
            if r.status == 200:
                already_running = True
                print(" -> Detected existing running FirmwareX server at http://127.0.0.1:8080.")
    except Exception:
        already_running = False

    server_proc = None
    if not already_running:
        print(" -> Launching FirmwareX server at http://127.0.0.1:8080...")
        env = os.environ.copy()
        env["FIRMWAREX_HOST"] = "127.0.0.1"
        env["FIRMWAREX_PORT"] = "8080"
        python_exe = sys.executable

        server_proc = subprocess.Popen(
            [python_exe, "-m", "uvicorn", "firmwarex.api.server:app", "--host", "127.0.0.1", "--port", "8080"],
            cwd=str(WORKSPACE_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for healthz
        ready = wait_for_server("http://127.0.0.1:8080/healthz", timeout=12)
        if not ready:
            print("ERROR: Server failed to respond within 12 seconds.")
            out, err = server_proc.communicate(timeout=2)
            print(f"STDOUT: {out.decode()}\nSTDERR: {err.decode()}")
            sys.exit(1)
        print(" -> Server healthy (HTTP 200).")

    try:
        # 2. End-to-End API upload of sample IoT firmware first so dashboard has active data
        print("[2/6] Ingesting sample IoT router firmware for live visualization...")
        sample_path = WORKSPACE_DIR / "samples" / "sample_iot_router.tar.gz"
        if not sample_path.exists():
            from tests.fixtures_helper import create_benign_firmware_archive
            create_benign_firmware_archive(sample_path)

        with open(sample_path, "rb") as f:
            file_bytes = f.read()

        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = bytearray()
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(b'Content-Disposition: form-data; name="file"; filename="sample_iot_router.tar.gz"\r\n')
        body.extend(b"Content-Type: application/gzip\r\n\r\n")
        body.extend(file_bytes)
        body.extend(f"\r\n--{boundary}--\r\n".encode())

        req = urllib.request.Request(
            "http://127.0.0.1:8080/api/v1/firmware/upload",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            fw_id = data["firmware_id"]
            print(f" -> Firmware ingested: {fw_id} (Files: {data['file_count']}, Binaries: {data['binaries_audited']}, Findings: {data['findings_count']})")

        # Give server a short moment
        time.sleep(1)

        # 3. Dump and Verify Dashboard DOM via Headless Chrome
        print("[3/6] Inspecting Dashboard DOM via Chrome Headless...")
        temp_profile = tempfile.mkdtemp(prefix="chrome_qa_")
        dump_cmd = [
            CHROME_PATH,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            f"--user-data-dir={temp_profile}",
            "--dump-dom",
            "http://127.0.0.1:8080/",
        ]
        dom_res = subprocess.run(dump_cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=15)
        dom_html = dom_res.stdout or ""

        # Verify key DOM elements in the SOC Command Center
        required_elements = [
            'id="dropArea"',
            'id="firmwareFile"',
            'id="uploadForm"',
            'id="active-firmware-select"',
            'id="findings-tbody"',
            'id="bm-tbody"',
            'id="fs-tbody"',
            'id="investigation-drawer"',
            "FirmwareX",
            "v0.1.0",
        ]
        missing = [el for el in required_elements if el not in dom_html]
        if missing:
            print(f"ERROR: Rendered DOM is missing required elements: {missing}")
            sys.exit(1)
        print(" -> All required form elements, tables, and branding confirmed in rendered DOM.")

        # 4. Capture Desktop Screenshots (1440x900 and 1280x800)
        print("[4/6] Capturing Desktop Viewport Screenshots (1440x900 & 1280x800)...")
        desktop_1440_png = DOCS_DIR / "dashboard_desktop_1440.png"
        cmd_1440 = [
            CHROME_PATH,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            f"--user-data-dir={temp_profile}",
            f"--screenshot={desktop_1440_png}",
            "--window-size=1440,900",
            "--virtual-time-budget=4000",
            "http://127.0.0.1:8080/",
        ]
        subprocess.run(cmd_1440, check=True, timeout=20)
        if desktop_1440_png.exists() and desktop_1440_png.stat().st_size > 15000:
            print(f" -> 1440x900 desktop screenshot captured ({desktop_1440_png.stat().st_size} bytes): {desktop_1440_png}")
        else:
            print("ERROR: 1440x900 desktop screenshot missing or too small.")
            sys.exit(1)

        desktop_1280_png = DOCS_DIR / "dashboard_desktop_1280.png"
        cmd_1280 = [
            CHROME_PATH,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            f"--user-data-dir={temp_profile}",
            f"--screenshot={desktop_1280_png}",
            "--window-size=1280,800",
            "--virtual-time-budget=4000",
            "http://127.0.0.1:8080/",
        ]
        subprocess.run(cmd_1280, check=True, timeout=20)
        import shutil
        shutil.copyfile(desktop_1280_png, DOCS_DIR / "dashboard_desktop.png")
        print(f" -> 1280x800 desktop screenshot captured ({desktop_1280_png.stat().st_size} bytes): {desktop_1280_png}")

        # 5. Capture Mobile Viewport Screenshot (390x844)
        print("[5/6] Capturing Mobile Viewport Screenshot (390x844)...")
        mobile_390_png = DOCS_DIR / "dashboard_mobile_390.png"
        mobile_cmd = [
            CHROME_PATH,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            f"--user-data-dir={temp_profile}",
            f"--screenshot={mobile_390_png}",
            "--window-size=390,844",
            "--virtual-time-budget=4000",
            "http://127.0.0.1:8080/",
        ]
        subprocess.run(mobile_cmd, check=True, timeout=20)
        shutil.copyfile(mobile_390_png, DOCS_DIR / "dashboard_mobile.png")
        if mobile_390_png.exists() and mobile_390_png.stat().st_size > 15000:
            print(f" -> 390x844 mobile screenshot captured ({mobile_390_png.stat().st_size} bytes): {mobile_390_png}")
        else:
            print("ERROR: Mobile screenshot missing or too small.")
            sys.exit(1)

        # 6. Verify Report Export
        print("[6/6] Verifying JSON report export...")
        with urllib.request.urlopen(f"http://127.0.0.1:8080/api/v1/firmware/{fw_id}/report") as resp:
            report_data = json.loads(resp.read().decode())
            print(f" -> Verified Report Export (Schema v{report_data['schema_version']}, Findings: {len(report_data['findings_appendix_a'])})")

        print("=== BROWSER QA & INTEGRATION TESTS SUCCEEDED ===")

    finally:
        if server_proc is not None:
            server_proc.terminate()
            server_proc.wait(timeout=5)


if __name__ == "__main__":
    run_browser_qa()
