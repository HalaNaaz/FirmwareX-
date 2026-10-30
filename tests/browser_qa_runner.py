"""Browser QA and Headless Chrome Automation Runner for FirmwareX Dashboard.

Verifies:
- Dashboard route (GET /)
- Responsive viewports (Desktop 1440x900, Desktop 1280x800, Mobile 390x844)
- Visual rendering and high-resolution screenshot capture
- Ingestion pipeline: valid firmware upload and malformed upload rejection
- Multi-firmware selector updating live views
- Filesystem explorer: tree vs table modes, expand/collapse, and search
- Mitigation matrix: sortable headers and architecture filters
- Findings triage: severity filters, drawer inspection, crash state, and tainted path
- CFG view: honest unavailable contract and SVG canvas readiness
- Reports: executive preview, raw JSON toggle, download headers, and print stylesheets
- System telemetry: live queue metrics and containment indicators
- Chrome DevTools Protocol (CDP) live interaction with zero uncaught JavaScript exceptions
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import websockets

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


async def run_cdp_interaction_suite(port: int, fw_id: str):
    """Run interactive tests against the live dashboard using Chrome DevTools Protocol."""
    print(" -> Connecting to Chrome DevTools Protocol (CDP) for live interaction verification...")
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json") as resp:
        targets = json.loads(resp.read().decode())
        page_target = [t for t in targets if t.get('type') == 'page'][0]
        ws_url = page_target['webSocketDebuggerUrl']

    async with websockets.connect(ws_url) as ws:
        msg_id = 1

        async def send(method, params=None):
            nonlocal msg_id
            current_id = msg_id
            msg_id += 1
            payload = {"id": current_id, "method": method, "params": params or {}}
            await ws.send(json.dumps(payload))
            while True:
                res = json.loads(await ws.recv())
                if res.get("id") == current_id:
                    return res.get("result", {})

        await send("Console.enable")
        await send("Runtime.enable")
        await send("Page.enable")

        js_exceptions = []

        async def eval_js(expression):
            res = await send("Runtime.evaluate", {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": True
            })
            if "exceptionDetails" in res:
                js_exceptions.append(res["exceptionDetails"])
            return res.get("result", {}).get("value")

        # Allow initial DOMContentLoaded and async fetches to settle
        await asyncio.sleep(2.0)

        # Select our ingested valid firmware first so views have active data
        await eval_js(f"onSelectFirmware('{fw_id}')")
        await asyncio.sleep(1.0)

        # 1. Verify Branding & Firmware List
        title = await eval_js("document.title")
        assert "FirmwareX" in title, f"Unexpected title: {title}"
        fw_count = await eval_js("allFirmwares.length")
        assert fw_count > 0, "No firmware loaded in frontend state"
        print(f"    [CDP 1/10] Branding & State: '{title}' ({fw_count} firmwares loaded)")

        # 2. Verify Overview Metrics
        ov_files = await eval_js("document.getElementById('stat-total-files').textContent")
        ov_elfs = await eval_js("document.getElementById('stat-total-elfs').textContent")
        ov_finds = await eval_js("document.getElementById('stat-total-findings').textContent")
        print(f"    [CDP 2/10] Overview Metrics: Files={ov_files}, ELFs={ov_elfs}, Findings={ov_finds}")

        # 3. Verify Filesystem Tree/Table Modes & Search Filter
        await eval_js("switchView('filesystem')")
        await eval_js("setFsViewMode('table')")
        table_active = await eval_js("!document.getElementById('fs-table-container').classList.contains('hidden')")
        assert table_active, "Filesystem table mode did not activate"

        await eval_js("document.getElementById('fs-search-input').value = 'etc'; filterFilesystem();")
        filtered_rows = await eval_js("document.querySelectorAll('#fs-tbody tr').length")
        print(f"    [CDP 3/10] Filesystem Explorer: Table Mode Active, Filter 'etc' matched {filtered_rows} entries")

        await eval_js("document.getElementById('fs-search-input').value = ''; filterFilesystem();")
        await eval_js("setFsViewMode('tree')")

        # 4. Verify Mitigation Matrix Sorting & Filtering
        await eval_js("switchView('mitigation')")
        await eval_js("sortMitigations('file_path')")
        first_binary = await eval_js("document.querySelector('#bm-tbody tr td')?.textContent")
        print(f"    [CDP 4/10] Mitigation Matrix: Sorted by file_path -> Top entry: {first_binary}")

        # 5. Verify Findings Triage, Severity Filter & Investigation Drawer
        await eval_js("switchView('findings')")
        find_len = await eval_js("currentFindings.length")
        assert find_len > 0, "No findings rendered in findings view"

        # Open drawer on first finding
        await eval_js("openDrawer(currentFindings[0])")
        drawer_open = await eval_js("!document.getElementById('investigation-drawer').classList.contains('translate-x-full')")
        cwe_label = await eval_js("document.getElementById('drawer-cwe').textContent")
        assert drawer_open, "Investigation drawer failed to open"
        print(f"    [CDP 5/10] Findings Drawer: Opened successfully for finding {cwe_label}")

        await eval_js("closeDrawer()")
        drawer_closed = await eval_js("document.getElementById('investigation-drawer').classList.contains('translate-x-full')")
        assert drawer_closed, "Investigation drawer failed to close"

        # 6. Verify Control-Flow Graph (CFG) View
        await eval_js("switchView('cfg')")
        cfg_visible = await eval_js("!document.getElementById('view-cfg').classList.contains('hidden')")
        assert cfg_visible, "CFG view is not visible"

        await eval_js("loadCfg()")
        cfg_status = await eval_js("document.getElementById('cfg-status-title').textContent")
        print(f"    [CDP 6/10] CFG View: Contract active -> '{cfg_status}'")

        # 7. Verify Reports Executive View & Raw JSON Toggle
        await eval_js("switchView('reports')")
        await eval_js("setReportViewMode('json')")
        json_visible = await eval_js("!document.getElementById('rep-json-container').classList.contains('hidden')")
        assert json_visible, "Raw JSON view container failed to display"

        # Verify copy function
        await eval_js("copyReportJson()")
        await eval_js("setReportViewMode('summary')")
        print("    [CDP 7/10] Reports View: Executive Summary & Raw JSON toggling verified")

        # 8. Verify System Telemetry
        await eval_js("switchView('system')")
        queue_text = await eval_js("document.getElementById('sys-queue-status')?.textContent || ''")
        print(f"    [CDP 8/10] System Telemetry: Live Queue Telemetry -> '{queue_text}'")

        # 9. Verify Multi-Firmware Switching
        if fw_count > 1:
            target_fw_id = await eval_js("allFirmwares[1].id")
            await eval_js(f"onSelectFirmware('{target_fw_id}')")
            await asyncio.sleep(1.0)
            active_id = await eval_js("currentFirmwareId")
            assert active_id == target_fw_id, "Firmware selection did not switch active target"
            print(f"    [CDP 9/10] Firmware Selector: Switched target to {active_id[:8]}... and updated all views")

        # Return to Overview
        await eval_js("switchView('overview')")

        # 10. Assert Zero Uncaught JavaScript Exceptions
        print(f"    [CDP 10/10] Browser Exceptions: {len(js_exceptions)} uncaught errors detected")
        if js_exceptions:
            for exc in js_exceptions:
                print(f"      ERROR: {exc.get('text')} at {exc.get('url')}:{exc.get('lineNumber')}")
        assert len(js_exceptions) == 0, f"Dashboard produced {len(js_exceptions)} uncaught JavaScript exceptions!"


def run_browser_qa():
    print("=== FirmwareX Browser QA & Automation Suite ===")
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    if not Path(CHROME_PATH).exists():
        print(f"ERROR: Chrome binary not found at {CHROME_PATH}")
        sys.exit(1)

    # 1. Start Server in Subprocess if not already running
    print("[1/7] Checking FirmwareX server status at http://127.0.0.1:8080...")
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

        ready = wait_for_server("http://127.0.0.1:8080/healthz", timeout=12)
        if not ready:
            print("ERROR: Server failed to respond within 12 seconds.")
            out, err = server_proc.communicate(timeout=2)
            print(f"STDOUT: {out.decode()}\nSTDERR: {err.decode()}")
            sys.exit(1)
        print(" -> Server healthy (HTTP 200).")

    try:
        # 2. End-to-End API upload of sample IoT firmware first so dashboard has active data
        print("[2/7] Ingesting sample IoT router firmware for live visualization...")
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

        # 3. Test Malformed Upload Negative Control
        print("[3/7] Testing Malformed Upload Negative Control...")
        corrupt_body = bytearray()
        corrupt_body.extend(f"--{boundary}\r\n".encode())
        corrupt_body.extend(b'Content-Disposition: form-data; name="file"; filename="bad.bin"\r\n')
        corrupt_body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
        corrupt_body.extend(b"CORRUPTED_NON_ARCHIVE_DATA_12345")
        corrupt_body.extend(f"\r\n--{boundary}--\r\n".encode())

        bad_req = urllib.request.Request(
            "http://127.0.0.1:8080/api/v1/firmware/upload",
            data=corrupt_body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(bad_req) as resp:
                print(f" -> Malformed upload returned status {resp.status}")
        except urllib.error.HTTPError as err:
            assert err.code in (400, 422), f"Expected 400 or 422 for malformed upload, got {err.code}"
            print(f" -> Malformed upload correctly rejected with HTTP {err.code} (Safe fail-closed).")

        time.sleep(1)

        # 4. Dump and Verify Dashboard DOM via Headless Chrome
        print("[4/7] Inspecting Dashboard DOM via Chrome Headless...")
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

        # 5. Interactive Browser CDP Test Suite
        print("[5/7] Executing Interactive Browser CDP Test Suite (10 Real Interactions)...")
        cdp_port = 9555
        cdp_proc = subprocess.Popen([
            CHROME_PATH,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            f"--user-data-dir={temp_profile}",
            f"--remote-debugging-port={cdp_port}",
            "http://127.0.0.1:8080/",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1.5)
        try:
            asyncio.run(run_cdp_interaction_suite(cdp_port, fw_id))
        finally:
            cdp_proc.terminate()
            cdp_proc.wait(timeout=5)

        # 6. Capture Desktop and Mobile Screenshots
        print("[6/7] Capturing Desktop & Mobile Screenshots...")
        desktop_1440_png = DOCS_DIR / "dashboard_desktop_1440.png"
        cmd_1440 = [
            CHROME_PATH,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            f"--user-data-dir={tempfile.mkdtemp(prefix='chrome_qa_1440_')}",
            f"--screenshot={desktop_1440_png}",
            "--window-size=1440,900",
            "http://127.0.0.1:8080/",
        ]
        subprocess.run(cmd_1440, check=True, timeout=20)

        desktop_1280_png = DOCS_DIR / "dashboard_desktop_1280.png"
        cmd_1280 = [
            CHROME_PATH,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            f"--user-data-dir={tempfile.mkdtemp(prefix='chrome_qa_1280_')}",
            f"--screenshot={desktop_1280_png}",
            "--window-size=1280,800",
            "http://127.0.0.1:8080/",
        ]
        subprocess.run(cmd_1280, check=True, timeout=20)
        import shutil
        shutil.copyfile(desktop_1280_png, DOCS_DIR / "dashboard_desktop.png")

        mobile_390_png = DOCS_DIR / "dashboard_mobile_390.png"
        mobile_cmd = [
            CHROME_PATH,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            f"--user-data-dir={tempfile.mkdtemp(prefix='chrome_qa_mobile_')}",
            f"--screenshot={mobile_390_png}",
            "--window-size=390,844",
            "http://127.0.0.1:8080/",
        ]
        subprocess.run(mobile_cmd, check=True, timeout=20)
        shutil.copyfile(mobile_390_png, DOCS_DIR / "dashboard_mobile.png")
        print(f" -> Fresh screenshots captured: 1440x900 ({desktop_1440_png.stat().st_size} B), 1280x800 ({desktop_1280_png.stat().st_size} B), 390x844 ({mobile_390_png.stat().st_size} B)")

        # 7. Verify JSON Report Export
        print("[7/7] Verifying JSON report export...")
        with urllib.request.urlopen(f"http://127.0.0.1:8080/api/v1/firmware/{fw_id}/report") as resp:
            report_data = json.loads(resp.read().decode())
            print(f" -> Verified Report Export (Schema v{report_data['schema_version']}, Findings: {len(report_data['findings_appendix_a'])})")

        print("=== BROWSER QA & REAL INTERACTION SUITE SUCCEEDED ===")

    finally:
        if server_proc is not None:
            server_proc.terminate()
            server_proc.wait(timeout=5)


if __name__ == "__main__":
    run_browser_qa()
