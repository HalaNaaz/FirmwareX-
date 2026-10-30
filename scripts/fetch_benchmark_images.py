import json
import re
import urllib.request

base_url = "https://downloads.openwrt.org/releases/23.05.4/targets/"
req = urllib.request.Request(base_url, headers={"User-Agent": "FirmwareX/1.0"})
with urllib.request.urlopen(req, timeout=10) as resp:
    html = resp.read().decode("utf-8")

subdirs = re.findall(r'href="([^"/]+)/"', html)
print("Found subdirs:", len(subdirs))

found_images = []
for sub in subdirs:
    if sub in ("packages", "kmods", "..", "."):
        continue
    sub_url = f"{base_url}{sub}/"
    try:
        req = urllib.request.Request(sub_url, headers={"User-Agent": "FirmwareX/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            sub_html = resp.read().decode("utf-8")
        profiles = re.findall(r'href="([^"/]+)/"', sub_html)
        for prof in profiles:
            if prof in ("packages", "kmods", "..", "."):
                continue
            sha_url = f"{base_url}{sub}/{prof}/sha256sums"
            try:
                req = urllib.request.Request(sha_url, headers={"User-Agent": "FirmwareX/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    sha_content = resp.read().decode("utf-8")
                for line in sha_content.splitlines():
                    if "rootfs.tar.gz" in line:
                        parts = line.split()
                        sha = parts[0]
                        fname = parts[1].lstrip("*")
                        img_url = f"{base_url}{sub}/{prof}/{fname}"
                        found_images.append({
                            "target": f"{sub}/{prof}",
                            "filename": fname,
                            "sha256": sha,
                            "url": img_url
                        })
                        print(f"[{len(found_images)}] Found: {sub}/{prof} -> {fname}")
                        break
            except Exception:
                pass
            if len(found_images) >= 15:
                break
    except Exception:
        pass
    if len(found_images) >= 15:
        break

print(f"Total found images: {len(found_images)}")

with open("benchmark_candidates.json", "w", encoding="utf-8") as f:
    json.dump(found_images, f, indent=2)

