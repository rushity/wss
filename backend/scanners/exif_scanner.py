"""
exif_scanner.py — EXIF Metadata Leak Scanner
"""
import re, struct, urllib.request
from scanners.base_scanner import BaseScanner

class ExifScanner(BaseScanner):
    SCANNER_NAME = "EXIF Metadata Leak Scanner"
    _SCANNER_KEY = "exif"
    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[EXIF] Scanning images for EXIF metadata leaks on {self.target}...")
        try:
            req = urllib.request.Request(self.target, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=8, context=self.get_ssl_context()) as r:
                html = r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.log("WARNING", f"[EXIF] Error: {e}"); return self.vulns

        imgs = re.findall(r'(?:src|href)=["\']([^"\']+\.(?:jpg|jpeg|png|tiff|webp))["\']', html, re.I)
        leaky = []
        for img_src in set(imgs[:10]):
            url = self._resolve(img_src)
            if self._has_exif(url):
                leaky.append(url)

        if leaky:
            self.add_vuln(
                title=f"EXIF Metadata Exposed in {len(leaky)} Image(s)",
                severity="Low", category="Information Disclosure", cvss_score=3.5,
                description=f"Images with EXIF data (GPS, camera model, software):\n\n" +
                    "\n".join(f"- `{u}`" for u in leaky[:5]) +
                    "\n\nEXIF data can expose physical locations, device info, and timestamps.",
                remediation="Strip EXIF metadata before serving images. Use tools like "
                    "`exiftool -all= image.jpg` or server-side libraries (Pillow, Sharp).")
        else:
            self.log("SUCCESS", "[EXIF] No EXIF metadata leaks detected.")
        return self.vulns

    def _has_exif(self, url):
        try:
            req = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context()) as r:
                header = r.read(12)
                # JPEG with EXIF: starts with FF D8 FF E1
                if header[:4] == b'\xff\xd8\xff\xe1':
                    return True
                # TIFF header (also used in EXIF)
                if header[:2] in (b'II', b'MM') and header[2:4] in (b'\x2a\x00', b'\x00\x2a'):
                    return True
        except Exception as e:
            self.log("ERROR", f"[EXIF] _has_exif error: {e}")
        return False

    def _resolve(self, src):
        if src.startswith("//"): return f"https:{src}"
        if src.startswith("/"):
            from urllib.parse import urlparse; p = urlparse(self.target)
            return f"{p.scheme}://{p.netloc}{src}"
        if not src.startswith("http"): return f"{self.target.rstrip('/')}/{src}"
        return src
