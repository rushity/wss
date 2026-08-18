"""
sri_scanner.py — Subresource Integrity (SRI) Scanner
"""
import re, urllib.request
from scanners.base_scanner import BaseScanner

class SriScanner(BaseScanner):
    SCANNER_NAME = "Subresource Integrity (SRI) Scanner"
    _SCANNER_KEY = "sri"
    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[SRI] Checking SRI on external resources at {self.target}...")
        try:
            req = urllib.request.Request(self.target, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=8, context=self.get_ssl_context()) as r:
                html = r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.log("WARNING", f"[SRI] Error: {e}"); return self.vulns

        ext_scripts = re.findall(r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>', html, re.I)
        ext_links = re.findall(r'<link[^>]+href=["\']https?://[^"\']+["\'][^>]*>', html, re.I)
        missing_scripts = [s for s in ext_scripts if "integrity=" not in s.lower()]
        missing_links = [l for l in ext_links if "integrity=" not in l.lower() and "stylesheet" in l.lower()]
        total = len(missing_scripts) + len(missing_links)

        if total > 0:
            examples = (missing_scripts + missing_links)[:3]
            self.add_vuln(title=f"Missing SRI on {total} External Resource(s)",
                severity="Medium", category="Supply Chain Security", cvss_score=5.9,
                description=f"{len(missing_scripts)} script(s) and {len(missing_links)} stylesheet(s) "
                    f"from external CDNs lack `integrity` attributes.\n\nExamples:\n" +
                    "\n".join(f"- `{e[:150]}`" for e in examples),
                remediation="Add integrity and crossorigin attrs:\n"
                    '<script src="..." integrity="sha384-..." crossorigin="anonymous"></script>')
        else:
            self.log("SUCCESS", "[SRI] All external resources have SRI.")
        return self.vulns
