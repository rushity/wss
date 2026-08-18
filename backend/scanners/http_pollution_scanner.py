"""
http_pollution_scanner.py — HTTP Parameter Pollution Scanner
"""
import urllib.request, urllib.error, urllib.parse
from scanners.base_scanner import BaseScanner

class HttpPollutionScanner(BaseScanner):
    SCANNER_NAME = "HTTP Parameter Pollution Scanner"
    _SCANNER_KEY = "http_pollution"
    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[HPP] Testing HTTP Parameter Pollution on {self.target}...")
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        if not qs:
            self.log("INFO", "[HPP] No query parameters to test.")
            return self.vulns

        baseline = self._fetch(self.target) or ""
        for k, v in qs:
            # Duplicate the parameter with a different value
            dup_qs = urllib.parse.urlencode(qs) + f"&{k}=HPP_PROBE"
            test_url = parsed._replace(query=dup_qs).geturl()
            resp = self._fetch(test_url)
            if resp and "HPP_PROBE" in resp and "HPP_PROBE" not in baseline:
                self.add_vuln(
                    title=f"HTTP Parameter Pollution in `{k}`",
                    severity="Medium", category="HTTP Parameter Pollution", cvss_score=5.3,
                    description=f"Duplicating parameter `{k}` with value `HPP_PROBE` caused "
                        f"the injected value to appear in the response. The server uses the "
                        f"last/first occurrence, which can bypass WAFs and input validation.",
                    remediation="Explicitly handle duplicate parameters. Use the first occurrence "
                        "only and reject requests with duplicate security-sensitive params.")
                self.log("WARNING", f"[HPP] Pollution confirmed in `{k}`!")
                return self.vulns
        self.log("SUCCESS", "[HPP] No HTTP Parameter Pollution detected.")
        return self.vulns

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context()) as r:
                return r.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e: return e.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.log("ERROR", f"[HPP] _fetch error: {e}")
            return self.vulns