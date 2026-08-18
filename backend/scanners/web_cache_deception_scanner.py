"""
web_cache_deception_scanner.py — Web Cache Deception Scanner
=============================================================
Distinct from cache poisoning: tricks the cache into storing authenticated
responses by appending fake static extensions to authenticated paths.
"""
import time, urllib.request, urllib.error
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector

# Paths that typically contain authenticated/personal data
AUTH_PATHS = [
    "/account", "/profile", "/dashboard", "/settings",
    "/user", "/me", "/api/me", "/api/user/profile",
    "/account/settings", "/my-account",
]

# Static extensions to append
STATIC_SUFFIXES = [
    "/test.css", "/test.js", "/test.png", "/test.jpg",
    "/test.html", "/test.htm", "/test.txt",
    "/wss-probe.css", "/../test.css", "/test.css?",
    "/test.xml", "/test.pdf", "/test.gif", "/test.svg",
    "/test.ico", "/test.woff", "/test.woff2", "/test.eot",
]

class WebCacheDeceptionScanner(BaseScanner):
    SCANNER_NAME = "Web Cache Deception Scanner"
    _SCANNER_KEY = "web_cache_deception"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._timing = TimingAnomalyDetector()

    def run(self) -> list:
        self.log("INFO", f"[CacheDeception] Testing web cache deception on {self.target}...")
        base = self.target.rstrip("/")

        cwe = ["CWE-444"]
        owasp = "A04:2021 – Insecure Design"

        for auth_path in AUTH_PATHS:
            clean_body, clean_status = self._probe(base + auth_path)
            if clean_status not in (200, 302):
                continue

            for suffix in STATIC_SUFFIXES:
                deception_url = base + auth_path + suffix
                t0 = time.monotonic()
                dec_body, dec_status = self._probe(deception_url)
                elapsed = time.monotonic() - t0

                if dec_status == 200 and dec_body and len(dec_body) > 100:
                    self._timing.record_timing(deception_url, elapsed)
                    cache_headers = self._get_cache_headers(deception_url)
                    cached = any(v in cache_headers.get("cache-control", "").lower()
                                 for v in ["public", "max-age", "s-maxage"])
                    cached = cached or "hit" in cache_headers.get("x-cache", "").lower()
                    cached = cached or "HIT" in cache_headers.get("cf-cache-status", "")
                    timing_anomaly = self._timing.test_payload(f"deception_{deception_url}", elapsed, z_threshold=2.5)

                    sev = "Critical" if cached else "High" if timing_anomaly else "Medium"
                    cvss = 9.1 if cached else 7.0 if timing_anomaly else 5.3

                    self.add_vuln(
                        title=f"Web Cache Deception: `{auth_path + suffix}`" + (" (CACHED!)" if cached else "") +
                            (" (Timing Anomaly)" if timing_anomaly else ""),
                        severity=sev,
                        category="Web Cache Deception",
                        cvss_score=cvss,
                        description=f"Appending `{suffix}` to authenticated path `{auth_path}` "
                            f"returned HTTP 200 with content ({len(dec_body)} bytes). "
                            + ("The response was **actively cached** (cache headers confirm). "
                               "An unauthenticated attacker can now retrieve this response. "
                               if cached else
                               "If a CDN/proxy caches static extensions, this response may be served to unauthenticated users. ") +
                            "\n\nThis is distinct from cache poisoning — the attacker does not inject content, "
                            "they trick the cache into storing YOUR authenticated response.",
                        remediation="1. Cache responses based on URL path AND Content-Type, not just extension.\n"
                            "2. Add `Cache-Control: no-store` on all authenticated endpoints.\n"
                            "3. Return 404 for unknown sub-paths of authenticated routes.\n"
                            "4. Configure CDN to never cache paths under /account/, /profile/, /api/.",
                        cwe_ids=cwe,
                        owasp_category=owasp,
                    )
                    self.log("WARNING", f"[CacheDeception] Potential deception at {deception_url}")
                    break

        # X-Forwarded-Host cache poisoning variant
        for auth_path in AUTH_PATHS:
            for suffix in [".css", ".js", ".png"]:
                deception_url = base + auth_path + suffix
                body, status = self._make_request(
                    deception_url,
                    headers={"X-Forwarded-Host": "evil-cache-poison.com"}
                )
                if status == 200 and body and len(body) > 100 and "evil-cache-poison" in body:
                    self.add_vuln(
                        title="Web Cache Deception + X-Forwarded-Host Cache Poisoning",
                        severity="Critical",
                        category="Web Cache Deception",
                        cvss_score=9.1,
                        description=f"X-Forwarded-Host value reflected via deception URL `{deception_url}`. "
                            "An attacker can combine cache deception with cache poisoning to serve "
                            "attacker-controlled content to victims.",
                        remediation="Strip X-Forwarded-Host at the proxy layer. "
                            "Do not reflect unkeyed headers in cached responses.",
                        evidence=f"X-Forwarded-Host value 'evil-cache-poison' reflected in {deception_url}",
                        payload="X-Forwarded-Host: evil-cache-poison.com",
                        cwe_ids=["CWE-444", "CWE-644"],
                        owasp_category=owasp,
                    )
                    break

        if not self.vulns:
            self.log("SUCCESS", "[CacheDeception] No cache deception vulnerabilities detected.")
        return self.vulns

    def _probe(self, url):
        try:
            req = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=6, context=self.get_ssl_context()) as r:
                return r.read().decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e:
            return "", e.code
        except Exception as e:
            self.log("ERROR", f"[CacheDeception] _probe error: {e}")
            return "", 0

    def _get_cache_headers(self, url):
        try:
            req = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context()) as r:
                return {k.lower(): v for k, v in r.headers.items()}
        except Exception as e:
            self.log("ERROR", f"[CacheDeception] _get_cache_headers error: {e}")
            return {}
