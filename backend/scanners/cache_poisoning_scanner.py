"""
cache_poisoning_scanner.py — Web Cache Poisoning Scanner
=========================================================
Tests whether unkeyed HTTP headers (X-Forwarded-Host, X-Original-URL,
X-Rewrite-URL) are reflected in the response, enabling CDN/reverse-proxy
cache poisoning.
"""
import urllib.parse, time
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector
from utils.callback import build_callback_url

UNKEYED_HEADERS = [
    ("X-Forwarded-Host",   "wss-cache-poison-test.evil"),
    ("X-Original-URL",     "/wss-cache-poison-probe"),
    ("X-Rewrite-URL",      "/wss-cache-poison-probe"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Forwarded-Proto",  "nothttps"),
    ("X-Host",             "wss-cache-poison-test.evil"),
]


class CachePoisoningScanner(BaseScanner):
    SCANNER_NAME = "Web Cache Poisoning Scanner"
    _SCANNER_KEY = "cache_poisoning"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._timing = TimingAnomalyDetector()

    def run(self) -> list:
        self.log("INFO", f"[CachePoison] Testing cache poisoning via unkeyed headers on {self.target}...")

        cwe = ["CWE-644"]
        owasp = "A04:2021 – Insecure Design"
        self._cwe = cwe
        self._owasp = owasp

        for header_name, header_val in UNKEYED_HEADERS:
            self._test_unkeyed_header(header_name, header_val)

        self._test_callback_header()
        self._test_cache_key_confusion()
        self._test_web_cache_deception()

        if not self.vulns:
            self.log("SUCCESS", "[CachePoison] No cache poisoning vectors detected.")
        return self.vulns

    def _test_unkeyed_header(self, header_name, header_val):
        body, status, resp_headers = self._make_request(
            self.target,
            headers={"User-Agent": "LarShield/2.0", header_name: header_val},
            return_response_obj=True,
        )

        if body is None:
            self.log("ERROR", f"[CachePoison] Request failed for header {header_name}")
            return

        reflected_in_body = header_val in body
        reflected_in_headers = any(header_val in v for v in resp_headers.values())

        if reflected_in_body or reflected_in_headers:
            location = "response body" if reflected_in_body else "response headers"
            self.add_vuln(
                title=f"Cache Poisoning via Unkeyed Header: {header_name}",
                severity="High",
                category="Cache Poisoning",
                cvss_score=7.4,
                description=f"Injecting `{header_name}: {header_val}` caused the value to be "
                    f"reflected in the {location}. If the CDN/reverse proxy caches this response "
                    f"without keying on `{header_name}`, all subsequent users will receive the "
                    f"poisoned response, enabling XSS or phishing at scale.",
                remediation=f"1. Configure the cache to vary on `{header_name}` or strip it.\n"
                    f"2. The application should not reflect `{header_name}` in output.\n"
                    f"3. Use Cache-Control: private, no-store for sensitive pages.\n"
                    f"4. Test with: `curl -H '{header_name}: evil' {self.target}`",
                evidence=f"Value '{header_val}' reflected in {location}",
                payload=f"{header_name}: {header_val}",
                request_details=f"GET with {header_name}: {header_val}",
                response_details=f"Reflected in {location}",
                confidence="Confirmed",
                cwe_ids=self._cwe,
                owasp_category=self._owasp,
            )
            self.log("WARNING", f"[CachePoison] Reflected {header_name} in {location}!")
        else:
            self.log("SUCCESS", f"[CachePoison] {header_name}: Not reflected")

    def _test_cache_key_confusion(self):
        self.log("INFO", "[CachePoison] Testing cache key confusion...")
        try:
            probe_val = "wss-cache-confusion-probe"
            body, status, resp_headers = self._make_request(
                self.target,
                headers={
                    "User-Agent": "LarShield/2.0",
                    "X-Forwarded-Host": probe_val,
                    "X-Host": probe_val,
                },
                return_response_obj=True,
            )
            if body and probe_val in body:
                self.add_vuln(
                    title="Cache Key Confusion — Multiple Unkeyed Headers",
                    severity="High",
                    category="Cache Poisoning",
                    cvss_score=7.0,
                    description="Multiple unkeyed headers (X-Forwarded-Host and X-Host) were sent together and their value was reflected. An attacker can exploit cache key confusion by injecting different values that get merged into the cached response.",
                    remediation="Normalize or strip all unkeyed headers at the reverse proxy before they reach the application.",
                    evidence=f"Probe value '{probe_val}' reflected in body",
                    payload=f"X-Forwarded-Host: {probe_val}, X-Host: {probe_val}",
                    request_details="GET with multiple conflicting host headers",
                    response_details=f"Reflected probe in body",
                    confidence="High",
                    cwe_ids=self._cwe,
                    owasp_category=self._owasp,
                )
        except Exception as e:
            self.log("ERROR", f"[CachePoison] Cache key confusion test error: {e}")

    def _test_callback_header(self):
        self.log("INFO", "[CachePoison] Testing callback-based cache poisoning...")
        callback_url = build_callback_url("/cache-poison")
        for header_name in ["X-Forwarded-Host", "X-Host", "X-Original-URL"]:
            body, status, resp_headers = self._make_request(
                self.target,
                headers={header_name: callback_url},
                return_response_obj=True,
            )
            if body and callback_url in body:
                self.add_vuln(
                    title=f"Cache Poisoning via Callback URL in {header_name}",
                    severity="Critical",
                    category="Cache Poisoning",
                    cvss_score=8.6,
                    description=f"Injecting a callback URL in `{header_name}` was reflected in the response. "
                        "This confirms the header is unkeyed and can be used for blind cache poisoning "
                        "with out-of-band detection.",
                    remediation=f"Strip or key `{header_name}`. Validate header values at the proxy.",
                    evidence=f"Callback URL '{callback_url}' reflected in body",
                    payload=f"{header_name}: {callback_url}",
                    request_details=f"GET with {header_name}: {callback_url}",
                    response_details="Callback URL reflected in body",
                    confidence="Confirmed",
                    cwe_ids=self._cwe,
                    owasp_category=self._owasp,
                )
                self.log("WARNING", f"[CachePoison] Callback reflected via {header_name}!")

    def _test_web_cache_deception(self):
        self.log("INFO", "[CachePoison] Testing web cache deception...")
        try:
            parsed = urllib.parse.urlparse(self.target)
            deception_path = parsed.path.rstrip("/") + "/nonexistent.css"
            test_url = parsed._replace(path=deception_path).geturl()

            t0 = time.monotonic()
            body, status, resp_headers = self._make_request(
                test_url, return_response_obj=True,
            )
            elapsed = time.monotonic() - t0
            self._timing.record_timing(f"deception_{test_url}", elapsed)

            if body and status == 200 and "text/css" not in str(resp_headers.get("Content-Type", "")):
                cache_ctl = str(resp_headers.get("Cache-Control", ""))
                if "public" in cache_ctl or ("max-age" in cache_ctl and int(resp_headers.get("Content-Length", "0") or "0") > 100):
                    timing_anomaly = self._timing.is_anomalous(elapsed, 2.5)
                    sev = "Critical" if timing_anomaly else "Medium"
                    cvss = 8.0 if timing_anomaly else 5.4
                    self.add_vuln(
                        title="Web Cache Deception — Static Extension Serves Dynamic Content" +
                            (" (Timing Anomaly)" if timing_anomaly else ""),
                        severity=sev,
                        category="Cache Poisoning",
                        cvss_score=cvss,
                        description=f"Appending '.css' to the path returns a 200 response with non-CSS content. "
                            "If the CDN caches this based on extension, an attacker can trick users into "
                            "leaking sensitive data via cached responses.",
                        remediation="Configure the cache to not cache based on file extension alone. "
                            "Use Cache-Control: no-store for sensitive pages. Reject or redirect unknown paths.",
                        evidence=f"GET {test_url} returned {status} with Content-Type: "
                            f"{resp_headers.get('Content-Type', 'N/A')}",
                        payload=deception_path,
                        request_details=f"GET {test_url}",
                        response_details=f"Status: {status}, Content-Type: "
                            f"{resp_headers.get('Content-Type', 'N/A')}",
                        confidence="Medium",
                        cwe_ids=["CWE-444"],
                        owasp_category=self._owasp,
                    )
        except Exception as e:
            self.log("ERROR", f"[CachePoison] Web cache deception test error: {e}")
