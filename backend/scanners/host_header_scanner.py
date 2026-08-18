"""
host_header_scanner.py — Host Header Injection Scanner
=======================================================
Tests for Host and X-Forwarded-Host header injection, checking if
the injected arbitrary domain is reflected in redirects (Location)
or internal link generation (password reset poisoning).
"""
import urllib.parse, time
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector
from utils.callback import build_callback_url


class HostHeaderScanner(BaseScanner):
    SCANNER_NAME = "Host Header Injection Scanner"
    _SCANNER_KEY = "host_header"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._timing = TimingAnomalyDetector()

    def run(self) -> list:
        self.log("INFO", f"[HostHeader] Testing Host header injection on {self.target}...")

        self._cwe = ["CWE-644"]
        self._owasp = "A04:2021 – Insecure Design"

        self._test_host_override()
        self._test_x_forwarded_host()
        self._test_x_host()
        self._test_x_original_host()
        self._test_port_confusion()
        self._test_absolute_url_in_host()
        self._test_callback_injection()
        self._test_timing_anomaly()

        if not self.vulns:
            self.log("SUCCESS", "[HostHeader] No Host header reflection detected.")
        return self.vulns

    def _test_host_override(self):
        payload = "evil-host-injection.com"
        body, status, resp_headers = self._make_request(
            self.target,
            headers={"User-Agent": "LarShield/2.0", "Host": payload},
            return_response_obj=True,
        )
        if body is None:
            self.log("ERROR", "[HostHeader] Host override request failed")
            return
        self._check_reflection(
            resp_headers.get("Location", "") if resp_headers else "",
            body, payload, "Host"
        )

    def _test_x_forwarded_host(self):
        payload = "evil-xfh-injection.com"
        body, status, resp_headers = self._make_request(
            self.target,
            headers={"User-Agent": "LarShield/2.0", "X-Forwarded-Host": payload},
            return_response_obj=True,
        )
        if body is None:
            self.log("ERROR", "[HostHeader] X-Forwarded-Host request failed")
            return
        self._check_reflection(
            resp_headers.get("Location", "") if resp_headers else "",
            body, payload, "X-Forwarded-Host"
        )

    def _test_x_host(self):
        payload = "evil-xhost-injection.com"
        body, status, resp_headers = self._make_request(
            self.target,
            headers={"X-Host": payload},
            return_response_obj=True,
        )
        if body and resp_headers:
            self._check_reflection(
                resp_headers.get("Location", "") if resp_headers else "",
                body, payload, "X-Host"
            )

    def _test_x_original_host(self):
        payload = "evil-xoriginal-injection.com"
        body, status, resp_headers = self._make_request(
            self.target,
            headers={"X-Original-Host": payload},
            return_response_obj=True,
        )
        if body and resp_headers:
            self._check_reflection(
                resp_headers.get("Location", "") if resp_headers else "",
                body, payload, "X-Original-Host"
            )

    def _test_port_confusion(self):
        payload = "localhost:8080"
        body, status, resp_headers = self._make_request(
            self.target,
            headers={"User-Agent": "LarShield/2.0", "Host": payload},
            return_response_obj=True,
        )
        if body is None:
            self.log("ERROR", "[HostHeader] Port confusion request failed")
            return
        if resp_headers:
            location = resp_headers.get("Location", "")
            if payload in location or "localhost" in location:
                self.add_vuln(
                    title="Host Header Injection — Port Confusion",
                    severity="Medium",
                    category="Host Header Injection",
                    cvss_score=6.1,
                    description=f"Setting Host header to '{payload}' caused the server to include "
                        "this host:port in the Location header. This can be used for open redirect "
                        "or SSRF attacks against internal services.",
                    remediation="Validate the Host header against an allowlist of valid domains and ports.",
                    evidence=f"Location header: {location}",
                    payload=f"Host: {payload}",
                    request_details=f"GET with Host: {payload}",
                    response_details=f"Location: {location}",
                    confidence="High",
                    cwe_ids=self._cwe,
                    owasp_category=self._owasp,
                )
                self.log("WARNING", f"[HostHeader] Port confusion via Host: {payload}")

    def _test_absolute_url_in_host(self):
        payload = "https://evil-absolute.com"
        body, status, resp_headers = self._make_request(
            self.target,
            headers={"User-Agent": "LarShield/2.0", "Host": payload},
            return_response_obj=True,
        )
        if body is None:
            self.log("ERROR", "[HostHeader] Absolute URL in Host test failed")
            return
        if resp_headers:
            location = resp_headers.get("Location", "")
            if payload in location or payload in body:
                ref = "Location header" if payload in location else "response body"
                self.add_vuln(
                    title="Host Header Injection — Absolute URL in Host",
                    severity="High",
                    category="Host Header Injection",
                    cvss_score=7.4,
                    description=f"Injecting an absolute URL '{payload}' in the Host header was "
                        f"reflected in the {ref}. This enables open redirect and phishing attacks.",
                    remediation="Reject non-hostname values (absolute URLs) in the Host header. "
                        "Only allow valid domain names.",
                    evidence=f"'{payload}' reflected in {ref}",
                    payload=f"Host: {payload}",
                    request_details=f"GET with Host: {payload}",
                    response_details=f"Reflected in {ref}",
                    confidence="Confirmed",
                    cwe_ids=self._cwe,
                    owasp_category=self._owasp,
                )
                self.log("WARNING", f"[HostHeader] Absolute URL reflected in {ref}")

    def _test_callback_injection(self):
        callback_url = build_callback_url("/host-header")
        for hdr in ["Host", "X-Forwarded-Host", "X-Host", "X-Original-Host"]:
            body, status, resp_headers = self._make_request(
                self.target,
                headers={hdr: callback_url},
                return_response_obj=True,
            )
            if body and callback_url in body:
                self.add_vuln(
                    title=f"Blind Host Header Injection via Callback URL in {hdr}",
                    severity="High",
                    category="Host Header Injection",
                    cvss_score=8.2,
                    description=f"Injecting a callback URL in the `{hdr}` header reflects the value "
                        "in the server response. This enables blind host header injection with out-of-band "
                        "detection and can be used for password reset poisoning or SSRF.",
                    remediation="Validate and allowlist the Host header. "
                        "Do not reflect unvalidated header values in responses.",
                    evidence=f"Callback URL '{callback_url}' reflected in response body",
                    payload=f"{hdr}: {callback_url}",
                    request_details=f"GET with {hdr}: {callback_url}",
                    response_details="Callback URL reflected in body",
                    confidence="Confirmed",
                    cwe_ids=self._cwe,
                    owasp_category=self._owasp,
                )
                self.log("WARNING", f"[HostHeader] Callback injection via {hdr}!")

    def _test_timing_anomaly(self):
        self.log("INFO", "[HostHeader] Testing timing anomalies for host overrides...")
        for hdr in ["Host", "X-Forwarded-Host", "X-Host", "X-Original-Host"]:
            for _ in range(3):
                body, status, elapsed = self._make_timed_request(
                    self.target,
                    headers={hdr: "timing-test.example.com"},
                )
                self._timing.record_timing(f"baseline_{hdr}", elapsed)
            t0 = time.monotonic()
            body, status = self._make_request(
                self.target,
                headers={hdr: "evil-timing-test.example.com"},
            )
            elapsed = time.monotonic() - t0
            if self._timing.test_payload(f"anomaly_{hdr}", elapsed, "evil-timing-test.example.com", 3.0):
                self.log("WARNING", f"[HostHeader] Timing anomaly detected for {hdr} override")

    def _check_reflection(self, location: str, body: str, payload: str, header_name: str):
        cwe = self._cwe
        owasp = self._owasp
        if payload in location:
            self.add_vuln(
                title=f"Host Header Injection (Redirect) via {header_name}",
                severity="Medium",
                category="Host Header Injection",
                cvss_score=6.1,
                description=f"Injecting `{header_name}: {payload}` causes the server to redirect "
                    f"users to the injected domain (Location: {location}). This can be used for phishing "
                    f"and open redirects.",
                remediation="Ensure the application uses a hardcoded domain or validates the Host header "
                    "against an allowlist. Do not trust the Host or X-Forwarded-Host headers for redirects.",
                evidence=f"Location header: {location}",
                payload=f"{header_name}: {payload}",
                request_details=f"GET with {header_name}: {payload}",
                response_details=f"Location: {location}",
                confidence="Confirmed",
                cwe_ids=cwe,
                owasp_category=owasp,
            )
            self.log("WARNING", f"[HostHeader] Redirect reflection found via {header_name}")

        elif f'"{payload}' in body or f"'{payload}" in body or f"//{payload}" in body:
            self.add_vuln(
                title=f"Host Header Reflection (Body) via {header_name}",
                severity="High",
                category="Host Header Injection",
                cvss_score=7.4,
                description=f"Injecting `{header_name}: {payload}` reflects the attacker-controlled "
                    f"domain in the HTML body (e.g., in links, script tags, or meta tags). This often "
                    f"leads to Password Reset Poisoning or Web Cache Poisoning.",
                remediation="Configure the web application to use a statically defined site URL for link "
                    "generation instead of dynamically extracting it from the request headers.",
                evidence=f"Payload '{payload}' found in response body",
                payload=f"{header_name}: {payload}",
                request_details=f"GET with {header_name}: {payload}",
                response_details="Payload reflected in HTML body",
                confidence="Confirmed",
                cwe_ids=cwe,
                owasp_category=owasp,
            )
            self.log("WARNING", f"[HostHeader] Body reflection found via {header_name}")
        else:
            self.log("SUCCESS", f"[HostHeader] {header_name}: No reflection detected")
