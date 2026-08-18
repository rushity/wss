"""
http_method_tampering_scanner.py — HTTP Method Tampering Scanner
=================================================================
Tests all HTTP methods (TRACE, PUT, DELETE, PATCH, OPTIONS, CONNECT) on
discovered endpoints. TRACE enables XST, PUT can write files.
Also tests HTTP method override headers.
"""
from scanners.base_scanner import BaseScanner

DANGEROUS_METHODS = {
    "TRACE":   ("High",   "Enables Cross-Site Tracing (XST) — reflects HTTP headers including cookies/auth tokens back to the client. Can be used to bypass HttpOnly cookie protection via JavaScript."),
    "PUT":     ("Critical","HTTP PUT on a web server may allow direct file upload, enabling Remote Code Execution (e.g., uploading a webshell)."),
    "DELETE":  ("High",   "HTTP DELETE allowed. An attacker could delete files or resources if the web server maps it to the filesystem."),
    "CONNECT": ("Medium", "CONNECT method may allow the server to be used as an HTTP proxy for SSRF or network pivoting."),
    "PATCH":   ("Medium", "HTTP PATCH allowed. May allow partial modification of server-side resources."),
    "PROPFIND":("Medium", "WebDAV PROPFIND allowed. May leak file listings and metadata."),
    "MOVE":    ("High",   "WebDAV MOVE allowed. An attacker can rename/move files on the server."),
    "COPY":    ("Medium", "WebDAV COPY allowed. An attacker can copy files on the server."),
    "MKCOL":   ("Medium", "WebDAV MKCOL allowed. An attacker can create directories on the server."),
}

# Curated list of HTTP method override header name variants used in real WAF bypass scenarios.
# Only valid HTTP header name chars (printable ASCII, no control chars) are used.
# Do NOT use waf_evade() here — it generates URL-encoded / control-char variants
# that urllib rejects as invalid header names.
OVERRIDE_HEADERS = [
    # Standard override headers
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    # Case variations (common WAF bypass)
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "X-Http-Method-Override",
    "X-Http-Method",
    # Additional known override header aliases
    "X-Forwarded-Method",
    "X-Original-Method",
    "X-Rewrite-Method",
    "XHTTP-Method",
]


class HttpMethodTamperingScanner(BaseScanner):
    SCANNER_NAME = "HTTP Method Tampering Scanner"
    _SCANNER_KEY = "http_method_tampering"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[HTTPMethod] Testing dangerous HTTP methods on {self.target}...")

        advertised = self._get_options_methods()
        if advertised:
            self.log("INFO", f"[HTTPMethod] OPTIONS Allow header: {advertised}")

        for method, (severity, description) in DANGEROUS_METHODS.items():
            status, headers, body = self._send_method(method, self.target)
            if status and status not in (405, 501, 400, 0):
                cwe = ["CWE-749"]
                owasp = "A05:2021 – Security Misconfiguration"
                if method == "TRACE" and body and "TRACE" in body.upper():
                    self.add_vuln(
                        title="TRACE Method Enabled — Cross-Site Tracing (XST) Risk",
                        severity=severity,
                        category="HTTP Method Tampering",
                        cvss_score=7.4,
                        description=f"The server responded to a TRACE request with HTTP {status} "
                            f"and reflected the request body back. {description}",
                        remediation="Disable TRACE globally: Apache: `TraceEnable Off` | "
                            "Nginx: `map $request_method $block {{ TRACE 1; }} if ($block) {{ return 405; }}`",
                        evidence=f"TRACE request reflected body, status {status}",
                        confidence="Confirmed",
                        cwe_ids=cwe,
                        owasp_category=owasp,
                    )
                elif method == "PUT":
                    self.add_vuln(
                        title="HTTP PUT Method Accepted",
                        severity=severity,
                        category="HTTP Method Tampering",
                        cvss_score=9.1,
                        description=f"Server responded HTTP {status} to a PUT request. {description}",
                        remediation="Disable PUT in web server config unless explicitly required by the API. "
                            "If required, restrict to authenticated endpoints only.",
                        evidence=f"PUT request accepted with status {status}",
                        confidence="Confirmed",
                        cwe_ids=cwe,
                        owasp_category=owasp,
                    )
                elif method == "DELETE":
                    self.add_vuln(
                        title="HTTP DELETE Method Accepted",
                        severity=severity,
                        category="HTTP Method Tampering",
                        cvss_score=7.5,
                        description=f"Server responded HTTP {status} to a DELETE request. {description}",
                        remediation="Restrict DELETE to authenticated, authorized API routes. "
                            "Disable WebDAV if not needed.",
                        evidence=f"DELETE request accepted with status {status}",
                        confidence="Confirmed",
                        cwe_ids=cwe,
                        owasp_category=owasp,
                    )
                elif method == "CONNECT":
                    self.add_vuln(
                        title="HTTP CONNECT Method Accepted",
                        severity=severity,
                        category="HTTP Method Tampering",
                        cvss_score=5.3,
                        description=f"Server responded HTTP {status} to CONNECT. {description}",
                        remediation="Block CONNECT at the web server level unless operating a proxy.",
                        evidence=f"CONNECT request accepted with status {status}",
                        confidence="Confirmed",
                        cwe_ids=cwe,
                        owasp_category=owasp,
                    )
                elif method == "PATCH":
                    self.add_vuln(
                        title="HTTP PATCH Method Accepted",
                        severity=severity,
                        category="HTTP Method Tampering",
                        cvss_score=5.3,
                        description=f"Server responded HTTP {status} to a PATCH request. {description}",
                        remediation="Restrict PATCH to authenticated API routes with proper input validation.",
                        evidence=f"PATCH request accepted with status {status}",
                        confidence="Confirmed",
                        cwe_ids=cwe,
                        owasp_category=owasp,
                    )
                elif method in ("PROPFIND", "MOVE", "COPY", "MKCOL"):
                    self.add_vuln(
                        title=f"HTTP {method} Method Accepted (WebDAV)",
                        severity=severity,
                        category="HTTP Method Tampering",
                        cvss_score=6.5 if method == "MOVE" else 5.3,
                        description=f"Server responded HTTP {status} to {method}. {description}",
                        remediation="Disable WebDAV methods unless explicitly required. "
                            "Restrict to authenticated API routes with proper input validation.",
                        evidence=f"{method} request accepted with status {status}",
                        confidence="Confirmed",
                        cwe_ids=cwe,
                        owasp_category=owasp,
                    )
                self.log("WARNING", f"[HTTPMethod] {method} → HTTP {status}")

        if advertised and any(m in advertised for m in ["TRACE", "PUT", "DELETE"]):
            self.add_vuln(
                title="Dangerous Methods Advertised in OPTIONS Response",
                severity="Medium",
                category="HTTP Method Tampering",
                cvss_score=5.3,
                description=f"OPTIONS Allow header reveals: `{advertised}`. Dangerous methods are publicly advertised.",
                remediation="Filter the Allow header to only expose methods actually required.",
                evidence=f"Allow header: {advertised}",
                confidence="Confirmed",
                cwe_ids=["CWE-749"],
                owasp_category="A05:2021 – Security Misconfiguration",
            )

        self._test_method_override_headers()

        if not self.vulns:
            self.log("SUCCESS", "[HTTPMethod] No dangerous HTTP methods accepted.")
        return self.vulns

    def _get_options_methods(self):
        body, status, headers = self._make_request(
            self.target, method="OPTIONS", return_response_obj=True
        )
        if status == 0:
            return ""
        if isinstance(headers, dict):
            return headers.get("Allow", headers.get("allow", ""))
        return getattr(headers, "get", lambda x, y="": y)("Allow", "")

    def _send_method(self, method, url):
        data = b"WSS-probe" if method in ("PUT", "PATCH") else None
        body, status, headers = self._make_request(
            url, method=method, data=data, return_response_obj=True
        )
        return status, headers if isinstance(headers, dict) else {}, body or ""

    def _test_method_override_headers(self):
        for header_name in OVERRIDE_HEADERS:
            for override_method in ["PUT", "DELETE", "PATCH", "TRACE"]:
                body, status = self._make_request(
                    self.target,
                    method="POST",
                    data=b"WSS-override-test",
                    headers={"Content-Type": "application/x-www-form-urlencoded", header_name: override_method}
                )
                if status and status not in (405, 501, 400, 404, 0):
                    self.add_vuln(
                        title=f"HTTP Method Override via `{header_name}` — {override_method}",
                        severity="Medium",
                        category="HTTP Method Tampering",
                        cvss_score=6.1,
                        description=f"Server accepted `{override_method}` via `{header_name}: {override_method}` header. "
                            f"Response status: {status}. HTTP method override headers can bypass access controls "
                            f"that only check the HTTP method.",
                        remediation="Disable HTTP method override headers at the reverse proxy "
                            "unless explicitly required. Validate the actual HTTP method, not the override header.",
                        evidence=f"{header_name}: {override_method} → HTTP {status}",
                        confidence="High",
                        cwe_ids=["CWE-749"],
                        owasp_category="A05:2021 – Security Misconfiguration",
                    )
