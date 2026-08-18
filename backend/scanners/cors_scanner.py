"""
cors_scanner.py — Tests for CORS (Cross-Origin Resource Sharing) misconfigurations.
No external dependencies required.
"""
import urllib.request
import urllib.error
import urllib.parse
from scanners.base_scanner import BaseScanner
from utils.callback import build_callback_url

TEST_ORIGINS = [
    "https://evil.attacker.com",
    "https://malicious-site.net",
    "null",
]

CALLBACK_ORIGIN = build_callback_url("/cors").replace("https://", "https://callback.").replace("http://", "http://callback.")


class CorsScanner(BaseScanner):
    SCANNER_NAME = "CORS Misconfiguration Scanner"
    _SCANNER_KEY = "cors"

    def _make_ctx(self):
        return self.get_ssl_context()

    def run(self):
        self.log("INFO", f"[CORS] Testing Cross-Origin Resource Sharing policy on {self.target}...")

        for origin in TEST_ORIGINS:
            self._test_origin(origin)

        self._test_origin(CALLBACK_ORIGIN)
        self._test_subdomain_trust()
        self._test_preflight()
        self._test_preflight_credentials()
        self.log("INFO", f"[CORS] CORS analysis complete. {len(self.vulns)} issue(s) found.")
        return self.vulns

    def _test_origin(self, origin):
        try:
            headers = {
                "User-Agent": "LarShield/2.0",
                "Origin": origin,
            }
            if self.auth_headers:
                headers.update(self.auth_headers)

            req = urllib.request.Request(
                self.target,
                headers=headers,
            )
            with urllib.request.urlopen(req, timeout=8, context=self._make_ctx()) as resp:
                headers = {k.lower(): v for k, v in resp.getheaders()}
                acao = headers.get("access-control-allow-origin", "")
                acac = headers.get("access-control-allow-credentials", "").lower()

                if acao == "*":
                    self.log("WARNING", f"[CORS] Wildcard ACAO header: Access-Control-Allow-Origin: *")
                    if acac == "true":
                        self.log("CRITICAL", "[CORS] CRITICAL: Wildcard CORS + credentials=true!")
                        self.add_vuln(
                            title="Critical CORS: Wildcard Origin with Credentials Allowed",
                            severity="Critical", category="CORS", cvss_score=9.8,
                            description="The server responds with Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true. This combination is exploitable — any malicious website can make authenticated cross-origin requests on behalf of logged-in users, enabling account takeover and data theft.",
                            remediation="Never combine wildcard ACAO with credentials. Use explicit allowlisted origins:\n  Access-Control-Allow-Origin: https://yourdomain.com\n  Access-Control-Allow-Credentials: true",
                            evidence=f"Response headers: Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                            payload=f"Origin: {origin}",
                            request_details="GET with Origin header",
                            response_details=f"ACAO: *, ACAC: true",
                            confidence="Confirmed",
                            cwe_ids=["CWE-942"],
                            owasp_category="A01:2021 – Broken Access Control",
                        )
                    else:
                        self.add_vuln(
                            title="Overly Permissive CORS Policy (Wildcard Origin)",
                            severity="Medium", category="CORS", cvss_score=5.4,
                            description="The server allows cross-origin requests from any domain (Access-Control-Allow-Origin: *). This may expose public APIs to abuse from malicious websites.",
                            remediation="Restrict CORS to specific trusted origins:\n  Access-Control-Allow-Origin: https://yourfrontenddomain.com\nUse environment-based origin allowlists.",
                            evidence=f"Response header: Access-Control-Allow-Origin: *",
                            payload=f"Origin: {origin}",
                            request_details="GET with Origin header",
                            response_details=f"ACAO: *",
                            confidence="Confirmed",
                            cwe_ids=["CWE-942"],
                            owasp_category="A01:2021 – Broken Access Control",
                        )

                elif acao == origin and origin != "null":
                    self.log("WARNING", f"[CORS] Origin reflected back: {origin} -> ACAO: {acao}")
                    if acac == "true":
                        self.log("CRITICAL", f"[CORS] Arbitrary origin reflected with credentials=true!")
                        self.add_vuln(
                            title="CORS: Arbitrary Origin Reflected with Credentials",
                            severity="Critical", category="CORS", cvss_score=9.1,
                            description=f"The server reflected the attacker-controlled origin '{origin}' in the ACAO header AND allows credentials. This enables cross-origin authenticated requests from any malicious website — a classic CORS-based account takeover vector.",
                            remediation="Implement an explicit origin allowlist. Never reflect arbitrary origins:\n  allowed = ['https://app.yourdomain.com']\n  if request.headers.get('Origin') in allowed:\n      response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']",
                            evidence=f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac}",
                            payload=f"Origin: {origin}",
                            request_details="GET with Origin header",
                            response_details=f"ACAO: {acao}, ACAC: {acac}",
                            confidence="Confirmed",
                            cwe_ids=["CWE-942"],
                            owasp_category="A01:2021 – Broken Access Control",
                        )
                    else:
                        self.add_vuln(
                            title="CORS: Arbitrary Origin Reflected Without Credentials",
                            severity="Medium", category="CORS", cvss_score=5.4,
                            description=f"The server reflected the arbitrary origin '{origin}'. While credentials are not allowed, this still permits cross-origin data theft of non-credentialed responses.",
                            remediation="Use a static allowlist of trusted origins rather than reflecting the request Origin header.",
                            evidence=f"Origin: {origin} -> ACAO: {acao}",
                            payload=f"Origin: {origin}",
                            request_details="GET with Origin header",
                            response_details=f"ACAO: {acao}",
                            confidence="Confirmed",
                            cwe_ids=["CWE-942"],
                            owasp_category="A01:2021 – Broken Access Control",
                        )

                elif origin == "null" and acao == "null":
                    self.log("WARNING", "[CORS] null origin accepted! Sandboxed iframes can exploit this.")
                    self.add_vuln(
                        title="CORS: Null Origin Accepted",
                        severity="Medium", category="CORS", cvss_score=6.1,
                        description="The server accepts 'null' as a valid CORS origin. Sandboxed iframes or locally opened HTML files send Origin: null, which attackers can exploit to bypass CORS restrictions.",
                        remediation="Remove 'null' from any CORS origin allowlist. Only accept explicit https:// origins.",
                        evidence="Origin: null -> ACAO: null",
                        payload="Origin: null",
                        request_details="GET with Origin: null",
                        response_details="ACAO: null",
                        confidence="Confirmed",
                        cwe_ids=["CWE-942"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )
                else:
                    self.log("SUCCESS", f"[CORS] Origin '{origin}': Correctly rejected")

        except urllib.error.HTTPError as e:
            acao = e.headers.get("Access-Control-Allow-Origin", "")
            if acao:
                self.log("INFO", f"[CORS] HTTP {e.code} but ACAO header present: {acao}")
        except Exception as e:
            self.log("ERROR", f"[CORS] Request to {self.target} with origin '{origin}': {e}")

    def _test_subdomain_trust(self):
        try:
            parsed = urllib.parse.urlparse(self.target)
            domain = parsed.netloc
            sub_origin = f"{parsed.scheme}://evil.{domain}"
            headers = {
                "User-Agent": "LarShield/2.0",
                "Origin": sub_origin,
            }
            if self.auth_headers:
                headers.update(self.auth_headers)

            req = urllib.request.Request(
                self.target,
                headers=headers,
            )
            with urllib.request.urlopen(req, timeout=8, context=self._make_ctx()) as resp:
                headers = {k.lower(): v for k, v in resp.getheaders()}
                acao = headers.get("access-control-allow-origin", "")
                acac = headers.get("access-control-allow-credentials", "").lower()

                if acao == sub_origin:
                    self.log("WARNING", f"[CORS] Subdomain trust detected: {sub_origin} is allowed!")
                    self.add_vuln(
                        title="CORS: Subdomain Trust - Evil Subdomain Allowed",
                        severity="High", category="CORS", cvss_score=7.0,
                        description=f"The server trusts subdomains of its own origin. If any subdomain is compromised (e.g., via XSS or takeover), an attacker can make authenticated CORS requests.",
                        remediation="Explicitly list only the exact subdomains that need CORS access, or use a dedicated API domain.",
                        evidence=f"Origin: {sub_origin} -> ACAO: {acao}",
                        payload=f"Origin: {sub_origin}",
                        request_details="GET with subdomain Origin header",
                        response_details=f"ACAO: {acao}, ACAC: {acac}",
                        confidence="Confirmed",
                        cwe_ids=["CWE-942"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )
                else:
                    self.log("SUCCESS", f"[CORS] Subdomain '{sub_origin}': Correctly rejected")
        except Exception as e:
            self.log("ERROR", f"[CORS] Subdomain trust test error: {e}")

    def _test_preflight(self):
        try:
            req = urllib.request.Request(
                self.target,
                method="OPTIONS",
                headers={
                    "User-Agent": "LarShield/2.0",
                    "Origin": "https://evil.attacker.com",
                    "Access-Control-Request-Method": "DELETE",
                    "Access-Control-Request-Headers": "Authorization",
                },
            )
            with urllib.request.urlopen(req, timeout=8, context=self._make_ctx()) as resp:
                headers = {k.lower(): v for k, v in resp.getheaders()}
                acam = headers.get("access-control-allow-methods", "")
                acah = headers.get("access-control-allow-headers", "")
                acao = headers.get("access-control-allow-origin", "")

                if acao == "https://evil.attacker.com":
                    self.log("WARNING", "[CORS] Preflight reflects arbitrary origin!")
                    self.add_vuln(
                        title="CORS Preflight Origin Reflection",
                        severity="Medium", category="CORS", cvss_score=5.4,
                        description="The OPTIONS preflight response reflects the Origin header in Access-Control-Allow-Origin. This indicates a permissive CORS policy that trusts arbitrary origins.",
                        remediation="Do not reflect the Origin header in preflight responses. Use explicit allowlisted origins.",
                        evidence=f"Origin: https://evil.attacker.com -> ACAO: {acao}",
                        payload="Origin: https://evil.attacker.com",
                        request_details="OPTIONS with Origin: https://evil.attacker.com",
                        response_details=f"ACAO: {acao}, ACAM: {acam}",
                        confidence="Confirmed",
                        cwe_ids=["CWE-942"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )

                if "DELETE" in acam.upper() or "PUT" in acam.upper():
                    self.log("WARNING", f"[CORS] Preflight allows dangerous methods: {acam}")
                    self.add_vuln(
                        title="CORS Preflight Allows Dangerous HTTP Methods",
                        severity="Medium", category="CORS", cvss_score=5.4,
                        description=f"The CORS preflight response allows dangerous HTTP methods from cross-origin requests: {acam}. Combined with a weak origin policy, this enables destructive cross-origin operations.",
                        remediation="Restrict ACAM to only the methods your API actually requires:\n  Access-Control-Allow-Methods: GET, POST\nNever include DELETE or PUT unless explicitly required cross-origin.",
                        evidence=f"ACAM: {acam}",
                        payload="Access-Control-Request-Method: DELETE",
                        request_details="OPTIONS with Access-Control-Request-Method: DELETE",
                        response_details=f"ACAM: {acam}, ACAH: {acah}",
                        confidence="High",
                        cwe_ids=["CWE-942"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )
                else:
                    self.log("SUCCESS", "[CORS] Preflight method policy: Appropriate")

                if acah and "Authorization" in acah:
                    self.log("INFO", "[CORS] Preflight allows Authorization header")
        except Exception as e:
            self.log("ERROR", f"[CORS] Preflight check error: {e}")

    def _test_preflight_credentials(self):
        try:
            req = urllib.request.Request(
                self.target,
                method="OPTIONS",
                headers={
                    "User-Agent": "LarShield/2.0",
                    "Origin": "https://evil.attacker.com",
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization",
                },
            )
            with urllib.request.urlopen(req, timeout=8, context=self._make_ctx()) as resp:
                headers = {k.lower(): v for k, v in resp.getheaders()}
                acac = headers.get("access-control-allow-credentials", "").lower()
                acao = headers.get("access-control-allow-origin", "")

                if acac == "true" and acao == "https://evil.attacker.com":
                    self.log("CRITICAL", "[CORS] Preflight allows credentials with arbitrary origin!")
                    self.add_vuln(
                        title="CORS Preflight Allows Credentials with Arbitrary Origin",
                        severity="Critical", category="CORS", cvss_score=9.1,
                        description="The OPTIONS preflight response allows credentials AND reflects arbitrary origin. This enables authenticated cross-origin requests from any attacker-controlled domain.",
                        remediation="Only allow credentials with specific allowlisted origins. Never reflect arbitrary origins with credentials=true.",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        payload="Origin: https://evil.attacker.com",
                        request_details="OPTIONS with credentials check",
                        response_details=f"ACAO: {acao}, ACAC: {acac}",
                        confidence="Confirmed",
                        cwe_ids=["CWE-942"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )
        except Exception as e:
            self.log("ERROR", f"[CORS] Preflight credentials test error: {e}")
