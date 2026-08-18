"""
headers_scanner.py
------------------
Checks HTTP response headers for the presence / correct configuration of
security-critical headers.  Performs a real HTTP request against the target.
"""
from scanners.base_scanner import BaseScanner
from utils.fingerprint_db import match_tech, find_cves

HEADERS_POLICY = {
    "Strict-Transport-Security": (
        "Medium", 6.1,
        "HSTS forces browsers to use HTTPS exclusively, preventing SSL-stripping attacks.",
        "Add to your web server config:\n"
        "  Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
        "  Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
    ),
    "Content-Security-Policy": (
        "High", 7.2,
        "CSP restricts which resources the browser may load, mitigating XSS and data-injection attacks.",
        "Define a strict policy:\n"
        "  add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; "
        "object-src 'none'; base-uri 'self';\" always;",
    ),
    "X-Frame-Options": (
        "Medium", 5.4,
        "X-Frame-Options prevents clickjacking by restricting iframe embedding.",
        "add_header X-Frame-Options \"DENY\" always;\n"
        "(or SAMEORIGIN if you require same-origin iframes)",
    ),
    "X-Content-Type-Options": (
        "Low", 3.7,
        "Prevents MIME-sniffing attacks by instructing browsers not to guess content-type.",
        "add_header X-Content-Type-Options \"nosniff\" always;",
    ),
    "Referrer-Policy": (
        "Low", 3.1,
        "Controls how much referrer information is sent with outgoing requests.",
        "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
    ),
    "Permissions-Policy": (
        "Low", 3.1,
        "Permissions-Policy restricts access to browser APIs (camera, microphone, geolocation).",
        "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;",
    ),
    "X-XSS-Protection": (
        "Low", 3.1,
        "Legacy XSS auditor header (deprecated but still expected by some scanners).",
        "add_header X-XSS-Protection \"1; mode=block\" always;",
    ),
    "Cross-Origin-Opener-Policy": (
        "Medium", 5.3,
        "COOP isolates your document from other cross-origin documents, preventing XS-Leaks attacks.",
        "add_header Cross-Origin-Opener-Policy \"same-origin\" always;\n"
        "  Options: same-origin, same-origin-allow-popups, unsafe-none",
    ),
    "Cross-Origin-Embedder-Policy": (
        "Medium", 5.3,
        "COEP requires documents to be COOP-isolated, enabling powerful features like SharedArrayBuffer.",
        "add_header Cross-Origin-Embedder-Policy \"require-corp\" always;\n"
        "  Options: require-corp, credentialless, unsafe-none",
    ),
    "Cross-Origin-Resource-Policy": (
        "Medium", 5.3,
        "CORP protects your resources from being loaded by other origins, preventing Spectre-style attacks.",
        "add_header Cross-Origin-Resource-Policy \"same-origin\" always;\n"
        "  Options: same-origin, same-site, cross-origin",
    ),
    "Expect-CT": (
        "Medium", 5.5,
        "Expect-CT allows sites to report Certificate Transparency violations and enforce CT compliance.",
        "add_header Expect-CT \"max-age=86400, enforce, report-uri=\"https://your-report-uri\" always;\n"
        "  Note: Being deprecated in favor of Certificate Transparency enforcement",
    ),
}


class HeadersScanner(BaseScanner):
    SCANNER_NAME = "HTTP Security Headers Scanner"
    _SCANNER_KEY = "headers"

    def run(self) -> list[dict]:
        self.log("INFO", "[Headers] Starting HTTP Security Headers audit...")
        headers_found = {}

        body, status, resp_headers = self._make_request(
            self.target,
            headers={"User-Agent": "LarShield/2.0 (Security Audit Bot)"},
            timeout=10,
            return_response_obj=True,
        )
        if status == 0:
            self.log("WARNING", "[Headers] Could not reach target. Header audit skipped.")
            return self.vulns

        headers_found = {k.lower(): v for k, v in resp_headers.items()}
        self.log("SUCCESS", f"[Headers] Connected to target. HTTP {status}. Analysing response headers...")

        for header, (severity, cvss, description, remediation) in HEADERS_POLICY.items():
            if header.lower() in headers_found:
                val = headers_found[header.lower()]
                self.log("SUCCESS", f"[Headers] \u2714 {header}: {val[:80]}")
            else:
                self.log("WARNING", f"[Headers] \u2718 Missing: {header} \u2014 {description[:80]}")
                self.add_vuln(
                    title=f"Missing Security Header: {header}",
                    severity=severity,
                    category="Security Headers",
                    cvss_score=cvss,
                    description=(
                        f"The HTTP response from {self.target} does not include the '{header}' header. "
                        f"{description}"
                    ),
                    remediation=remediation,
                    confidence="High",
                )

        leak_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-php-version", "x-runtime", "x-nginx-version"]
        for lh in leak_headers:
            if lh in headers_found:
                self.log("WARNING", f"[Headers] Information Disclosure: '{lh}': {headers_found[lh]}")
                self.add_vuln(
                    title=f"Server Information Disclosure via '{lh}' Header",
                    severity="Low",
                    category="Security Headers",
                    cvss_score=3.1,
                    description=(
                        f"The response header '{lh}' reveals server technology details: "
                        f"'{headers_found[lh]}'. This aids fingerprinting and targeted attacks."
                    ),
                    remediation=(
                        f"Remove or obfuscate the '{lh}' header in your server configuration.\n"
                        "  Nginx: server_tokens off;\n"
                        "  Apache: ServerTokens Prod; ServerSignature Off"
                    ),
                    confidence="Confirmed",
                )

        self._check_cookie_security(headers_found)

        self._test_cache_poisoning()

        fp_matches = match_tech(body if body else "", headers_found)
        for fp in fp_matches:
            cves = find_cves(fp["name"], fp.get("version", ""))
            if cves:
                cve_ids = [c["cve"] for c in cves]
                self.log("WARNING", f"[Headers] Known CVEs for {fp['name']}: {', '.join(cve_ids)}")
                self.add_vuln(
                    title=f"Known CVEs for Server Technology: {fp['name']}",
                    severity="High", category="Security Headers", cvss_score=max(c["cvss"] for c in cves),
                    description=f"Server technology {fp['name']} has known CVEs: {', '.join(cve_ids)}.",
                    remediation=f"Upgrade {fp['name']} to the latest version.",
                    evidence=f"CVEs: {', '.join(cve_ids)}",
                    confidence="Confirmed",
                    cve_ids=cve_ids,
                )

        self.log("INFO", f"[Headers] Header audit complete. {len(self.vulns)} issue(s) found.")
        return self.vulns

    def _check_cookie_security(self, headers_found):
        if "set-cookie" not in headers_found:
            return

        cookies = headers_found["set-cookie"]
        if isinstance(cookies, str):
            cookies = [cookies]

        for cookie in cookies:
            cookie_lower = cookie.lower()

            if "secure" not in cookie_lower:
                self.log("WARNING", f"[Headers] Cookie missing Secure attribute: {cookie[:50]}")
                self.add_vuln(
                    title="Cookie Missing Secure Attribute",
                    severity="Medium",
                    category="Security Headers",
                    cvss_score=5.5,
                    description=f"Cookie '{cookie[:50]}...' is missing the Secure attribute, allowing transmission over HTTP.",
                    remediation="Add the 'Secure' attribute to all cookies to ensure they are only sent over HTTPS.",
                    confidence="Confirmed",
                )

            if "httponly" not in cookie_lower:
                self.log("WARNING", f"[Headers] Cookie missing HttpOnly attribute: {cookie[:50]}")
                self.add_vuln(
                    title="Cookie Missing HttpOnly Attribute",
                    severity="Medium",
                    category="Security Headers",
                    cvss_score=5.5,
                    description=f"Cookie '{cookie[:50]}...' is missing the HttpOnly attribute, making it accessible to JavaScript.",
                    remediation="Add the 'HttpOnly' attribute to cookies to prevent XSS from accessing them.",
                    confidence="Confirmed",
                )

            if "samesite" not in cookie_lower:
                self.log("WARNING", f"[Headers] Cookie missing SameSite attribute: {cookie[:50]}")
                self.add_vuln(
                    title="Cookie Missing SameSite Attribute",
                    severity="Medium",
                    category="Security Headers",
                    cvss_score=5.3,
                    description=f"Cookie '{cookie[:50]}...' is missing the SameSite attribute, vulnerable to CSRF attacks.",
                    remediation="Add the 'SameSite=Strict' or 'SameSite=Lax' attribute to cookies to prevent CSRF.",
                    confidence="Confirmed",
                )

    def _test_cache_poisoning(self):
        poison_header = "poison.attacker.com"
        body, status, _ = self._make_request(
            self.target,
            headers={
                "User-Agent": "LarShield/2.0",
                "X-Forwarded-Host": poison_header,
                "X-Host": poison_header,
            },
            timeout=5,
            return_response_obj=True,
        )
        if body and poison_header in body:
            self.log("CRITICAL", "[Headers] CACHE POISONING VULNERABILITY DETECTED via X-Forwarded-Host!")
            self.add_vuln(
                title="Web Cache Poisoning via X-Forwarded-Host",
                severity="High",
                category="Configuration",
                cvss_score=8.6,
                description=f"The server reflects the injected unkeyed header 'X-Forwarded-Host: {poison_header}' in the response body. If this response is cached by a CDN or reverse proxy, the malicious payload will be served to all subsequent users visiting the page.",
                remediation="Ensure that headers like 'X-Forwarded-Host' and 'X-Host' are either ignored or explicitly included in the CDN/proxy cache key. Validate the Host header against a strict allowlist.",
                confidence="Confirmed",
                evidence=f"Reflected payload: {poison_header}",
                payload=f"X-Forwarded-Host: {poison_header}",
            )

        body, status, _ = self._make_request(
            self.target,
            headers={
                "User-Agent": "LarShield/2.0",
                "X-Forwarded-Proto": "http",
            },
            timeout=5,
            return_response_obj=True,
        )
        if body and ("http://" in body or "evil.com" in body):
            self.log("CRITICAL", "[Headers] CACHE POISONING VULNERABILITY DETECTED via X-Forwarded-Proto!")
            self.add_vuln(
                title="Web Cache Poisoning via X-Forwarded-Proto",
                severity="High",
                category="Configuration",
                cvss_score=8.6,
                description="The server reflects X-Forwarded-Proto header in responses, potentially allowing protocol downgrade attacks through cache poisoning.",
                remediation="Ignore or properly validate X-Forwarded-Proto header. Ensure HTTPS is enforced regardless of proxy headers.",
                confidence="Confirmed",
                payload="X-Forwarded-Proto: http",
            )
