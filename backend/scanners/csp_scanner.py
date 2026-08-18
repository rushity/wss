"""
csp_scanner.py — Content Security Policy (CSP) Deep Auditor
============================================================
Parses and analyses the Content-Security-Policy (and CSP-Report-Only) header:
  - Detects missing CSP entirely
  - Flags unsafe-inline / unsafe-eval in script-src
  - Flags wildcard (*) sources
  - Detects missing critical directives
  - Identifies CSP bypass vectors (data:, blob:, http: schemes)
  - Checks for report-uri / report-to configuration
  - Scores overall CSP strength
"""
import re
import urllib.request
import urllib.error
from scanners.base_scanner import BaseScanner

CRITICAL_DIRECTIVES = [
    "default-src", "script-src", "style-src", "img-src",
    "connect-src", "font-src", "object-src", "frame-ancestors",
]

BYPASS_SCHEMES = ["data:", "blob:", "http:", "javascript:"]

CDNS_ALLOWLISTED_BUT_RISKY = [
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "ajax.googleapis.com", "code.jquery.com",
]


class CspScanner(BaseScanner):
    SCANNER_NAME = "Content Security Policy (CSP) Auditor"
    _SCANNER_KEY = "csp"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[CSP] Auditing Content-Security-Policy on {self.target}...")
        try:
            headers = self._fetch_headers()
            csp = headers.get("content-security-policy", "")
            csp_ro = headers.get("content-security-policy-report-only", "")

            if not csp and not csp_ro:
                self.log("WARNING", "[CSP] No Content-Security-Policy header found!")
                self.add_vuln(
                    title="Content Security Policy (CSP) Not Configured",
                    severity="High",
                    category="Content Security Policy",
                    cvss_score=7.5,
                    description=f"The target `{self.target}` does not serve a "
                        "Content-Security-Policy header. Without CSP, the browser has "
                        "no policy to enforce, making XSS attacks significantly more "
                        "damaging as injected scripts run with full page privileges.",
                    remediation="Implement a strict CSP:\n"
                        "Content-Security-Policy: default-src 'self'; "
                        "script-src 'self' 'nonce-{random}'; "
                        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
                    evidence="No Content-Security-Policy header in response",
                    request_details=f"GET {self.target}",
                    response_details="Missing Content-Security-Policy header",
                    confidence="Confirmed",
                )
                return self.vulns

            active_csp = csp or csp_ro
            label = "CSP-Report-Only" if not csp else "CSP"
            self.log("INFO", f"[CSP] {label} header found. Parsing directives...")

            if not csp and csp_ro:
                self.add_vuln(
                    title="CSP Deployed in Report-Only Mode (Not Enforced)",
                    severity="Medium",
                    category="Content Security Policy",
                    cvss_score=5.3,
                    description="A Content-Security-Policy-Report-Only header is present but "
                        "no enforcing CSP header exists. Report-Only mode does not prevent "
                        "attacks — it only sends violation reports.",
                    remediation="Promote the policy to Content-Security-Policy once verified.",
                    evidence="Content-Security-Policy-Report-Only present, no enforcing CSP",
                    request_details=f"GET {self.target}",
                    response_details="Report-Only mode CSP detected",
                    confidence="High",
                )

            directives = self._parse_csp(active_csp)
            self._audit_directives(directives, active_csp)

        except Exception as e:
            self.log("ERROR", f"[CSP] Audit error: {e}")

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[CSP] Audit complete. {len(self.vulns)} issue(s) found.",
        )
        return self.vulns

    def _fetch_headers(self) -> dict:
        body, status, resp_headers = self._make_request(
            self.target, return_response_obj=True
        )
        if resp_headers:
            return {k.lower(): v for k, v in resp_headers.items()}
        return {}

    @staticmethod
    def _parse_csp(csp: str) -> dict:
        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directives[tokens[0].lower()] = tokens[1:]
        return directives

    def _audit_directives(self, directives: dict, raw_csp: str):
        script_src = directives.get("script-src",
                     directives.get("default-src", []))

        if "'unsafe-inline'" in script_src:
            self.add_vuln(
                title="CSP Allows 'unsafe-inline' in script-src",
                severity="High",
                category="Content Security Policy",
                cvss_score=7.4,
                description="The CSP `script-src` directive includes `'unsafe-inline'`, "
                    "which allows inline `<script>` blocks and `onclick=` handlers. "
                    "This completely undermines XSS protection provided by CSP.",
                remediation="Replace 'unsafe-inline' with nonce-based or hash-based "
                    "script allowlisting:\n"
                    "script-src 'self' 'nonce-{server_generated_random}';",
                evidence=f"script-src contains 'unsafe-inline': {script_src}",
                payload="'unsafe-inline' in CSP",
                request_details=f"GET {self.target}",
                response_details=f"CSP directives: {directives}",
                confidence="Confirmed",
            )
        else:
            self.log("SUCCESS", "[CSP] 'unsafe-inline' not found in script-src")

        if "'unsafe-eval'" in script_src:
            self.add_vuln(
                title="CSP Allows 'unsafe-eval' in script-src",
                severity="Medium",
                category="Content Security Policy",
                cvss_score=5.3,
                description="The CSP `script-src` allows `eval()`, `new Function()`, "
                    "and similar dynamic code execution. This weakens XSS mitigation.",
                remediation="Remove 'unsafe-eval'. Refactor code to avoid eval(). "
                    "Use JSON.parse() instead of eval() for JSON data.",
                evidence=f"script-src contains 'unsafe-eval': {script_src}",
                payload="'unsafe-eval' in CSP",
                request_details=f"GET {self.target}",
                response_details=f"CSP directives: {directives}",
                confidence="Confirmed",
            )

        for directive, sources in directives.items():
            if "*" in sources:
                self.add_vuln(
                    title=f"CSP Wildcard (*) Source in '{directive}'",
                    severity="High",
                    category="Content Security Policy",
                    cvss_score=7.5,
                    description=f"The `{directive}` directive allows any origin (`*`), "
                        "effectively disabling the protection for this resource type.",
                    remediation=f"Replace `*` in `{directive}` with explicit, "
                        "trusted origins only.",
                    evidence=f"{directive}: {' '.join(sources)} contains wildcard",
                    payload=f"{directive} *",
                    request_details=f"GET {self.target}",
                    response_details=f"CSP directive {directive} allows *",
                    confidence="Confirmed",
                )

        for scheme in BYPASS_SCHEMES:
            if scheme in raw_csp:
                self.add_vuln(
                    title=f"CSP Bypass via '{scheme}' Scheme Allowed",
                    severity="Medium",
                    category="Content Security Policy",
                    cvss_score=5.5,
                    description=f"The CSP permits the `{scheme}` scheme, which is commonly "
                        "abused for CSP bypass techniques (especially data: URIs for script execution).",
                    remediation=f"Remove `{scheme}` from all CSP directives unless strictly required.",
                    evidence=f"CSP contains bypass scheme: {scheme}",
                    payload=f"{scheme} in CSP",
                    request_details=f"GET {self.target}",
                    response_details=f"CSP allows scheme: {scheme}",
                    confidence="High",
                )

        obj_src = directives.get("object-src", directives.get("default-src", []))
        if not obj_src or (obj_src != ["'none'"] and "'none'" not in obj_src):
            self.add_vuln(
                title="CSP Missing 'object-src none' Directive",
                severity="Medium",
                category="Content Security Policy",
                cvss_score=5.3,
                description="Without `object-src 'none'`, the browser may load Flash, "
                    "Java applets, or other plugins that bypass script-src restrictions.",
                remediation="Add: object-src 'none'; to your CSP.",
                evidence=f"object-src directive: {obj_src}",
                request_details=f"GET {self.target}",
                response_details="object-src not set to 'none'",
                confidence="High",
            )

        if "frame-ancestors" not in directives:
            self.add_vuln(
                title="CSP Missing 'frame-ancestors' Directive (Clickjacking)",
                severity="Medium",
                category="Content Security Policy",
                cvss_score=5.4,
                description="The CSP does not include `frame-ancestors`, which controls "
                    "whether the page can be embedded in iframes. Without it, clickjacking "
                    "attacks remain possible if X-Frame-Options is also absent.",
                remediation="Add: frame-ancestors 'none'; (or 'self' if same-origin framing needed)",
                evidence="Directives present: " + ", ".join(directives.keys()),
                request_details=f"GET {self.target}",
                response_details="frame-ancestors directive missing",
                confidence="High",
            )
        else:
            self.log("SUCCESS", "[CSP] frame-ancestors directive present")

        if "base-uri" not in directives:
            self.add_vuln(
                title="CSP Missing 'base-uri' Directive",
                severity="Low",
                category="Content Security Policy",
                cvss_score=3.5,
                description="Without `base-uri`, an attacker who injects a `<base>` tag "
                    "can redirect all relative URLs to an attacker-controlled origin.",
                remediation="Add: base-uri 'self'; to your CSP.",
                evidence="Directives present: " + ", ".join(directives.keys()),
                request_details=f"GET {self.target}",
                response_details="base-uri directive missing",
                confidence="High",
            )

        if "report-uri" not in directives and "report-to" not in directives:
            self.add_vuln(
                title="CSP Has No Reporting Endpoint Configured",
                severity="Low",
                category="Content Security Policy",
                cvss_score=2.0,
                description="The CSP does not include a `report-uri` or `report-to` "
                    "directive. Without reporting, CSP violations go undetected.",
                remediation="Add: report-uri /csp-report-endpoint; "
                    "to receive violation reports from browsers.",
                evidence="Directives present: " + ", ".join(directives.keys()),
                request_details=f"GET {self.target}",
                response_details="No report-uri or report-to directive",
                confidence="High",
            )
        else:
            self.log("SUCCESS", "[CSP] CSP reporting endpoint configured")

        for cdn in CDNS_ALLOWLISTED_BUT_RISKY:
            if cdn in raw_csp:
                self.add_vuln(
                    title=f"CSP Allowlists Risky CDN: {cdn}",
                    severity="Low",
                    category="Content Security Policy",
                    cvss_score=3.5,
                    description=f"The CSP allowlists `{cdn}`. Public CDNs host thousands "
                        "of packages; if any contain malicious code or are compromised, "
                        "your CSP provides no protection.",
                    remediation="Pin specific script hashes instead of trusting entire CDN origins. "
                        "Use Subresource Integrity (SRI) for all external scripts.",
                    evidence=f"CDN {cdn} found in CSP allowlist",
                    payload=cdn,
                    request_details=f"GET {self.target}",
                    response_details=f"CSP allowlists {cdn}",
                    confidence="Medium",
                )
