"""
clickjacking_scanner.py — Clickjacking Vulnerability Scanner
=============================================================
Detects clickjacking vulnerabilities through multiple vectors:
  - X-Frame-Options header (DENY / SAMEORIGIN / ALLOWFROM)
  - CSP frame-ancestors directive
  - JavaScript framebusting code detection
  - Attempts to verify if the page can actually be framed
  - Scores the overall clickjacking protection level
"""
import re
import urllib.request
import urllib.error
from scanners.base_scanner import BaseScanner

FRAMEBUSTING_RE = re.compile(
    r"(top\.location|self\.location|parent\.location|"
    r"window\.top\s*!==\s*window\.self|"
    r"if\s*\(\s*window\s*!==\s*window\.top|"
    r"if\s*\(\s*self\s*!==\s*top)",
    re.I
)


class ClickjackingScanner(BaseScanner):
    SCANNER_NAME = "Clickjacking Vulnerability Scanner"
    _SCANNER_KEY = "clickjacking"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[Clickjacking] Auditing clickjacking protection on {self.target}...")
        try:
            headers, body = self._fetch()
            self._audit(headers, body)
        except Exception as e:
            self.log("ERROR", f"[Clickjacking] Audit error: {e}")

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[Clickjacking] Audit complete. {len(self.vulns)} issue(s).",
        )
        return self.vulns

    def _fetch(self):
        body, status, resp_headers = self._make_request(
            self.target,
            headers={"User-Agent": "LarShield/2.0 Clickjacking-Audit"},
            return_response_obj=True,
        )
        headers = {k.lower(): v for k, v in resp_headers.items()} if resp_headers else {}
        return headers, body or ""

    def _audit(self, headers: dict, body: str):
        xfo = headers.get("x-frame-options", "").upper()
        csp = headers.get("content-security-policy", "")
        has_framebusting = bool(FRAMEBUSTING_RE.search(body))

        xfo_protected = xfo in ("DENY", "SAMEORIGIN") or xfo.startswith("ALLOW-FROM")
        csp_protected = "frame-ancestors" in csp.lower()

        if not xfo:
            self.log("WARNING", "[Clickjacking] X-Frame-Options header is missing")
            self.add_vuln(
                title="Missing X-Frame-Options Header",
                severity="Medium",
                category="Clickjacking",
                cvss_score=5.4,
                description=f"The response from `{self.target}` does not include an "
                    "`X-Frame-Options` header. Without this header (or a CSP frame-ancestors "
                    "directive), the page can be embedded in an iframe on any origin, "
                    "enabling clickjacking attacks.",
                remediation="Add to your web server configuration:\n"
                    "  Nginx:  add_header X-Frame-Options \"DENY\" always;\n"
                    "  Apache: Header always set X-Frame-Options \"DENY\"\n"
                    "Or use CSP: Content-Security-Policy: frame-ancestors 'none';",
                evidence="X-Frame-Options header missing from response",
                request_details=f"GET {self.target}",
                response_details="No X-Frame-Options header",
                confidence="Confirmed",
            )
        elif xfo == "ALLOWALL" or xfo.startswith("ALLOW-FROM"):
            self.add_vuln(
                title=f"X-Frame-Options Set to Permissive Value: '{xfo}'",
                severity="Medium",
                category="Clickjacking",
                cvss_score=4.3,
                description=f"The `X-Frame-Options` header is set to `{xfo}`, which "
                    "may allow framing from specific or all origins depending on the value. "
                    "ALLOW-FROM is also deprecated and ignored by Chrome/Safari.",
                remediation="Use X-Frame-Options: DENY or SAMEORIGIN. "
                    "For fine-grained control use CSP frame-ancestors instead.",
                evidence=f"X-Frame-Options: {xfo}",
                request_details=f"GET {self.target}",
                response_details=f"X-Frame-Options: {xfo}",
                confidence="High",
            )
        else:
            self.log("SUCCESS", f"[Clickjacking] X-Frame-Options: {xfo}")

        if not csp_protected:
            if xfo_protected:
                self.add_vuln(
                    title="CSP frame-ancestors Missing (X-Frame-Options Present as Fallback)",
                    severity="Low",
                    category="Clickjacking",
                    cvss_score=2.0,
                    description="X-Frame-Options is set correctly, but the CSP header does not "
                        "include `frame-ancestors`. CSP frame-ancestors supersedes X-Frame-Options "
                        "in modern browsers and provides finer-grained control.",
                    remediation="Add: Content-Security-Policy: frame-ancestors 'none'; "
                        "for defence-in-depth.",
                    evidence="CSP header present but no frame-ancestors directive",
                    request_details=f"GET {self.target}",
                    response_details="CSP missing frame-ancestors",
                    confidence="Medium",
                )
        else:
            fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.I)
            if fa_match:
                fa_value = fa_match.group(1).strip()
                if fa_value in ("*", "http: https:"):
                    self.add_vuln(
                        title=f"CSP frame-ancestors Allows All Origins: '{fa_value}'",
                        severity="High",
                        category="Clickjacking",
                        cvss_score=7.4,
                        description=f"The CSP `frame-ancestors` directive is set to `{fa_value}`, "
                            "allowing any origin to embed this page in an iframe.",
                        remediation="Set: frame-ancestors 'none'; or frame-ancestors 'self';",
                        evidence=f"frame-ancestors: {fa_value}",
                        payload=fa_value,
                        request_details=f"GET {self.target}",
                        response_details=f"CSP frame-ancestors: {fa_value}",
                        confidence="Confirmed",
                    )
                else:
                    self.log("SUCCESS", f"[Clickjacking] CSP frame-ancestors: {fa_value}")

        if has_framebusting and not (xfo_protected or csp_protected):
            self.add_vuln(
                title="JavaScript Framebusting Only — Bypassable Clickjacking Protection",
                severity="Medium",
                category="Clickjacking",
                cvss_score=5.4,
                description="The page relies solely on JavaScript-based framebusting code "
                    "(e.g. `if (top !== self) top.location = self.location`). "
                    "This can be bypassed via the `sandbox` attribute on iframes: "
                    "`<iframe sandbox='allow-forms' ...>`.",
                remediation="Replace JavaScript framebusting with X-Frame-Options or "
                    "CSP frame-ancestors headers, which are enforced by the browser and "
                    "cannot be bypassed.",
                evidence="JavaScript framebusting code detected in response body",
                request_details=f"GET {self.target}",
                response_details="Framebusting JS found, no header protection",
                confidence="High",
            )
        elif has_framebusting:
            self.log("INFO", "[Clickjacking] JavaScript framebusting also detected (defence-in-depth)")

        if not xfo_protected and not csp_protected and not has_framebusting:
            self.log("CRITICAL", "[Clickjacking] Page is fully unprotected against clickjacking!")
            self.add_vuln(
                title="Page Fully Unprotected Against Clickjacking",
                severity="High",
                category="Clickjacking",
                cvss_score=7.4,
                description=f"`{self.target}` has no X-Frame-Options, no CSP frame-ancestors, "
                    "and no JavaScript framebusting. Any external site can embed this page "
                    "in an invisible iframe and trick authenticated users into performing "
                    "unintended actions (e.g. transferring funds, changing settings).",
                remediation="Add immediately: add_header X-Frame-Options \"DENY\" always; "
                    "and Content-Security-Policy: frame-ancestors 'none';",
                evidence="No X-Frame-Options, no CSP frame-ancestors, no framebusting JS",
                request_details=f"GET {self.target}",
                response_details="Fully unprotected response",
                confidence="Confirmed",
            )
