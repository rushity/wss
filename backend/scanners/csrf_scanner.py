"""
csrf_scanner.py — Cross-Site Request Forgery (CSRF) Scanner
============================================================
Detects CSRF vulnerabilities by:
  1. Discovering all HTML forms via crawler
  2. Checking for CSRF tokens in form fields and custom request headers
  3. Verifying SameSite cookie attributes
  4. Submitting forms without CSRF tokens to see if the server rejects them
  5. Checking Content-Type validation on state-changing endpoints

OWASP Top 10: A01:2021 — CVSS 8.8
"""
import re, ssl, urllib.parse, urllib.request, urllib.error
from scanners.base_scanner import BaseScanner
from utils.anomaly import SizeAnomalyDetector

# Token field name patterns
CSRF_FIELD_RE = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|nonce|__RequestVerificationToken"
    r"|csrfmiddlewaretoken|antiForgery|formToken)", re.I
)

# Header names that indicate CSRF protection
CSRF_HEADERS = {
    "x-csrf-token", "x-xsrf-token", "x-request-id",
    "x-csrftoken", "x-antiforgery",
}


class CsrfScanner(BaseScanner):
    SCANNER_NAME = "CSRF Vulnerability Scanner"
    _SCANNER_KEY = "csrf"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._tested = 0
        self._found  = 0
        self._seen: set = set()
        self._size_detector = SizeAnomalyDetector()

    # ------------------------------------------------------------------
    def run(self) -> list:
        self.log("INFO", f"[CSRF] Starting CSRF analysis on {self.target}...")
        try:
            forms = self._crawl_forms()
            self.log("INFO", f"[CSRF] Discovered {len(forms)} form(s)")

            for form in forms:
                self._audit_form(form)

            # Also probe common API/action endpoints
            self._probe_endpoints()

            # Run advanced CSRF checks
            self._check_origin_header_validation()
            self._check_custom_header_validation()
            self._check_samesite_cookie_attribute()
            self._test_samesite_lax_vs_strict()
            self._detect_anti_csrf_patterns()
            self._test_csrf_size_anomaly()

        except Exception as e:
            self.log("WARNING", f"[CSRF] Error: {e}")

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[CSRF] Complete — {self._tested} check(s) | "
            f"{self._found} CSRF vulnerability/vulnerabilities found",
        )
        return self.vulns

    # ------------------------------------------------------------------
    def _crawl_forms(self) -> list:
        try:
            results = self.discovery_context or {}
            forms = results.get("forms", [])
            return forms if forms is not None else []
        except Exception as e:
            self.log("ERROR", f"[CSRF] _crawl_forms error: {e}")
            return []

    # ------------------------------------------------------------------
    def _audit_form(self, form: dict):
        action  = form.get("action") or self.target
        method  = form.get("method", "get").upper()
        fields  = form.get("fields", [])
        page    = form.get("page_url", self.target)

        # Only POST / PUT / PATCH / DELETE forms are CSRF-relevant
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            return

        key = f"{action}:{method}"
        if key in self._seen:
            return
        self._seen.add(key)
        self._tested += 1

        field_names = [f.get("name","") for f in fields]

        # ── Check 1: No CSRF token field ──────────────────────────────
        has_token_field = any(
            CSRF_FIELD_RE.search(n) for n in field_names if n
        )

        if not has_token_field:
            self.log("WARNING",
                f"[CSRF] No CSRF token field in form at {action} (from {page})")

            # ── Check 2: Try submitting the form without a token ───────
            if self._submit_without_token_succeeds(action, method, fields):
                self._found += 1
                self.log("CRITICAL",
                    f"[CSRF] CONFIRMED — form at {action} accepted request without token!")
                self.add_vuln(
                    title=f"CSRF — Unprotected State-Changing Form at '{action}'",
                    severity="High",
                    category="CSRF",
                    cvss_score=8.8,
                    description=(
                        f"The `{method}` form at `{action}` (discovered via `{page}`) "
                        "does not include a CSRF token and accepted a forged cross-site "
                        "request in testing.\n\n"
                        "An attacker can craft a page that silently submits this form on "
                        "behalf of any authenticated victim who visits it, performing "
                        "account changes, data deletion, or privilege escalation."
                    ),
                    remediation=(
                        "1. Add a server-generated, per-session CSRF token to every "
                        "state-changing form.\n"
                        "2. Validate the token server-side on every POST/PUT/PATCH/DELETE.\n"
                        "3. Set SameSite=Strict or SameSite=Lax on session cookies.\n"
                        "4. Verify the Origin / Referer header as a secondary check.\n"
                        "5. Use the Synchronizer Token Pattern or Double Submit Cookie."
                    ),
                    cwe_ids=["CWE-352"],
                    owasp_category="A01:2021 – Broken Access Control",
                )
            else:
                # Form is protected (token enforced) but field is missing —
                # could be token injected via JS or header-based; flag as info
                self.add_vuln(
                    title=f"CSRF — No Visible Token Field in Form at '{action}'",
                    severity="Low",
                    category="CSRF",
                    cvss_score=3.1,
                    description=(
                        f"The `{method}` form at `{action}` contains no visible CSRF token "
                        "field. The server rejected the tokenless request (possible JS-based "
                        "or header-based protection), but this should be verified manually."
                    ),
                    remediation=(
                        "Confirm CSRF protection is applied via header inspection or "
                        "framework documentation. Prefer visible form tokens for defence-in-depth."
                    ),
                    cwe_ids=["CWE-352"],
                    owasp_category="A01:2021 – Broken Access Control",
                )
        else:
            self.log("SUCCESS",
                f"[CSRF] Form at {action} has CSRF token field: "
                f"{[n for n in field_names if CSRF_FIELD_RE.search(n or '')]}")

    # ------------------------------------------------------------------
    def _submit_without_token_succeeds(self, action, method, fields) -> bool:
        """Submit form with plausible dummy values but no CSRF token.
        Returns True if the server returns 2xx (not rejected)."""
        try:
            data = {}
            for f in fields:
                name = f.get("name","")
                if not name or CSRF_FIELD_RE.search(name):
                    continue   # skip the token field itself
                ftype = f.get("type","text").lower()
                if ftype == "email":
                    data[name] = "test@example.com"
                elif ftype in ("number","tel"):
                    data[name] = "1"
                else:
                    data[name] = "csrf_test_value"

            if not data:
                data = {"test": "csrf_test_value"}

            encoded = urllib.parse.urlencode(data).encode()
            headers = {
                "User-Agent":   "LarShield/2.0 CSRF-Probe",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin":       "https://evil.attacker.com",
                "Referer":      "https://evil.attacker.com/",
            }
            headers.update(self.auth_headers or {})
            body, status = self._make_request(action, method=method, data=encoded, headers=headers, timeout=8)
            return status in range(200, 300) if body is not None else False
        except urllib.error.HTTPError as e:
            return e.code not in (403, 405, 422, 400)
        except Exception as ex:
            self.log("ERROR", f"[CSRF] _submit_without_token_succeeds error: {ex}")
            return False

    # ------------------------------------------------------------------
    def _probe_endpoints(self):
        """Probe common action endpoints for missing CSRF protection."""
        common_actions = [
            "/account/settings", "/user/update", "/profile/edit",
            "/password/change", "/email/change", "/admin/action",
            "/api/user", "/api/account", "/api/settings",
        ]
        base = self.target.rstrip("/")
        for path in common_actions:
            url = f"{base}{path}"
            self._tested += 1
            if self._submit_without_token_succeeds(url, "POST", []):
                self.log("WARNING",
                    f"[CSRF] Endpoint {url} accepted cross-origin POST without token")
                self._found += 1
                self.add_vuln(
                    title=f"CSRF — API Endpoint '{path}' Accepts Cross-Origin POST",
                    severity="Medium",
                    category="CSRF",
                    cvss_score=6.5,
                    description=(
                        f"The endpoint `{url}` accepted a POST request from a cross-origin "
                        "`evil.attacker.com` without a CSRF token, Content-Type restriction, "
                        "or Origin validation."
                    ),
                    remediation=(
                        "Validate the Origin / Referer header on all state-changing API "
                        "endpoints. Require a CSRF token header (X-CSRF-Token) or use "
                        "SameSite=Strict cookies."
                    ),
                    cwe_ids=["CWE-352"],
                    owasp_category="A01:2021 – Broken Access Control",
                )

    # ------------------------------------------------------------------
    def _check_origin_header_validation(self):
        """Test if the server validates the Origin header on state-changing endpoints."""
        test_endpoints = self._crawl_forms()
        tested_actions = set()

        for form in test_endpoints:
            action = form.get("action") or self.target
            method = form.get("method", "post").upper()
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue
            if action in tested_actions:
                continue
            tested_actions.add(action)
            self._tested += 1

            data = {"test": "csrf_origin_check"}
            encoded = urllib.parse.urlencode(data).encode()

            # PROBE: send request with missing Origin header
            headers_no_origin = {"User-Agent": "LarShield/2.0 CSRF-Probe", "Content-Type": "application/x-www-form-urlencoded"}
            body, status_no = self._make_request(action, method=method, data=encoded, headers=headers_no_origin, timeout=8)

            # PROBE: send request with attacker Origin header
            headers_evil = dict(headers_no_origin)
            headers_evil["Origin"] = "https://evil.attacker.com"
            body, status_evil = self._make_request(action, method=method, data=encoded, headers=headers_evil, timeout=8)

            # CONFIRM: if both succeed, Origin validation is missing
            if status_no and status_evil and status_no in range(200, 300) and status_evil in range(200, 300):
                self._found += 1
                self.log("WARNING", f"[CSRF] No Origin header validation at {action}")
                self.add_vuln(
                    title=f"CSRF — Missing Origin Header Validation at '{action}'",
                    severity="High",
                    category="CSRF",
                    cvss_score=7.5,
                    description=f"The endpoint `{action}` accepted requests with no Origin header "
                        "and with a spoofed Origin header from `evil.attacker.com`. "
                        "This means the server does not validate the Origin header, making "
                        "CSRF attacks possible from any origin.",
                    evidence=f"No-Origin: {status_no}, Attacker-Origin: {status_evil}",
                    request_details=f"{method} {action} (with and without Origin header)",
                    response_details=f"Status without Origin: {status_no}, with attacker Origin: {status_evil}",
                    confidence="Confirmed",
                    remediation="1. Validate the Origin header on all state-changing requests.\n"
                        "2. Maintain an allowlist of permitted origins.\n"
                        "3. Reject requests with unexpected or missing Origin headers.",
                    cwe_ids=["CWE-352"],
                    owasp_category="A01:2021 – Broken Access Control",
                )

    # ------------------------------------------------------------------
    def _check_custom_header_validation(self):
        """Test if the server validates a custom CSRF header like X-CSRF-Token or X-Requested-With."""
        custom_headers = ["X-CSRF-Token", "X-XSRF-Token", "X-Requested-With", "X-CSRF", "X-Antiforgery"]
        test_endpoints = self._crawl_forms()
        tested_actions = set()

        for form in test_endpoints:
            action = form.get("action") or self.target
            method = form.get("method", "post").upper()
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue
            if action in tested_actions:
                continue
            tested_actions.add(action)
            self._tested += 1

            data = {"test": "csrf_header_check"}
            encoded = urllib.parse.urlencode(data).encode()

            # Test request with each custom CSRF header
            for hdr in custom_headers:
                headers = {
                    "User-Agent": "LarShield/2.0 CSRF-Probe",
                    "Content-Type": "application/x-www-form-urlencoded",
                    hdr: "test-csrf-value",
                }
                body, status = self._make_request(action, method=method, data=encoded, headers=headers, timeout=8)

                if status in range(200, 300):
                    self.log("SUCCESS", f"[CSRF] {action} accepts custom header {hdr} — CSRF protection may be header-based")
                    self.add_vuln(
                        title=f"CSRF — Protection Relies on Custom Header '{hdr}'",
                        severity="Low",
                        category="CSRF",
                        cvss_score=0.0,
                        description=f"The endpoint `{action}` accepted a request with the custom "
                            f"header `{hdr}`. If the server relies solely on custom headers for "
                            "CSRF protection (double-submit cookie pattern), this can be bypassed "
                            "if an attacker can set cookies in the victim's browser.",
                        evidence=f"Accepted {method} {action} with {hdr}: test-csrf-value",
                        request_details=f"{method} {action} with header {hdr}",
                        response_details=f"HTTP {status}",
                        confidence="Info",
                        remediation="1. Use SameSite=Strict cookies as defence-in-depth.\n"
                            "2. Combine custom headers with Origin/Referer validation.\n"
                            "3. Ensure custom headers cannot be set by third-party scripts.",
                        cwe_ids=["CWE-352"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )

    # ------------------------------------------------------------------
    def _check_samesite_cookie_attribute(self):
        """Check if cookies set by the application have SameSite attribute for CSRF protection."""
        try:
            result = self._make_request(self.target, timeout=8, return_response_obj=True)
            if not result or len(result) < 3:
                return
            body, status, resp_headers = result
            if resp_headers is None:
                return
            set_cookies = resp_headers.get_all("Set-Cookie") if hasattr(resp_headers, "get_all") else []
            if not set_cookies:
                return
            for raw in set_cookies:
                samesite_match = re.search(r'SameSite=(Strict|Lax|None)', raw, re.I)
                if not samesite_match:
                    cookie_name = raw.split("=")[0] if "=" in raw else "unknown"
                    self.add_vuln(
                        title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                        severity="Medium",
                        category="CSRF",
                        cvss_score=5.3,
                        description=f"The cookie `{cookie_name}` set by the application does not "
                            "include the SameSite attribute. Without SameSite, cookies are sent "
                            "on cross-site requests, enabling CSRF attacks.",
                        evidence=f"Set-Cookie: {raw[:80]}",
                        request_details=f"GET {self.target}",
                        response_details=f"Set-Cookie: {raw[:80]}",
                        confidence="Confirmed",
                        remediation="1. Set SameSite=Strict on session cookies.\n"
                            "2. Use SameSite=Lax for cookies that need to persist across safe navigations.\n"
                            "3. Avoid SameSite=None unless required and combined with Secure flag.",
                        cwe_ids=["CWE-352"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )
        except Exception as e:
            self.log("DEBUG", f"[CSRF] _check_samesite_cookie_attribute error: {e}")

    # ------------------------------------------------------------------
    def _detect_anti_csrf_patterns(self):
        """Detect anti-CSRF token patterns in HTML/JS responses to assess protection coverage."""
        probe_paths = ["/", "/login", "/register", "/account", "/admin", "/api/csrf-token"]
        base = self.target.rstrip("/")

        csrf_patterns = {
            "meta[name=\"csrf-token\"]": re.compile(r'meta\s+name=["\']csrf-token["\']', re.I),
            "X-CSRF-Token header": re.compile(r'X-CSRF-Token', re.I),
            "csrf_token variable": re.compile(r'(csrfToken|csrf_token|csrfToken)', re.I),
            "antiForgeryToken": re.compile(r'antiForgeryToken', re.I),
            "__RequestVerificationToken": re.compile(r'__RequestVerificationToken', re.I),
        }

        for path in probe_paths:
            url = f"{base}{path}"
            body, status = self._make_request(url, timeout=5)
            if not body:
                continue

            found_patterns = [name for name, pattern in csrf_patterns.items() if pattern.search(body)]

            if found_patterns:
                self.log("SUCCESS", f"[CSRF] Anti-CSRF pattern(s) found at {url}: {', '.join(found_patterns)}")

                # Record baseline size for anomaly detection
                if status and status in range(200, 300):
                    self._size_detector.record_size(len(body))

                self.add_vuln(
                    title=f"Anti-CSRF Protection Patterns Detected at '{path}'",
                    severity="Low",
                    category="CSRF",
                    cvss_score=0.0,
                    description=f"The page `{url}` contains CSRF protection patterns: "
                        f"{', '.join(found_patterns)}. These should be verified for correct "
                        "implementation (token uniqueness, per-session binding, server-side validation).",
                    evidence=f"Patterns found: {', '.join(found_patterns)}",
                    request_details=f"GET {url}",
                    response_details=f"HTTP {status}",
                    confidence="Info",
                    remediation="Verify that CSRF tokens are: 1) Cryptographically random, "
                        "2) Bound to the user session, 3) Validated server-side on every request.",
                    cwe_ids=["CWE-352"],
                    owasp_category="A01:2021 – Broken Access Control",
                )
                return

    def _test_samesite_lax_vs_strict(self):
        try:
            result = self._make_request(self.target, timeout=8, return_response_obj=True)
            if not result or len(result) < 3:
                return
            body, status, resp_headers = result
            if resp_headers is None:
                return
            set_cookies = resp_headers.get_all("Set-Cookie") if hasattr(resp_headers, "get_all") else []
            if not set_cookies:
                return
            for raw in set_cookies:
                lax_match = re.search(r'SameSite=Lax', raw, re.I)
                if lax_match:
                    cookie_name = raw.split("=")[0] if "=" in raw else "unknown"
                    self.add_vuln(
                        title=f"Cookie '{cookie_name}' Uses SameSite=Lax",
                        severity="Low",
                        category="CSRF",
                        cvss_score=0.0,
                        description=f"The cookie `{cookie_name}` uses SameSite=Lax. Lax mode permits cookies on top-level GET navigations, which may still enable certain CSRF attacks (e.g., GET-based state changes). Strict mode is recommended for sensitive operations.",
                        evidence=f"Set-Cookie: {raw[:80]}",
                        request_details=f"GET {self.target}",
                        response_details=f"Set-Cookie: {raw[:80]}",
                        confidence="Info",
                        remediation="Consider using SameSite=Strict for session cookies on sensitive endpoints to provide stronger CSRF protection.",
                        cwe_ids=["CWE-352"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )
        except Exception as e:
            self.log("DEBUG", f"[CSRF] _test_samesite_lax_vs_strict error: {e}")

    def _test_csrf_size_anomaly(self):
        if not self._size_detector.has_baseline:
            return
        test_endpoints = self._crawl_forms()
        for form in test_endpoints:
            action = form.get("action") or self.target
            method = form.get("method", "post").upper()
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue
            data = {"test": "csrf_anomaly_check"}
            encoded = urllib.parse.urlencode(data).encode()
            headers = {
                "User-Agent": "LarShield/2.0 CSRF-Probe",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://evil.attacker.com",
            }
            headers.update(self.auth_headers or {})
            test_body, test_status = self._make_request(action, method=method, data=encoded, headers=headers, timeout=8)
            if test_body and self._size_detector.test_size(len(test_body)):
                self.log("WARNING",
                         f"[CSRF] Size anomaly at {action}: {len(test_body)} bytes "
                         f"(z={self._size_detector.z_score(float(len(test_body))):.1f})")
                self._found += 1
                self.add_vuln(
                    title=f"CSRF — Response Size Anomaly at '{action}'",
                    severity="Medium",
                    category="CSRF",
                    cvss_score=5.3,
                    description=f"The endpoint `{action}` returned an anomalous response size ({len(test_body)} bytes) "
                        "when accessed without a valid CSRF token. This may indicate partial CSRF protection that "
                        "doesn't fully block forged requests.",
                    evidence=f"Response size: {len(test_body)} bytes (z-score anomaly)",
                    request_details=f"{method} {action} (without CSRF token)",
                    response_details=f"HTTP {test_status}, body length: {len(test_body)}",
                    confidence="Medium",
                    remediation="Ensure CSRF tokens are validated server-side on all state-changing requests.",
                    cwe_ids=["CWE-352"],
                    owasp_category="A01:2021 – Broken Access Control",
                )
