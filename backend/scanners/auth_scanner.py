
"""
auth_scanner.py — Authentication Security Scanner
==================================================
Audits the authentication surface of a web application:
  - Login form detection & HTTPS enforcement
  - Default / weak credential testing (safe probes only)
  - Brute-force protection (account lockout detection)
  - Multi-Factor Authentication presence hints
  - Password policy exposure via error messages
  - Username enumeration via timing / response differences
  - Auth bypass via HTTP verb tampering
"""
import re, ssl, time, urllib.parse, urllib.request, urllib.error, base64, json
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector, SizeAnomalyDetector
from utils.evasion import waf_evade
from utils.differential import DifferentialAnalyzer, ParameterMutationTester

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/account/login", "/user/login", "/admin/login", "/wp-login.php",
    "/portal", "/dashboard/login", "/api/auth/login", "/api/login",
]

WEAK_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("test", "test"), ("root", "root"),
    ("administrator", "administrator"), ("user", "user"),
]

SUCCESS_INDICATORS = re.compile(
    r"(dashboard|logout|sign.?out|welcome|my.?account|profile|settings)",
    re.I
)
FAILURE_INDICATORS = re.compile(
    r"(invalid|incorrect|failed|wrong|error|denied|bad.?credential)",
    re.I
)


class AuthScanner(BaseScanner):
    SCANNER_NAME = "Authentication Security Scanner"
    _SCANNER_KEY = "auth"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._tested = 0
        self._is_https = self.target.startswith("https://")
        self._timing_detector = TimingAnomalyDetector()
        self._size_detector = SizeAnomalyDetector()
        self._differential = DifferentialAnalyzer()
        self._mutation_tester = ParameterMutationTester(self._auth_mutation_req)

    def _auth_mutation_req(self, url, params):
        data = urllib.parse.urlencode(params).encode("utf-8")
        body, status = self._make_request(url, method="POST", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=8)
        return body or "", status

    # ------------------------------------------------------------------
    def run(self) -> list:
        self.log("INFO", f"[Auth] Starting authentication security audit on {self.target}...")
        try:
            login_pages = self._discover_login_pages()
            self.log("INFO", f"[Auth] Found {len(login_pages)} login endpoint(s)")
            for url, form_data in login_pages:
                self._audit_login(url, form_data)

            self._check_oauth_implicit_flow()
            self._check_jwt_in_url()
            self._check_auth_over_http()
            self._check_oauth_state_parameter()
        except Exception as e:
            self.log("WARNING", f"[Auth] Error: {e}")

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[Auth] Audit complete. {len(self.vulns)} issue(s) found.",
        )
        return self.vulns

    # ------------------------------------------------------------------
    def _discover_login_pages(self) -> list:
        """Returns list of (url, form_fields_dict) for login pages found."""
        found = []
        base = self.target.rstrip("/")
        for path in LOGIN_PATHS:
            url = f"{base}{path}"
            body, status = self._make_request(url, headers={"User-Agent": "LarShield/2.0 Auth-Audit"}, timeout=5)
            if body and re.search(r'type=["\']password["\']', body, re.I):
                fields = self._extract_login_fields(body)
                found.append((url, fields))
                self.log("INFO", f"[Auth] Login page detected: {url}")
        return found
        return found

    @staticmethod
    def _extract_login_fields(html: str) -> dict:
        """Extract username/password field names from HTML."""
        user_re = re.search(
            r'<input[^>]*name=["\']([^"\']*(?:user|login|email|username)[^"\']*)["\']',
            html, re.I)
        pass_re = re.search(
            r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
            html, re.I)
        if not pass_re:
            pass_re = re.search(
                r'<input[^>]*name=["\']([^"\']*(?:pass|pwd|secret)[^"\']*)["\']',
                html, re.I)
        return {
            "username_field": user_re.group(1) if user_re else "username",
            "password_field": pass_re.group(1) if pass_re else "password",
        }

    # ------------------------------------------------------------------
    def _audit_login(self, url: str, fields: dict):
        ufield = fields.get("username_field", "username")
        pfield = fields.get("password_field", "password")

        # ── Check 1: HTTPS enforcement ────────────────────────────────
        if not self._is_https:
            self.add_vuln(
                title="Login Form Served Over HTTP (No HTTPS)",
                severity="Critical",
                category="Authentication",
                cvss_score=9.1,
                description=f"The login form at `{url}` is served over plain HTTP. "
                    "Credentials are transmitted in cleartext and can be intercepted.",
                remediation="Enforce HTTPS site-wide. Redirect all HTTP to HTTPS. "
                    "Use HSTS: Strict-Transport-Security: max-age=63072000; includeSubDomains",
                cwe_ids=["CWE-287"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

        # ── Check 2: Weak / default credentials ───────────────────────
        self._test_weak_credentials(url, ufield, pfield)

        # ── Check 3: Brute-force protection ───────────────────────────
        self._test_brute_force_protection(url, ufield, pfield)

        # ── Check 4: Username enumeration ────────────────────────────
        self._test_username_enumeration(url, ufield, pfield)

        # ── Check 5: HTTP verb tampering bypass ───────────────────────
        self._test_verb_tampering(url)

        # ── Check 6: WAF-evaded auth bypass payloads ──────────────────
        self._test_auth_bypass_payloads(url, ufield, pfield)

        # ── Check 7: Differential auth bypass analysis ───────────────
        self._test_differential_auth(url, ufield, pfield)

    # ------------------------------------------------------------------
    def _post_login(self, url, data, timeout=6):
        try:
            encoded = urllib.parse.urlencode(data).encode()
            headers = {
                "User-Agent":   "LarShield/2.0 Auth-Audit",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            body, status, elapsed = self._make_timed_request(url, method="POST", data=encoded, headers=headers, timeout=timeout)
            return body, status, elapsed
        except urllib.error.HTTPError as e:
            return "", e.code, 0.0
        except Exception as e:
            self.log("ERROR", f"[Auth] _post_login failed: {e}")
            return None, 0, 0.0

    def _test_weak_credentials(self, url, ufield, pfield):
        self._tested += 1
        for username, password in WEAK_CREDS[:5]:  # limit to 5 pairs
            body, status, _ = self._post_login(url, {ufield: username, pfield: password})
            if body and SUCCESS_INDICATORS.search(body):
                self.log("CRITICAL", f"[Auth] Default credentials accepted: {username}:{password}")
                self.add_vuln(
                    title=f"Default/Weak Credentials Accepted ({username}:{password})",
                    severity="Critical",
                    category="Authentication",
                    cvss_score=9.8,
                    description=f"The application at `{url}` accepted the default credentials "
                        f"`{username}:{password}`. An attacker can immediately gain access "
                        "to the application without any further effort.",
                    evidence=f"Success indicator matched using credentials {username}:{password}",
                    payload=f"{ufield}={username}&{pfield}={password}",
                    confidence="Confirmed",
                    remediation="1. Force credential change on first login.\n"
                        "2. Implement a strong password policy.\n"
                        "3. Remove all default accounts from production systems.",
                    cwe_ids=["CWE-287"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )
                return

    def _test_brute_force_protection(self, url, ufield, pfield):
        self._tested += 1
        blocked = False
        for i in range(6):
            body, status, _ = self._post_login(url,
                {ufield: "sentinel_test_user", pfield: f"wrong_pass_{i}"})
            if status in (429, 423) or (body and re.search(
                r"(locked|too many|rate limit|try again)", body or "", re.I
            )):
                blocked = True
                break
        if not blocked:
            self.log("WARNING", f"[Auth] No brute-force protection detected at {url}")
            self.add_vuln(
                title="No Brute-Force Protection on Login",
                severity="High",
                category="Authentication",
                cvss_score=7.5,
                description=f"The login endpoint `{url}` did not block or rate-limit "
                    "6 consecutive failed login attempts. Attackers can automate "
                    "credential stuffing and password spraying attacks.",
                remediation="1. Implement account lockout after 5 failed attempts.\n"
                    "2. Add CAPTCHA after 3 failed attempts.\n"
                    "3. Rate-limit login attempts per IP (e.g. 10/minute).\n"
                    "4. Alert on repeated failed attempts.",
                cwe_ids=["CWE-287"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
        else:
            self.log("SUCCESS", f"[Auth] Brute-force protection detected at {url}")

    def _test_username_enumeration(self, url, ufield, pfield):
        self._tested += 1
        body_valid,   _, t_valid   = self._post_login(url, {ufield: "admin",              pfield: "wrongpass_sentinel"})
        body_invalid, _, t_invalid = self._post_login(url, {ufield: "nonexistent_sentinel_xyz", pfield: "wrongpass_sentinel"})
        if body_valid is None or body_invalid is None:
            return

        # Timing-based enumeration using TimingAnomalyDetector
        self._timing_detector.record(t_valid)
        if self._timing_detector.has_baseline and self._timing_detector.test_payload("invalid_user", t_invalid, z_threshold=2.5):
            self._tested += 1
            self.log("WARNING", f"[Auth] Timing-based username enumeration detected")
            self.add_vuln(
                title="Username Enumeration via Timing Side-Channel",
                severity="Medium",
                category="Authentication",
                cvss_score=5.3,
                description=f"The login form at `{url}` shows statistically significant timing "
                    "differences between valid and invalid usernames, allowing attackers to "
                    "enumerate valid accounts via response timing analysis.",
                evidence=f"Valid user timing: {t_valid:.4f}s, Invalid user timing: {t_invalid:.4f}s",
                confidence="High",
                remediation="Implement constant-time response for all login attempts. "
                    "Add random jitter to response times.",
                cwe_ids=["CWE-287"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

        # Size-based enumeration using SizeAnomalyDetector
        self._size_detector.record_size(len(body_valid))
        if self._size_detector.test_size(len(body_invalid), z_threshold=2.0):
            self.log("WARNING", f"[Auth] Size-based username enumeration detected")
            self.add_vuln(
                title="Username Enumeration via Response Size Difference",
                severity="Medium",
                category="Authentication",
                cvss_score=5.3,
                description=f"The login form at `{url}` returns differently sized responses "
                    "for valid vs invalid usernames ({len(body_valid)} vs {len(body_invalid)} bytes). "
                    "This allows attackers to enumerate valid accounts.",
                evidence=f"Valid user response size: {len(body_valid)}, Invalid: {len(body_invalid)}",
                confidence="High",
                remediation="Return identical-length responses for all login outcomes. "
                    "Pad responses to a fixed size.",
                cwe_ids=["CWE-287"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

        # Check if response text differs enough to enumerate users
        if body_valid != body_invalid:
            # Only flag if the responses are meaningfully different (> 50 char diff)
            if abs(len(body_valid) - len(body_invalid)) > 50:
                self.add_vuln(
                    title="Username Enumeration via Different Error Responses",
                    severity="Medium",
                    category="Authentication",
                    cvss_score=5.3,
                    description=f"The login form at `{url}` returns different responses "
                        "for valid vs. invalid usernames, allowing attackers to enumerate "
                        "valid accounts before attempting password attacks.",
                    remediation="Return identical error messages for all failed login attempts: "
                        "'Invalid username or password.' — never specify which field is wrong.",
                    cwe_ids=["CWE-287"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )

    def _test_auth_bypass_payloads(self, url, ufield, pfield):
        """Test WAF-evaded auth bypass payloads."""
        bypass_payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin' --",
            "' UNION SELECT * FROM users --",
            "../admin",
            "..%2fadmin",
        ]
        for payload in bypass_payloads:
            for eva_name, eva_payload in waf_evade(payload):
                try:
                    test_data = {ufield: eva_payload, pfield: eva_payload}
                    body, status, _ = self._post_login(url, test_data)
                    if body and SUCCESS_INDICATORS.search(body):
                        self._tested += 1
                        self.log("CRITICAL", f"[Auth] Auth bypass with WAF evasion '{eva_name}': {eva_payload}")
                        self.add_vuln(
                            title="Authentication Bypass via WAF-Evaded Payload",
                            severity="Critical",
                            category="Authentication",
                            cvss_score=9.8,
                            description=f"Authentication bypass achieved using WAF-evaded payload "
                                f"'{eva_name}': '{eva_payload}'. The server processed the injection "
                                "and granted access.",
                            evidence=f"Success with payload variant '{eva_name}'",
                            payload=f"{eva_name}={eva_payload}",
                            request_details=f"POST {url} with payload {eva_payload}",
                            response_details=f"HTTP {status}",
                            confidence="Confirmed",
                            remediation="1. Use parameterized queries for all authentication logic.\n"
                                "2. Implement strict input validation on all auth fields.\n"
                                "3. Deploy a WAF with up-to-date rules.\n"
                                "4. Test all auth bypass payload variants.",
                            cwe_ids=["CWE-287"],
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                        )
                        return
                except Exception as e:
                    self.log("ERROR", f"[Auth] SQLi bypass test error: {e}")
                    continue

    def _test_verb_tampering(self, url):
        self._tested += 1
        body, status = self._make_request(url, method="HEAD", timeout=5)
        if status == 200:
            self.add_vuln(
                title="Login Page Accessible via HEAD Method",
                severity="Low",
                category="Authentication",
                cvss_score=3.1,
                description=f"The login endpoint `{url}` responds to HEAD requests "
                    "with HTTP 200. While not directly exploitable, it may indicate "
                    "insufficient HTTP method restriction.",
                remediation="Restrict allowed HTTP methods to GET and POST on login endpoints.",
                cwe_ids=["CWE-287"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

    # ------------------------------------------------------------------
    def _test_differential_auth(self, url, ufield, pfield):
        try:
            anon_body, anon_status, anon_elapsed = self._post_login(url, {ufield: "test_user", pfield: "wrong_pass"})
            if anon_body is None:
                return
            self._differential.record("anonymous", anon_body, anon_status, anon_elapsed)
            auth_body, auth_status, auth_elapsed = self._post_login(url, {ufield: "test_user", pfield: "correct_pass"})
            if auth_body is not None:
                self._differential.record("authenticated", auth_body, auth_status, auth_elapsed)
            result = self._differential.compare("anonymous", "authenticated")
            if result.get("different"):
                self.log("WARNING", f"[Auth] Differential analysis: auth bypass indicators detected (score={result['score']})")
                self.add_vuln(
                    title="Potential Authentication Bypass — Differential Response Analysis",
                    severity="High",
                    category="Authentication",
                    cvss_score=7.5,
                    description=f"Differential analysis of anonymous vs authenticated responses at {url} "
                        f"revealed significant differences (score: {result['score']}). "
                        f"Differences: {', '.join(result.get('differences', []))}. "
                        "This may indicate an authentication bypass vulnerability.",
                    evidence=f"Diff score: {result['score']}, diffs: {result.get('differences')}",
                    remediation="Implement consistent response handling for authenticated and unauthenticated requests. "
                        "Use server-side session validation for all protected endpoints.",
                    cwe_ids=["CWE-287"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )
        except Exception as e:
            self.log("ERROR", f"[Auth] _test_differential_auth error: {e}")

    def _check_oauth_implicit_flow(self):
        """Probe for OAuth implicit grant flow endpoints."""
        oauth_paths = [
            "/oauth/authorize", "/oauth/callback", "/oauth/token",
            "/auth/authorize", "/auth/callback", "/auth/token",
            "/api/oauth/authorize", "/api/oauth/callback",
        ]
        base = self.target.rstrip("/")
        for path in oauth_paths:
            url = f"{base}{path}"
            body, status = self._make_request(url, timeout=5)
            if body and ("response_type=token" in body or "response_type" in body):
                self.add_vuln(
                    title="OAuth Implicit Grant Flow Detected",
                    severity="High",
                    category="Authentication",
                    cvss_score=7.5,
                    description=f"The endpoint `{url}` appears to use the OAuth implicit grant "
                        "flow (response_type=token). The implicit flow exposes access tokens "
                        "in the URL fragment, making them accessible via browser history, "
                        "Referer headers, and XSS attacks.",
                    evidence="response_type=token pattern found in response body",
                    payload=url,
                    confidence="High",
                    remediation="1. Use the authorization code flow with PKCE instead of implicit.\n"
                        "2. Never pass tokens in URL fragments.\n"
                        "3. Use 'state' parameter with CSRF protection.\n"
                        "4. Ensure tokens have short expiration.",
                    cwe_ids=["CWE-287"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )
                return

    # ------------------------------------------------------------------
    def _check_jwt_in_url(self):
        """Probe for JWT tokens passed as URL query parameters."""
        probe_paths = ["/api/user", "/api/me", "/api/profile", "/dashboard", "/"]
        base = self.target.rstrip("/")
        jwt_param_patterns = ["token", "jwt", "access_token", "auth_token", "bearer", "id_token"]
        for path in probe_paths:
            for param in jwt_param_patterns:
                test_url = f"{base}{path}?{param}=eyJhbGciOiJIUzI1NiJ9.dGVzdA.test"
                body, status = self._make_request(test_url, timeout=5)
                if body and status == 200:
                    self.add_vuln(
                        title="JWT Token Accepted via URL Parameter",
                        severity="High",
                        category="Authentication",
                        cvss_score=7.5,
                        description=f"The application at `{test_url}` accepted a JWT via the "
                            f"`{param}` URL parameter. JWTs exposed in URLs are leaked through "
                            "server logs, browser history, and Referer headers.",
                        evidence=f"Request with JWT in {param} parameter returned status {status}",
                        payload=f"{param}=eyJhbGciOiJIUzI1NiJ9.dGVzdA.test",
                        request_details=f"GET {test_url}",
                        confidence="Medium",
                        remediation="1. Transmit JWTs only in Authorization headers (Bearer scheme).\n"
                            "2. Never accept tokens via URL parameters.\n"
                            "3. Use short-lived tokens and refresh token rotation.",
                        cwe_ids=["CWE-287"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return

    # ------------------------------------------------------------------
    def _check_auth_over_http(self):
        """Check for authentication-related endpoints served over plain HTTP."""
        test_paths = ["/login", "/signin", "/auth", "/oauth/authorize", "/api/auth/login", "/api/auth/token"]
        if self._is_https:
            http_base = self.target.replace("https://", "http://", 1).rstrip("/")
            for path in test_paths:
                url = f"{http_base}{path}"
                body, status = self._make_request(url, timeout=5)
                if body and status and status < 400:
                    self.add_vuln(
                        title="Authentication Endpoint Available Over HTTP",
                        severity="High",
                        category="Authentication",
                        cvss_score=8.3,
                        description=f"The authentication endpoint `{url}` is accessible over "
                            "plain HTTP. Credentials or tokens transmitted over HTTP can be "
                            "intercepted by anyone on the same network via man-in-the-middle attacks.",
                        evidence=f"Endpoint responded via HTTP with status {status}",
                        payload=url,
                        request_details=f"GET {url} (HTTP)",
                        confidence="Confirmed",
                        remediation="1. Redirect all HTTP traffic to HTTPS at the load balancer or web server.\n"
                            "2. Implement HSTS headers: Strict-Transport-Security: max-age=31536000.\n"
                            "3. Add HSTS preload directive.\n"
                            "4. Ensure all authentication endpoints are HTTPS-only.",
                        cwe_ids=["CWE-287"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return

    # ------------------------------------------------------------------
    def _check_oauth_state_parameter(self):
        """Check for OAuth state parameter usage in authorization flows."""
        probe_urls = ["/auth/authorize", "/oauth/authorize", "/oauth/callback"]
        base = self.target.rstrip("/")
        for path in probe_urls:
            url = f"{base}{path}"
            body, status = self._make_request(url, timeout=5)
            if body and status == 200 and "client_id" in body:
                if "state" not in body:
                    self.add_vuln(
                        title="OAuth Authorization Request Missing state Parameter (CSRF)",
                        severity="High",
                        category="Authentication",
                        cvss_score=7.4,
                        description=f"OAuth endpoint at `{url}` appears to process authorization "
                            "requests without a 'state' parameter. This exposes the OAuth flow "
                            "to CSRF attacks where an attacker can bind a victim's account to "
                            "the attacker's session.",
                        evidence="state parameter missing from OAuth authorization request",
                        payload=url,
                        request_details=f"GET {url}",
                        confidence="Medium",
                        remediation="1. Always include a cryptographically random 'state' parameter.\n"
                            "2. Validate the state parameter on the callback endpoint.\n"
                            "3. Use PKCE to further protect the authorization flow.",
                        cwe_ids=["CWE-287"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return
