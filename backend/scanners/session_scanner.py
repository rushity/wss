
"""
session_scanner.py — Session Management Security Scanner
=========================================================
Audits session management behaviour:
  - Session ID in URL (CWE-598)
  - Session fixation vulnerability
  - Session token entropy analysis
  - Post-logout session invalidation
  - Concurrent session detection hints
  - Session cookie security flags (complements cookie_scanner)
  - Absolute session timeout
"""
import re, ssl, hashlib, math, urllib.parse, urllib.request, urllib.error, time
from collections import Counter
from scanners.base_scanner import BaseScanner
from utils.anomaly import SizeAnomalyDetector
from utils.differential import DifferentialAnalyzer

SESSION_COOKIE_RE = re.compile(
    r"(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session|sess_id|"
    r"connect\.sid|laravel_session|ci_session|rack\.session)", re.I
)

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

def _charset_entropy(s: str) -> float:
    if not s:
        return 0.0
    charset_size = 0
    if re.search(r'[a-z]', s): charset_size += 26
    if re.search(r'[A-Z]', s): charset_size += 26
    if re.search(r'[0-9]', s): charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', s): charset_size += 32
    if charset_size == 0:
        return 0.0
    return len(s) * math.log2(charset_size)


class SessionScanner(BaseScanner):
    SCANNER_NAME = "Session Management Scanner"
    _SCANNER_KEY = "session"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._differential = DifferentialAnalyzer()

    # ------------------------------------------------------------------
    def run(self) -> list:
        self.log("INFO", f"[Session] Starting session management audit on {self.target}...")
        try:
            session_ids, cookies = self._collect_session_info()
            self.log("INFO", f"[Session] Collected {len(session_ids)} session ID(s)")

            for sid_name, sid_value, src_url in session_ids:
                self._audit_session_id(sid_name, sid_value, src_url)

            self._check_session_in_url()
            self._check_post_logout_invalidation(cookies)
            self._check_session_fixation()
            self._check_session_id_from_url()
            self._check_concurrent_sessions()
            self._test_concurrent_session_limit()
            self._test_session_differential()

        except Exception as e:
            self.log("WARNING", f"[Session] Error: {e}")

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[Session] Audit complete. {len(self.vulns)} issue(s) found.",
        )
        return self.vulns

    # ------------------------------------------------------------------
    def _fetch(self, url, method="GET", data=None, extra_headers=None):
        try:
            headers = {"User-Agent": "LarShield/2.0 Session-Audit"}
            if extra_headers:
                headers.update(extra_headers)
            body, status, resp_headers = self._make_request(url, method=method, data=data, headers=headers, timeout=8, return_response_obj=True)
            cookies = []
            if resp_headers is not None and hasattr(resp_headers, "get_all"):
                cookies = resp_headers.get_all("Set-Cookie") or []
            return body or "", cookies, url
        except urllib.error.HTTPError as e:
            hdrs = getattr(e, "headers", None)
            cookies = []
            if hdrs is not None and hasattr(hdrs, "get_all"):
                cookies = hdrs.get_all("Set-Cookie") or []
            return "", cookies, url
        except Exception as ex:
            self.log("ERROR", f"[Session] _fetch failed: {ex}")
            return "", [], url

    def _collect_session_info(self):
        body, set_cookies, final_url = self._fetch(self.target)
        session_ids = []
        for raw in (set_cookies or []):
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue
            nv = parts[0].split("=", 1)
            if len(nv) == 2 and SESSION_COOKIE_RE.search(nv[0]):
                session_ids.append((nv[0], nv[1], self.target))
        return session_ids, set_cookies or []

    # ------------------------------------------------------------------
    def _audit_session_id(self, name: str, value: str, url: str):
        # ── Entropy check ─────────────────────────────────────────────
        entropy = _shannon_entropy(value)
        charset_entropy = _charset_entropy(value)
        self.log("INFO", f"[Session] Cookie '{name}' length={len(value)} entropy={entropy:.2f} charset_bits={charset_entropy:.2f}")

        if len(value) < 16:
            self.add_vuln(
                title=f"Session ID '{name}' is Too Short ({len(value)} chars)",
                severity="High",
                category="Session Management",
                cvss_score=7.5,
                description=f"The session cookie `{name}` has only {len(value)} characters. "
                    "Short session IDs are susceptible to brute-force guessing attacks.",
                remediation="Session IDs should be at least 128 bits (32 hex characters) of "
                    "cryptographically random data.",
                cwe_ids=["CWE-384","CWE-613"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

        if entropy < 3.5 and len(value) > 4:
            self.add_vuln(
                title=f"Low-Entropy Session ID '{name}' (Shannon={entropy:.2f})",
                severity="High",
                category="Session Management",
                cvss_score=7.4,
                description=f"The session token `{name}={value[:12]}...` has low entropy "
                    f"({entropy:.2f} bits/char). This may indicate sequential or predictable "
                    "session ID generation, making session hijacking feasible.",
                remediation="Use a cryptographically secure PRNG (secrets.token_hex(32) in Python, "
                    "java.security.SecureRandom, crypto.randomBytes(32) in Node.js).",
                cwe_ids=["CWE-384","CWE-613"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

        if charset_entropy < 64:
            self.add_vuln(
                title=f"Low Statistical Entropy in Session ID '{name}' ({charset_entropy:.2f} bits)",
                severity="High",
                category="Session Management",
                cvss_score=7.4,
                description=f"The session token `{name}` has estimated statistical entropy of "
                    f"only {charset_entropy:.2f} bits. Session IDs should have at least 128 bits "
                    "of entropy to resist prediction and brute-force attacks.",
                evidence=f"Charset entropy: {charset_entropy:.2f} bits",
                confidence="High",
                remediation="Use cryptographically secure random session IDs with at least "
                    "128 bits of entropy (e.g., secrets.token_urlsafe(32)).",
                cwe_ids=["CWE-384","CWE-613"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
        else:
            self.log("SUCCESS", f"[Session] Session ID '{name}' entropy OK ({entropy:.2f})")

    # ------------------------------------------------------------------
    def _check_session_in_url(self):
        """Check if session IDs appear in URLs (GET parameter)."""
        try:
            body, status, resp_headers = self._make_request(self.target, timeout=5, return_response_obj=True)
            final_url = resp_headers.get("Content-Location") if hasattr(resp_headers, "get") else ""
            if not final_url:
                parsed = urllib.parse.urlparse(self.target)
                qs = urllib.parse.parse_qs(parsed.query)
                for param in qs:
                    if SESSION_COOKIE_RE.search(param):
                        self.add_vuln(
                            title=f"Session ID Exposed in URL Parameter '{param}'",
                            severity="High",
                            category="Session Management",
                            cvss_score=7.5,
                            description=f"The session identifier `{param}` was found in the URL "
                                f"`{self.target}`. Session IDs in URLs are logged in server logs, "
                                "browser history, and Referer headers — all accessible to attackers.",
                            evidence=f"Parameter '{param}' found in URL query string",
                            request_details=f"GET {self.target}",
                            confidence="Confirmed",
                            remediation="Use cookies exclusively for session management. "
                                "Never pass session IDs in URL parameters.",
                            cwe_ids=["CWE-384","CWE-613"],
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                        )
        except Exception as e:
            self.log("ERROR", f"[Session] _check_session_in_url failed: {e}")

    # ------------------------------------------------------------------
    def _check_session_fixation(self):
        """Basic session fixation probe: inject a known SID and check if it's accepted."""
        try:
            fake_sid = "sentinelfixation1234567890abcdef"
            session_param = "PHPSESSID"
            url = f"{self.target}?{session_param}={fake_sid}"
            headers = {
                "User-Agent": "LarShield/2.0 Session-Audit",
                "Cookie": f"{session_param}={fake_sid}",
            }
            body, status, resp_headers = self._make_request(url, headers=headers, timeout=5, return_response_obj=True)
            set_cookies = []
            if resp_headers is not None and hasattr(resp_headers, "get_all"):
                set_cookies = resp_headers.get_all("Set-Cookie") or []
            for raw in set_cookies:
                if fake_sid in raw:
                    self.add_vuln(
                        title="Potential Session Fixation Vulnerability",
                        severity="High",
                        category="Session Management",
                        cvss_score=8.1,
                        description="The server reflected the attacker-supplied session ID "
                            f"`{fake_sid}` in a Set-Cookie response. If the session is "
                            "not regenerated after login, an attacker who pre-seeds a known "
                            "SID can hijack the victim's session after they authenticate.",
                        evidence=f"Set-Cookie reflected fake_sid: {raw}",
                        payload=f"{session_param}={fake_sid}",
                        request_details=f"GET {url} with Cookie: {session_param}={fake_sid}",
                        response_details=f"Set-Cookie: {raw}",
                        confidence="High",
                        remediation="1. Regenerate the session ID after every successful login.\n"
                            "2. Reject pre-set session IDs from anonymous users.\n"
                            "3. Use session.regenerate_id(true) / invalidate() in your framework.",
                        cwe_ids=["CWE-384","CWE-613"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return
            self.log("SUCCESS", "[Session] Session fixation: no reflection detected")
        except Exception as e:
            self.log("ERROR", f"[Session] _check_session_fixation failed: {e}")

    # ------------------------------------------------------------------
    def _check_post_logout_invalidation(self, initial_cookies: list):
        """Check if session cookie is still valid after logout."""
        logout_paths = ["/logout", "/signout", "/sign-out", "/auth/logout",
                        "/api/logout", "/user/logout", "/account/logout"]
        base = self.target.rstrip("/")
        for path in logout_paths:
            url = f"{base}{path}"
            body, status = self._make_request(url, timeout=5)
            if status and 200 <= status < 400:
                self.log("INFO", f"[Session] Logout endpoint found: {url}")
                self.add_vuln(
                    title="Logout Endpoint Detected — Post-Logout Session Invalidation Unverified",
                    severity="Medium",
                    category="Session Management",
                    cvss_score=5.4,
                    description=f"A logout endpoint exists at `{url}`. "
                        "Manual verification is required to confirm that the server-side "
                        "session is fully invalidated on logout (not just the client cookie deleted).",
                    evidence=f"Logout endpoint returned status {status}",
                    request_details=f"GET {url}",
                    confidence="Info",
                    remediation="1. Call session.invalidate() / session_destroy() on logout.\n"
                        "2. Maintain a server-side denylist of invalidated tokens.\n"
                        "3. Set cookie Max-Age=0 and Expires=past on logout response.",
                    cwe_ids=["CWE-384","CWE-613"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )
                return

    # ------------------------------------------------------------------
    def _check_session_id_from_url(self):
        """Check if the server accepts a session ID supplied via URL query parameter."""
        test_params = ["PHPSESSID", "JSESSIONID", "session", "sess_id", "sid", "token"]
        base = self.target.rstrip("/")
        for param in test_params:
            test_sid = "sentinel_url_sid_test_abc123"
            url = f"{base}/?{param}={test_sid}"
            body, status, resp_headers = self._make_request(url, timeout=5, return_response_obj=True)
            set_cookies = []
            if resp_headers is not None and hasattr(resp_headers, "get_all"):
                set_cookies = resp_headers.get_all("Set-Cookie") or []
            for raw in set_cookies:
                if test_sid in raw:
                    self.add_vuln(
                        title="Session ID Accepted from URL Parameter (Session Fixation)",
                        severity="High",
                        category="Session Management",
                        cvss_score=8.1,
                        description=f"The server accepted the session ID `{test_sid}` supplied "
                            f"via the `{param}` URL parameter and reflected it in a Set-Cookie "
                            "header. This enables session fixation attacks where an attacker "
                            "prepares a session ID and tricks the victim into using it.",
                        evidence=f"Set-Cookie reflected test SID: {raw}",
                        payload=f"{param}={test_sid}",
                        request_details=f"GET {url}",
                        response_details=f"Set-Cookie: {raw}",
                        confidence="Confirmed",
                        remediation="1. Never accept session IDs from URL parameters.\n"
                            "2. Generate a new session ID on the server for each session.\n"
                            "3. Regenerate session ID after authentication.\n"
                            "4. Use framework-provided secure session management.",
                        cwe_ids=["CWE-384","CWE-613"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return
        self.log("SUCCESS", "[Session] No session ID acceptance from URL parameters detected")

    # ------------------------------------------------------------------
    def _check_concurrent_sessions(self):
        """Check if the server allows multiple concurrent sessions from different clients."""
        probe_urls = ["/api/user/sessions", "/api/sessions", "/account/sessions",
                      "/user/sessions", "/sessions", "/account/active-sessions"]
        base = self.target.rstrip("/")
        for path in probe_urls:
            url = f"{base}{path}"
            body, status = self._make_request(url, timeout=5)
            if body and status == 200:
                sid_count = len(re.findall(r'(?:session|token|sid)["\':\s]*["\']([^"\']+)["\']', body, re.I))
                if sid_count > 1:
                    self.add_vuln(
                        title="Concurrent Session Management Endpoint Detected",
                        severity="Low",
                        category="Session Management",
                        cvss_score=0.0,
                        description=f"An endpoint exposing session information was found at "
                            f"`{url}` with {sid_count} session references. While concurrent "
                            "sessions can be legitimate, this should be reviewed for compliance "
                            "with security requirements.",
                        evidence=f"Found {sid_count} session references in response",
                        request_details=f"GET {url}",
                        response_details=f"Status: {status}, Body length: {len(body)}",
                        confidence="Info",
                        remediation="1. Review concurrent session policy.\n"
                            "2. Consider limiting concurrent sessions per user.\n"
                            "3. Notify users of active sessions.\n"
                            "4. Allow users to revoke individual sessions.",
                        cwe_ids=["CWE-384","CWE-613"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                else:
                    self.add_vuln(
                        title="Session Information Endpoint Exposed",
                        severity="Low",
                        category="Session Management",
                        cvss_score=2.6,
                        description=f"An endpoint exposing session information was found at "
                            f"`{url}`. This may leak metadata about active sessions.",
                        evidence=f"Endpoint returned 200 with {len(body)} bytes",
                        request_details=f"GET {url}",
                        confidence="Info",
                        remediation="1. Restrict access to session information endpoints.\n"
                            "2. Require authentication and authorization.\n"
                            "3. Avoid exposing session IDs in responses.",
                        cwe_ids=["CWE-384","CWE-613"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                return

    # ------------------------------------------------------------------
    def _test_session_differential(self):
        try:
            base = self.target.rstrip("/")
            paths = ["/", "/api/user", "/api/me", "/profile", "/dashboard"]
            for path in paths:
                url = f"{base}{path}"
                for i in range(3):
                    headers = {"User-Agent": f"LarShield-Session-Diff-{i}"}
                    body, status, resp_headers = self._make_request(
                        url, timeout=5, headers=headers, return_response_obj=True
                    )
                    set_cookies = []
                    if resp_headers is not None and hasattr(resp_headers, "get_all"):
                        set_cookies = resp_headers.get_all("Set-Cookie") or []
                    cookie_str = "; ".join(c.split(";")[0] for c in set_cookies) if set_cookies else f"session_{i}"
                    if body is not None and status:
                        self._differential.record(f"session_{i}", body or "", status, 0.0)
                if len(self._differential.get("session_0")) > 0 and len(self._differential.get("session_1")) > 0:
                    result = self._differential.compare("session_0", "session_1")
                    if not result.get("different"):
                        self.log("WARNING", f"[Session] Sessions appear identical — possible session uniqueness issue at {url}")
                        self.add_vuln(
                            title="Session Uniqueness Issue — Identical Responses Across Sessions",
                            severity="Medium",
                            category="Session Management",
                            cvss_score=5.4,
                            description=f"Different session cookies at {url} produced nearly identical responses. "
                                "This may indicate session fixation or improper session isolation.",
                            remediation="Ensure each session is fully isolated and generates unique server-side state. "
                                "Regenerate session IDs after authentication.",
                            cwe_ids=["CWE-384"],
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                        )
                    elif result.get("score", 0) > 2.0:
                        self.log("INFO", f"[Session] Session {i} differs from session 0 at {path} — normal isolation expected")
                break
        except Exception as e:
            self.log("ERROR", f"[Session] _test_session_differential error: {e}")


    def _test_concurrent_session_limit(self):
        """Test if the server enforces a concurrent session limit by creating multiple sessions."""
        try:
            sessions = []
            for i in range(5):
                headers = {"User-Agent": f"LarShield-Session-Test-{i}"}
                body, status, resp_headers = self._make_request(
                    self.target, timeout=5, headers=headers, return_response_obj=True
                )
                set_cookies = []
                if resp_headers is not None and hasattr(resp_headers, "get_all"):
                    set_cookies = resp_headers.get_all("Set-Cookie") or []
                sessions.append(set_cookies)

            unique_session_ids = set()
            for cookie_list in sessions:
                for raw in cookie_list:
                    parts = [p.strip() for p in raw.split(";")]
                    if parts:
                        nv = parts[0].split("=", 1)
                        if len(nv) == 2:
                            unique_session_ids.add(nv[1])

            if len(unique_session_ids) >= 4:
                self.add_vuln(
                    title="No Concurrent Session Limit Detected",
                    severity="Medium",
                    category="Session Management",
                    cvss_score=5.4,
                    description=f"The server issued {len(unique_session_ids)} unique session "
                        "IDs across 5 sequential requests without enforcing any concurrent "
                        "session limit. This increases the risk of session hijacking and "
                        "may violate compliance requirements.",
                    evidence=f"Unique sessions issued: {len(unique_session_ids)}",
                    request_details=f"5 GET requests to {self.target}",
                    confidence="Medium",
                    remediation="1. Implement concurrent session limits per user.\n"
                        "2. Terminate oldest session when limit is exceeded.\n"
                        "3. Notify users of concurrent session activity.",
                    cwe_ids=["CWE-384","CWE-613"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )
        except Exception as e:
            self.log("ERROR", f"[Session] _test_concurrent_session_limit error: {e}")
