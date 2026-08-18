"""
cookie_scanner.py — Cookie Security Flags Auditor
==================================================
Performs a deep audit of all Set-Cookie headers across the site:
  - Secure flag (absent on HTTPS)
  - HttpOnly flag (missing XSS protection)
  - SameSite attribute (None / Lax / Strict / absent)
  - __Host- / __Secure- prefix compliance
  - Excessive cookie lifetime (> 1 year)
  - Sensitive names without protection
  - Cookie scoping (Domain= too broad)
  - Path= attribute
"""
import re, ssl, urllib.request, urllib.error, urllib.parse
from scanners.base_scanner import BaseScanner

# Cookie names that strongly suggest session / auth usage
SENSITIVE_NAMES = re.compile(
    r"(sess|session|auth|token|jwt|access|refresh|user|uid|account|login|"
    r"remember|csrf|xsrf|cart|order|payment)", re.I
)

MAX_SAFE_AGE_SECONDS = 365 * 24 * 3600   # 1 year


class CookieScanner(BaseScanner):
    SCANNER_NAME = "Cookie Security Auditor"
    _SCANNER_KEY = "cookie"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._is_https = self.target.startswith("https://")

    # ------------------------------------------------------------------
    def run(self) -> list:
        self.log("INFO", f"[Cookies] Starting cookie security audit on {self.target}...")

        try:
            endpoints = self._crawl()
            seen_cookies: set = set()

            for url in endpoints:
                cookies = self._collect_cookies(url)
                for name, attrs, raw in cookies:
                    key = (name.lower(), url)
                    if key in seen_cookies:
                        continue
                    seen_cookies.add(key)
                    self._audit_cookie(name, attrs, raw, url)

            self._check_cookie_scope(url if endpoints else self.target)
            self._check_session_without_expiration()
            self._check_persistent_cookies()

        except Exception as e:
            self.log("WARNING", f"[Cookies] Audit error: {e}")

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[Cookies] Audit complete. {len(self.vulns)} issue(s) found.",
        )
        return self.vulns

    # ------------------------------------------------------------------
    def _crawl(self) -> list:
        try:
            # GAP-ADV: Centralized context
            if self.discovery_context and "urls" in self.discovery_context:
                return [u.get("url") if isinstance(u, dict) else u for u in self.discovery_context["urls"]]
            return [self.target][:20]
        except Exception as e:
            self.log("ERROR", f"[Cookies] _crawl error: {e}")
            return [self.target]

    # ------------------------------------------------------------------
    def _collect_cookies(self, url: str) -> list:
        """Return list of (name, attrs_dict, raw_header) tuples."""
        cookies = []
        try:
            headers = {"User-Agent": "LarShield/2.0 Cookie-Auditor"}
            headers.update(self.auth_headers or {})
            body, status, resp_headers = self._make_request(url, headers=headers, timeout=8, return_response_obj=True)

            raw_headers = resp_headers.get_all("Set-Cookie") if hasattr(resp_headers, "get_all") else []
            if raw_headers is None: raw_headers = []
            for raw in raw_headers:
                name, attrs = self._parse_cookie(raw)
                if name:
                    cookies.append((name, attrs, raw))

        except Exception as e:
            self.log("ERROR", f"[Cookies] _collect_cookies error: {e}")
        return cookies

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_cookie(raw: str) -> tuple:
        """Parse a Set-Cookie header into (name, attrs_dict)."""
        parts  = [p.strip() for p in raw.split(";")]
        if not parts:
            return None, {}
        name_val = parts[0].split("=", 1)
        name     = name_val[0].strip()
        attrs    = {}
        for part in parts[1:]:
            kv = part.split("=", 1)
            attrs[kv[0].strip().lower()] = kv[1].strip() if len(kv) > 1 else True
        return name, attrs

    # ------------------------------------------------------------------
    def _audit_cookie(self, name: str, attrs: dict, raw: str, url: str):
        is_sensitive = bool(SENSITIVE_NAMES.search(name))
        issues = []

        # ── Secure flag ───────────────────────────────────────────────
        if self._is_https and "secure" not in attrs:
            issues.append("missing Secure flag")
            self.add_vuln(
                title=f"Cookie '{name}' Missing Secure Flag",
                severity="Medium",
                category="Cookie Security",
                cvss_score=5.3,
                description=(
                    f"The cookie `{name}` set at `{url}` does not have the `Secure` flag. "
                    "On an HTTPS site, omitting Secure allows the cookie to be transmitted "
                    "over plain HTTP, exposing it to network eavesdroppers."
                ),
                remediation=(
                    f"Set-Cookie: {name}=<value>; Secure; HttpOnly; SameSite=Strict\n"
                    "Ensure all cookies on HTTPS sites include the Secure attribute."
                ),
            )

        # ── HttpOnly flag ─────────────────────────────────────────────
        if "httponly" not in attrs and is_sensitive:
            issues.append("missing HttpOnly flag on sensitive cookie")
            self.add_vuln(
                title=f"Sensitive Cookie '{name}' Missing HttpOnly Flag",
                severity="High",
                category="Cookie Security",
                cvss_score=7.4,
                description=(
                    f"The cookie `{name}` at `{url}` appears to be a session/auth cookie "
                    "(its name matches sensitive patterns) but does not have the `HttpOnly` "
                    "flag set. This allows JavaScript code to read it via `document.cookie`, "
                    "making it trivially stealable via any XSS vulnerability."
                ),
                remediation=(
                    f"Set-Cookie: {name}=<value>; HttpOnly; Secure; SameSite=Strict\n"
                    "Add HttpOnly to all session and authentication cookies."
                ),
            )

        # ── SameSite attribute ────────────────────────────────────────
        samesite = attrs.get("samesite", None)
        if samesite is None:
            issues.append("missing SameSite attribute")
            sev = "High" if is_sensitive else "Medium"
            self.add_vuln(
                title=f"Cookie '{name}' Missing SameSite Attribute",
                severity=sev,
                category="Cookie Security",
                cvss_score=6.5 if is_sensitive else 4.3,
                description=(
                    f"The cookie `{name}` at `{url}` has no `SameSite` attribute. "
                    "Without SameSite, the cookie is sent on all cross-site requests, "
                    "enabling Cross-Site Request Forgery (CSRF) attacks."
                ),
                remediation=(
                    f"Set-Cookie: {name}=<value>; SameSite=Strict; Secure; HttpOnly\n"
                    "Use SameSite=Strict for session cookies, Lax for others."
                ),
            )
        elif samesite.lower() == "none":
            if "secure" not in attrs:
                self.add_vuln(
                    title=f"Cookie '{name}' SameSite=None Without Secure",
                    severity="High",
                    category="Cookie Security",
                    cvss_score=7.5,
                    description=(
                        f"Cookie `{name}` at `{url}` has `SameSite=None` but is missing "
                        "the `Secure` flag. Modern browsers reject such cookies; when they "
                        "fall back to legacy behaviour, they become vulnerable to CSRF."
                    ),
                    remediation="Set-Cookie: SameSite=None; Secure",
                )

        # ── Cookie lifetime ───────────────────────────────────────────
        max_age = attrs.get("max-age")
        if max_age and max_age is not True:
            try:
                if int(max_age) > MAX_SAFE_AGE_SECONDS:
                    self.add_vuln(
                        title=f"Cookie '{name}' Has Excessive Lifetime",
                        severity="Low",
                        category="Cookie Security",
                        cvss_score=3.1,
                        description=(
                            f"Cookie `{name}` has Max-Age={max_age}s "
                            f"(>{MAX_SAFE_AGE_SECONDS // (365*3600*24)} years). "
                            "Long-lived session cookies increase the window of attack "
                            "after a user's session is compromised or stolen."
                        ),
                        remediation=(
                            "Limit session cookie lifetime to the session duration.\n"
                            "Use short Max-Age values and implement server-side session expiry."
                        ),
                    )
            except ValueError:
                pass

        # ── __Host- / __Secure- prefix compliance ─────────────────────
        if name.startswith("__Host-"):
            if "secure" not in attrs or "domain" in attrs or attrs.get("path","") != "/":
                self.add_vuln(
                    title=f"__Host- Cookie '{name}' Prefix Violation",
                    severity="Medium",
                    category="Cookie Security",
                    cvss_score=5.3,
                    description=(
                        f"Cookie `{name}` uses the `__Host-` prefix but violates its "
                        "requirements (must have Secure, no Domain=, Path=/)."
                    ),
                    remediation=(
                        "For __Host- cookies: set Secure, omit Domain=, set Path=/."
                    ),
                )
        if name.startswith("__Secure-") and "secure" not in attrs:
            self.add_vuln(
                title=f"__Secure- Cookie '{name}' Missing Secure Flag",
                severity="Medium",
                category="Cookie Security",
                cvss_score=5.3,
                description=(
                    f"Cookie `{name}` uses the `__Secure-` prefix but is missing the "
                    "`Secure` flag, violating the prefix contract."
                ),
                remediation="Add the Secure flag to all __Secure- prefixed cookies.",
            )

        if not issues:
            self.log("SUCCESS", f"[Cookies] Cookie '{name}' — all flags OK")
        else:
            self.log("WARNING", f"[Cookies] Cookie '{name}' issues: {', '.join(issues)}")

    # ------------------------------------------------------------------
    def _check_cookie_scope(self, url: str):
        """Analyze cookie Domain and Path attributes for overly broad scoping."""
        cookies = self._collect_cookies(url)
        target_domain = urllib.parse.urlparse(self.target).hostname or ""

        for name, attrs, raw in cookies:
            # Check Domain attribute
            domain = attrs.get("domain", "")
            if domain:
                domain = domain.lstrip(".")
                if target_domain and domain != target_domain and not target_domain.endswith("." + domain):
                    self.add_vuln(
                        title=f"Cookie '{name}' Has Overly Broad Domain Scope",
                        severity="Medium",
                        category="Cookie Security",
                        cvss_score=5.3,
                        description=f"The cookie `{name}` has Domain=`{domain}` which is broader "
                            f"than the target domain `{target_domain}`. Cookies scoped to a broader "
                            "domain are sent to all subdomains, increasing exposure.",
                        evidence=f"Domain={domain}, Target={target_domain}",
                        request_details=f"Set-Cookie: {raw[:100]}",
                        confidence="High",
                        remediation="1. Set Domain to the exact origin domain.\n"
                            "2. Avoid broad domain scoping for session cookies.\n"
                            "3. Use __Host- prefix cookies which forbid Domain attribute.",
                    )

            # Check Path attribute
            path = attrs.get("path", "/")
            if path == "/":
                self.add_vuln(
                    title=f"Cookie '{name}' Has Root Path Scope (Path=/)",
                    severity="Low",
                    category="Cookie Security",
                    cvss_score=2.6,
                    description=f"The cookie `{name}` has Path=/ which means it is sent to "
                        "all endpoints on the domain. Consider restricting the path to reduce "
                        "the cookie's exposure.",
                    evidence=f"Path={path}",
                    request_details=f"Set-Cookie: {raw[:100]}",
                    confidence="Medium",
                    remediation="1. Set Path to the specific application path.\n"
                        "2. For admin-only cookies, use Path=/admin.\n"
                        "3. Use __Host- prefix cookies which require Path=/ only.",
                )

    # ------------------------------------------------------------------
    def _check_session_without_expiration(self):
        """Check if session cookies have no expiration (should be session-scoped)."""
        session_keywords = re.compile(r"(sess|session|sid|token|auth|jwt)", re.I)
        cookies = self._collect_cookies(self.target)

        for name, attrs, raw in cookies:
            if not session_keywords.search(name):
                continue

            has_max_age = "max-age" in attrs
            has_expires = "expires" in attrs

            if not has_max_age and not has_expires:
                self.add_vuln(
                    title=f"Session Cookie '{name}' Has No Expiration",
                    severity="Medium",
                    category="Cookie Security",
                    cvss_score=5.3,
                    description=f"The session cookie `{name}` has no Max-Age or Expires attribute. "
                        "While this likely means it is a session cookie (deleted on browser close), "
                        "it should be explicitly configured for clarity and consistency.",
                    evidence=f"Set-Cookie: {raw[:100]}",
                    request_details=f"GET {self.target}",
                    response_details=f"Set-Cookie: {raw[:100]}",
                    confidence="Info",
                    remediation="1. Explicitly set session cookie: remove Max-Age/Expires.\n"
                        "2. For persistent sessions, set reasonable Max-Age.\n"
                        "3. Implement server-side session expiry as a fallback.",
                )

    # ------------------------------------------------------------------
    def _check_persistent_cookies(self):
        """Detect cookies with long expiration (persistent cookies) that may be risky."""
        cookies = self._collect_cookies(self.target)
        for name, attrs, raw in cookies:
            max_age = attrs.get("max-age")
            expires = attrs.get("expires")
            duration_days = 0

            if max_age and max_age is not True:
                try:
                    duration_days = int(max_age) / 86400
                except (ValueError, TypeError):
                    pass

            if duration_days > 30:
                self.add_vuln(
                    title=f"Persistent Cookie '{name}' With Long Expiration ({duration_days:.0f} days)",
                    severity="Low",
                    category="Cookie Security",
                    cvss_score=3.1,
                    description=f"The cookie `{name}` has a Max-Age of {int(duration_days)} days. "
                        "Persistent cookies with long lifetimes increase the risk of session hijacking "
                        "and should be audited for necessity.",
                    evidence=f"Max-Age={max_age}s ({duration_days:.0f} days)",
                    request_details=f"Set-Cookie: {raw[:100]}",
                    confidence="Medium",
                    remediation="1. Use session cookies (no expiration) for authentication.\n"
                        "2. Limit persistent cookie lifetime to a maximum of 30 days.\n"
                        "3. Implement refresh token rotation for long-lived sessions.",
                )
