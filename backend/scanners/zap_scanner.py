"""
zap_scanner.py — OWASP ZAP integration via REST API with Python fallback.
==========================================================================
Connects to a running ZAP daemon if available.
Falls back to targeted Python-based checks when ZAP is not running.

ZAP daemon setup:
  zap.bat -daemon -port 8080 -config api.key=sentinel-zap-key-2026
  Set ZAP_API_KEY=sentinel-zap-key-2026 in .env

FIXES (July 2026):
  - Enhanced fallback mode with real HTTP checks (not just a skip)
  - More robust cleanup in finally block
  - Better scan_id_spider scoping fix
  - Added active scan progress log
"""
import os
import re
import time
import urllib.parse
from scanners.base_scanner import BaseScanner

# ZAP severity → WSS severity + CVSS mapping
ZAP_RISK_MAP = {
    "High":          ("High",     7.5),
    "Medium":        ("Medium",   5.3),
    "Low":           ("Low",      3.1),
    "Informational": ("Low",      2.0),
}

# ──────────────────────────────────────────────────────────────────────────────
# Security headers that ZAP would normally check (used in fallback)
SECURITY_HEADERS_REQUIRED = {
    "Strict-Transport-Security": {
        "desc": "HSTS not set — allows HTTP downgrade attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "severity": "Medium", "cvss": 5.3,
    },
    "X-Content-Type-Options": {
        "desc": "X-Content-Type-Options not set — allows MIME sniffing attacks.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "severity": "Low", "cvss": 3.1,
    },
    "X-Frame-Options": {
        "desc": "X-Frame-Options not set — allows clickjacking.",
        "remediation": "Add: X-Frame-Options: SAMEORIGIN",
        "severity": "Medium", "cvss": 5.3,
    },
    "Content-Security-Policy": {
        "desc": "Content-Security-Policy (CSP) not set — allows XSS and injection attacks.",
        "remediation": "Implement a restrictive CSP policy.",
        "severity": "Medium", "cvss": 5.3,
    },
    "X-XSS-Protection": {
        "desc": "X-XSS-Protection not set.",
        "remediation": "Add: X-XSS-Protection: 1; mode=block",
        "severity": "Low", "cvss": 2.5,
    },
    "Referrer-Policy": {
        "desc": "Referrer-Policy not set — may leak sensitive URL data in Referer headers.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "severity": "Low", "cvss": 3.1,
    },
    "Permissions-Policy": {
        "desc": "Permissions-Policy not set — browser features not restricted.",
        "remediation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "severity": "Low", "cvss": 2.0,
    },
}

SENSITIVE_PATH_PROBES = [
    ("/server-status",   "Apache Status", "Exposed Apache server-status page leaks real-time request data."),
    ("/server-info",     "Apache Info",   "Exposed Apache server-info page reveals config/module details."),
    ("/actuator",        "Spring Actuator", "Exposed Spring Actuator exposes app internals and health data."),
    ("/actuator/env",    "Spring Env",    "Spring Actuator /env endpoint leaks environment variables."),
    ("/actuator/health", "Spring Health", "Spring Actuator /health endpoint confirms backend services."),
    ("/swagger-ui.html","Swagger UI",    "Swagger UI exposed — full API documentation accessible publicly."),
    ("/api-docs",        "API Docs",     "OpenAPI/Swagger docs exposed publicly."),
    ("/console",         "H2 Console",   "H2 Database console accessible — remote SQL execution risk."),
    ("/admin",           "Admin Panel",  "Admin panel accessible without authentication check."),
    ("/metrics",         "Metrics Page", "Application metrics page exposed — leaks internal counters."),
    ("/.well-known/security.txt", "Security.txt", None),  # None = informational, don't report as vuln
]


class ZapScanner(BaseScanner):
    SCANNER_NAME = "OWASP ZAP Web Scanner"
    _SCANNER_KEY = "zap"

    def __init__(self, scan_id, target, domain, mode="passive", **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self.mode     = mode  # 'passive' | 'active'
        self.zap_host = os.getenv("ZAP_HOST", "localhost")
        self.zap_port = int(os.getenv("ZAP_PORT", "8080"))
        self.zap_key  = os.getenv("ZAP_API_KEY", "sentinel-zap-key-2026")

    # ── ZAP daemon connection ──────────────────────────────────────────────

    def _get_zap(self):
        try:
            from zapv2 import ZAPv2  # type: ignore[import-untyped]
            proxies = {
                "http":  f"http://{self.zap_host}:{self.zap_port}",
                "https": f"http://{self.zap_host}:{self.zap_port}",
            }
            zap = ZAPv2(apikey=self.zap_key, proxies=proxies)
            zap.core.version()  # Quick connectivity test
            return zap
        except ImportError:
            self.log("INFO", "[ZAP] python-owasp-zap-v2.4 not installed.")
            return None
        except Exception as e:
            err_str = str(e).lower()
            if any(x in err_str for x in ("connection refused", "actively refused", "proxy error",
                                           "max retries", "newconnectionerror", "errno 10061")):
                self.log("INFO", f"[ZAP] Daemon not running at {self.zap_host}:{self.zap_port}.")
            else:
                self.log("WARNING", f"[ZAP] Connection error: {e}")
            return None

    # ── Main scan entry ────────────────────────────────────────────────────

    def run(self):
        self.log("INFO", f"[ZAP] Connecting to OWASP ZAP daemon at {self.zap_host}:{self.zap_port}...")
        zap = self._get_zap()

        if zap is None:
            self.log("INFO",
                     "[ZAP] ZAP daemon not running — executing Python-based ZAP-equivalent checks.\n"
                     "  → To enable full ZAP scan, start ZAP in daemon mode:\n"
                     "       zap.bat -daemon -port 8080 -config api.key=sentinel-zap-key-2026\n"
                     "  → Then add ZAP_API_KEY=sentinel-zap-key-2026 to your .env file.")
            self._run_fallback_checks()
            return self.vulns

        self.log("SUCCESS", f"[ZAP] Connected to ZAP daemon. Version: {zap.core.version()}")

        scan_id_spider = None
        try:
            # Spider
            self.log("INFO", f"[ZAP] Starting Spider on {self.target}...")
            scan_id_spider = zap.spider.scan(self.target)
            self._wait_for_completion(zap.spider.status, scan_id_spider, "[ZAP Spider]", timeout=120)
            urls_found = zap.spider.results(scan_id_spider)
            self.log("SUCCESS", f"[ZAP] Spider complete. {len(urls_found)} URL(s) discovered.")

            # Passive scan
            self.log("INFO", "[ZAP] Waiting for passive scan to complete...")
            self._wait_for_passive(zap, timeout=60)

            # Active scan (deep mode only)
            if self.mode == "active":
                self.log("INFO", f"[ZAP] Starting ACTIVE scan on {self.target}...")
                active_id = zap.ascan.scan(self.target)
                self._wait_for_completion(zap.ascan.status, active_id, "[ZAP Active]", timeout=600)
                self.log("SUCCESS", "[ZAP] Active scan complete.")

            # Collect alerts
            self.log("INFO", "[ZAP] Retrieving vulnerability alerts...")
            alerts = zap.core.alerts(baseurl=self.target, start=0, count=200)
            self._process_alerts(alerts)

        except Exception as e:
            self.log("WARNING", f"[ZAP] Scan error: {e}")
        finally:
            try:
                zap.core.delete_all_alerts()
                if scan_id_spider is not None:
                    zap.spider.remove_scan(scan_id_spider)
            except Exception as e:
                self.log("WARNING", f"[ZAP] Cleanup error: {e}")

        return self.vulns

    # ── ZAP polling helpers ────────────────────────────────────────────────

    def _wait_for_completion(self, status_fn, scan_id, prefix, timeout=300):
        elapsed = 0
        while int(status_fn(scan_id)) < 100 and elapsed < timeout:
            pct = status_fn(scan_id)
            self.log("INFO", f"{prefix} Progress: {pct}%")
            time.sleep(5)
            elapsed += 5
        self.log("SUCCESS", f"{prefix} Finished.")

    def _wait_for_passive(self, zap, timeout=60):
        elapsed = 0
        while int(zap.pscan.records_to_scan()) > 0 and elapsed < timeout:
            remaining = zap.pscan.records_to_scan()
            self.log("INFO", f"[ZAP Passive] Records remaining: {remaining}")
            time.sleep(3)
            elapsed += 3
        self.log("SUCCESS", "[ZAP Passive] Passive scan complete.")

    # ── Alert processing ───────────────────────────────────────────────────

    def _process_alerts(self, alerts):
        seen = set()
        for alert in alerts:
            name     = alert.get("name", "Unknown")
            risk     = alert.get("risk", "Low")
            desc     = alert.get("description", "No description provided.")
            solution = alert.get("solution", "Review ZAP documentation for remediation.")
            evidence = alert.get("evidence", "")
            url      = alert.get("url", self.target)
            cweid    = alert.get("cweid", "")
            wascid   = alert.get("wascid", "")

            key = f"{name}|{risk}"
            if key in seen:
                continue
            seen.add(key)

            severity, cvss = ZAP_RISK_MAP.get(risk, ("Low", 2.0))
            log_level = "CRITICAL" if cvss >= 9.0 else ("WARNING" if cvss >= 5.0 else "INFO")
            self.log(log_level, f"[ZAP] Alert [{risk}]: {name} — URL: {url[:60]}")

            references = []
            if cweid:  references.append(f"CWE-{cweid}")
            if wascid: references.append(f"WASC-{wascid}")
            ref_str = " | ".join(references) if references else "N/A"

            self.add_vuln(
                title=f"ZAP: {name}",
                severity=severity,
                category="OWASP ZAP",
                cvss_score=cvss,
                description=(
                    f"{desc}\n\n"
                    f"Detected at: {url}\n"
                    f"References: {ref_str}"
                    + (f"\nEvidence: {evidence[:200]}" if evidence else "")
                ),
                remediation=solution,
            )

        self.log("SUCCESS", f"[ZAP] {len(seen)} unique alert(s) processed.")

    # ── Python fallback checks (when ZAP daemon is not available) ──────────

    def _run_fallback_checks(self):
        """ZAP-equivalent security checks using Python HTTP requests."""
        self.log("INFO", "[ZAP-Fallback] Running ZAP-equivalent security header and path checks...")

        # 1. Security headers audit
        self._check_security_headers()

        # 2. Sensitive path exposure
        self._check_sensitive_paths()

        # 3. Cookie security flags
        self._check_cookie_security()

        # 4. Redirect chain safety
        self._check_open_redirect_probe()

        self.log(
            "INFO" if not self.vulns else "WARNING",
            f"[ZAP-Fallback] Complete. {len(self.vulns)} finding(s)."
        )

    def _check_security_headers(self):
        """Check required security response headers."""
        body, status, response_headers = self._make_request(self.target, return_response_obj=True)
        if not response_headers:
            self.log("WARNING", "[ZAP-Fallback] Could not fetch response headers from target.")
            return

        # Build a normalised dict from the http.client HTTPMessage object
        try:
            header_dict = {k.lower(): v for k, v in response_headers.items()}
        except Exception:
            try:
                header_dict = {}
                for k in response_headers:
                    header_dict[k.lower()] = response_headers[k]
            except Exception:
                self.log("WARNING", "[ZAP-Fallback] Could not parse response headers.")
                return

        self.log("INFO", f"[ZAP-Fallback] Checking {len(SECURITY_HEADERS_REQUIRED)} security headers...")
        for header, info in SECURITY_HEADERS_REQUIRED.items():
            if header.lower() not in header_dict:
                self.log("INFO", f"[ZAP-Fallback] Missing header: {header}")
                self.add_vuln(
                    title=f"ZAP-Fallback: Missing Security Header — {header}",
                    severity=info["severity"],
                    category="Security Headers",
                    cvss_score=info["cvss"],
                    description=(
                        f"The `{header}` HTTP response header is missing.\n\n"
                        f"{info['desc']}\n\n"
                        f"Detected at: `{self.target}`"
                    ),
                    remediation=info["remediation"],
                    evidence=f"Header '{header}' absent from HTTP response",
                    confidence="Confirmed",
                )

    def _check_sensitive_paths(self):
        """Probe common sensitive/misconfigured paths."""
        self.log("INFO", "[ZAP-Fallback] Probing sensitive paths...")
        base = self.target.rstrip("/")

        for path, label, description in SENSITIVE_PATH_PROBES:
            url = f"{base}{path}"
            try:
                body, status = self._make_request(url, timeout=8)
                if status == 200 and body:
                    if description:  # None = informational, skip
                        self.log("WARNING", f"[ZAP-Fallback] EXPOSED: {label} at {path}")
                        self.add_vuln(
                            title=f"ZAP-Fallback: Sensitive Path Exposed — {label}",
                            severity="Medium",
                            category="Information Disclosure",
                            cvss_score=5.3,
                            description=f"{description}\n\nDetected at: `{url}`",
                            remediation=(
                                f"Restrict access to `{path}` via web server configuration. "
                                "Only allow access from trusted IPs or disable entirely."
                            ),
                            evidence=f"HTTP 200 response from {url}",
                            payload=path,
                            confidence="Confirmed",
                        )
            except Exception:
                pass  # Path not reachable — expected

    def _check_cookie_security(self):
        """Check session cookies for missing Secure/HttpOnly/SameSite flags."""
        _, _, response_headers = self._make_request(self.target, return_response_obj=True)
        if not response_headers:
            return

        try:
            cookies = []
            try:
                cookies = response_headers.get_all("Set-Cookie") or []
            except Exception:
                raw = response_headers.get("Set-Cookie")
                if raw:
                    cookies = [raw]

            for cookie in cookies:
                name = cookie.split("=")[0].strip()
                flags = cookie.lower()
                issues = []
                if "secure" not in flags:
                    issues.append("missing Secure flag (cookie sent over HTTP)")
                if "httponly" not in flags:
                    issues.append("missing HttpOnly flag (accessible via JavaScript)")
                if "samesite" not in flags:
                    issues.append("missing SameSite flag (CSRF risk)")

                if issues:
                    self.log("INFO", f"[ZAP-Fallback] Cookie `{name}` has flag issues: {', '.join(issues)}")
                    self.add_vuln(
                        title=f"ZAP-Fallback: Cookie Security Flags — {name}",
                        severity="Medium",
                        category="Cookie Security",
                        cvss_score=4.3,
                        description=(
                            f"Cookie `{name}` has security flag issues:\n"
                            + "\n".join(f"• {i}" for i in issues)
                        ),
                        remediation=(
                            f"Set the following flags on the `{name}` cookie:\n"
                            "  Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict"
                        ),
                        evidence=f"Set-Cookie: {cookie[:120]}",
                        confidence="Confirmed",
                    )
        except Exception as e:
            self.log("ERROR", f"[ZAP-Fallback] Cookie check error: {e}")

    def _check_open_redirect_probe(self):
        """Probe common redirect parameters for open redirect."""
        probes = [
            f"{self.target}?next=//evil.com",
            f"{self.target}?redirect=//evil.com",
            f"{self.target}?return=//evil.com",
        ]
        for url in probes:
            try:
                body, status = self._make_request(url, timeout=6)
                if status in (301, 302, 303, 307, 308):
                    self.log("INFO", f"[ZAP-Fallback] Redirect from {url} — status {status}")
                    # Check if redirect target is external
                    if body and "evil.com" in body:
                        self.add_vuln(
                            title="ZAP-Fallback: Open Redirect Detected",
                            severity="Medium",
                            category="Open Redirect",
                            cvss_score=5.4,
                            description=(
                                f"The application redirects to an attacker-controlled URL "
                                f"when `next`, `redirect`, or `return` parameters are supplied.\n\n"
                                f"Probe URL: `{url}`"
                            ),
                            remediation=(
                                "Validate all redirect targets against an allowlist of trusted URLs. "
                                "Never redirect to user-supplied URLs without validation."
                            ),
                            evidence=f"HTTP {status} redirect triggered by probe",
                            confidence="High",
                        )
            except Exception:
                pass
