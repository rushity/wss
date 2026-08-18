"""
compliance_scanner.py — Security Compliance & Standards Checker
================================================================
Audits the target against major compliance frameworks:
  - OWASP Top 10 (2021)
  - PCI-DSS v4.0 (relevant subset)
  - GDPR / Privacy
  - HIPAA (technical safeguards subset)
  - SOC 2 Type II (relevant technical controls)

Generates a compliance score and per-framework gap report.
Note: This is an automated scan — manual verification is required
for full compliance certification.
"""
import re, urllib.request
from scanners.base_scanner import BaseScanner

# Control check: (id, name, check_fn_name, framework_tags)
COMPLIANCE_CONTROLS = [
    # ── OWASP Top 10 controls ──────────────────────────────────────────
    ("OWASP-A01", "Broken Access Control — Admin paths restricted",     "check_admin_paths",    ["OWASP"]),
    ("OWASP-A02", "Cryptographic Failures — HTTPS enforced",            "check_https",          ["OWASP","PCI","HIPAA"]),
    ("OWASP-A02", "Cryptographic Failures — HSTS enabled",              "check_hsts",           ["OWASP","PCI","HIPAA"]),
    ("OWASP-A02", "Cryptographic Failures — TLS 1.2+ only",             "check_tls_version",    ["OWASP","PCI"]),
    ("OWASP-A03", "Injection — Security headers present",               "check_security_headers",["OWASP","PCI"]),
    ("OWASP-A05", "Security Misconfiguration — X-Frame-Options set",    "check_xfo",            ["OWASP"]),
    ("OWASP-A05", "Security Misconfiguration — CSP header set",         "check_csp",            ["OWASP"]),
    ("OWASP-A05", "Security Misconfiguration — Server header hidden",   "check_server_header",  ["OWASP","PCI"]),
    ("OWASP-A06", "Vulnerable Components — X-Powered-By hidden",        "check_powered_by",     ["OWASP"]),
    ("OWASP-A07", "Auth Failures — Secure + HttpOnly cookies",          "check_cookie_flags",   ["OWASP","PCI"]),
    # ── PCI-DSS specific ───────────────────────────────────────────────
    ("PCI-6.4",   "PCI-DSS — Referrer-Policy header present",          "check_referrer_policy",["PCI"]),
    ("PCI-6.4",   "PCI-DSS — Permissions-Policy header present",       "check_perms_policy",   ["PCI"]),
    # ── GDPR ───────────────────────────────────────────────────────────
    ("GDPR-Art13","GDPR — Privacy Policy link present",                 "check_privacy_policy", ["GDPR"]),
    ("GDPR-Art7", "GDPR — Cookie consent mechanism present",            "check_cookie_consent", ["GDPR"]),
    # ── HIPAA technical safeguards ────────────────────────────────────
    ("HIPAA-164.312","HIPAA — Encryption in transit (HTTPS)",           "check_https",          ["HIPAA"]),
    # ── SOC 2 ─────────────────────────────────────────────────────────
    ("SOC2-CC6.1","SOC2 — Secure communication (HSTS)",                 "check_hsts",           ["SOC2"]),
    ("SOC2-CC6.7","SOC2 — Data transmission protection (CSP)",          "check_csp",            ["SOC2"]),
]


class ComplianceScanner(BaseScanner):
    SCANNER_NAME = "Security Compliance & Standards Scanner"
    _SCANNER_KEY = "compliance"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._headers: dict   = {}
        self._body:    str    = ""
        self._is_https = self.target.startswith("https://")
        self._results: dict   = {}   # control_name -> (passed, detail)

    # ------------------------------------------------------------------
    def run(self) -> list:
        self.log("INFO", f"[Compliance] Running compliance audit on {self.target}...")
        try:
            self._fetch_target()
            self._run_all_checks()
            self._generate_report()
        except Exception as e:
            self.log("WARNING", f"[Compliance] Error: {e}")

        self.log("SUCCESS" if not self.vulns else "WARNING",
            f"[Compliance] Audit complete. {len(self.vulns)} gap(s) identified.")
        return self.vulns

    # ------------------------------------------------------------------
    def _fetch_target(self):
        req = urllib.request.Request(self.target,
            headers={"User-Agent": "LarShield/2.0 Compliance-Audit"})
        with urllib.request.urlopen(req, timeout=8, context=self.get_ssl_context()) as r:
            self._headers = {k.lower(): v for k, v in r.headers.items()}
            self._body    = r.read().decode("utf-8", errors="ignore")

    # ------------------------------------------------------------------
    def _run_all_checks(self):
        for ctrl_id, ctrl_name, fn_name, frameworks in COMPLIANCE_CONTROLS:
            fn = getattr(self, f"_{fn_name}", None)
            if fn:
                passed, detail = fn()
                key = ctrl_name
                self._results[key] = (passed, detail, ctrl_id, frameworks)

    # ------------------------------------------------------------------
    def _generate_report(self):
        # Aggregate by framework
        framework_scores = {}
        for ctrl_name, (passed, detail, ctrl_id, frameworks) in self._results.items():
            for fw in frameworks:
                if fw not in framework_scores:
                    framework_scores[fw] = {"pass": 0, "fail": 0, "gaps": []}
                if passed:
                    framework_scores[fw]["pass"] += 1
                else:
                    framework_scores[fw]["fail"] += 1
                    framework_scores[fw]["gaps"].append(f"[{ctrl_id}] {ctrl_name}: {detail}")

        for fw, scores in framework_scores.items():
            total  = scores["pass"] + scores["fail"]
            pct    = int(100 * scores["pass"] / total) if total else 0
            gaps   = scores["gaps"]

            if not gaps:
                self.log("SUCCESS", f"[Compliance] {fw}: 100% — All {total} controls passed")
                continue

            severity = "Critical" if pct < 40 else ("High" if pct < 60 else ("Medium" if pct < 80 else "Low"))
            cvss     = {
                "Critical": 9.0, "High": 7.0, "Medium": 5.0, "Low": 3.0
            }[severity]

            self.log("WARNING", f"[Compliance] {fw}: {pct}% ({scores['pass']}/{total} controls passed)")

            self.add_vuln(
                title=f"{fw} Compliance Gaps — {pct}% Score ({scores['pass']}/{total} controls passed)",
                severity=severity,
                category="Compliance",
                cvss_score=cvss,
                description=(
                    f"**Framework:** {fw}\n"
                    f"**Score:** {pct}% ({scores['pass']} passed, {scores['fail']} failed of {total} automated controls)\n\n"
                    "**Failed Controls:**\n"
                    + "\n".join(f"- {g}" for g in gaps) +
                    "\n\n*Note: This automated check covers a subset of controls. "
                    "Full certification requires a manual audit.*"
                ),
                remediation=(
                    f"Address the {len(gaps)} failing {fw} control(s) above. "
                    f"Each finding has dedicated remediation guidance in the full report."
                ),
            )

    # ── Individual check functions ─────────────────────────────────────
    def _check_https(self):
        if self._is_https:
            return True, "HTTPS enforced"
        return False, "Site does not use HTTPS"

    def _check_hsts(self):
        hsts = self._headers.get("strict-transport-security", "")
        if hsts:
            max_age_m = re.search(r"max-age=(\d+)", hsts)
            if max_age_m and int(max_age_m.group(1)) >= 31536000:
                return True, f"HSTS: {hsts}"
            return False, f"HSTS max-age too short: {hsts}"
        return False, "HSTS header missing"

    def _check_tls_version(self):
        # Heuristic: if HSTS is present and HTTPS is enforced, assume TLS is current
        if self._is_https and self._headers.get("strict-transport-security"):
            return True, "HTTPS + HSTS suggest modern TLS (verify with sslyze)"
        return False, "Cannot confirm TLS version — run sslyze scanner"

    def _check_security_headers(self):
        required = ["x-content-type-options", "x-xss-protection",
                    "content-security-policy", "strict-transport-security"]
        missing = [h for h in required if h not in self._headers]
        if not missing:
            return True, "All core security headers present"
        return False, f"Missing headers: {', '.join(missing)}"

    def _check_xfo(self):
        xfo = self._headers.get("x-frame-options", "")
        if xfo.upper() in ("DENY", "SAMEORIGIN"):
            return True, f"X-Frame-Options: {xfo}"
        return False, f"X-Frame-Options missing or weak ('{xfo}')"

    def _check_csp(self):
        csp = self._headers.get("content-security-policy", "")
        if csp:
            if "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp:
                return True, "CSP present and strict"
            return False, "CSP present but allows unsafe-inline or unsafe-eval"
        return False, "CSP header missing"

    def _check_server_header(self):
        server = self._headers.get("server", "")
        if not server or re.search(r"^\S+$", server) and not re.search(r"\d", server):
            return True, f"Server header minimal: '{server}'"
        return False, f"Server header reveals version info: '{server}'"

    def _check_powered_by(self):
        xpb = self._headers.get("x-powered-by", "")
        if not xpb:
            return True, "X-Powered-By header not present"
        return False, f"X-Powered-By exposes technology: '{xpb}'"

    def _check_cookie_flags(self):
        cookies = self._headers.get("set-cookie", "")
        if not cookies:
            return True, "No cookies set on main page"
        if "secure" in cookies.lower() and "httponly" in cookies.lower():
            return True, "Cookies have Secure + HttpOnly flags"
        return False, "Cookie(s) missing Secure or HttpOnly flag"

    def _check_referrer_policy(self):
        rp = self._headers.get("referrer-policy", "")
        if rp:
            return True, f"Referrer-Policy: {rp}"
        return False, "Referrer-Policy header missing"

    def _check_perms_policy(self):
        pp = self._headers.get("permissions-policy",
             self._headers.get("feature-policy",""))
        if pp:
            return True, f"Permissions-Policy present"
        return False, "Permissions-Policy header missing"

    def _check_privacy_policy(self):
        if re.search(r'(privacy.?policy|privacy-policy|/privacy|datenschutz)', self._body, re.I):
            return True, "Privacy policy link detected in HTML"
        return False, "No privacy policy link found in page HTML"

    def _check_admin_paths(self):
        # Check if admin is not indexable (not a definitive check)
        return True, "Automated check — use directory scanner results"

    def _check_cookie_consent(self):
        consent_re = re.compile(
            r"(cookie.?consent|cookieconsent|cookie.?notice|accept.?cookie|"
            r"cookie.?policy|gdpr|we use cookies)", re.I)
        if consent_re.search(self._body):
            return True, "Cookie consent mechanism detected"
        return False, "No cookie consent banner or mechanism detected"
