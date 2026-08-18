
"""
password_reset_scanner.py — Insecure Password Reset Scanner
"""
import re, time, urllib.parse, math
from collections import Counter
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector
from utils.callback import build_callback_url

RESET_PATHS = [
    "/forgot-password", "/forgot_password", "/reset-password",
    "/password/reset", "/password/forgot", "/auth/forgot-password",
    "/api/auth/forgot-password", "/api/password/reset",
]


class PasswordResetScanner(BaseScanner):
    SCANNER_NAME = "Insecure Password Reset Scanner"
    _SCANNER_KEY = "password_reset"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._timing_detector = TimingAnomalyDetector()

    def run(self) -> list:
        self.log("INFO", f"[PwReset] Auditing password reset flow on {self.target}...")
        base = self.target.rstrip("/")
        reset_url = None
        for path in RESET_PATHS:
            body, status = self._make_request(base + path)
            if status == 200 and body and len(body) > 100:
                reset_url = base + path
                self.log("INFO", f"[PwReset] Found reset page: {reset_url}")
                break
        if not reset_url:
            self.log("INFO", "[PwReset] No password reset page found.")
            return self.vulns
        self._test_host_header_poisoning(reset_url)
        self._test_user_enumeration(reset_url)
        self._check_token_in_url()
        self._test_rate_limiting(reset_url)
        self._test_token_expiration(reset_url)
        self._test_token_brute_force(reset_url)
        self._test_host_header_overwrite_in_link(reset_url)
        self._test_token_entropy(reset_url)
        self._test_token_timing_enumeration(reset_url)
        if not self.vulns:
            self.log("SUCCESS", "[PwReset] No issues found.")
        return self.vulns

    def _test_host_header_poisoning(self, url):
        evil = "wss-poison.evil"
        headers = {"Host": evil, "X-Forwarded-Host": evil}
        body, status = self._make_request(
            url, method="POST",
            data=urllib.parse.urlencode({"email": f"test@{self.domain}"}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Host": evil, "X-Forwarded-Host": evil}
        )
        if body is None:
            return
        if evil in body:
            self.add_vuln(
                title="Password Reset Host Header Poisoning",
                severity="High",
                category="Password Reset Security",
                cvss_score=7.5,
                description=f"Reset endpoint `{url}` reflected spoofed Host header `{evil}` in the response. "
                    "If the reset link uses the Host header, victim tokens will be sent to the attacker.",
                remediation="Hardcode the app domain in reset email templates. Never use Host header.",
                evidence=f"Host header `{evil}` reflected in response body",
                payload=evil,
                request_details=f"POST {url} with Host: {evil}",
                response_details=body[:500],
                confidence="Confirmed",
                cwe_ids=["CWE-640"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

    def _test_user_enumeration(self, url):
        valid_bodies, invalid_bodies = [], []
        for email in [f"admin@{self.domain}", f"user@{self.domain}"]:
            body, _ = self._make_request(url, method="POST",
                data=urllib.parse.urlencode({"email": email}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            if body:
                valid_bodies.append(body.lower())
        for email in ["zzzfake99@notreal.invalid", "aaabbb@fakefake.invalid"]:
            body, _ = self._make_request(url, method="POST",
                data=urllib.parse.urlencode({"email": email}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            if body:
                invalid_bodies.append(body.lower())
        if valid_bodies and invalid_bodies and valid_bodies[0] != invalid_bodies[0]:
            v_sent = any(w in valid_bodies[0] for w in ["sent", "email", "check", "success"])
            i_err = any(w in invalid_bodies[0] for w in ["not found", "invalid", "no account", "doesn't exist"])
            if v_sent or i_err:
                self.add_vuln(
                    title="Username Enumeration via Password Reset",
                    severity="Medium",
                    category="Password Reset Security",
                    cvss_score=5.3,
                    description="Different responses for valid vs invalid emails allows account enumeration.",
                    remediation="Return the same generic message regardless of email existence.",
                    evidence=f"Valid email response: {valid_bodies[0][:200]} ... Invalid: {invalid_bodies[0][:200]}",
                    confidence="High",
                    cwe_ids=["CWE-640"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )

    def _check_token_in_url(self):
        body, _ = self._make_request(self.target)
        if body:
            tokens = re.findall(r'href=["\'][^"\']*(?:token|reset|verify|code)=[^"\'&]{8,}', body, re.I)
            if tokens:
                self.add_vuln(
                    title="Reset Tokens Exposed in URL",
                    severity="Medium",
                    category="Password Reset Security",
                    cvss_score=5.3,
                    description="Reset tokens found in page URLs — leaked via browser history and Referer headers.\n" +
                        "\n".join(f"- `{t[:120]}`" for t in tokens[:3]),
                    remediation="Use POST-only token submission. Never embed tokens in URLs.",
                    evidence="\n".join(t[:120] for t in tokens[:3]),
                    confidence="Confirmed",
                    cwe_ids=["CWE-640"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )

    def _test_rate_limiting(self, url):
        statuses = []
        for _ in range(6):
            _, s = self._make_request(url, method="POST",
                data=urllib.parse.urlencode({"email": f"test@{self.domain}"}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            statuses.append(s)
        if statuses.count(200) >= 5:
            self.add_vuln(
                title="No Rate Limiting on Password Reset Endpoint",
                severity="Medium",
                category="Password Reset Security",
                cvss_score=5.3,
                description="6 rapid reset requests all returned HTTP 200 — no rate limiting detected.",
                remediation="Limit to 3-5 resets per email/hour. Add CAPTCHA after 2 attempts.",
                evidence=f"Status codes from 6 rapid requests: {statuses}",
                confidence="Confirmed",
                cwe_ids=["CWE-640"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

    def _test_token_expiration(self, url):
        # Probe for token patterns in reset URL, test if expired tokens are accepted
        body, _ = self._make_request(url)
        if body:
            token_urls = re.findall(r'href=["\']([^"\']*(?:token|reset|code)=[^"\']+)["\']', body, re.I)
            for token_url in token_urls[:2]:
                resolved = token_url if token_url.startswith("http") else self.target.rstrip("/") + "/" + token_url.lstrip("/")
                body2, status = self._make_request(resolved)
                if body2 and "expired" in body2.lower():
                    self.add_vuln(
                        title="Reset Token Expiration Enforced",
                        severity="Low",
                        category="Password Reset Security",
                        cvss_score=0.0,
                        description="Reset token endpoint properly rejects expired tokens.",
                        remediation="None required — this is a positive finding.",
                        evidence=f"Expired token URL: {resolved}",
                        confidence="Info",
                        cwe_ids=["CWE-640"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )

    def _test_token_brute_force(self, url):
        body, _ = self._make_request(url)
        if body:
            patterns = re.findall(r'name=["\'](?:token|reset_token|code)["\']', body, re.I)
            if patterns:
                self.add_vuln(
                    title="Reset Token Brute Force Possible",
                    severity="Medium",
                    category="Password Reset Security",
                    cvss_score=5.9,
                    description=f"Reset token field found in form: `{patterns[0]}`. "
                        "If tokens are short or lack rate limiting, brute force may be feasible.",
                    remediation="Use cryptographically random 128+ bit tokens. "
                        "Rate-limit token validation attempts. Invalidate after 3 failures.",
                    evidence=f"Token field detected: {patterns[0]}",
                    confidence="Medium",
                    cwe_ids=["CWE-640"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )

    def _test_host_header_overwrite_in_link(self, url):
        evil_host = "evil-attacker.com"
        body, status = self._make_request(url, method="POST",
            data=urllib.parse.urlencode({"email": f"test@{self.domain}"}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Host": evil_host})
        if body and evil_host in body:
            reset_links = re.findall(r'href=["\'](https?://[^"\']+)["\']', body, re.I)
            for link in reset_links:
                if evil_host in link:
                    self.add_vuln(
                        title="Host Header Overwrite in Reset Link",
                        severity="Critical",
                        category="Password Reset Security",
                        cvss_score=8.5,
                        description=f"Password reset link includes attacker-controlled host `{evil_host}`. "
                            "Victims clicking the link will be sent to the attacker's server.",
                        remediation="Always use a hardcoded base URL for reset links. "
                            "Never derive the hostname from the Host header.",
                        evidence=f"Reset link with spoofed host: {link}",
                        payload=evil_host,
                        request_details=f"POST {url} with Host: {evil_host}",
                        response_details=body[:500],
                        confidence="Confirmed",
                        cwe_ids=["CWE-640"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )

    def _test_token_entropy(self, url):
        """Analyze reset token entropy using statistical methods."""
        body, _ = self._make_request(url)
        if body:
            tokens = re.findall(r'(?:token|reset|code|key)=([a-zA-Z0-9]+)', body, re.I)
            for token in set(tokens[:5]):
                freq = Counter(token)
                n = len(token)
                if n == 0:
                    continue
                shannon = -sum((c/n) * math.log2(c/n) for c in freq.values())
                charset_size = 0
                if re.search(r'[a-z]', token): charset_size += 26
                if re.search(r'[A-Z]', token): charset_size += 26
                if re.search(r'[0-9]', token): charset_size += 10
                total_bits = n * (math.log2(charset_size) if charset_size else 0)
                if total_bits < 64:
                    self.add_vuln(
                        title="Weak Reset Token Entropy",
                        severity="High",
                        category="Password Reset Security",
                        cvss_score=7.5,
                        description=f"Reset token '{token[:20]}...' has only {total_bits:.1f} bits "
                            f"of entropy (Shannon: {shannon:.2f}). Tokens should have at least "
                            f"128 bits to resist brute-force prediction attacks.",
                        evidence=f"Token entropy: {total_bits:.1f} bits, Shannon: {shannon:.2f}",
                        payload=token[:40],
                        confidence="High",
                        remediation="1. Use secrets.token_urlsafe(32) for token generation.\n"
                            "2. Ensure tokens contain at least 128 bits of entropy.\n"
                            "3. Use a cryptographically secure PRNG.",
                        cwe_ids=["CWE-640"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return

    def _test_token_timing_enumeration(self, url):
        """Use TimingAnomalyDetector to detect timing differences in token validation."""
        try:
            baseline_count = 3
            for _ in range(baseline_count):
                data = urllib.parse.urlencode({"email": f"test@{self.domain}"}).encode()
                _, _, elapsed = self._make_timed_request(
                    url, method="POST", data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=8
                )
                self._timing_detector.record(elapsed)

            if not self._timing_detector.has_baseline:
                return

            data = urllib.parse.urlencode({"email": "nonexistent@invalid.invalid"}).encode()
            _, _, elapsed = self._make_timed_request(
                url, method="POST", data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=8
            )

            if self._timing_detector.test_payload("invalid_email", elapsed, z_threshold=2.5):
                self.add_vuln(
                    title="Token Enumeration via Timing Side-Channel",
                    severity="Medium",
                    category="Password Reset Security",
                    cvss_score=5.3,
                    description="Statistically significant timing differences detected between "
                        "valid and invalid email submissions in password reset. This timing "
                        "side-channel allows attackers to enumerate valid user accounts.",
                    evidence=f"Z-score: {self._timing_detector.z_score(elapsed):.2f}",
                    confidence="Medium",
                    remediation="1. Implement constant-time response for all email submissions.\n"
                        "2. Add random jitter to response timing.\n"
                        "3. Use a generic response regardless of email validity.",
                    cwe_ids=["CWE-640"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )
        except Exception as e:
            self.log("ERROR", f"[PwReset] _test_token_timing_enumeration error: {e}")
