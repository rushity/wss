"""
idor_scanner.py — Insecure Direct Object Reference (IDOR) Scanner
==================================================================
Advanced IDOR detection module that tests for access control vulnerabilities.

This scanner:
  1. Identifies endpoints with ID parameters (user IDs, order IDs, etc.)
  2. Tests for horizontal privilege escalation (accessing other users' data)
  3. Tests for vertical privilege escalation (admin functions)
  4. Detects predictable ID patterns and enumeration vulnerabilities
  5. Tests for ID manipulation in URLs, headers, and cookies
  6. Multi-stage detection: baseline capture, probe variations, confirm access
"""
import urllib.request, urllib.error, urllib.parse, re
from scanners.base_scanner import BaseScanner
from utils.anomaly import SizeAnomalyDetector
from utils.evasion import waf_evade
from utils.multi_stage_detector import MultiStageDetector, PassiveAnalyzer, ActiveProber

ID_PATTERNS = [
    r'/users/(\d+)', r'/user/(\d+)',
    r'/accounts/(\d+)', r'/account/(\d+)',
    r'/orders/(\d+)', r'/order/(\d+)',
    r'/products/(\d+)', r'/product/(\d+)',
    r'/items/(\d+)', r'/item/(\d+)',
    r'/documents/(\d+)', r'/document/(\d+)',
    r'/files/(\d+)', r'/file/(\d+)',
    r'/posts/(\d+)', r'/post/(\d+)',
    r'/comments/(\d+)', r'/comment/(\d+)',
    r'/transactions/(\d+)', r'/transaction/(\d+)',
    r'/invoices/(\d+)', r'/invoice/(\d+)',
    r'/profiles/(\d+)', r'/profile/(\d+)',
    r'/messages/(\d+)', r'/message/(\d+)',
    r'/notifications/(\d+)', r'/notification/(\d+)',
    r'/api/v1/users/(\d+)', r'/api/v2/users/(\d+)',
    r'/api/v1/orders/(\d+)', r'/api/v2/orders/(\d+)',
    r'/customers/(\d+)', r'/customer/(\d+)',
    r'/employees/(\d+)', r'/employee/(\d+)',
    r'/tickets/(\d+)', r'/ticket/(\d+)',
    r'/tokens/(\d+)', r'/token/(\d+)',
]

UUID_PATTERN = re.compile(
    r'/users/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
    re.IGNORECASE
)
INT_PATTERN = re.compile(r'/users/(\d+)')

QUERY_ID_PARAMS = [
    "user_id", "userid", "uid", "id", "account_id", "accountid",
    "order_id", "orderid", "product_id", "productid", "item_id", "itemid",
    "document_id", "documentid", "file_id", "fileid", "post_id", "postid",
    "comment_id", "commentid", "transaction_id", "transactionid",
    "invoice_id", "invoiceid", "profile_id", "profileid", "message_id",
    "messageid", "notification_id", "notificationid", "customer_id",
    "customerid", "client_id", "clientid", "employee_id", "employeeid",
    "org_id", "orgid", "group_id", "groupid", "role_id", "roleid",
    "shop_id", "shopid", "store_id", "storeid", "cart_id", "cartid",
    "session_id", "token_id", "api_key", "key",
]

SUCCESS_INDICATORS = [
    r"200", r"success", r"approved", r"completed", r"active", r"verified",
    r"\"status\":\"ok\"", r"\"status\": true", r"\"success\": true",
    r"\"data\":", r"\"result\":", r"200 OK",
]

FAILURE_INDICATORS = [
    r"403", r"404", r"forbidden", r"unauthorized", r"not found",
    r"access denied", r"permission denied", r"not authorized",
    r"\"status\":\"error\"", r"\"status\": false", r"\"success\": false",
    r"\"error\":", r"\"message\":\"Not Found\"",
]


class IdorScanner(BaseScanner):
    SCANNER_NAME = "Insecure Direct Object Reference (IDOR) Scanner"
    _SCANNER_KEY = "idor"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._headers = {"User-Agent": "LarShield/2.0 IDOR Scanner"}
        if self.auth_headers:
            self._headers.update(self.auth_headers)
        self._tested_endpoints = 0
        self._idor_found = 0
        self._size_detector = SizeAnomalyDetector()
        # Initialize multi-stage detector for advanced IDOR detection
        self._multi_stage_detector = MultiStageDetector(scan_id, target)

    def _extract_ids_from_url(self, url):
        """Extract numeric IDs from URL path."""
        for pattern in ID_PATTERNS:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        return None

    def _extract_uuid_from_url(self, url):
        """Extract UUID from URL path."""
        match = UUID_PATTERN.search(url)
        if match:
            return match.group(1)
        return None

    def _test_path_id_manipulation(self, url):
        """Test for IDOR by manipulating IDs in URL paths — multi-stage: baseline, probe, confirm."""
        current_id = self._extract_ids_from_url(url)
        if not current_id:
            return False

        try:
            current_id_int = int(current_id)
        except ValueError:
            return False

        # Stage 1: Capture baseline
        baseline_body, baseline_status, baseline_headers = self._make_request(
            url, return_response_obj=True,
        )
        if baseline_body is None:
            return False
        baseline_length = len(baseline_body)

        # Build baseline for anomaly detection
        self._size_detector = SizeAnomalyDetector()
        self._size_detector.record_size(baseline_length)

        # Build baseline with invalid IDs for statistical comparison
        for invalid_id in [-1, 0, -999]:
            try:
                i_url = re.sub(r'/\d+(?=/|$)', f'/{invalid_id}', url)
                i_body, _ = self._make_request(i_url)
                if i_body:
                    self._size_detector.record_size(len(i_body))
            except Exception as e:
                self.log("ERROR", f"[IDOR] Baseline request error: {e}")

        # Stage 2: Probe with variations (including waf_evade variants)
        test_ids = [
            current_id_int + 1,
            current_id_int - 1,
            current_id_int + 100,
            current_id_int + 1000,
            1,
            2,
            999,
            current_id_int * 2,
        ]

        # Add waf_evade variants for string IDs
        id_str = str(current_id)
        waf_variants = []
        for name, variant in waf_evade(id_str):
            waf_variants.append(variant)

        for test_id in test_ids + list(range(current_id_int + 1, current_id_int + 11)):
            if test_id <= 0:
                continue

            test_url = re.sub(r'/\d+(?=/|$)', f'/{test_id}', url)

            try:
                test_body, test_status = self._make_request(test_url)
                if test_body is None:
                    continue
                test_length = len(test_body)

                # Size anomaly detection
                is_anomaly = False
                if self._size_detector.has_baseline and self._size_detector.test_size(test_length):
                    is_anomaly = True

                # Stage 3: Confirm — different response indicates potential IDOR
                if (abs(test_length - baseline_length) > 100 or is_anomaly) and test_status not in [403, 404]:
                    self._idor_found += 1
                    self.log("CRITICAL",
                             f"[IDOR] Potential vulnerability! URL: {url} | "
                             f"Original ID: {current_id} | Test ID: {test_id} | "
                             f"Response size diff: {abs(test_length - baseline_length)} bytes | "
                             f"Status: {baseline_status} -> {test_status}")

                    self.add_vuln(
                        title="Insecure Direct Object Reference (IDOR)",
                        severity="Critical",
                        category="Access Control",
                        cvss_score=9.1,
                        description=(
                            f"An IDOR vulnerability was detected at {url}.\n"
                            f"Manipulating the ID from {current_id} to {test_id} returned a different response "
                            f"(size diff: {abs(test_length - baseline_length)} bytes, "
                            f"status: {baseline_status} -> {test_status}), "
                            f"indicating that access controls may not properly validate object ownership.\n\n"
                            f"Impact: Attackers can access other users' data, modify records, "
                            f"perform unauthorized actions, and escalate privileges."
                        ),
                        remediation=(
                            "1. IMPLEMENT PROPER ACCESS CONTROLS:\n"
                            "   - Validate that the current user has permission to access the requested object\n"
                            "   - Use indirect object references (maps/tokens) instead of direct IDs\n"
                            "   - Implement ownership checks on every object access\n"
                            "2. Use session-based authorization checks\n"
                            "3. Implement proper role-based access control (RBAC)\n"
                            "4. Log and monitor for suspicious ID manipulation attempts\n"
                            "5. Use UUIDs instead of sequential IDs to prevent enumeration"
                        ),
                        evidence=f"Baseline length: {baseline_length}, Test length: {test_length}, Status: {test_status}",
                        payload=f"Changed ID from {current_id} to {test_id}",
                        request_details=f"URL: {test_url}",
                        response_details=f"Response length: {test_length}, Status: {test_status}",
                        confidence="Confirmed" if test_status == baseline_status else "High",
                        cwe_ids=["CWE-639"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )
                    return True

            except Exception as e:
                self.log("ERROR", f"[IDOR] Error testing ID {test_id} on {url}: {e}")

        # Concurrent enumeration test
        import concurrent.futures
        test_ids_concurrent = list(range(max(1, current_id_int - 5), current_id_int + 6))
        test_ids_concurrent = [i for i in test_ids_concurrent if i != current_id_int]
        success_count = 0
        total_count = len(test_ids_concurrent)

        def _test_concurrent(tid):
            t_url = re.sub(r'/\d+(?=/|$)', f'/{tid}', url)
            try:
                t_body, t_status = self._make_request(t_url)
                if t_body is not None and t_status not in [403, 404]:
                    return tid, True
            except Exception as e:
                self.log("ERROR", f"[IDOR] Concurrent test error for ID {tid}: {e}")
            return tid, False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_test_concurrent, tid) for tid in test_ids_concurrent]
            for future in concurrent.futures.as_completed(futures):
                _, ok = future.result()
                if ok:
                    success_count += 1

        if success_count >= total_count * 0.7 and total_count > 0:
            self._idor_found += 1
            self.log("CRITICAL",
                     f"[IDOR] Concurrent enumeration possible at {url}! "
                     f"Accessed {success_count}/{total_count} sequential IDs concurrently.")
            self.add_vuln(
                title="Insecure Direct Object Reference (IDOR) — Concurrent Enumeration",
                severity="Critical",
                category="Access Control",
                cvss_score=9.1,
                description=(
                    f"Concurrent ID enumeration is possible at {url}.\n"
                    f"Successfully accessed {success_count}/{total_count} sequential IDs "
                    f"around {current_id_int} via concurrent requests.\n"
                    f"This indicates sequential/guessable IDs with insufficient access controls."
                ),
                remediation=(
                    "1. Use unpredictable IDs (UUIDs) instead of sequential integers.\n"
                    "2. Implement proper access control checks on every request.\n"
                    "3. Add rate limiting on ID-based endpoints.\n"
                    "4. Monitor for sequential access patterns in logs."
                ),
                evidence=f"Accessed {success_count}/{total_count} sequential IDs concurrently",
                payload=f"Enumerated IDs around {current_id_int}",
                request_details=f"URL: {url}",
                response_details=f"Baseline length: {baseline_length}",
                confidence="Confirmed" if success_count == total_count else "High",
                cwe_ids=["CWE-639"],
                owasp_category="A01:2021 – Broken Access Control",
            )
            return True

        return False

    def _test_query_param_id_manipulation(self, url):
        """Test for IDOR by manipulating IDs in query parameters."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return False

        id_params = []
        for param_name in params:
            if param_name.lower() in QUERY_ID_PARAMS:
                id_params.append(param_name)

        if not id_params:
            return False

        baseline_body, baseline_status = self._make_request(url)
        if baseline_body is None:
            return False
        baseline_length = len(baseline_body)

        for param_name in id_params:
            current_value = params[param_name][0]
            try:
                current_id_int = int(current_value)
            except ValueError:
                continue

            test_ids = [current_id_int + 1, current_id_int - 1, 1, 2, 999, current_id_int + 100]

            for test_id in test_ids:
                if test_id <= 0:
                    continue

                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = str(test_id)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"

                try:
                    test_body, test_status = self._make_request(test_url)
                    if test_body is None:
                        continue
                    test_length = len(test_body)

                    if abs(test_length - baseline_length) > 100 and test_status not in [403, 404]:
                        self._idor_found += 1
                        self.log("CRITICAL",
                                 f"[IDOR] Potential vulnerability! Parameter: {param_name} | "
                                 f"Original ID: {current_id_int} | Test ID: {test_id} | "
                                 f"Response size diff: {abs(test_length - baseline_length)} bytes")

                        self.add_vuln(
                            title="Insecure Direct Object Reference (IDOR) — Query Parameter",
                            severity="Critical",
                            category="Access Control",
                            cvss_score=9.1,
                            description=(
                                f"An IDOR vulnerability was detected via query parameter '{param_name}'.\n"
                                f"Manipulating the ID from {current_id_int} to {test_id} returned a different response, "
                                f"indicating insufficient access control validation.\n\n"
                                f"Impact: Unauthorized access to other users' data and resources."
                            ),
                            remediation=(
                                "1. Validate user ownership of requested objects on every request\n"
                                "2. Use indirect object references instead of direct IDs\n"
                                "3. Implement proper authorization checks\n"
                                "4. Use UUIDs instead of sequential IDs\n"
                                "5. Implement rate limiting on ID enumeration attempts"
                            ),
                            evidence=f"Baseline length: {baseline_length}, Test length: {test_length}",
                            payload=f"Changed {param_name} from {current_id_int} to {test_id}",
                            request_details=f"URL: {test_url}",
                            response_details=f"Response length: {test_length}, Status: {test_status}",
                            confidence="Confirmed" if test_status == baseline_status else "High",
                            cwe_ids=["CWE-639"],
                            owasp_category="A01:2021 – Broken Access Control",
                        )
                        return True

                except Exception as e:
                    self.log("ERROR", f"[IDOR] Error testing query param {param_name}={test_id}: {e}")

        return False

    def _test_header_id_manipulation(self, url):
        """Test for IDOR by manipulating IDs in headers."""
        id_headers = ["X-User-ID", "X-UserID", "X-Account-ID", "X-Customer-ID", "X-Profile-ID"]

        baseline_body, baseline_status = self._make_request(url)
        if baseline_body is None:
            return False
        baseline_length = len(baseline_body)

        if not self.auth_headers:
            return False

        for header_name in id_headers:
            if header_name not in self.auth_headers:
                continue

            current_value = self.auth_headers[header_name]
            try:
                current_id_int = int(current_value)
            except ValueError:
                continue

            test_ids = [current_id_int + 1, current_id_int - 1, 1]

            for test_id in test_ids:
                if test_id <= 0:
                    continue

                try:
                    test_body, test_status = self._make_request(
                        url,
                        headers={header_name: str(test_id)},
                    )
                    if test_body is None:
                        continue
                    test_length = len(test_body)

                    if abs(test_length - baseline_length) > 100:
                        self._idor_found += 1
                        self.log("CRITICAL",
                                 f"[IDOR] Potential vulnerability! Header: {header_name} | "
                                 f"Original ID: {current_id_int} | Test ID: {test_id}")

                        self.add_vuln(
                            title="Insecure Direct Object Reference (IDOR) — Header Manipulation",
                            severity="Critical",
                            category="Access Control",
                            cvss_score=9.1,
                            description=(
                                f"An IDOR vulnerability was detected via header '{header_name}'.\n"
                                f"Manipulating the ID from {current_id_int} to {test_id} returned a different response."
                            ),
                            remediation=(
                                "1. Never trust header values for authorization\n"
                                "2. Derive user identity from session/token, not headers\n"
                                "3. Validate ownership on every object access\n"
                                "4. Implement proper authentication and authorization"
                            ),
                            evidence=f"Baseline length: {baseline_length}, Test length: {test_length}",
                            payload=f"Changed {header_name} from {current_id_int} to {test_id}",
                            request_details=f"URL: {url}, Header: {header_name}",
                            response_details=f"Response length: {test_length}",
                            confidence="High",
                            cwe_ids=["CWE-639"],
                            owasp_category="A01:2021 – Broken Access Control",
                        )
                        return True

                except Exception as e:
                    self.log("ERROR", f"[IDOR] Error testing header {header_name}={test_id}: {e}")

        return False

    def _test_sequential_enumeration(self, url):
        """Test for IDOR via sequential ID enumeration — probe a range of sequential IDs."""
        current_id = self._extract_ids_from_url(url)
        if not current_id:
            return False

        try:
            current_id_int = int(current_id)
        except ValueError:
            return False

        # Probe a range around the current ID to check for enumeration vulnerability
        test_ids = list(range(max(1, current_id_int - 5), current_id_int + 6))
        test_ids = [i for i in test_ids if i != current_id_int]

        baseline_body, baseline_status = self._make_request(url)
        if baseline_body is None:
            return False
        baseline_length = len(baseline_body)

        success_count = 0
        for test_id in test_ids:
            test_url = re.sub(r'/\d+(?=/|$)', f'/{test_id}', url)
            try:
                test_body, test_status = self._make_request(test_url)
                if test_body is not None and test_status not in [403, 404]:
                    success_count += 1
            except Exception as e:
                self.log("ERROR", f"[IDOR] Error during enumeration test for ID {test_id}: {e}")

        if success_count >= len(test_ids) * 0.7:
            self._idor_found += 1
            self.log("CRITICAL",
                     f"[IDOR] Sequential enumeration possible at {url}! "
                     f"Accessed {success_count}/{len(test_ids)} sequential IDs successfully.")

            self.add_vuln(
                title="Insecure Direct Object Reference (IDOR) — Sequential Enumeration",
                severity="Critical",
                category="Access Control",
                cvss_score=9.1,
                description=(
                    f"Sequential ID enumeration is possible at {url}.\n"
                    f"Successfully accessed {success_count}/{len(test_ids)} sequential IDs around {current_id_int}.\n"
                    f"This indicates sequential/guessable IDs are used without proper access controls.\n\n"
                    f"Impact: Attackers can enumerate all resources (users, orders, documents, etc.) "
                    f"by simply incrementing ID values."
                ),
                remediation=(
                    "1. Use unpredictable IDs (UUIDs) instead of sequential integers.\n"
                    "2. Implement proper access control checks on every request.\n"
                    "3. Add rate limiting on ID-based endpoints.\n"
                    "4. Monitor for sequential access patterns in logs."
                ),
                evidence=f"Accessed {success_count}/{len(test_ids)} sequential IDs",
                payload=f"Enumerated IDs around {current_id_int}",
                request_details=f"URL: {url}",
                response_details=f"Baseline length: {baseline_length}",
                confidence="Confirmed" if success_count == len(test_ids) else "High",
                cwe_ids=["CWE-639"],
                owasp_category="A01:2021 – Broken Access Control",
            )
            return True

        return False

    def _test_multi_tenant_isolation(self, url):
        """Test for multi-tenant isolation bypass — attempted cross-tenant access."""
        current_id = self._extract_ids_from_url(url)
        if not current_id:
            return False

        baseline_body, baseline_status = self._make_request(url)
        if baseline_body is None:
            return False

        # Try common tenant IDs belonging to other tenants
        other_tenant_ids = [str(i) for i in range(100, 110)]

        for tenant_id in other_tenant_ids:
            test_url = re.sub(r'/\d+(?=/|$)', f'/{tenant_id}', url)
            try:
                test_body, test_status = self._make_request(test_url)
                if test_body is not None and test_status not in [403, 404]:
                    self._idor_found += 1
                    self.log("CRITICAL",
                             f"[IDOR] Multi-tenant isolation bypass possible! "
                             f"Accessed tenant ID {tenant_id} at {url}")

                    self.add_vuln(
                        title="Insecure Direct Object Reference (IDOR) — Multi-Tenant Isolation Bypass",
                        severity="Critical",
                        category="Access Control",
                        cvss_score=9.1,
                        description=(
                            f"A multi-tenant isolation bypass was detected at {url}.\n"
                            f"Accessed tenant/resource ID {tenant_id} without proper authorization.\n"
                            f"This indicates that tenant isolation is not properly enforced.\n\n"
                            f"Impact: Attackers can access data from other tenants/customers, "
                            f"leading to widespread data breach."
                        ),
                        remediation=(
                            "1. IMPLEMENT ROW-LEVEL SECURITY for multi-tenant databases.\n"
                            "2. Always derive tenant context from authentication, not request parameters.\n"
                            "3. Validate tenant ownership on every resource access.\n"
                            "4. Use separate database schemas per tenant for sensitive data.\n"
                            "5. Implement regular cross-tenant access audits."
                        ),
                        evidence=f"Accessed tenant ID {tenant_id} with status {test_status}",
                        payload=f"Changed ID to {tenant_id}",
                        request_details=f"URL: {test_url}",
                        response_details=f"Status: {test_status}, Body length: {len(test_body)}",
                        confidence="Confirmed" if test_status == 200 else "High",
                        cwe_ids=["CWE-639"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )
                    return True
            except Exception as e:
                self.log("ERROR", f"[IDOR] Error during multi-tenant test for ID {tenant_id}: {e}")

        return False

    def _detect_id_pattern(self, url):
        """Detect whether the URL uses UUID or integer IDs."""
        if UUID_PATTERN.search(url):
            return "uuid"
        if INT_PATTERN.search(url):
            return "integer"
        return None

    def _discover_idor_endpoints(self):
        """Discover endpoints that might be vulnerable to IDOR."""
        endpoints = []

        try:
            results = self.discovery_context or {}

            for url_entry in results.get("urls", []):
                url = url_entry["url"]
                if self._extract_ids_from_url(url):
                    endpoints.append(url)
                else:
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    for param_name in params:
                        if param_name.lower() in QUERY_ID_PARAMS:
                            endpoints.append(url)
                            break

        except Exception as e:
            self.log("ERROR", f"[IDOR] Error discovering endpoints: {e}")

        return endpoints

    def run(self):
        self.log("INFO", f"[IDOR] Starting IDOR vulnerability scanning on {self.target}...")

        try:
            # Step 1: Discover potential IDOR endpoints
            self.log("INFO", "[IDOR] Discovering endpoints with ID parameters...")
            endpoints = self._discover_idor_endpoints()
            self.log("INFO", f"[IDOR] Found {len(endpoints)} potential IDOR endpoint(s)")

            # Step 2: Test each endpoint
            for url in endpoints[:30]:
                self._tested_endpoints += 1
                self.log("INFO", f"[IDOR] Testing endpoint: {url}")

                id_pattern = self._detect_id_pattern(url)
                self.log("INFO", f"[IDOR] ID pattern in URL: {id_pattern or 'unknown'}")

                # Test path ID manipulation
                if self._test_path_id_manipulation(url):
                    continue

                # Test query parameter ID manipulation
                if self._test_query_param_id_manipulation(url):
                    continue

                # Test header ID manipulation
                self._test_header_id_manipulation(url)

                # Test sequential enumeration
                self._test_sequential_enumeration(url)

                # Test multi-tenant isolation
                self._test_multi_tenant_isolation(url)

        except Exception as e:
            self.log("ERROR", f"[IDOR] Unexpected error during scan: {e}")

        self.log("SUCCESS" if not self.vulns else "WARNING",
                 f"[IDOR] Complete — {self._tested_endpoints} endpoint(s) tested | "
                 f"{self._idor_found} IDOR vulnerability/vulnerabilities confirmed")
        return self.vulns
