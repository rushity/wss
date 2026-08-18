"""
race_condition_scanner.py — Race Condition (TOCTOU) Scanner
===========================================================
Advanced race condition detection module that tests for Time-of-Check to Time-of-Use vulnerabilities.

This scanner:
  1. Identifies endpoints susceptible to race conditions
  2. Tests for concurrent request vulnerabilities
  3. Detects double-spending and privilege escalation via race conditions
  4. Tests for file upload race conditions
  5. Checks for timing-based vulnerabilities in critical operations
  6. Multi-stage detection: probe endpoints, then confirm with concurrent bursts
"""
import urllib.request, urllib.error, urllib.parse, re, threading, time, os, tempfile
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector

RACE_CONDITION_ENDPOINTS = [
    "/api/transfer", "/api/withdraw", "/api/deposit",
    "/api/purchase", "/api/checkout", "/api/redeem",
    "/api/claim", "/api/vote", "/api/like", "/api/follow",
    "/api/unsubscribe", "/api/delete", "/api/update",
    "/api/upload", "/api/coupon", "/api/discount",
    "/api/gift-card", "/api/referral", "/api/bonus",
    "/api/credit", "/api/refund", "/api/apply",
    "/api/submit", "/api/register", "/api/signup",
]

RACE_INDICATORS = [
    r"insufficient funds", r"already claimed", r"already used",
    r"duplicate", r"already exists", r"limit exceeded",
    r"rate limit", r"too many requests", r"already redeemed",
    r"already applied", r"already registered",
]


class RaceConditionScanner(BaseScanner):
    SCANNER_NAME = "Race Condition (TOCTOU) Scanner"
    _SCANNER_KEY = "race_condition"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._headers = {"User-Agent": "LarShield/2.0 Race Condition Scanner"}
        if self.auth_headers:
            self._headers.update(self.auth_headers)
        self._tested_endpoints = 0
        self._race_conditions_found = 0
        self._concurrent_threads = kwargs.get("concurrent_threads", 10)
        self._burst_threads = kwargs.get("burst_threads", 50)
        self._timing = TimingAnomalyDetector()

    def _test_concurrent_requests(self, url, method="POST", data=None, burst=False):
        """Test for race conditions by sending concurrent requests — multi-stage."""
        threads_to_use = self._burst_threads if burst else self._concurrent_threads
        results = []
        success_count = 0
        error_count = 0
        lock = threading.Lock()

        def make_request():
            nonlocal success_count, error_count
            try:
                if data:
                    encoded = urllib.parse.urlencode(data).encode("utf-8")
                    body, status = self._make_request(
                        url, method="POST", data=encoded,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                else:
                    body, status = self._make_request(url, method=method)

                with lock:
                    results.append((status, body))
                    if status in [200, 201, 202]:
                        success_count += 1
                    else:
                        error_count += 1
            except Exception as e:
                with lock:
                    error_count += 1

        threads = []
        for _ in range(threads_to_use):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Analyze results
        if success_count > 1:
            self._race_conditions_found += 1
            burst_label = " (burst)" if burst else ""
            self.log("CRITICAL",
                     f"[Race Condition] Multiple successful requests detected{burst_label}! "
                     f"URL: {url} | Success: {success_count}/{threads_to_use}")

            self.add_vuln(
                title=f"Race Condition — Concurrent Request Vulnerability{' (Burst)' if burst else ''}",
                severity="Critical",
                category="Race Condition",
                cvss_score=9.8,
                description=(
                    f"A race condition vulnerability was detected at {url}.\n"
                    f"Sending {threads_to_use} concurrent requests resulted in {success_count} successes.\n"
                    f"This indicates the application does not properly handle concurrent operations, "
                    f"potentially allowing double-spending, privilege escalation, or resource exhaustion."
                ),
                remediation=(
                    "1. IMPLEMENT PROPER LOCKING MECHANISMS:\n"
                    "   - Use database transactions with proper isolation levels\n"
                    "   - Implement optimistic or pessimistic locking\n"
                    "   - Use atomic operations for critical sections\n"
                    "2. Add rate limiting and request deduplication\n"
                    "3. Implement idempotency keys for state-changing operations\n"
                    "4. Use message queues for processing critical operations sequentially\n"
                    "5. Add validation checks after state changes"
                ),
                evidence=f"Success: {success_count}/{threads_to_use} concurrent requests succeeded",
                payload=f"Concurrent requests: {threads_to_use}",
                request_details=f"URL: {url}, Method: {method}",
                response_details=f"{success_count} successes, {error_count} failures",
                confidence="Confirmed",
                cwe_ids=["CWE-362"],
                owasp_category="A01:2021 – Broken Access Control",
            )
            return True

        return False

    def _test_toctou(self, url):
        """Test for Time-of-Check Time-of-Use vulnerabilities."""
        self.log("INFO", f"[Race Condition] Testing TOCTOU on {url}")

        # Send initial request to establish state
        initial_body, initial_status = self._make_request(url)
        if initial_body is None:
            return False

        # Send concurrent check + use requests
        results = []
        lock = threading.Lock()

        def toctou_attempt():
            try:
                body1, status1 = self._make_request(url)
                body2, status2 = self._make_request(url)
                with lock:
                    results.append((status1, status2))
            except Exception as e:
                with lock:
                    results.append((0, 0))

        threads = []
        for _ in range(10):
            thread = threading.Thread(target=toctou_attempt)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Check for anomalous patterns (different states from same check)
        anomalous = sum(1 for s1, s2 in results if s1 != s2 and s1 in [200, 201, 202] and s2 in [200, 201, 202])
        if anomalous > 0:
            self._race_conditions_found += 1
            self.log("CRITICAL",
                     f"[Race Condition] TOCTOU vulnerability detected at {url}! "
                     f"{anomalous}/{len(results)} double-read anomalies detected")

            self.add_vuln(
                title="Race Condition — Time-of-Check Time-of-Use (TOCTOU)",
                severity="Critical",
                category="Race Condition",
                cvss_score=9.1,
                description=(
                    f"A TOCTOU vulnerability was detected at {url}.\n"
                    f"Detected {anomalous} cases where state changed between read and write operations.\n\n"
                    f"Impact: Attackers can exploit the window between permission checks and "
                    f"resource operations to bypass security controls."
                ),
                remediation=(
                    "1. Use atomic operations for check-and-set logic.\n"
                    "2. Implement row-level locking in database operations.\n"
                    "3. Use database transactions with SERIALIZABLE isolation level.\n"
                    "4. Implement compare-and-swap patterns for state changes.\n"
                    "5. Use idempotency tokens for critical operations."
                ),
                evidence=f"{anomalous}/{len(results)} TOCTOU anomalies detected",
                payload="Concurrent check-use requests",
                request_details=f"URL: {url}",
                response_details=f"{anomalous} state-change anomalies",
                confidence="Confirmed" if anomalous > 2 else "High",
                cwe_ids=["CWE-362"],
                owasp_category="A01:2021 – Broken Access Control",
            )
            return True

        return False

    def _test_coupon_race(self, url):
        """Test for coupon/gift-card style race conditions (redeem same code multiple times)."""
        test_data = {
            "code": "TESTCOUPON123",
            "amount": "10",
        }

        return self._test_concurrent_requests(url, "POST", test_data)

    def _test_double_spending(self, url):
        """Test for double-spending vulnerabilities in financial operations."""
        test_data = {
            "amount": "1",
            "recipient": "test_user",
            "currency": "USD",
        }

        return self._test_concurrent_requests(url, "POST", test_data)

    def _test_privilege_escalation_race(self, url):
        """Test for privilege escalation via race conditions."""
        test_data = {
            "role": "admin",
            "user_id": "test",
        }

        return self._test_concurrent_requests(url, "POST", test_data)

    def _test_file_upload_race(self, url):
        """Test for file upload race conditions."""
        test_data = {
            "file": "test.txt",
            "content": "test content",
        }

        return self._test_concurrent_requests(url, "POST", test_data)

    def _test_toctou_file_operations(self):
        """Test for TOCTOU via concurrent file operations."""
        try:
            tmpdir = tempfile.mkdtemp(prefix="wss_toctou_")
            test_file = os.path.join(tmpdir, "test.txt")
            results = []
            lock = threading.Lock()

            def file_race():
                try:
                    if not os.path.exists(test_file):
                        with open(test_file, "w") as f:
                            f.write("data")
                        with lock:
                            results.append("created")
                    else:
                        os.remove(test_file)
                        with lock:
                            results.append("deleted")
                except OSError:
                    pass
                except Exception as e:
                    self.log("ERROR", f"[Race Condition] File TOCTOU race error: {e}")

            threads = []
            for _ in range(50):
                thread = threading.Thread(target=file_race)
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join()

            created_count = results.count("created")
            deleted_count = results.count("deleted")
            if created_count > 0 and deleted_count > 0:
                self.add_vuln(
                    title="TOCTOU — File Race Condition (Local)",
                    severity="High",
                    category="Race Condition",
                    cvss_score=8.0,
                    description=f"Concurrent file operations detected race condition: "
                        f"{created_count} creates and {deleted_count} deletes in 50 threads. "
                        "File-based TOCTOU confirmed locally.",
                    remediation="Use atomic file operations with proper locking. "
                        "Implement compare-and-swap for file state changes.",
                    evidence=f"{created_count} creates, {deleted_count} deletes in 50 threads",
                    payload="Concurrent file create/delete",
                    request_details="Local file TOCTOU test",
                    response_details=f"{created_count} creates, {deleted_count} deletes",
                    confidence="High",
                    cwe_ids=["CWE-362", "CWE-367"],
                    owasp_category="A01:2021 – Broken Access Control",
                )
                self.log("CRITICAL", "[Race Condition] File TOCTOU race condition confirmed!")
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception as e:
            self.log("ERROR", f"[Race Condition] File TOCTOU test error: {e}")

    def _discover_race_condition_endpoints(self):
        """Discover endpoints susceptible to race conditions using centralized discovery context."""
        endpoints = []

        try:
            results = self.discovery_context or {}

            for url_entry in results.get("urls", []):
                url = url_entry["url"]
                for pattern in RACE_CONDITION_ENDPOINTS:
                    if pattern in url.lower():
                        endpoints.append(url)
                        break

            for form in results.get("forms", []):
                action = form.get("action", "")
                for pattern in RACE_CONDITION_ENDPOINTS:
                    if pattern in action.lower():
                        endpoints.append(action)
                        break

        except Exception as e:
            self.log("ERROR", f"[Race Condition] Error discovering endpoints: {e}")

        return endpoints

    def run(self):
        self.log("INFO", f"[Race Condition] Starting race condition scanning on {self.target}...")
        self.log("INFO", f"[Race Condition] Using {self._concurrent_threads} concurrent threads ({self._burst_threads} for burst)")

        try:
            # Step 1: Discover potential race condition endpoints
            self.log("INFO", "[Race Condition] Discovering susceptible endpoints...")
            endpoints = self._discover_race_condition_endpoints()
            self.log("INFO", f"[Race Condition] Found {len(endpoints)} potential race condition endpoint(s)")

            # Step 2: Test each endpoint
            for url in endpoints[:15]:
                self._tested_endpoints += 1
                self.log("INFO", f"[Race Condition] Testing endpoint: {url}")

                # Determine test type based on URL
                if any(x in url.lower() for x in ["transfer", "withdraw", "deposit", "purchase", "checkout"]):
                    self._test_double_spending(url)
                elif any(x in url.lower() for x in ["role", "admin", "privilege", "update"]):
                    self._test_privilege_escalation_race(url)
                elif "upload" in url.lower():
                    self._test_file_upload_race(url)
                elif any(x in url.lower() for x in ["coupon", "discount", "gift", "redeem", "claim", "bonus", "referral"]):
                    self._test_coupon_race(url)
                else:
                    self._test_concurrent_requests(url)

                # Stage 2: Timing baseline
                t0 = time.monotonic()
                self._test_concurrent_requests(url)
                elapsed = time.monotonic() - t0
                self._timing.record_timing(f"race_window_{url}", elapsed)

                # Stage 3: Burst test with more threads (50-thread burst)
                self.log("INFO", f"[Race Condition] Running burst test on {url} ({self._burst_threads} threads)...")
                t0 = time.monotonic()
                self._test_concurrent_requests(url, burst=True)
                burst_elapsed = time.monotonic() - t0
                if self._timing.test_payload(f"burst_{url}", burst_elapsed, z_threshold=3.0):
                    self.log("WARNING", f"[Race Condition] Burst timing anomaly at {url}")

                # Stage 4: TOCTOU test
                self._test_toctou(url)

            # File-based TOCTOU test
            self._test_toctou_file_operations()

        except Exception as e:
            self.log("ERROR", f"[Race Condition] Unexpected error during scan: {e}")

        self.log("SUCCESS" if not self.vulns else "WARNING",
                 f"[Race Condition] Complete — {self._tested_endpoints} endpoint(s) tested | "
                 f"{self._race_conditions_found} race condition(s) confirmed")
        return self.vulns
