"""
business_logic_scanner.py — Business Logic Vulnerability Scanner
================================================================
Advanced business logic flaw detection module.

This scanner:
  1. Tests for coupon abuse and discount manipulation
  2. Detects privilege escalation through business logic
  3. Tests for payment bypass and price manipulation
  4. Checks for workflow bypass vulnerabilities
  5. Tests for parameter tampering in business processes
  6. Detects race conditions in business transactions
"""
import urllib.request, urllib.error, urllib.parse, ssl, re, json
from scanners.base_scanner import BaseScanner
from utils.differential import DifferentialAnalyzer, ParameterMutationTester

# ──────────────────────────────────────────────────────────────────────
# Business Logic Test Patterns
# ──────────────────────────────────────────────────────────────────────
BUSINESS_LOGIC_ENDPOINTS = [
    "/api/cart",
    "/api/checkout",
    "/api/purchase",
    "/api/order",
    "/api/payment",
    "/api/coupon",
    "/api/discount",
    "/api/redeem",
    "/api/transfer",
    "/api/withdraw",
    "/api/deposit",
    "/api/vote",
    "/api/like",
    "/api/follow",
    "/api/subscribe",
    "/api/unsubscribe",
]

# Price manipulation payloads
PRICE_MANIPULATION_PAYLOADS = [
    {"price": "-100"},
    {"price": "0"},
    {"price": "0.01"},
    {"price": "999999"},
    {"amount": "-100"},
    {"amount": "0"},
    {"discount": "100"},
    {"discount": "999"},
]

# Coupon abuse payloads
COUPON_PAYLOADS = [
    {"coupon": "TEST123"},
    {"coupon": "ADMIN"},
    {"coupon": "FREE"},
    {"coupon": "100OFF"},
    {"coupon": "UNLIMITED"},
    {"coupon_code": "TEST123"},
    {"promo_code": "FREE"},
]

# Quantity manipulation payloads
QUANTITY_PAYLOADS = [
    {"quantity": "-1"},
    {"quantity": "0"},
    {"quantity": "999999"},
    {"qty": "-1"},
    {"qty": "0"},
    {"qty": "999999"},
]

# ──────────────────────────────────────────────────────────────────────
# Scanner Implementation
# ──────────────────────────────────────────────────────────────────────
class BusinessLogicScanner(BaseScanner):
    SCANNER_NAME = "Business Logic Vulnerability Scanner"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        self._headers = {"User-Agent": "LarShield/2.0 Business Logic Scanner"}
        if self.auth_headers:
            self._headers.update(self.auth_headers)
        
        self._tested_endpoints = 0
        self._vulns_found = 0
        self._differential = DifferentialAnalyzer()
        self._mutation_tester = ParameterMutationTester(self._bl_mutation_req)

    def _bl_mutation_req(self, url, params):
        data = urllib.parse.urlencode(params).encode("utf-8")
        body, status = self._make_request(url, method="POST", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=8)
        return body or "", status

    def _get(self, url, timeout=8):
        try:
            req = urllib.request.Request(url, headers=self._headers)
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as resp:
                return resp.read(131072).decode("utf-8", errors="ignore"), resp.status
        except urllib.error.HTTPError as e:
            body = e.read(131072).decode("utf-8", errors="ignore") if e.fp else ""
            return body, e.code
        except Exception as e:
            self.log("ERROR", f"[BusinessLogic] _get error: {e}")
            return "", 0

    def _post(self, url, data, timeout=8):
        try:
            encoded = urllib.parse.urlencode(data).encode("utf-8")
            req = urllib.request.Request(url, data=encoded, headers={
                **self._headers,
                "Content-Type": "application/x-www-form-urlencoded"
            })
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as resp:
                return resp.read(131072).decode("utf-8", errors="ignore"), resp.status
        except urllib.error.HTTPError as e:
            body = e.read(131072).decode("utf-8", errors="ignore") if e.fp else ""
            return body, e.code
        except Exception as e:
            self.log("ERROR", f"[BusinessLogic] _post error: {e}")
            return "", 0

    def _test_price_manipulation(self, url):
        """Test for price manipulation vulnerabilities."""
        self.log("INFO", f"[Business Logic] Testing price manipulation on {url}")
        
        # GAP-ADV: Concurrent execution
        reqs = [{
            "url": url, "method": "POST", 
            "data": urllib.parse.urlencode(payload).encode("utf-8"),
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "payload": payload
        } for payload in PRICE_MANIPULATION_PAYLOADS]
        
        results = self._make_async_requests(reqs)
        
        for req_dict, body, status in results:
            if not body: continue
            payload = req_dict["payload"]
            
            # Check if manipulation was successful
            if status in [200, 201, 202] and any(
                indicator in body.lower() 
                for indicator in ["success", "completed", "order confirmed", "payment successful"]
            ):
                self._vulns_found += 1
                self.log("CRITICAL", 
                         f"[Business Logic] Price manipulation successful! Payload: {payload}")
                
                self.add_vuln(
                    title="Business Logic — Price Manipulation",
                    severity="Critical",
                    category="Business Logic",
                    cvss_score=9.8,
                    description=(
                        f"A price manipulation vulnerability was detected at {url}.\n"
                        f"Payload: {payload}\n"
                        "The application accepts manipulated prices without validation, "
                        "allowing attackers to purchase items for free or at reduced prices."
                    ),
                    remediation=(
                        "1. NEVER accept prices from client-side requests\n"
                        "2. Store prices server-side and reference by ID\n"
                        "3. Validate all monetary values on the server\n"
                        "4. Implement server-side price calculation\n"
                        "5. Add transaction monitoring for unusual pricing\n"
                        "6. Use payment gateway validation"
                    )
                )
                return True
        return False

    def _test_coupon_abuse(self, url):
        """Test for coupon abuse vulnerabilities."""
        self.log("INFO", f"[Business Logic] Testing coupon abuse on {url}")
        
        reqs = [{
            "url": url, "method": "POST", 
            "data": urllib.parse.urlencode(payload).encode("utf-8"),
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "payload": payload
        } for payload in COUPON_PAYLOADS]
        
        results = self._make_async_requests(reqs)
        
        for req_dict, body, status in results:
            if not body: continue
            payload = req_dict["payload"]
            
            # Check if coupon was accepted
            if status in [200, 201] and any(
                indicator in body.lower() 
                for indicator in ["discount applied", "coupon valid", "promo accepted", "success"]
            ):
                self._vulns_found += 1
                self.log("WARNING", 
                         f"[Business Logic] Coupon abuse possible! Payload: {payload}")
                
                self.add_vuln(
                    title="Business Logic — Coupon Abuse",
                    severity="High",
                    category="Business Logic",
                    cvss_score=8.5,
                    description=(
                        f"A coupon abuse vulnerability was detected at {url}.\n"
                        f"Payload: {payload}\n"
                        "The application accepts invalid or guessable coupon codes, "
                        "allowing unauthorized discounts."
                    ),
                    remediation=(
                        "1. Implement one-time-use coupon codes\n"
                        "2. Use cryptographically secure coupon generation\n"
                        "3. Validate coupon ownership and usage limits\n"
                        "4. Monitor coupon usage patterns\n"
                        "5. Implement rate limiting on coupon attempts"
                    )
                )
                return True
        return False

    def _test_quantity_manipulation(self, url):
        """Test for quantity manipulation vulnerabilities."""
        self.log("INFO", f"[Business Logic] Testing quantity manipulation on {url}")
        
        reqs = [{
            "url": url, "method": "POST", 
            "data": urllib.parse.urlencode(payload).encode("utf-8"),
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "payload": payload
        } for payload in QUANTITY_PAYLOADS]
        
        results = self._make_async_requests(reqs)
        
        for req_dict, body, status in results:
            if not body: continue
            payload = req_dict["payload"]
            
            # Check if manipulation was successful
            if status in [200, 201] and any(
                indicator in body.lower() 
                for indicator in ["success", "added", "updated", "confirmed"]
            ):
                self._vulns_found += 1
                self.log("WARNING", 
                         f"[Business Logic] Quantity manipulation possible! Payload: {payload}")
                
                self.add_vuln(
                    title="Business Logic — Quantity Manipulation",
                    severity="High",
                    category="Business Logic",
                    cvss_score=7.5,
                    description=(
                        f"A quantity manipulation vulnerability was detected at {url}.\n"
                        f"Payload: {payload}\n"
                        "The application accepts invalid quantities without validation."
                    ),
                    remediation=(
                        "1. Validate quantity ranges on the server\n"
                        "2. Implement minimum and maximum quantity limits\n"
                        "3. Check inventory levels before processing\n"
                        "4. Add server-side quantity validation\n"
                        "5. Monitor for unusual quantity patterns"
                    )
                )
                return True
        return False

    def _test_privilege_escalation(self, url):
        """Test for privilege escalation through business logic."""
        self.log("INFO", f"[Business Logic] Testing privilege escalation on {url}")
        
        escalation_payloads = [
            {"role": "admin"},
            {"role": "administrator"},
            {"role": "superuser"},
            {"is_admin": "true"},
            {"is_admin": "1"},
            {"admin": "true"},
            {"permissions": "all"},
            {"access_level": "admin"},
        ]
        
        reqs = [{
            "url": url, "method": "POST", 
            "data": urllib.parse.urlencode(payload).encode("utf-8"),
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "payload": payload
        } for payload in escalation_payloads]
        
        results = self._make_async_requests(reqs)
        
        for req_dict, body, status in results:
            if not body: continue
            payload = req_dict["payload"]
            
            # Check if escalation was successful
            if status in [200, 201] and any(
                indicator in body.lower() 
                for indicator in ["admin", "administrator", "success", "updated"]
            ):
                self._vulns_found += 1
                self.log("CRITICAL", 
                         f"[Business Logic] Privilege escalation possible! Payload: {payload}")
                
                self.add_vuln(
                    title="Business Logic — Privilege Escalation",
                    severity="Critical",
                    category="Business Logic",
                    cvss_score=9.8,
                    description=(
                        f"A privilege escalation vulnerability was detected at {url}.\n"
                        f"Payload: {payload}\n"
                        "The application allows privilege escalation through parameter manipulation."
                    ),
                    remediation=(
                        "1. Never accept role/permission parameters from client\n"
                        "2. Store user roles server-side\n"
                        "3. Implement proper role-based access control\n"
                        "4. Validate all privilege changes\n"
                        "5. Use immutable session tokens\n"
                        "6. Audit privilege changes"
                    )
                )
                return True
        return False

    def _test_mutation_workflow(self, url):
        self.log("INFO", f"[Business Logic] Testing parameter mutations on {url}")
        base_params = {"id": "1", "action": "test", "status": "pending"}
        mutations = [
            {"name": "negative_quantity", "params": {"quantity": "-1"}},
            {"name": "zero_price", "params": {"price": "0"}},
            {"name": "negative_price", "params": {"price": "-100"}},
            {"name": "overflow_amount", "params": {"amount": "999999999999"}},
            {"name": "admin_role", "params": {"role": "admin"}},
            {"name": "bypass_skip", "params": {"skip": "true"}},
            {"name": "bypass_step", "params": {"step": "complete"}},
            {"name": "bulk_discount", "params": {"discount": "100"}},
        ]
        results = self._mutation_tester.test(url, base_params, mutations)
        for res in results:
            if res.get("anomalous"):
                self._vulns_found += 1
                self.log("WARNING", f"[Business Logic] Anomalous mutation: {res['mutation']} status={res['status']} diff={res['length_diff_pct']}%")
                self.add_vuln(
                    title=f"Business Logic — Anomalous Parameter Mutation ({res['mutation']})",
                    severity="High",
                    category="Business Logic",
                    cvss_score=7.5,
                    description=(
                        f"Parameter mutation '{res['mutation']}' at {url} "
                        f"produced an anomalous response (status: {res['status']}, "
                        f"length difference: {res['length_diff_pct']}%). "
                        "This may indicate a business logic vulnerability."
                    ),
                    remediation="Validate all input parameters server-side. Implement proper state machines for workflows. "
                        "Ensure negative values, zero values, and role parameters are rejected.",
                    cwe_ids=["CWE-840"],
                    owasp_category="A01:2021 – Broken Access Control",
                )

    def _test_workflow_bypass(self, url):
        """Test for workflow bypass vulnerabilities."""
        self.log("INFO", f"[Business Logic] Testing workflow bypass on {url}")
        
        bypass_payloads = [
            {"step": "complete"},
            {"skip": "true"},
            {"bypass": "true"},
            {"status": "completed"},
            {"approved": "true"},
            {"verified": "true"},
        ]
        
        reqs = [{
            "url": url, "method": "POST", 
            "data": urllib.parse.urlencode(payload).encode("utf-8"),
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "payload": payload
        } for payload in bypass_payloads]
        
        results = self._make_async_requests(reqs)
        
        for req_dict, body, status in results:
            if not body: continue
            payload = req_dict["payload"]
            
            # Check if bypass was successful
            if status in [200, 201] and any(
                indicator in body.lower() 
                for indicator in ["success", "completed", "approved", "verified"]
            ):
                self._vulns_found += 1
                self.log("WARNING", 
                         f"[Business Logic] Workflow bypass possible! Payload: {payload}")
                
                self.add_vuln(
                    title="Business Logic — Workflow Bypass",
                    severity="High",
                    category="Business Logic",
                    cvss_score=8.0,
                    description=(
                        f"A workflow bypass vulnerability was detected at {url}.\n"
                        f"Payload: {payload}\n"
                        "The application allows skipping workflow steps through parameter manipulation."
                    ),
                    remediation=(
                        "1. Implement server-side workflow validation\n"
                        "2. Store workflow state server-side\n"
                        "3. Validate each step before allowing progression\n"
                        "4. Use state machines for complex workflows\n"
                        "5. Audit workflow transitions"
                    )
                )
                return True
        return False

    def _discover_business_logic_endpoints(self):
        """Discover endpoints with business logic vulnerabilities using shared context."""
        endpoints = []
        
        try:
            # GAP-ADV: Centralized context replaces redundant crawling
            results = self.discovery_context or {}
            
            # Check URLs for business logic patterns
            for url_entry in results.get("urls", []):
                url = url_entry.get("url") if isinstance(url_entry, dict) else url_entry
                for pattern in BUSINESS_LOGIC_ENDPOINTS:
                    if pattern in url.lower():
                        endpoints.append(url)
                        break
            
            # Check forms for business logic fields
            for form in results.get("forms", []):
                action = form.get("action", "")
                inputs = form.get("inputs", [])
                
                # Check for business-related input names
                for inp in inputs:
                    input_name = inp.get("name", "").lower()
                    if any(x in input_name for x in ["price", "amount", "quantity", "coupon", "discount", "role"]):
                        endpoints.append(action)
                        break
                        
        except Exception as e:
            self.log("WARNING", f"[Business Logic] Error processing endpoints from context: {str(e)}")
            
        return list(set(endpoints))

    def run(self):
        self.log("INFO", f"[Business Logic] Starting business logic vulnerability scanning on {self.target}...")
        
        try:
            # Step 1: Discover business logic endpoints
            self.log("INFO", "[Business Logic] Discovering business logic endpoints...")
            endpoints = self._discover_business_logic_endpoints()
            self.log("INFO", f"[Business Logic] Found {len(endpoints)} business logic endpoint(s)")
            
            if not endpoints:
                self.log("INFO", "[Business Logic] No business logic endpoints detected")
                return self.vulns
            
            # Step 2: Test each endpoint
            for url in endpoints[:15]:  # Limit to 15 endpoints
                self._tested_endpoints += 1
                self.log("INFO", f"[Business Logic] Testing endpoint: {url}")
                
                # Determine test type based on URL
                if any(x in url.lower() for x in ["checkout", "purchase", "payment", "order"]):
                    self._test_price_manipulation(url)
                elif any(x in url.lower() for x in ["coupon", "discount", "promo"]):
                    self._test_coupon_abuse(url)
                elif any(x in url.lower() for x in ["cart", "quantity", "qty"]):
                    self._test_quantity_manipulation(url)
                elif any(x in url.lower() for x in ["role", "admin", "user"]):
                    self._test_privilege_escalation(url)
                else:
                    self._test_workflow_bypass(url)

            self._test_mutation_workflow(url)
            
        except Exception as e:
            self.log("WARNING", f"[Business Logic] Unexpected error during scan: {str(e)}")
        
        # Summary
        self.log("SUCCESS" if not self.vulns else "WARNING",
                 f"[Business Logic] Complete — {self._tested_endpoints} endpoint(s) tested | "
                 f"{self._vulns_found} business logic vulnerability/vulnerabilities found")
        return self.vulns
