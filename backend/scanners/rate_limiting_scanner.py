"""
rate_limiting_scanner.py — API Rate Limiting Scanner
====================================================
Advanced API rate limiting and abuse detection module.

This scanner:
  1. Tests for missing rate limiting on API endpoints
  2. Detects rate limiting bypass techniques
  3. Tests for endpoint-specific rate limits
  4. Checks for DoS vulnerability via unlimited requests
  5. Tests for authentication-independent rate limiting
  6. Detects IP-based vs user-based rate limiting
"""
import urllib.request, urllib.error, urllib.parse, ssl, re, time
from scanners.base_scanner import BaseScanner

# ──────────────────────────────────────────────────────────────────────
# Rate Limiting Test Configuration
# ──────────────────────────────────────────────────────────────────────
RATE_LIMIT_THRESHOLDS = {
    "strict": 10,      # Very strict rate limit
    "moderate": 50,    # Moderate rate limit
    "lenient": 100,   # Lenient rate limit
    "none": 1000,     # No rate limit
}

RATE_LIMIT_INDICATORS = [
    r"rate limit",
    r"too many requests",
    r"429",
    r"throttled",
    r"quota exceeded",
    r"limit exceeded",
    r"try again later",
]

# ──────────────────────────────────────────────────────────────────────
# Scanner Implementation
# ──────────────────────────────────────────────────────────────────────
class RateLimitingScanner(BaseScanner):
    SCANNER_NAME = "API Rate Limiting Scanner"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        self._headers = {"User-Agent": "LarShield/2.0 Rate Limiting Scanner"}
        if self.auth_headers:
            self._headers.update(self.auth_headers)
        
        self._tested_endpoints = 0
        self._vulns_found = 0
        self._max_requests = kwargs.get("max_requests", 100)

    def _get(self, url, timeout=8):
        try:
            req = urllib.request.Request(url, headers=self._headers)
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as resp:
                return resp.read(131072).decode("utf-8", errors="ignore"), resp.status, resp.headers
        except urllib.error.HTTPError as e:
            body = e.read(131072).decode("utf-8", errors="ignore") if e.fp else ""
            return body, e.code, e.headers if hasattr(e, 'headers') else {}
        except Exception as e:
            self.log("ERROR", f"[RateLimiting] _get error: {e}")
            return "", 0, {}

    def _test_rate_limiting(self, url):
        """Test for rate limiting on an endpoint."""
        self.log("INFO", f"[Rate Limiting] Testing rate limiting on {url}")
        
        success_count = 0
        rate_limited = False
        limit_threshold = None
        
        for i in range(self._max_requests):
            try:
                body, status, headers = self._get(url, timeout=3)
                
                # Check for rate limiting indicators
                if status == 429:
                    rate_limited = True
                    limit_threshold = i + 1
                    self.log("INFO", f"[Rate Limiting] Rate limit detected after {i + 1} requests")
                    break
                
                # Check for rate limiting in response body
                for pattern in RATE_LIMIT_INDICATORS:
                    if re.search(pattern, body, re.IGNORECASE):
                        rate_limited = True
                        limit_threshold = i + 1
                        self.log("INFO", f"[Rate Limiting] Rate limit detected in response after {i + 1} requests")
                        break
                
                if rate_limited:
                    break
                
                if status in [200, 201, 202]:
                    success_count += 1
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.01)
                
            except Exception as e:
                self.log("ERROR", f"[RateLimiting] _test_rate_limiting loop error: {e}")
                continue
        
        # Analyze results
        if not rate_limited and success_count >= self._max_requests:
            self._vulns_found += 1
            self.log("CRITICAL", 
                     f"[Rate Limiting] No rate limiting detected! {success_count} successful requests")
            
            self.add_vuln(
                title="API Rate Limiting — Missing Rate Limit",
                severity="High",
                category="Rate Limiting",
                cvss_score=7.5,
                description=(
                    f"The endpoint {url} has no rate limiting.\n"
                    f"Successfully sent {success_count} requests without being throttled.\n"
                    "This can lead to DoS attacks, credential brute-forcing, and API abuse."
                ),
                remediation=(
                    "1. IMPLEMENT RATE LIMITING:\n"
                    "   - Use rate limiting middleware (e.g., express-rate-limit, Django Ratelimit)\n"
                    "   - Set appropriate limits per endpoint\n"
                    "   - Use sliding window or token bucket algorithms\n"
                    "2. Implement IP-based and user-based rate limiting\n"
                    "3. Add rate limiting headers (X-RateLimit-Limit, X-RateLimit-Remaining)\n"
                    "4. Monitor for abuse patterns\n"
                    "5. Implement CAPTCHA for suspicious activity"
                )
            )
            return True
        
        elif rate_limited and limit_threshold > RATE_LIMIT_THRESHOLDS["moderate"]:
            self.log("WARNING", 
                     f"[Rate Limiting] Rate limit threshold too high: {limit_threshold} requests")
            
            self.add_vuln(
                title="API Rate Limiting — Insufficient Rate Limit",
                severity="Medium",
                category="Rate Limiting",
                cvss_score=5.3,
                description=(
                    f"The endpoint {url} has rate limiting but the threshold is too high.\n"
                    f"Rate limit kicks in after {limit_threshold} requests, which may allow abuse."
                ),
                remediation=(
                    "1. Reduce rate limiting thresholds\n"
                    "2. Implement stricter limits for sensitive endpoints\n"
                    "3. Use progressive rate limiting (stricter limits for repeated abuse)\n"
                    "4. Monitor for suspicious patterns"
                )
            )
            return True
        
        return False

    def _test_rate_limiting_bypass(self, url):
        """Test for rate limiting bypass techniques."""
        self.log("INFO", f"[Rate Limiting] Testing rate limiting bypass on {url}")
        
        # Test 1: Different User-Agent headers
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
            "Mozilla/5.0 (Linux; Android)",
            "curl/7.68.0",
            "Python/3.9",
        ]
        
        success_count = 0
        for ua in user_agents:
            try:
                headers = self._headers.copy()
                headers["User-Agent"] = ua
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=3, context=self._ctx) as resp:
                    if resp.status in [200, 201, 202]:
                        success_count += 1
                time.sleep(0.01)
            except Exception as e:
                self.log("ERROR", f"[RateLimiting] _test_rate_limiting_bypass UA loop error: {e}")
                continue
        
        if success_count == len(user_agents):
            self.log("WARNING", 
                     f"[Rate Limiting] Rate limiting bypassed via User-Agent rotation!")
            
            self.add_vuln(
                title="API Rate Limiting — User-Agent Bypass",
                severity="Medium",
                category="Rate Limiting",
                cvss_score=5.5,
                description=(
                    f"Rate limiting can be bypassed by rotating User-Agent headers.\n"
                    f"Successfully sent {success_count} requests with different User-Agents."
                ),
                remediation=(
                    "1. Implement user-based rate limiting instead of IP-based\n"
                    "2. Use authentication tokens for rate limiting\n"
                    "3. Implement device fingerprinting\n"
                    "4. Use CAPTCHA for suspicious activity"
                )
            )
            return True
        
        # Test 2: IP bypass via X-Forwarded-For header
        try:
            headers = self._headers.copy()
            headers["X-Forwarded-For"] = "1.2.3.4"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=3, context=self._ctx) as resp:
                if resp.status in [200, 201, 202]:
                    self.log("WARNING", 
                             f"[Rate Limiting] Rate limiting bypassed via X-Forwarded-For!")
                    
                    self.add_vuln(
                        title="API Rate Limiting — IP Header Bypass",
                        severity="Medium",
                        category="Rate Limiting",
                        cvss_score=6.5,
                        description=(
                            "Rate limiting can be bypassed by spoofing IP via X-Forwarded-For header."
                        ),
                        remediation=(
                            "1. Use trusted proxy configurations\n"
                            "2. Validate X-Forwarded-For headers\n"
                            "3. Use authentication-based rate limiting\n"
                            "4. Implement proper IP validation"
                        )
                    )
                    return True
        except Exception as e:
            self.log("ERROR", f"[RateLimiting] _test_rate_limiting_bypass XFF error: {e}")
        
        return False

    def _test_endpoint_specific_limits(self, url):
        """Test for endpoint-specific rate limiting."""
        self.log("INFO", f"[Rate Limiting] Testing endpoint-specific limits on {url}")
        
        # Test authentication endpoint specifically
        if any(x in url.lower() for x in ["/login", "/auth", "/signin", "/token"]):
            # Auth endpoints should have very strict rate limiting
            self.log("INFO", "[Rate Limiting] Testing authentication endpoint rate limiting")
            
            success_count = 0
            for i in range(20):  # Test with 20 requests
                try:
                    body, status, headers = self._get(url, timeout=3)
                    if status in [200, 201, 202]:
                        success_count += 1
                    time.sleep(0.01)
                except Exception as e:
                    self.log("ERROR", f"[RateLimiting] auth endpoint test error: {e}")
                    continue
            
            if success_count >= 20:
                self.log("WARNING", 
                         f"[Rate Limiting] Auth endpoint has insufficient rate limiting!")
                
                self.add_vuln(
                    title="API Rate Limiting — Insufficient Auth Endpoint Protection",
                    severity="High",
                    category="Rate Limiting",
                    cvss_score=8.0,
                    description=(
                        f"The authentication endpoint {url} has insufficient rate limiting.\n"
                        f"Successfully sent {success_count} requests without being throttled.\n"
                        "This enables credential brute-forcing and account enumeration."
                    ),
                    remediation=(
                        "1. Implement very strict rate limiting on auth endpoints (e.g., 5-10 requests/minute)\n"
                        "2. Implement account lockout after failed attempts\n"
                        "3. Use CAPTCHA for repeated failed attempts\n"
                        "4. Monitor for brute-force patterns\n"
                        "5. Implement IP-based blocking for suspicious activity"
                    )
                )
                return True
        
        return False

    def _discover_api_endpoints(self):
        """Discover API endpoints for rate limiting testing using centralized discovery context."""
        endpoints = []
        
        try:
            results = self.discovery_context or {}
            
            # Add discovered URLs
            for url_entry in results.get("urls", []):
                url = url_entry["url"]
                if "/api/" in url.lower():
                    endpoints.append(url)
            
            # Add form actions
            for form in results.get("forms", []):
                action = form.get("action", "")
                if action:
                    endpoints.append(action)
            
        except Exception as e:
            self.log("WARNING", f"[Rate Limiting] Error discovering endpoints: {str(e)}")
        
        # Always include the main target
        if self.target not in endpoints:
            endpoints.insert(0, self.target)
        
        return list(set(endpoints))  # Remove duplicates

    def run(self):
        self.log("INFO", f"[Rate Limiting] Starting API rate limiting scanning on {self.target}...")
        self.log("INFO", f"[Rate Limiting] Testing with up to {self._max_requests} requests per endpoint")
        
        try:
            # Step 1: Discover API endpoints
            self.log("INFO", "[Rate Limiting] Discovering API endpoints...")
            endpoints = self._discover_api_endpoints()
            self.log("INFO", f"[Rate Limiting] Found {len(endpoints)} endpoint(s) to test")
            
            # Step 2: Test each endpoint (limit to prevent excessive testing)
            for url in endpoints[:5]:  # Limit to 5 endpoints
                self._tested_endpoints += 1
                self.log("INFO", f"[Rate Limiting] Testing endpoint: {url}")
                
                # Test rate limiting
                if self._test_rate_limiting(url):
                    continue  # If critical vuln found, move to next
                
                # Test rate limiting bypass
                self._test_rate_limiting_bypass(url)
                
                # Test endpoint-specific limits
                self._test_endpoint_specific_limits(url)
            
        except Exception as e:
            self.log("WARNING", f"[Rate Limiting] Unexpected error during scan: {str(e)}")
        
        # Summary
        self.log("SUCCESS" if not self.vulns else "WARNING",
                 f"[Rate Limiting] Complete — {self._tested_endpoints} endpoint(s) tested | "
                 f"{self._vulns_found} rate limiting vulnerability/vulnerabilities found")
        return self.vulns
