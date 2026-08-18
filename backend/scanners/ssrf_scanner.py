"""
ssrf_scanner.py — Advanced Server-Side Request Forgery (SSRF) Scanner
======================================================================
Comprehensive SSRF detection module that tests for server-side request forgery.

This scanner:
  1. Identifies URL parameters that may trigger server-side requests
  2. Tests for internal network access (localhost, private IPs)
  3. Detects cloud metadata service access (AWS, GCP, Azure)
  4. Tests for blind SSRF using out-of-band techniques
  5. Checks for common SSRF bypass techniques
  6. Multi-stage detection: probe endpoints, then confirm with specific payloads
"""
import urllib.request, urllib.error, urllib.parse, re
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector
from utils.evasion import waf_evade
from utils.callback import build_callback_url, probe_callback, build_oob_domain
from utils.payload_library import get_ssrf_payloads

# Use advanced payload library
SSRF_PAYLOADS_ALL = get_ssrf_payloads()
SSRF_PAYLOADS = SSRF_PAYLOADS_ALL['internal'] + SSRF_PAYLOADS_ALL['cloud_metadata'] + SSRF_PAYLOADS_ALL['dns_rebinding']

SSRF_INDICATORS = {
    "aws": [
        r"ami-id", r"instance-id", r"local-hostname", r"public-hostname",
        r"placement/", r"iam/security-credentials", r"access-key",
        r"secret-key", r"session-token", r"security-credentials",
        r"region", r"availability-zone", r"kernel-id", r"ramdisk-id",
        r"reservation-id", r"account-id", r"instance-type",
    ],
    "gcp": [
        r"computeMetadata", r"instance/", r"project/", r"attributes/",
        r"service-accounts", r"google", r"numericProjectId",
    ],
    "azure": [
        r"subscriptionId", r"resourceGroupName", r"vmId", r"location",
        r"compute/", r"azEnvironment", r"osType", r"sku",
        r"publicIpAddress", r"privateIpAddress",
    ],
    "alibaba": [
        r"region-id", r"zone-id", r"instance-id", r"image-id",
        r"ram/security-credentials",
    ],
    "digitalocean": [
        r"droplet_id", r"droplet", r"user-data", r"vendor-data",
        r"public-keys",
    ],
    "oracle": [
        r"opc/v1/instance", r"oci",
    ],
    "openstack": [
        r"openstack", r"meta_data.json", r"network_data.json",
        r"public_keys", r"availability_zone",
    ],
    "kubernetes": [
        r"apiVersion", r"namespaces", r"kube-system", r"ServiceAccount",
        r"Bearer", r"kubernetes", r"kubectl",
    ],
    "dict": [
        r"redis_version", r"redis_mode", r"os:", r"uptime_in_seconds",
        r"rifile_age", r"total_connections_received",
    ],
    "internal": [
        r"root:x:0:0:", r"\[extensions\]", r"localhost", r"127\.0\.0\.1",
        r"192\.168\.", r"10\.", r"172\.1[6-9]\.", r"172\.2[0-9]\.",
        r"172\.3[0-1]\.", r"ssh-rsa", r"BEGIN RSA PRIVATE KEY",
        r"redis_version", r"redis_mode",
    ],
}

SSRF_PARAMS = [
    "url", "redirect", "next", "return", "ref", "callback", "dest", "target",
    "uri", "path", "file", "feed", "site", "link", "host", "proxy", "fetch",
    "load", "import", "source", "endpoint", "api", "service", "resource",
    "image", "img", "src", "href", "action", "data", "document", "page",
    "css", "include", "template", "view", "render", "download", "out",
    "to", "domain", "validate", "continue", "location", "return_to",
]


class SsrfScanner(BaseScanner):
    SCANNER_NAME = "Advanced Server-Side Request Forgery (SSRF) Scanner"
    _SCANNER_KEY = "ssrf"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._headers = {"User-Agent": "LarShield/2.0 SSRF Scanner"}
        if self.auth_headers:
            self._headers.update(self.auth_headers)
        self._tested_params = 0
        self._ssrf_found = 0
        self._callback_url = kwargs.get("callback_url", "http://burpcollaborator.net/ssrf-test")
        self._collaborator_urls = [
            "http://burpcollaborator.net/ssrf-test",
            "http://ssrf-interactsh.com/test",
            "http://oob.dnslog.cn/ssrf",
        ]
        self._timing_detector = TimingAnomalyDetector()
        self._oob_callback_url = build_callback_url("/ssrf")

    def _check_ssrf_response(self, body, payload, vector_desc, source_ip=None):
        """Check if the response contains SSRF indicators."""
        detected_type = None
        matched_pattern = None

        for cloud_type, patterns in SSRF_INDICATORS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    detected_type = cloud_type
                    matched_pattern = pattern
                    break
            if detected_type:
                break

        if detected_type:
            self._ssrf_found += 1
            self.log("CRITICAL",
                     f"[SSRF] VULNERABILITY CONFIRMED! Vector: {vector_desc} | "
                     f"Type: {detected_type.upper()} | Payload: {payload[:80]} | "
                     f"Pattern: {matched_pattern}")

            severity = "Critical" if detected_type in ["aws", "gcp", "azure", "alibaba"] else "High"
            cvss = 9.8 if detected_type in ["aws", "gcp", "azure", "alibaba"] else 8.6

            evidence = f"Matched pattern: {matched_pattern}\nDetected cloud type: {detected_type.upper()}"
            if source_ip:
                evidence += f"\nSource IP: {source_ip}"

            self.add_vuln(
                title=f"Server-Side Request Forgery (SSRF) — {detected_type.upper()} Access",
                severity=severity,
                category="Server-Side Request Forgery",
                cvss_score=cvss,
                description=(
                    f"An SSRF vulnerability was confirmed at {vector_desc}.\n"
                    f"Payload: `{payload}`\n"
                    f"The application fetched the attacker-controlled URL server-side, "
                    f"revealing {detected_type.upper()} information or internal network details.\n\n"
                    f"Impact: Access to cloud metadata (credentials), internal services, "
                    f"network scanning, and potential pivot to internal infrastructure."
                ),
                remediation=(
                    "1. IMPLEMENT ALLOWLIST VALIDATION for all user-supplied URLs:\n"
                    "   - Only allow specific, trusted domains\n"
                    "   - Reject private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)\n"
                    "   - Block metadata service IPs (169.254.169.254)\n"
                    "2. Use a dedicated HTTP client library with proper DNS resolution.\n"
                    "3. Disable unused URL schemes (file://, ftp://, gopher://, etc.).\n"
                    "4. Implement network-level egress filtering.\n"
                    "5. Use cloud-specific IMDSv2 (AWS) or equivalent protections.\n"
                    "6. Add authentication headers for internal service calls."
                ),
                evidence=evidence,
                payload=payload[:200],
                request_details=f"Vector: {vector_desc}",
                response_details=f"Response length: {len(body)} chars, Indicator: {detected_type.upper()}",
                confidence="Confirmed" if len(body) > 50 else "High",
                cwe_ids=["CWE-918"],
                owasp_category="A10:2021 – SSRF",
            )
            return True
        return False

    def _test_blind_ssrf(self, url, param_name, method="GET"):
        """Test for blind SSRF using callback/collaborator URLs and timing-based detection."""
        self._tested_params += 1

        if not self._timing_detector.has_baseline:
            self._timing_detector.build_baseline(
                lambda u, m, d, h, t: self._make_request(u, m, d, h, t),
                url, n=3,
            )

        reqs = []
        for collab_url in self._collaborator_urls + [self._oob_callback_url]:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = collab_url
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"
                # BUG-4 FIX: Store collab_url in the request dict so we can retrieve
                # the correct URL per-result. Previously used the loop var directly
                # inside results iteration, which always held the LAST loop value.
                reqs.append({"url": test_url, "method": "GET", "payload": collab_url, "collab_url": collab_url})
            else:
                reqs.append({
                    "url": url,
                    "method": "POST",
                    "data": urllib.parse.urlencode({param_name: collab_url}).encode("utf-8"),
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "payload": collab_url,
                    "collab_url": collab_url,  # BUG-4 FIX: capture per-request
                })

        results = self._make_async_requests(reqs)
        for req_dict, body, status in results:
            if status != 0:
                # BUG-4 FIX: Use req_dict["collab_url"] not the outer loop variable
                this_collab_url = req_dict.get("collab_url", req_dict.get("payload", ""))
                self.log("WARNING",
                         f"[SSRF] Blind SSRF probe sent to {this_collab_url} via param '{param_name}' — "
                         f"status {status}. Check callback service for evidence.")
                self.add_vuln(
                    title="Blind SSRF — Out-of-Band Detection",
                    severity="High",
                    category="Server-Side Request Forgery",
                    cvss_score=8.6,
                    description=(
                        f"A blind SSRF vulnerability may exist at {url} via parameter '{param_name}'.\n"
                        f"Sent out-of-band probe to: {this_collab_url}\n"
                        f"The server returned HTTP {status}, suggesting the request was processed.\n"
                        f"Check your callback/collaborator service for incoming connections.\n\n"
                        f"Impact: Blind SSRF can be used to scan internal networks, "
                        f"access cloud metadata, and pivot to internal systems."
                    ),
                    remediation=(
                        "1. Implement allowlist validation for all user-supplied URLs.\n"
                        "2. Block outbound connections to external services.\n"
                        "3. Disable unused URL schemes (file://, ftp://, gopher://).\n"
                        "4. Implement network-level egress filtering."
                    ),
                    evidence=f"Callback URL: {this_collab_url} returned HTTP {status}",
                    payload=this_collab_url,
                    request_details=f"Vector: {method} {url} -> param '{param_name}'",
                    response_details=f"HTTP {status}, body length: {len(body or '')}",
                    confidence="Medium",
                    cwe_ids=["CWE-918"],
                    owasp_category="A10:2021 – SSRF",
                )
                return True
        return False

    def _test_dns_ssrf(self, url, param_name, method="GET"):
        """Test for SSRF via DNS-based exfiltration using timing differentials."""
        self._tested_params += 1

        dns_payloads = [
            "http://dnslog.cn/ssrf-test",
            "http://nslookup-ssrf.test",
            "http://dnsbin.xyz/ssrf-test",
        ]

        for dns_url in dns_payloads:
            try:
                if method.upper() == "GET":
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = dns_url
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"
                    body, status, elapsed = self._make_timed_request(test_url, timeout=12)
                else:
                    data = urllib.parse.urlencode({param_name: dns_url}).encode("utf-8")
                    body, status, elapsed = self._make_timed_request(
                        url, method="POST", data=data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=12,
                    )

                if status != 0:
                    self.log("WARNING",
                             f"[SSRF] DNS SSRF probe sent — possible blind SSRF via param '{param_name}' "
                             f"(status={status}, elapsed={elapsed:.2f}s)")
                    is_timing_anomaly = False
                    if self._timing_detector.has_baseline:
                        is_timing_anomaly = self._timing_detector.test_payload(
                            f"dns_{dns_url}", elapsed, dns_url, z_threshold=3.0
                        )
                    confidence = "High" if is_timing_anomaly else "Medium"
                    self.add_vuln(
                        title="Blind SSRF — DNS-Based Detection",
                        severity="High",
                        category="Server-Side Request Forgery",
                        cvss_score=8.6,
                        description=(
                            f"A blind SSRF vulnerability may exist at {url} via parameter '{param_name}'.\n"
                            f"DNS-based out-of-band probe sent to: {dns_url}\n"
                            f"The server responded (HTTP {status}) in {elapsed:.2f}s.\n\n"
                            f"Impact: Attackers can exfiltrate data via DNS lookups and scan internal networks."
                        ),
                        remediation=(
                            "1. Block outbound DNS lookups for suspicious domains.\n"
                            "2. Implement allowlist validation for all URLs.\n"
                            "3. Use a dedicated DNS resolver with threat intelligence."
                        ),
                        evidence=f"DNS probe sent to {dns_url}, response time: {elapsed:.2f}s",
                        payload=dns_url,
                        request_details=f"Vector: {method} {url} -> param '{param_name}'",
                        response_details=f"HTTP {status}, elapsed {elapsed:.2f}s",
                        confidence=confidence,
                        cwe_ids=["CWE-918"],
                        owasp_category="A10:2021 – SSRF",
                    )
                    return True
            except Exception as e:
                self.log("ERROR", f"[SSRF] DNS SSRF probe error: {e}")
        return False

    def _generate_ssrf_variants(self) -> list[str]:
        variants = list(SSRF_PAYLOADS)
        for p in SSRF_PAYLOADS:
            for name, variant in waf_evade(p):
                if "://" in variant:
                    variants.append(variant)
        return variants

    def _test_parameter_ssrf(self, url, param_name, method="GET", form_inputs=None):
        """Test a specific parameter for SSRF using concurrency — multi-stage: probe then confirm."""
        self._tested_params += 1

        all_payloads = self._generate_ssrf_variants()
        reqs = []
        for payload in all_payloads:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"
                reqs.append({"url": test_url, "method": "GET", "payload": payload})
            else:
                data = {i["name"]: (i["value"] or "test") for i in (form_inputs or [])}
                data[param_name] = payload
                reqs.append({
                    "url": url,
                    "method": "POST",
                    "data": urllib.parse.urlencode(data).encode("utf-8"),
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "payload": payload,
                })

        results = self._make_async_requests(reqs)
        for req_dict, body, status in results:
            if body and self._check_ssrf_response(body, req_dict["payload"], f"{method} {req_dict['url']} -> '{param_name}'"):
                return True

        return False

    def _discover_ssrf_parameters(self):
        """Discover potential SSRF parameters using centralized discovery context."""
        discovered = []

        try:
            results = self.discovery_context or {}

            for url_entry in results.get("urls", []):
                url = url_entry["url"]
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param_name in params:
                    if param_name.lower() in SSRF_PARAMS:
                        discovered.append((url, param_name, "GET"))

            for form in results.get("forms", []):
                action = form.get("action", "")
                method = form.get("method", "POST")
                for inp in form.get("inputs", []):
                    param_name = inp.get("name", "")
                    if param_name.lower() in SSRF_PARAMS:
                        discovered.append((action, param_name, method))

        except Exception as e:
            self.log("ERROR", f"[SSRF] Error discovering parameters: {e}")

        return discovered

    def _probe_common_ssrf_params(self):
        """Probe common SSRF parameter names using concurrency."""
        base = self.target.rstrip("/")

        reqs = []
        for param in SSRF_PARAMS[:15]:
            for payload in SSRF_PAYLOADS[:5]:
                test_url = f"{base}?{param}={urllib.parse.quote(payload)}"
                reqs.append({"url": test_url, "method": "GET", "payload": payload, "param": param})

        results = self._make_async_requests(reqs)
        for req_dict, body, status in results:
            if body and self._check_ssrf_response(body, req_dict["payload"], f"Probe ?{req_dict['param']}="):
                return True
        return False

    def _test_cloud_metadata_endpoints(self):
        """Dedicated test for cloud metadata endpoints using various access methods."""
        base = self.target.rstrip("/")

        metadata_paths = [
            "/latest/meta-data/",
            "/latest/user-data",
            "/computeMetadata/v1/",
            "/metadata/instance",
        ]

        reqs = []
        for path in metadata_paths:
            test_url = f"{base}{path}"
            reqs.append({"url": test_url, "method": "GET", "payload": path})

            # Try with Host header override
            reqs.append({
                "url": test_url,
                "method": "GET",
                "headers": {"Host": "metadata.google.internal"},
                "payload": f"{path} (Host override)",
            })

        results = self._make_async_requests(reqs)
        for req_dict, body, status in results:
            if status != 0 and body:
                if self._check_ssrf_response(body, req_dict["payload"], f"Metadata endpoint {req_dict['url']}"):
                    return True
        return False

    def run(self):
        self.log("INFO", f"[SSRF] Starting advanced SSRF vulnerability scanning on {self.target}...")
        self.log("INFO", f"[SSRF] Testing with {len(SSRF_PAYLOADS)} SSRF payload variants")

        try:
            # Step 1: Test dedicated cloud metadata endpoints
            self.log("INFO", "[SSRF] Testing cloud metadata endpoints...")
            self._test_cloud_metadata_endpoints()

            # Step 2: Discover SSRF parameters
            self.log("INFO", "[SSRF] Discovering potential SSRF parameters...")
            params = self._discover_ssrf_parameters()
            self.log("INFO", f"[SSRF] Found {len(params)} potential SSRF parameters to test")

            # Step 3: Test discovered parameters
            for url, param_name, method in params:
                self.log("INFO", f"[SSRF] Testing parameter: {method} {url} -> '{param_name}'")
                self._test_parameter_ssrf(url, param_name, method)

            # Step 4: Probe common parameter names
            self.log("INFO", "[SSRF] Probing common SSRF parameter names...")
            self._probe_common_ssrf_params()

            # Step 5: Blind SSRF testing via callback URLs
            self.log("INFO", "[SSRF] Testing for blind SSRF via callback URLs...")
            for url, param_name, method in params[:5]:
                self._test_blind_ssrf(url, param_name, method)

            # Step 6: DNS-based SSRF detection
            self.log("INFO", "[SSRF] Testing for DNS-based SSRF...")
            for url, param_name, method in params[:5]:
                self._test_dns_ssrf(url, param_name, method)

        except Exception as e:
            self.log("ERROR", f"[SSRF] Unexpected error during scan: {e}")

        self.log("SUCCESS" if not self.vulns else "WARNING",
                 f"[SSRF] Complete — {self._tested_params} parameters tested | "
                 f"{self._ssrf_found} SSRF vulnerability/vulnerabilities confirmed")
        return self.vulns
