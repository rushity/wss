"""
deserialization_scanner.py — Insecure Deserialization Scanner
==============================================================
Expert-grade rewrite (GAP-006 fix):
  1. Scans Set-Cookie headers (original)
  2. Scans POST/PUT request bodies for serialized content
  3. Scans custom headers (X-Java-Serialized-Object, X-Serialized-Object)
  4. Extended signatures: .NET ViewState, Ruby Marshal, Node ND_FUNC
  5. Active probe: sends crafted Java serialized header and checks error signals
  6. Fixes false-positive-prone PHP "O:" pattern (now length-validates)
  7. Java, PHP, Python, .NET, Ruby YAML markers
"""
import base64, urllib.parse, json, re
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector, SizeAnomalyDetector
from utils.evasion import waf_evade

# ── Serialization signatures ──────────────────────────────────────────────
SIGNATURES = {
    "Java (ysoserial / ACED)": [
        (lambda v: isinstance(v, bytes) and v.startswith(b"\xac\xed\x00\x05"), "raw_bytes"),
        (lambda v: isinstance(v, str) and v.startswith("rO0AB"), "base64"),
        (lambda v: isinstance(v, str) and "java.io.Serializable" in v, "raw"),
        (lambda v: isinstance(v, str) and "java.beans" in v and "ObjectInputStream" in v, "raw"),
    ],
    "PHP Object Serialize": [
        (lambda v: isinstance(v, str) and bool(re.match(r'O:\d+:"', v)), "raw"),
        (lambda v: isinstance(v, str) and bool(re.match(r'a:\d+:\{', v)), "raw"),
        (lambda v: isinstance(v, str) and bool(re.match(r'C:\d+:"', v)), "raw"),
        (lambda v: isinstance(v, str) and bool(re.match(r'R:\d+;', v)), "raw"),
    ],
    "Python Pickle": [
        (lambda v: isinstance(v, str) and "c__main__" in v, "raw"),
        (lambda v: isinstance(v, str) and v.startswith("gASV"), "base64"),
        (lambda v: isinstance(v, str) and v.startswith("gAN9cQAutSw="), "base64"),
        (lambda v: isinstance(v, bytes) and v.startswith(b"\x80\x04\x95"), "raw_bytes"),
        (lambda v: isinstance(v, bytes) and v.startswith(b"\x80\x05\x95"), "raw_bytes"),
        (lambda v: isinstance(v, str) and "__reduce__" in v, "raw"),
    ],
    "Node.js (serialize-javascript)": [
        (lambda v: isinstance(v, str) and "_$$ND_FUNC$$_" in v, "raw"),
        (lambda v: isinstance(v, str) and "$$ND_OBJ$$_" in v, "raw"),
    ],
    ".NET ViewState": [
        (lambda v: isinstance(v, str) and v.startswith("/wEy"), "base64"),
        (lambda v: isinstance(v, str) and "__VIEWSTATE" in v and len(v) > 40, "form_field"),
        (lambda v: isinstance(v, str) and v.startswith("/wE"), "base64"),
        (lambda v: isinstance(v, str) and "__EVENTVALIDATION" in v and len(v) > 20, "form_field"),
    ],
    "Ruby Marshal": [
        (lambda v: isinstance(v, bytes) and v.startswith(b"\x04\x08"), "raw_bytes"),
        (lambda v: isinstance(v, str) and v.startswith("BAh"), "base64"),
        (lambda v: isinstance(v, str) and "ruby/object:" in v, "raw"),
    ],
    "Ruby YAML": [
        (lambda v: isinstance(v, str) and "!ruby/object:" in v, "raw"),
        (lambda v: isinstance(v, str) and "!ruby/class:" in v, "raw"),
    ],
}

# Active probe: a truncated Java serialized stream header (safe — won't RCE)
JAVA_PROBE_HEADER = base64.b64encode(b"\xac\xed\x00\x05t\x00\x1dWSS-DESER-SAFE-PROBE").decode()

JAVA_PAYLOADS = [
    (b"\xac\xed\x00\x05t\x00\x1dWSS-DESER-SAFE-PROBE", "application/x-java-serialized-object", "Java ACED magic bytes"),
    (b"\xac\xed\x00\x05sr\x00\x0cwss.Calc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "application/x-java-serialized-object", "Java gadget probe"),
]

PHP_PAYLOADS = [
    (b'O:10:"WssProbe":1:{s:4:"test";s:2:"ok";}', "application/x-www-form-urlencoded", "PHP serialize mark"),
    (b'a:2:{s:4:"test";s:2:"ok";s:4:"waka";s:3:"waka";}', "application/x-www-form-urlencoded", "PHP array serialized"),
    (b'C:10:"WssProbe":8:{testdata}', "application/x-www-form-urlencoded", "PHP custom serialized"),
]

PYTHON_PICKLE_PAYLOADS = [
    (b"\x80\x05\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x06WSS-OK\x94.", "application/octet-stream", "Python pickle (protocol 5)"),
    (b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x06WSS-OK\x94.", "application/octet-stream", "Python pickle (protocol 4)"),
    (b"gASVHQAAAAAAAABdlCh9lCiMAXABlIwFdGVzdJRSlJRSlIWUUpQa", "application/python-pickle", "Python pickle base64"),
]

DOTNET_VIEWSTATE_PAYLOADS = [
    (b"/wEyWSS==", "application/x-www-form-urlencoded", ".NET ViewState probe"),
    (b"/wE", "application/x-www-form-urlencoded", ".NET ViewState short"),
]

RUBY_YAML_PAYLOADS = [
    (b"--- !ruby/object:WssProbe\nname: test\n", "application/x-yaml", "Ruby YAML object"),
    (b"--- !ruby/class:WssProbe\n", "application/x-yaml", "Ruby YAML class"),
]

DESER_RESPONSE_SIGNALS = [
    "ClassNotFoundException", "ObjectInputStream", "deserializ",
    "java.io", "InvalidClassException", "readObject",
    "unserialize", "Serializable", "PersistenceException",
    "com.sun.jndi", "log4j", "jndi:", "InvocationTargetException",
]


class DeserializationScanner(BaseScanner):
    SCANNER_NAME = "Insecure Deserialization Scanner"
    _SCANNER_KEY = "deserialization"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[Deserialization] Scanning {self.target}...")

        self._timing_detector = TimingAnomalyDetector()

        body, status, headers = self._make_request(self.target, return_response_obj=True)
        if headers:
            self._check_response_headers(headers)

        self._check_url_params()

        self._test_active_post()

        self._test_header_injection()

        self._test_yaml_pickle_probes()

        self._test_expanded_formats()

        self._test_timing_deser()

        if not self.vulns:
            self.log("SUCCESS", "[Deserialization] No insecure deserialization detected.")
        return self.vulns

    # ── 1. Response headers / cookies ────────────────────────────────────
    def _check_response_headers(self, headers):
        cookies = []
        try:
            all_cookies = headers.get_all("Set-Cookie") or []
            cookies.extend(all_cookies)
        except Exception as e:
            self.log("ERROR", f"[Deserialization] Failed to parse cookies: {e}")

        for cookie in cookies:
            parts = cookie.split(";")
            if not parts: continue
            c_val = parts[0].split("=", 1)
            if len(c_val) == 2:
                name, val = c_val[0].strip(), urllib.parse.unquote(c_val[1].strip())
                self._check_value("Cookie", name, val)

    # ── 2. URL params ─────────────────────────────────────────────────────
    def _check_url_params(self):
        parsed = urllib.parse.urlparse(self.target)
        for k, v in urllib.parse.parse_qsl(parsed.query):
            self._check_value("URL param", k, urllib.parse.unquote(v))

    # ── 3. Active POST body probing ───────────────────────────────────────
    def _test_active_post(self):
        probes = JAVA_PAYLOADS + PHP_PAYLOADS + PYTHON_PICKLE_PAYLOADS + DOTNET_VIEWSTATE_PAYLOADS + RUBY_YAML_PAYLOADS

        for payload_bytes, content_type, label in probes:
            body, status = self._make_request(
                self.target, "POST", payload_bytes,
                {"Content-Type": content_type}
            )
            if body and any(sig.lower() in body.lower() for sig in DESER_RESPONSE_SIGNALS):
                self.log("CRITICAL", f"[Deserialization] Active probe triggered deser signal: {label}")
                self.add_vuln(
                    title=f"Active Deserialization Response — {label}",
                    severity="Critical",
                    category="Insecure Deserialization",
                    cvss_score=9.8,
                    cwe_ids=["CWE-502"],
                    owasp_category="A08:2021 – Software and Data Integrity Failures",
                    confidence="High",
                    cve_ids=[],
                    references=["https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization"],
                    description=(
                        f"Sending a crafted `{label}` payload to `{self.target}` triggered "
                        f"deserialization error signals in the response (`{status}`).\n\n"
                        "The server appears to be deserializing the untrusted POST body, "
                        "which can lead to Remote Code Execution via gadget chains."
                    ),
                    remediation=(
                        "1. Never deserialize untrusted data.\n"
                        "2. Use safe formats: JSON, XML with schema validation.\n"
                        "3. Implement deserialization allowlisting (Java: `ObjectInputFilter`).\n"
                        "4. Run deserialization in a sandboxed/restricted ClassLoader.\n"
                        "5. Deploy serialization kill-switches (ysoserial DefensiveObjectInputStream)."
                    ),
                    payload=label,
                    evidence=f"Error signal matched for {label}",
                    request_details=f"POST {self.target} Content-Type: {content_type}",
                    response_details=f"HTTP {status} with error signal in response",
                )
                return

    # ── 4. Header injection probe ─────────────────────────────────────────
    def _test_header_injection(self):
        headers_to_test = {
            "X-Java-Serialized-Object": JAVA_PROBE_HEADER,
            "X-Serialized-Object":      JAVA_PROBE_HEADER,
            "X-ViewState":              "/wEyWSS==",
            "X-Yaml-Object":            base64.b64encode(b"--- !ruby/object:WssProbe\nname: test\n").decode(),
            "X-Pickle-Object":          base64.b64encode(b"\x80\x05\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x06WSS-OK\x94.").decode(),
            "X-PHP-Serialize":          base64.b64encode(b'O:10:"WssProbe":1:{s:4:"test";s:2:"ok";}').decode(),
        }
        for header_name, value in headers_to_test.items():
            for eva_name, eva_value in waf_evade(value):
                body, status = self._make_request(self.target, headers={header_name: eva_value})
                if body and any(sig.lower() in body.lower() for sig in DESER_RESPONSE_SIGNALS):
                    self.add_vuln(
                        title=f"Deserialization via HTTP Header `{header_name}`",
                        severity="Critical",
                        category="Insecure Deserialization",
                        cvss_score=9.8,
                        cwe_ids=["CWE-502"],
                        owasp_category="A08:2021 – Software and Data Integrity Failures",
                        confidence="High",
                        description=(
                            f"Injecting a serialized object via the `{header_name}` header triggered "
                            "deserialization error signals, suggesting the application deserializes "
                            "this header value without validation."
                        ),
                        remediation=(
                            "Reject or ignore custom serialization headers unless explicitly required. "
                            "Validate and type-check all incoming data before deserialization."
                        ),
                        payload=eva_value[:50] + "...",
                    evidence=f"Error signal matched for header {header_name}",
                    request_details=f"GET {self.target} with {header_name} header",
                    response_details=f"HTTP {status} with error signature",
                )
                return

    # ── 5. YAML / Pickle probes ──────────────────────────────────────────
    def _test_yaml_pickle_probes(self):
        probes = [
            (b"--- !ruby/object:WssProbe\nname: test\n",
             "application/x-yaml", "Ruby YAML (header)"),
            (b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x06WSS-OK\x94.",
             "application/python-pickle", "Python pickle (header)"),
        ]
        for payload_bytes, content_type, label in probes:
            body, status = self._make_request(
                self.target, headers={"X-Serialized-Payload": base64.b64encode(payload_bytes).decode()}
            )
            if body and any(sig.lower() in body.lower() for sig in DESER_RESPONSE_SIGNALS):
                self.log("CRITICAL", f"[Deserialization] {label} triggered error signal")
                self.add_vuln(
                    title=f"Deserialization Signal via Header — {label}",
                    severity="Critical",
                    category="Insecure Deserialization",
                    cvss_score=9.5,
                    cwe_ids=["CWE-502"],
                    owasp_category="A08:2021 – Software and Data Integrity Failures",
                    confidence="Medium",
                    description=(
                        f"Sending base64-encoded {label} via custom header triggered "
                        "deserialization errors."
                    ),
                    remediation="Restrict custom headers. Validate all incoming data.",
                    payload=label,
                    evidence="Error signal in response",
                    request_details=f"GET {self.target} with X-Serialized-Payload header",
                    response_details=f"HTTP {status}",
                )
                return

    # ── 6. Expanded format probing ────────────────────────────────────────
    def _test_expanded_formats(self):
        all_payloads = JAVA_PAYLOADS + PHP_PAYLOADS + PYTHON_PICKLE_PAYLOADS + DOTNET_VIEWSTATE_PAYLOADS + RUBY_YAML_PAYLOADS
        for payload_bytes, content_type, label in all_payloads:
            body, status = self._make_request(
                self.target, "POST", payload_bytes,
                {"Content-Type": content_type}
            )
            if body and any(sig.lower() in body.lower() for sig in DESER_RESPONSE_SIGNALS):
                self.add_vuln(
                    title=f"Deserialization via POST — {label}",
                    severity="Critical",
                    category="Insecure Deserialization",
                    cvss_score=9.8,
                    cwe_ids=["CWE-502"],
                    owasp_category="A08:2021 – Software and Data Integrity Failures",
                    confidence="High",
                    description=f"Sending `{label}` payload to {self.target} triggered deserialization error signals.",
                    remediation="Never deserialize untrusted data. Use JSON/XML with schema validation.",
                    payload=label,
                    evidence=f"Error signal matched for {label}",
                    request_details=f"POST {self.target} Content-Type: {content_type}",
                    response_details=f"HTTP {status} with error signal",
                )
                return

    # ── 7. Timing-based deserialization detection ─────────────────────────
    def _test_timing_deser(self):
        self._timing_detector.build_baseline(lambda u, m, d, h, t: self._make_request(u, m, d, h, t), self.target, n=5, headers={})
        for payload_bytes, content_type, label in JAVA_PAYLOADS[:2]:
            _, _, elapsed = self._make_timed_request(
                self.target, "POST", payload_bytes,
                {"Content-Type": content_type}, timeout=15
            )
            if self._timing_detector.test_payload(f"deser_time_{label}", elapsed, label, z_threshold=2.5):
                self.add_vuln(
                    title=f"Possible Timing-Based Deserialization — {label}",
                    severity="High",
                    category="Insecure Deserialization",
                    cvss_score=7.5,
                    cwe_ids=["CWE-502"],
                    owasp_category="A08:2021 – Software and Data Integrity Failures",
                    confidence="Low",
                    description=f"Sending `{label}` payload produced anomalous response time ({elapsed:.1f}s vs baseline {self._timing_detector.mean:.1f}s), suggesting deserialization processing.",
                    remediation="Never deserialize untrusted data. Implement ObjectInputFilter.",
                    payload=label,
                    evidence=f"Timing: {elapsed:.1f}s vs baseline {self._timing_detector.mean:.1f}s",
                    request_details=f"POST {self.target} Content-Type: {content_type}",
                    response_details=f"Response time: {elapsed:.2f}s",
                )
                return

    # ── Signature checker ─────────────────────────────────────────────────
    def _check_value(self, source: str, key: str, value: str):
        self._match_signatures(source, key, value)

        try:
            padded = value + "=" * ((4 - len(value) % 4) % 4)
            decoded_bytes = base64.b64decode(padded)
            decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
            self._match_signatures(source, key, decoded_str, encoding="base64")
            for tech, checks in SIGNATURES.items():
                for fn, enc in checks:
                    if enc == "raw_bytes" and fn(decoded_bytes):
                        self._report(source, key, tech, "base64->bytes")
        except Exception as e:
            self.log("ERROR", f"[Deserialization] Base64 decode error: {e}")

    def _match_signatures(self, source, key, content, encoding="raw"):
        for tech, checks in SIGNATURES.items():
            for fn, enc in checks:
                if enc in ("raw", "form_field", "base64") and fn(content):
                    if len(content) > 8:
                        self._report(source, key, tech, encoding)
                        return

    def _report(self, source, key, tech, encoding):
        if any(v["title"].startswith(f"Insecure Deserialization ({tech})") for v in self.vulns):
            return
        self.add_vuln(
            title=f"Insecure Deserialization ({tech}) in {source}",
            severity="Critical",
            category="Insecure Deserialization",
            cvss_score=9.8,
            cwe_ids=["CWE-502"],
            owasp_category="A08:2021 – Software and Data Integrity Failures",
            confidence="High",
            cve_ids=["CVE-2015-4852"] if "Java" in tech else [],
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"],
            description=(
                f"Detected a **{tech}** serialized object in `{source}` -> `{key}` ({encoding}).\n\n"
                "Untrusted deserialization typically leads to **Remote Code Execution (RCE)** "
                "via gadget chains (e.g., ysoserial, phpggc)."
            ),
            remediation=(
                "1. Use JSON/XML with schema validation instead of native serialization.\n"
                "2. Implement type allowlisting before deserialization.\n"
                "3. Java: use `ObjectInputFilter` (JDK 9+) to block unexpected classes.\n"
                "4. PHP: set `allowed_classes` in `unserialize()` calls.\n"
                "5. Monitor for deserialization exceptions in production logs."
            ),
            payload=key,
            evidence=f"Serialization format: {tech}",
            request_details=f"Source: {source}",
            response_details=f"Encoded as: {encoding}",
        )
        self.log("CRITICAL", f"[Deserialization] {tech} signature in {source}:{key}")
