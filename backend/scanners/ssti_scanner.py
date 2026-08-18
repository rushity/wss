"""
ssti_scanner.py — Server-Side Template Injection (SSTI) Scanner
===============================================================
Detects SSTI vulnerabilities by injecting engine-specific arithmetic/string
probes into every URL parameter and HTML form field discovered via crawler.

Engines probed: Jinja2, Twig, Freemarker, Mako, Smarty, Pebble, Velocity,
Jade/Pug, Erb, Tornado.
Severity: CRITICAL — SSTI often leads to full Remote Code Execution (RCE).
"""

import re
import time
import urllib.parse
import urllib.request
import urllib.error

from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector, SizeAnomalyDetector
from utils.evasion import waf_evade

# ── Payloads ───────────────────────────────────────────────────────────────
SSTI_PROBES = [
    # Generic / polyglot
    ("{{7*7}}",                    r"49",        "Generic/Jinja2/Twig"),
    ("${7*7}",                     r"49",        "Generic/Freemarker/Groovy"),
    ("#{7*7}",                     r"49",        "Generic/Thymeleaf/SpEL"),
    ("%{7*7}",                     r"49",        "Generic/Velocity/OGNL"),
    ("<%= 7*7 %>",                 r"49",        "ERB/JSP"),

    # Jinja2 (Python)
    ("{{7*'7'}}",                  r"7777777",   "Jinja2"),
    ("{{config.__class__}}",       r"Config|class", "Jinja2 (config leak)"),
    ("{{''.__class__.__mro__}}",   r"tuple|object", "Jinja2 (MRO leak)"),
    ("{% if 1==1 %}YES{% endif %}", r"YES",       "Jinja2 (conditional)"),
    ("{% macro foo() %}49{% endmacro %}{{ foo() }}",
                                   r"49",        "Jinja2 (macro)"),
    ("{% set x = 7*7 %}{{x}}",     r"49",        "Jinja2 (set)"),

    # Twig (PHP)
    ("{{7*'7'}}",                  r"49",        "Twig"),
    ("{{_self.env.registerUndefinedFilterCallback}}",
                                   r"registerUndefined|error", "Twig (env leak)"),
    ("{{_self.env.getFilter('id')}}", r"getFilter|error", "Twig (getFilter)"),

    # Freemarker (Java)
    ("${\"freemarker\".toUpperCase()}", r"FREEMARKER", "Freemarker"),
    ("<#assign x=7*7>${x}",        r"49",        "Freemarker (assign)"),
    ("${7*7}",                     r"49",        "Freemarker (math)"),

    # Smarty (PHP)
    ("{$smarty.version}",          r"\d+\.\d+",  "Smarty"),
    ("{math equation=\"7*7\"}",    r"49",        "Smarty (math)"),
    ("{php}echo 49;{/php}",        r"49",        "Smarty (php tag)"),

    # Mako (Python)
    ("${7*7}",                     r"49",        "Mako"),
    ("<%\n  import os\n%>${os.getcwd()}", r"[A-Za-z]:\\|/[a-z]", "Mako (os leak)"),
    ("${self.__class__}",          r"class",     "Mako (class leak)"),
    ("${self.module.cache}",       r"cache|dict", "Mako (namespace leak)"),

    # Pebble (Java)
    ("{{ 7 * 7 }}",                r"49",        "Pebble"),
    ("{% set x = 7*7 %}{{x}}",     r"49",        "Pebble (set)"),
    ("{{ 7 * 7 }}",                r"49",        "Pebble (math)"),

    # Velocity (Java)
    ("#set($x=7*7)$x",             r"49",        "Velocity"),
    ("#if(1==1)YES#end",           r"YES",       "Velocity (conditional)"),

    # Jade / Pug
    ("#{7*7}",                     r"49",        "Jade/Pug"),
    ("!{7*7}",                     r"49",        "Pug (unescaped)"),

    # Tornado (Python)
    ("{{7*7}}",                    r"49",        "Tornado"),
    ("{% import os %}{{os.popen('echo 49').read()}}",
                                   r"49",        "Tornado (rce)"),
    ("{{ escape(7*7) }}",          r"49",        "Tornado (escape)"),

    # Handlebars / Mustache
    ("{{7*7}}",                    r"49",        "Handlebars"),

    # Math expression detection
    ("{{7*'7'}}",                  r"7777777",   "Jinja2 (math string)"),
    ("${21*2}",                    r"42",        "Freemarker (math 21*2)"),
    ("{{3*3}}",                    r"9",         "Generic (3*3)"),

    # Polyglot SSTI payloads
    ("{{7*7}}{{'7'*7}}",           r"49|7777777","Polyglot Jinja2/Twig"),
    ("${7*7}#{7*7}",              r"49",        "Polyglot Freemarker/Thymeleaf"),
    ("#{7*7}${7*7}",              r"49",        "Polyglot Thymeleaf/Freemarker"),
    ("<%=7*7%>{{7*7}}",           r"49",        "Polyglot ERB/Jinja2"),
]

# ── Time-based SSTI detection ──────────────────────────────────────────────
TIME_BASED_PROBES = [
    # Jinja2 time-based
    ("{% if 1==1 %}{%endif%}",             0.1, "Jinja2 noop"),
    # Jinja2 sleep via range (Python)
    ("{% for x in range(5) %}{%endfor%}",  0.3, "Jinja2 range loop"),
]

COMMON_PARAMS = [
    "q", "query", "search", "name", "msg", "message", "input",
    "text", "comment", "title", "subject", "body", "content",
    "template", "page", "view", "lang", "locale", "redirect",
    "url", "path", "file", "id", "user", "email",
]


class SstiScanner(BaseScanner):
    SCANNER_NAME = "Server-Side Template Injection (SSTI) Scanner"
    _SCANNER_KEY = "ssti"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._tested   = 0
        self._found    = 0
        self._reported: set[str] = set()

    def run(self) -> list:
        self.log("INFO",
            f"[SSTI] Starting SSTI scan on {self.target} "
            f"with {len(SSTI_PROBES)} engine-specific probes...")

        self._timing_detector = TimingAnomalyDetector()

        try:
            endpoints, forms = self._crawl()
            self.log("INFO",
                f"[SSTI] Discovered {len(endpoints)} URL(s) and "
                f"{len(forms)} form(s) to test")

            for url in endpoints:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params = list(qs.keys()) if qs else COMMON_PARAMS[:8]
                self._probe_params(url, parsed, params)

            for form in forms:
                self._probe_form(form)

        except Exception as e:
            self.log("ERROR", f"[SSTI] Unexpected error: {e}")

        if not self.vulns:
            self._test_time_based()

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[SSTI] Complete — {self._tested} probe(s) fired | "
            f"{self._found} SSTI vulnerability/vulnerabilities confirmed",
        )
        return self.vulns

    def _crawl(self):
        try:
            if self.discovery_context and "urls" in self.discovery_context:
                urls = [u.get("url") if isinstance(u, dict) else u for u in self.discovery_context["urls"]]
                forms = self.discovery_context.get("forms", [])
                return urls, forms
            return [self.target], []
        except Exception as e:
            self.log("ERROR", f"[SSTI] Crawl error: {e}")
            return [self.target], []

    def _probe_params(self, url: str, parsed, params: list[str]):
        base = urllib.parse.urlunparse(
            parsed._replace(query="", fragment="")
        )
        for param in params:
            for payload, pattern, engine in SSTI_PROBES:
                for eva_name, eva_payload in waf_evade(payload):
                    encoded = urllib.parse.urlencode({param: eva_payload})
                    test_url = f"{base}?{encoded}"
                    self._tested += 1

                    body, status = self._make_request(test_url)
                    if body and re.search(pattern, body):
                        self._report(url, param, eva_payload, engine, test_url, pattern)
                        return

    def _probe_form(self, form: dict):
        action  = form.get("action") or self.target
        method  = form.get("method", "get").lower()
        fields  = form.get("fields", [])

        for payload, pattern, engine in SSTI_PROBES:
            for eva_name, eva_payload in waf_evade(payload):
                data = {f["name"]: eva_payload for f in fields if f.get("name")}
                if not data:
                    break
                self._tested += 1

                try:
                    if method == "post":
                        encoded = urllib.parse.urlencode(data).encode()
                        headers = {
                            "User-Agent": "LarShield/2.0 SSTI-Probe",
                            "Content-Type": "application/x-www-form-urlencoded",
                        }
                        body, status = self._make_request(action, "POST", encoded, headers)
                    else:
                        qs = urllib.parse.urlencode(data)
                        body, status = self._make_request(f"{action}?{qs}")

                    if body and re.search(pattern, body):
                        param_names = ", ".join(data.keys())
                        self._report(action, param_names, eva_payload, engine, action, pattern)
                        return
                except Exception as e:
                    self.log("ERROR", f"[SSTI] Form probe error: {e}")
                    continue

    def _test_time_based(self):
        """Test for time-based SSTI by comparing response times."""
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        if not qs:
            return

        self._timing_detector.build_baseline(lambda u, m, d, h, t: self._make_request(u, m, d, h, t), self.target, n=5, headers={})

        for k, _ in qs[:2]:
            for payload, expected_delay, label in TIME_BASED_PROBES:
                for eva_name, eva_payload in waf_evade(payload):
                    test_qs = [(k_p, (eva_payload if k_p == k else v_p)) for k_p, v_p in qs]
                    test_url = parsed._replace(query=urllib.parse.urlencode(test_qs)).geturl()
                    _, _, elapsed = self._make_timed_request(test_url, timeout=15)

                    if self._timing_detector.test_payload(f"ssti_time_{k}", elapsed, eva_payload, z_threshold=2.5) and elapsed > expected_delay + 0.5:
                        self.log("CRITICAL",
                            f"[SSTI] Time-based SSTI signal on param `{k}` "
                            f"({elapsed:.1f}s vs baseline {self._timing_detector.mean:.1f}s, {label})")
                        key = f"{self.target}:{k}:time-based"
                        if key in self._reported:
                            return
                        self._reported.add(key)
                        self._found += 1
                        self.add_vuln(
                            title=f"Possible Time-Based SSTI in parameter `{k}`",
                            severity="High",
                            category="SSTI",
                            cvss_score=8.5,
                            cwe_ids=["CWE-1336"],
                            owasp_category="A03:2021 – Injection",
                            confidence="Medium",
                            references=["https://portswigger.net/web-security/server-side-template-injection"],
                            description=(
                                f"Time-based SSTI probe `{eva_payload}` ({label}) in param `{k}` "
                                f"produced {elapsed:.1f}s response vs baseline {self._timing_detector.mean:.1f}s, "
                                "suggesting template expression evaluation."
                            ),
                            remediation=(
                                "1. NEVER pass raw user input to template render functions.\n"
                                "2. Use a sandboxed template environment.\n"
                                "3. Apply strict input validation and allowlisting."
                            ),
                            payload=eva_payload,
                            evidence=f"Timing delta: {elapsed - self._timing_detector.mean:.1f}s",
                            request_details=f"GET {test_url}",
                            response_details=f"Response time: {elapsed:.2f}s vs baseline {self._timing_detector.mean:.2f}s",
                        )
                        return

    def _report(self, url: str, param: str, payload: str, engine: str, test_url: str, pattern: str = ""):
        key = f"{url}:{param}:{engine}"
        if key in self._reported:
            return
        self._reported.add(key)
        self._found += 1

        self.log("CRITICAL",
            f"[SSTI] CONFIRMED! Engine={engine} | Param={param} | "
            f"Payload={payload!r} | URL={test_url}")

        self.add_vuln(
            title=f"Server-Side Template Injection ({engine})",
            severity="Critical",
            category="Injection",
            cvss_score=9.8,
            cwe_ids=["CWE-1336"],
            owasp_category="A03:2021 – Injection",
            confidence="Confirmed",
            description=(
                f"A Server-Side Template Injection vulnerability was confirmed at "
                f"`{url}` via the `{param}` parameter using a {engine} engine probe "
                f"(`{payload}`). The template expression was evaluated server-side, "
                f"confirming that user input is rendered directly by the template engine.\n\n"
                "SSTI is often exploitable for full Remote Code Execution (RCE), allowing an "
                "attacker to read files, exfiltrate environment variables, execute OS commands, "
                "and establish a reverse shell."
            ),
            remediation=(
                "1. NEVER pass raw user input to template render functions.\n"
                "2. Use a sandboxed template environment (e.g. Jinja2 SandboxedEnvironment).\n"
                "3. Apply strict input validation and allowlisting.\n"
                "4. If dynamic templates are required, use a logic-less engine (Mustache).\n"
                "5. Review all template render() / render_template_string() call sites."
            ),
            payload=payload,
            evidence=f"Pattern `{pattern}` matched in response for {engine}",
            request_details=f"GET {test_url}",
            response_details="Engine-specific pattern matched in response body",
        )
