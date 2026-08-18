"""
service_worker_scanner.py — Service Worker Security Scanner
"""
import re, urllib.request
from scanners.base_scanner import BaseScanner

SW_REGISTRATION_PATTERNS = [
    r"navigator\.serviceWorker\.register\s*\(",
    r"serviceWorker\.register\s*\(",
]
DANGEROUS_SW_PATTERNS = [
    ("self.addEventListener('fetch'",    "Intercepts all network requests"),
    ('self.addEventListener("fetch"',    "Intercepts all network requests"),
    ("cache.addAll(",                    "Caches resources — verify scope"),
    ("respondWith(",                     "Intercepts and modifies responses"),
    ("clients.claim(",                   "Immediately takes control of all pages"),
    ("skipWaiting(",                     "Skips waiting — may serve stale content"),
]

class ServiceWorkerScanner(BaseScanner):
    SCANNER_NAME = "Service Worker Security Scanner"
    _SCANNER_KEY = "service_worker"
    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[ServiceWorker] Auditing service worker configuration on {self.target}...")
        try:
            req = urllib.request.Request(self.target, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=8, context=self.get_ssl_context()) as r:
                html = r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.log("WARNING", f"[ServiceWorker] Error: {e}")
            return self.vulns

        # Find SW registrations
        sw_files = []
        for block in re.findall(r'<script[^>]*>(.*?)</script>', html, re.I | re.S):
            for pattern in SW_REGISTRATION_PATTERNS:
                m = re.search(pattern + r"['\"]([^'\"]+)['\"]", block)
                if m:
                    sw_files.append(self._resolve(m.group(1)))

        if not sw_files:
            self.log("SUCCESS", "[ServiceWorker] No service worker registrations found.")
            return self.vulns

        for sw_url in sw_files:
            self.log("INFO", f"[ServiceWorker] Found SW: {sw_url}")
            sw_code = self._fetch(sw_url)
            if sw_code:
                self._audit_sw(sw_url, sw_code)
            else:
                self.add_vuln(
                    title=f"Service Worker Registered but Not Accessible: {sw_url}",
                    severity="Low", category="Service Worker", cvss_score=0.0,
                    description="A service worker is registered but its file is not publicly accessible.",
                    remediation="Verify the SW file path is correct and accessible.",
                )
        return self.vulns

    def _audit_sw(self, sw_url, code):
        issues = []

        # Check scope — overly broad scope covers everything
        scope_m = re.search(r"register\s*\(['\"][^'\"]+['\"],\s*\{[^}]*scope\s*:\s*['\"]([^'\"]+)['\"]", code)
        if scope_m:
            scope = scope_m.group(1)
            if scope == "/" or scope == "/*":
                issues.append(("Service Worker Scope is '/' — Controls Entire Origin", "High",
                    "A SW with scope `/` intercepts ALL requests for the entire domain. "
                    "If compromised via dependency injection or prototype pollution, it can "
                    "serve malicious responses to every page.",
                    "Restrict SW scope to only the paths it needs: "
                    "navigator.serviceWorker.register('/sw.js', {scope: '/app/'})"))

        # Check for dangerous patterns
        for pattern, desc in DANGEROUS_SW_PATTERNS:
            if pattern in code:
                if "fetch" in pattern.lower() and "respondWith" in code:
                    issues.append(("Service Worker Intercepts and Modifies All Network Requests", "Medium",
                        f"The SW uses `fetch` + `respondWith` — it intercepts and can modify all network responses. "
                        "If the SW code is attackable, responses can be poisoned.",
                        "Audit SW fetch handlers. Validate cached responses. Use integrity checks."))
                    break

        # Missing updateViaCache
        if "updateViaCache" not in code:
            issues.append(("Service Worker Missing updateViaCache Configuration", "Low",
                "Without `updateViaCache: 'none'`, browsers may serve a cached SW file, "
                "delaying security updates to the SW.",
                "Set updateViaCache: 'none' in registration options."))

        for title, sev, desc, rem in issues:
            cvss = {"High": 7.4, "Medium": 5.3, "Low": 3.5}.get(sev, 0.0)
            self.add_vuln(title=title, severity=sev, category="Service Worker", cvss_score=cvss,
                description=f"SW file: `{sw_url}`\n\n{desc}", remediation=rem)

        if not issues:
            self.add_vuln(title=f"Service Worker Detected: {sw_url}", severity="Low",
                category="Service Worker", cvss_score=0.0,
                description="A service worker is active. Manual audit recommended for fetch interception logic.",
                remediation="Ensure the SW is audited for cache poisoning and request manipulation vectors.")

    def _resolve(self, src):
        if src.startswith("//"): return f"https:{src}"
        if src.startswith("/"):
            from urllib.parse import urlparse; p = urlparse(self.target)
            return f"{p.scheme}://{p.netloc}{src}"
        if not src.startswith("http"): return f"{self.target.rstrip('/')}/{src}"
        return src

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context()) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.log("ERROR", f"[ServiceWorker] _fetch error: {e}")
            return ""
