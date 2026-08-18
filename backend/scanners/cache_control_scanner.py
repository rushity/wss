"""
cache_control_scanner.py — Browser Cache Control Scanner
"""
import urllib.request, urllib.error
from scanners.base_scanner import BaseScanner

SENSITIVE_PATHS = [
    "/account", "/profile", "/dashboard", "/settings", "/api/me",
    "/api/user", "/admin", "/invoices", "/billing", "/orders",
    "/payment", "/statements", "/reports",
]

class CacheControlScanner(BaseScanner):
    SCANNER_NAME = "Browser Cache Control Scanner"
    _SCANNER_KEY = "cache_control"
    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[CacheControl] Checking Cache-Control headers on sensitive pages of {self.target}...")
        base = self.target.rstrip("/")
        risky = []

        # Check main page
        for path in [""] + SENSITIVE_PATHS:
            url = base + path if path else base
            headers, status = self._get_headers(url)
            if status not in (200, 302): continue
            cc = headers.get("cache-control", "").lower()
            pragma = headers.get("pragma", "").lower()
            ct = headers.get("content-type", "").lower()
            # Skip non-HTML/JSON (images, CSS, etc.)
            if any(t in ct for t in ("image/", "text/css", "font/", "javascript")): continue
            # Vulnerable if no-store is absent
            if "no-store" not in cc:
                risky.append({
                    "url": url, "cache-control": cc or "(missing)",
                    "pragma": pragma or "(missing)", "status": status
                })

        if risky:
            self.add_vuln(
                title=f"Sensitive Pages Cacheable by Browser ({len(risky)} pages)",
                severity="Medium",
                category="Information Disclosure",
                cvss_score=5.3,
                description="The following authenticated/sensitive pages lack `Cache-Control: no-store`, "
                    "allowing browsers and shared proxies to cache the responses. On shared/public devices, "
                    "a subsequent user can press Back or access the browser cache to retrieve private data:\n\n" +
                    "\n".join(f"- `{r['url']}` — Cache-Control: `{r['cache-control']}`" for r in risky[:8]),
                remediation="Add to all authenticated responses:\n"
                    "`Cache-Control: no-store, no-cache, must-revalidate, max-age=0`\n"
                    "`Pragma: no-cache`\n"
                    "`Expires: 0`",
            )
        else:
            self.log("SUCCESS", "[CacheControl] All sensitive pages properly set Cache-Control: no-store.")
        return self.vulns

    def _get_headers(self, url):
        try:
            req = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context()) as r:
                return {k.lower(): v for k, v in r.headers.items()}, r.status
        except urllib.error.HTTPError as e:
            return {k.lower(): v for k, v in e.headers.items()}, e.code
        except Exception as e:
            self.log("ERROR", f"[CacheControl] _get_headers error: {e}")
            return {}, 0
