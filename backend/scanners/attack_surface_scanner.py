"""
attack_surface_scanner.py — Attack Surface Mapper
==================================================
Enumerates and maps the full attack surface of a web application:
  - All discovered endpoints / routes
  - Query parameters and form fields across all pages
  - External domains and third-party scripts
  - API endpoints (REST / GraphQL hints)
  - Admin / sensitive paths
  - File upload endpoints
  - Technology stack identified
  - Email addresses / internal references exposed
"""
import re, urllib.parse, urllib.request
from scanners.base_scanner import BaseScanner

SENSITIVE_PATH_RE = re.compile(
    r"(admin|administrator|manager|console|panel|dashboard|config|backup|"
    r"phpmyadmin|wp-admin|wp-login|cpanel|webmail|api/v\d|swagger|graphql|"
    r"actuator|debug|trace|health|metrics|env|info|beans|heapdump)", re.I
)

FILE_UPLOAD_RE = re.compile(
    r'<input[^>]+type=["\']file["\']', re.I
)

EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)

INTERNAL_IP_RE = re.compile(
    r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b'
)

API_PATTERNS = re.compile(
    r'["\']/(api|v\d+|rest|graphql|query|endpoint)[^"\']*["\']', re.I
)


class AttackSurfaceScanner(BaseScanner):
    SCANNER_NAME = "Attack Surface Mapper"
    _SCANNER_KEY = "attack_surface"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    # ------------------------------------------------------------------
    def run(self) -> list:
        self.log("INFO", f"[AttackSurface] Mapping attack surface of {self.target}...")
        try:
            urls, forms, html, all_html = self._crawl_deep()
            self._analyze_surface(urls, forms, html, all_html)
        except Exception as e:
            self.log("WARNING", f"[AttackSurface] Error: {e}")

        self.log("SUCCESS",
            f"[AttackSurface] Mapping complete. {len(self.vulns)} exposure(s) documented.")
        return self.vulns

    # ------------------------------------------------------------------
    def _crawl_deep(self):
        try:
            results = self.discovery_context or {}
            urls = [u["url"] if isinstance(u, dict) else u for u in results.get("urls", [])]
            if self.target not in urls:
                urls.insert(0, self.target)
            forms = results.get("forms", [])
            all_html = results.get("page_contents", {})
            combined = " ".join(all_html.values()) if all_html else ""
            return urls, forms, combined, all_html
        except Exception as e:
            self.log("ERROR", f"[AttackSurface] _crawl_deep error: {e}")
            body = self._fetch(self.target)
            return [self.target], [], body or "", {}

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url,
                headers={"User-Agent": "LarShield/2.0 AttackSurface"})
            with urllib.request.urlopen(req, timeout=8, context=self.get_ssl_context()) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.log("ERROR", f"[AttackSurface] _fetch error: {e}")
            return ""

    # ------------------------------------------------------------------
    def _analyze_surface(self, urls, forms, combined_html, all_html):
        # ── 1. Endpoint inventory ─────────────────────────────────────
        unique_paths = sorted({urllib.parse.urlparse(u).path for u in urls})
        self.log("INFO",
            f"[AttackSurface] Discovered {len(unique_paths)} unique path(s), "
            f"{len(forms)} form(s)")

        # ── 2. Sensitive / admin paths ────────────────────────────────
        sensitive = [p for p in unique_paths if SENSITIVE_PATH_RE.search(p)]
        if sensitive:
            self.add_vuln(
                title=f"Sensitive/Admin Paths Discovered ({len(sensitive)} paths)",
                severity="Medium",
                category="Attack Surface",
                cvss_score=5.3,
                description="The following sensitive endpoints were found accessible:\n\n" +
                    "\n".join(f"- `{self.target.rstrip('/')}{p}`" for p in sensitive[:20]),
                remediation="1. Restrict access to admin/management paths by IP allowlist.\n"
                    "2. Enforce strong authentication on all /admin, /api, /console paths.\n"
                    "3. Remove or disable unused endpoints in production.",
            )

        # ── 3. API endpoints ──────────────────────────────────────────
        api_paths = [p for p in unique_paths if re.search(r'/api|/v\d+|/graphql|/rest', p, re.I)]
        if api_paths:
            self.log("INFO", f"[AttackSurface] API surface: {len(api_paths)} endpoint(s)")
            self.add_vuln(
                title=f"API Attack Surface: {len(api_paths)} Endpoint(s) Discovered",
                severity="Low",
                category="Attack Surface",
                cvss_score=0.0,
                description="The following API endpoints are part of the attack surface "
                    "and should be audited for authentication, authorization, and input validation:\n\n"
                    + "\n".join(f"- `{self.target.rstrip('/')}{p}`" for p in api_paths[:20]),
                remediation="Ensure all API endpoints require authentication, validate input, "
                    "implement rate limiting, and are covered by the security test suite.",
            )

        # ── 4. File upload endpoints ──────────────────────────────────
        upload_forms = [f for f in forms
                        if FILE_UPLOAD_RE.search(str(f.get("raw_html","")))]
        if upload_forms:
            self.add_vuln(
                title=f"File Upload Endpoint(s) Detected ({len(upload_forms)} forms)",
                severity="High",
                category="Attack Surface",
                cvss_score=7.5,
                description=f"Found {len(upload_forms)} file upload form(s). "
                    "File upload functionality is a high-risk attack surface and must be "
                    "protected against:\n"
                    "- Unrestricted file type uploads (webshell upload)\n"
                    "- Malicious filename attacks (path traversal)\n"
                    "- Oversized file DoS\n"
                    "- MIME-type spoofing",
                remediation="1. Validate file types by magic bytes, not extension/MIME.\n"
                    "2. Store uploads outside the web root.\n"
                    "3. Rename uploaded files to random UUIDs.\n"
                    "4. Enforce maximum file size limits.\n"
                    "5. Scan uploads with antivirus before serving.",
            )

        # ── 5. Exposed email addresses ────────────────────────────────
        emails = list(set(EMAIL_RE.findall(combined_html)))
        emails = [e for e in emails if not e.endswith((".png",".jpg",".gif",".css",".js"))]
        if emails:
            self.add_vuln(
                title=f"Email Addresses Exposed in HTML ({len(emails)} address(es))",
                severity="Low",
                category="Information Disclosure",
                cvss_score=3.1,
                description="The following email addresses were found in page source:\n\n"
                    + "\n".join(f"- `{e}`" for e in emails[:15]) + "\n\n"
                    "Exposed emails enable targeted phishing, spam, and social engineering.",
                remediation="1. Obfuscate contact emails using JavaScript or server-side rendering.\n"
                    "2. Use contact forms instead of direct email links.\n"
                    "3. Consider a generic contact@domain.com address.",
            )

        # ── 6. Internal IP / hostname leaks ───────────────────────────
        internal_ips = list(set(INTERNAL_IP_RE.findall(combined_html)))
        if internal_ips:
            self.add_vuln(
                title=f"Internal IP Address(es) Leaked in Page Source ({len(internal_ips)})",
                severity="Medium",
                category="Information Disclosure",
                cvss_score=5.3,
                description="Internal RFC-1918 IP addresses were found in the page source:\n\n"
                    + "\n".join(f"- `{ip}`" for ip in internal_ips[:10]) + "\n\n"
                    "Leaking internal IPs aids network reconnaissance.",
                remediation="Remove all internal hostnames and IPs from HTML output. "
                    "Use public-facing domain names or proxied URLs.",
            )

        # ── 7. Third-party script domains ─────────────────────────────
        ext_domains = set()
        for m in re.finditer(r'src=["\']https?://([^/"\']+)', combined_html, re.I):
            d = m.group(1)
            if self.domain not in d:
                ext_domains.add(d)

        if len(ext_domains) > 5:
            self.add_vuln(
                title=f"Large Third-Party Script Surface ({len(ext_domains)} external domains)",
                severity="Medium",
                category="Supply Chain Security",
                cvss_score=5.9,
                description=f"Found {len(ext_domains)} distinct external domains providing "
                    "scripts or resources. Each represents a supply-chain trust boundary:\n\n"
                    + "\n".join(f"- `{d}`" for d in sorted(ext_domains)[:20]),
                remediation="1. Audit all external dependencies for necessity.\n"
                    "2. Self-host critical scripts where possible.\n"
                    "3. Add SRI (Subresource Integrity) to all external scripts.\n"
                    "4. Monitor CDNs and third-party scripts for tampering.",
            )

        # ── 8. Parameters summary ─────────────────────────────────────
        all_params: set = set()
        for url in urls:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            all_params.update(qs.keys())
        for form in forms:
            all_params.update(f.get("name","") for f in form.get("fields",[]) if f.get("name"))

        if all_params:
            self.log("INFO",
                f"[AttackSurface] {len(all_params)} unique input parameter(s) identified: "
                f"{', '.join(sorted(all_params)[:20])}")
            self.add_vuln(
                title=f"Input Parameter Inventory ({len(all_params)} parameter(s))",
                severity="Low",
                category="Attack Surface",
                cvss_score=0.0,
                description="The following input parameters were identified across all crawled pages "
                    "and should be tested for injection vulnerabilities:\n\n"
                    + ", ".join(f"`{p}`" for p in sorted(all_params)[:40]),
                remediation="Ensure all listed parameters are covered by:\n"
                    "- Input validation and sanitization\n"
                    "- SQL/NoSQL injection testing\n"
                    "- XSS testing\n"
                    "- Business logic testing",
            )
