import re
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse
from scanners.base_scanner import BaseScanner

HIJACK_RISK = {
    "script": {"weight": 5, "desc": "JavaScript — full XSS capability"},
    "link": {"weight": 4, "desc": "CSS stylesheet — content injection, form hijacking"},
    "iframe": {"weight": 4, "desc": "iframe — page content takeover"},
    "src": {"weight": 3, "desc": "Embedded resource (image/font/object)"},
    "href": {"weight": 2, "desc": "Hyperlink — reputation/phishing risk"},
}

EXTERNAL_PATTERNS = [
    (r'<script[^>]+src=["\'](https?://[^"\'>\s]+)', "script"),
    (r'<link[^>]+href=["\'](https?://[^"\'>\s]+\.css[^"\'>\s]*)', "link"),
    (r'<iframe[^>]+src=["\'](https?://[^"\'>\s]+)', "iframe"),
    (r'<img[^>]+src=["\'](https?://[^"\'>\s]+)', "src"),
    (r'<source[^>]+src=["\'](https?://[^"\'>\s]+)', "src"),
    (r'@import\s+["\'](https?://[^"\'>\s]+)', "link"),
    (r'url\(["\']?(https?://[^"\'>\s]+)', "src"),
    (r'<a[^>]+href=["\'](https?://[^"\'>\s]+)', "href"),
]

DANGEROUS_RESOURCE_EXTS = {".js", ".css", ".woff", ".woff2", ".ttf", ".eot", ".svg", ".ico"}

COMMON_CNAME_TAKEOVER_SIGNATURES = [
    "herokudns.com", "herokuapp.com", "heroku.com",
    "cloudfront.net", "s3.amazonaws.com", "s3-website",
    "github.io", "githubusercontent.com",
    "unbouncepages.com", "unbounce.com",
    "surge.sh", "netlify.app", "netlify.com",
    "pages.dev", "workers.dev",
    "azureedge.net", "azurewebsites.net", "trafficmanager.net",
    "elb.amazonaws.com", "us-east-1.elb.amazonaws.com",
    "firebaseapp.com", "web.app",
    "wordpress.com", "wpengine.com",
    "squarespace.com", "squarespaceusercontent.com",
    "myshopify.com", "shopify.com",
    "bilohost.com", "pantheonsite.io",
    "aftership.com", "ghost.io",
    "fastly.net", "glitch.me",
    "bitbucket.io", "readme.io",
    "statuspage.io", "atlassian.net",
    "myshopify.io", "teachable.com",
    "thinkific.com", "clickfunnels.com",
    "cargocollective.com", "tictail.com",
    "zendesk.com", "freshdesk.com",
    "helpscout.net", "intercom.io",
]

EXPIRED_REGISTRAR_INDICATORS = [
    "this domain", "domain is parked", "buy this domain",
    "domain is for sale", "expired", "registrar",
    "whois protection", "this domain may be for sale",
    "domain not found", "no website configured",
    "server dns address could not be found",
    "this site is not available",
    "this domain registration",
    "pending renewal",
]


class BrokenLinkScanner(BaseScanner):
    SCANNER_NAME = "Broken Link Hijacking Scanner"
    _SCANNER_KEY = "broken_link"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._page_html = ""
        self._resources: list[dict] = []

    def run(self) -> list:
        self.log("INFO", f"[BrokenLink] Scanning {self.target} for hijackable external resources...")
        self._fetch_page()
        if not self._page_html:
            return self.vulns
        self._extract_external_resources()
        self._audit_resource_domains()
        self._check_unregistered_domains()
        self._check_nxdomain_resources()
        return self.vulns

    def _fetch_page(self):
        try:
            body, code = self._make_request(self.target, timeout=10)
            if body:
                self._page_html = body
        except Exception as e:
            self.log("ERROR", f"[BrokenLink] Fetch failed: {e}")

    def _extract_external_resources(self):
        found = set()
        for pattern, rtype in EXTERNAL_PATTERNS:
            for match in re.finditer(pattern, self._page_html, re.I):
                url = match.group(1).split('"')[0].split("'")[0].split(">")[0].strip()
                if self.domain not in url and url not in found:
                    found.add(url)
                    self._resources.append({"url": url, "type": rtype})
        self.log("INFO", f"[BrokenLink] Found {len(self._resources)} external resource(s)")

    def _audit_resource_domains(self):
        for res in self._resources:
            self._check_resource(res)

    def _check_resource(self, res: dict):
        url = res["url"]
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        rtype = res["type"]
        base_weight = HIJACK_RISK.get(rtype, {}).get("weight", 1)
        ext = self._get_extension(url)
        is_js_or_css = ext in DANGEROUS_RESOURCE_EXTS

        status, body, resolved = self._probe_resource(url)
        if status is None:
            return

        indicators = []
        if status in (404, 410):
            indicators.append(f"HTTP {status} Not Found — resource missing")
        elif status in (403, 401):
            indicators.append(f"HTTP {status} — access denied, may be misconfigured")
        elif status == 200 and self._is_expired_landing(body):
            indicators.append("HTTP 200 with domain-parked/expired content")

        if not resolved:
            nx = self._check_nxdomain(hostname)
            if nx == "nxdomain":
                indicators.append("DNS NXDOMAIN — domain does not exist")
            elif nx == "takeover_candidate":
                cname = self._get_cname(hostname)
                indicators.append(f"CNAME to known takeover-vulnerable service ({cname}) — hijackable")
                base_weight = min(base_weight + 2, 5)

        if not indicators:
            return

        severity = self._severity_from_weight(base_weight)
        cvss = self._cvss_from_weight(base_weight, len(indicators), is_js_or_css)

        self.add_vuln(
            title=f"Broken Link Hijacking — {url[:80]}",
            severity=severity,
            category="Broken Link Hijacking",
            cvss_score=cvss,
            description=(
                f"External {rtype} resource hijackable:\n"
                f"  URL: {url}\n"
                f"  Type: {HIJACK_RISK.get(rtype, {}).get('desc', rtype)}\n"
                f"  Indicators:\n" + "\n".join(f"    - {i}" for i in indicators)
            ),
            remediation=(
                "Remove or replace the resource. For critical JS/CSS/fonts, "
                "self-host or use a integrity-managed CDN (SRI). "
                "Monitor external dependencies for expiration."
            ),
            evidence=f"Resource URL: {url}\n" + "\n".join(indicators),
            payload="",
            request_details=f"GET {url}",
            response_details=f"HTTP {status}, body length {len(body or '')}",
            confidence="Confirmed" if base_weight >= 4 else "High",
        )

    def _probe_resource(self, url: str) -> tuple[int | None, str | None, bool]:
        try:
            body, code = self._make_request(url, timeout=6)
            if code and code < 400 and body:
                return code, body, True
            return code, body, False
        except Exception:
            return None, None, False

    def _check_unregistered_domains(self):
        domains = set()
        for res in self._resources:
            host = urlparse(res["url"]).hostname
            if host:
                domains.add(host)
        for domain in domains:
            nx = self._check_nxdomain(domain)
            if nx:
                desc = "NXDOMAIN — domain not registered" if nx == "nxdomain" else f"CNAME to vulnerable service ({self._get_cname(domain)})"
                cvss = 5.3 if nx == "nxdomain" else 7.5
                self.add_vuln(
                    title=f"Expired External Domain — {domain}",
                    severity="High" if nx == "takeover_candidate" else "Medium",
                    category="Broken Link Hijacking",
                    cvss_score=cvss,
                    description=f"External domain {domain} referenced by page resources: {desc}. Attacker can register this domain and serve malicious content.",
                    remediation="Remove references to this domain or ensure it remains registered and controlled.",
                    evidence=f"Domain: {domain}\nDNS result: {desc}",
                    confidence="High",
                )

    def _check_nxdomain_resources(self):
        pass

    def _check_nxdomain(self, hostname: str) -> str | None:
        hostname = hostname.lower().strip()
        try:
            socket.getaddrinfo(hostname, 80, socket.AF_INET)
            cname = self._get_cname(hostname)
            if cname:
                for sig in COMMON_CNAME_TAKEOVER_SIGNATURES:
                    if sig in cname:
                        return "takeover_candidate"
            return self.vulns
        except socket.gaierror:
            pass
        try:
            socket.getaddrinfo(hostname, 80, socket.AF_INET6)
            return self.vulns
        except socket.gaierror:
            return "nxdomain"

    def _get_cname(self, hostname: str) -> str:
        try:
            result = socket.getaddrinfo(hostname, 80, socket.AF_INET)
            for res in result:
                canon = res[3]
                if canon and canon != hostname and not canon.startswith("("):
                    return canon
        except Exception:
            pass
        return ""

    def _get_extension(self, url: str) -> str:
        path = urlparse(url).path.lower()
        match = re.search(r'(\.[a-z0-9]+)(?:\?|#|$)', path)
        return match.group(1) if match else ""

    def _is_expired_landing(self, body: str | None) -> bool:
        if not body:
            return False
        body_lower = body.lower()
        matches = sum(1 for ind in EXPIRED_REGISTRAR_INDICATORS if ind in body_lower)
        return matches >= 2

    def _severity_from_weight(self, w: int) -> str:
        if w >= 5:
            return "Critical"
        if w >= 4:
            return "High"
        if w >= 3:
            return "Medium"
        return "Low"

    def _cvss_from_weight(self, weight: int, indicators: int, is_js: bool) -> float:
        base = 3.0 + weight * 1.2
        if is_js:
            base += 1.5
        base += indicators * 0.3
        return round(min(base, 10.0), 1)
