"""
robots_scanner.py — Analyses robots.txt and sitemap.xml for security-relevant disclosures.
No external dependencies required.
"""
import urllib.request, urllib.error, ssl, re
from scanners.base_scanner import BaseScanner

# Paths in robots.txt that are security-sensitive when disallowed (revealing internal structure)
SENSITIVE_PATTERNS = [
    r"/admin", r"/wp-admin", r"/phpmyadmin", r"/dashboard",
    r"/\.git", r"/\.env", r"/config", r"/backup", r"/db",
    r"/api/internal", r"/private", r"/secret", r"/hidden",
    r"/upload", r"/temp", r"/logs?", r"/debug",
]

class RobotsScanner(BaseScanner):
    SCANNER_NAME = "Robots.txt & Sitemap Scanner"

    def _fetch(self, path):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        base = self.target.rstrip("/")
        url  = f"{base}{path}"
        try:
            req  = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                return r.read().decode("utf-8", errors="ignore"), url
        except urllib.error.HTTPError as e:
            return None, url
        except Exception as e:
            self.log("ERROR", f"[Robots] Fetch error: {e}")
            return None, url

    def run(self):
        self.log("INFO", f"[Robots] Analysing robots.txt and sitemap for {self.domain}...")
        self._check_robots()
        self._check_sitemap()
        self._check_sensitive_files()
        return self.vulns

    def _check_robots(self):
        content, url = self._fetch("/robots.txt")
        if content is None:
            self.log("INFO", f"[Robots] robots.txt not found at {url}.")
            return

        self.log("SUCCESS", f"[Robots] robots.txt found ({len(content)} bytes). Analysing directives...")
        sensitive_found = []

        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                for pattern in SENSITIVE_PATTERNS:
                    if re.search(pattern, path, re.IGNORECASE):
                        self.log("WARNING", f"[Robots] Sensitive path disclosed in Disallow: {path}")
                        sensitive_found.append(path)
                        break

        if sensitive_found:
            paths_str = "\n  - " + "\n  - ".join(set(sensitive_found))
            self.add_vuln(
                title="Sensitive Paths Disclosed in robots.txt",
                severity="Medium", category="Information Disclosure", cvss_score=4.3,
                description=(
                    f"The robots.txt file at {url} contains Disallow directives that reveal "
                    f"the existence of sensitive internal paths:{paths_str}\n\n"
                    "While robots.txt is intended to guide search engine crawlers, it is publicly "
                    "readable and should not be used to obscure sensitive resources."
                ),
                remediation=(
                    "Remove sensitive internal paths from robots.txt. Instead, protect them with:\n"
                    "  1. Proper authentication and authorisation controls\n"
                    "  2. IP-based access restrictions for admin panels\n"
                    "  3. Web Application Firewall (WAF) rules"
                ),
            )
        else:
            self.log("SUCCESS", "[Robots] robots.txt: No sensitive path disclosures detected ✔")

    def _check_sitemap(self):
        for path in ["/sitemap.xml", "/sitemap_index.xml"]:
            content, url = self._fetch(path)
            if content:
                self.log("SUCCESS", f"[Robots] Sitemap found at {url} ({len(content)} bytes).")
                # Check for admin/internal URLs in sitemap
                internal_urls = re.findall(r"<loc>(https?://[^<]*(?:admin|dashboard|internal|private|secret)[^<]*)</loc>", content, re.IGNORECASE)
                if internal_urls:
                    self.log("WARNING", f"[Robots] {len(internal_urls)} sensitive URL(s) in sitemap.")
                    self.add_vuln(
                        title="Sensitive URLs Exposed in sitemap.xml",
                        severity="Low", category="Information Disclosure", cvss_score=3.1,
                        description=f"The sitemap at {url} lists {len(internal_urls)} URL(s) containing sensitive keywords (admin, dashboard, internal, private). These URLs are indexed by search engines.\nExample: {internal_urls[0][:100]}",
                        remediation="Remove sensitive or internal URLs from your public sitemap. Restrict access to these paths with server-level authentication.",
                    )
                return

        self.log("INFO", "[Robots] No sitemap.xml found.")

    def _check_sensitive_files(self):
        """Check for commonly exposed sensitive files."""
        checks = [
            ("/.git/HEAD",    "Git Repository Exposed",      "Critical", 9.1,
             "The .git directory is publicly accessible. Attackers can reconstruct the full source code, including credentials and configuration files.",
             "Block access to .git in your web server config:\n  Nginx: location ~ /\\.git { deny all; }\n  Apache: RedirectMatch 404 /\\.git"),
            ("/.env",         ".env File Exposed",           "Critical", 9.8,
             "The .env configuration file is publicly readable. This file typically contains database credentials, API keys, and secret tokens.",
             "Immediately move .env outside the web root or block access:\n  Nginx: location ~ /\\.env { deny all; }"),
            ("/config.php",   "config.php Exposed",          "High",     7.5,
             "A PHP configuration file is publicly accessible and may contain database credentials.",
             "Move configuration files outside the web root or restrict access via .htaccess."),
            ("/wp-config.php","WordPress Config Exposed",    "Critical", 9.8,
             "The WordPress configuration file (wp-config.php) is publicly accessible, exposing database credentials.",
             "Ensure wp-config.php is not accessible via the web. WordPress itself should prevent this if properly installed."),
            ("/phpinfo.php",  "phpinfo() Page Exposed",      "Medium",   5.3,
             "A phpinfo() page is accessible, disclosing PHP configuration, loaded modules, and server environment details useful for attackers.",
             "Remove or password-protect phpinfo() pages in production environments."),
            ("/server-status","Apache server-status Exposed","Medium",   5.3,
             "Apache mod_status page is publicly accessible, disclosing active connections, server load, and request details.",
             "Restrict access to /server-status to trusted IP ranges only."),
        ]

        for path, title, severity, cvss, desc, remediation in checks:
            content, url = self._fetch(path)
            if content is not None and len(content) > 10:
                # PHASE 1: Suppress SPA catch-all responses
                if self._is_baseline(200, content):
                    self.log("INFO", f"[Robots] SUPPRESSED (baseline match): {url}")
                    continue
                self.log("CRITICAL" if cvss >= 9.0 else "WARNING",
                         f"[Robots] EXPOSED: {url}")
                self.add_vuln(
                    title=title, severity=severity, category="Information Disclosure",
                    cvss_score=cvss, description=f"{desc}\n\nExposed URL: {url}",
                    remediation=remediation,
                )
            else:
                self.log("SUCCESS", f"[Robots] {path}: Not exposed ✔")

        self.log("INFO", f"[Robots] File exposure check complete.")
