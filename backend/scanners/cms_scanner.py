"""
cms_scanner.py — CMS Detection & Vulnerability Scanner
=======================================================
Detects popular CMS platforms (WordPress, Drupal, Joomla) and checks
for exposed admin panels, sensitive endpoints (xmlrpc.php), and known
fingerprints.
"""
import re
from scanners.base_scanner import BaseScanner
from utils.fingerprint_db import match_tech, find_cves

CMS_FINGERPRINTS = {
    "WordPress": [
        ("/wp-login.php", "wp-submit"),
        ("/xmlrpc.php", "XML-RPC server accepts POST requests only"),
        ("/wp-json/wp/v2/users", "slug"),
        ("/wp-admin/", "wp-admin"),
        ("/wp-content/", "wp-content"),
    ],
    "Drupal": [
        ("/user/login", "form_id\" value=\"user_login"),
        ("/CHANGELOG.txt", "Drupal"),
        ("/sites/default/files/", "Drupal"),
        ("/core/", "Drupal"),
    ],
    "Joomla": [
        ("/administrator/", "Joomla!"),
        ("/components/", "option="),
        ("/modules/", "mod_"),
    ],
    "Magento": [
        ("/admin/", "Magento"),
        ("/static/version", "version"),
        ("/skin/frontend/", "Magento"),
    ],
    "Shopify": [
        ("/admin/", "Shopify"),
        ("/admin/auth/login", "shopify"),
    ],
    "Squarespace": [
        ("/config/", "Squarespace"),
        ("/api/v1/", "squarespace"),
    ],
    "Wix": [
        ("/_api/", "wix"),
        ("/wix-", "Wix"),
    ],
    "Blogger": [
        ("/feeds/posts/default", "atom"),
        ("/blog-", "blogger"),
    ],
    "Ghost": [
        ("/ghost/", "Ghost"),
        ("/ghost/api/", "ghost"),
    ],
    "TYPO3": [
        ("/typo3/", "TYPO3"),
        ("/typo3conf/", "typo3"),
    ],
    "PrestaShop": [
        ("/admin/", "PrestaShop"),
        ("/js/tools.js", "PrestaShop"),
    ],
    "Django CMS": [
        ("/admin/", "django"),
        ("/cms/", "cms"),
    ],
}

CMS_VERSION_PATTERNS = {
    "WordPress": [
        (r'<meta name="generator" content="WordPress ([0-9.]+)"', "meta generator"),
        (r'ver=([0-9.]+)"', "script param"),
        (r'/wp-includes/js/wp-embed.min.js\?ver=([0-9.]+)', "wp-embed"),
    ],
    "Drupal": [
        (r'Drupal ([0-9.]+)', "footer"),
        (r'<meta name="generator" content="Drupal ([0-9.]+)"', "meta generator"),
    ],
    "Joomla": [
        (r'<meta name="generator" content="Joomla! ([0-9.]+)"', "meta generator"),
        (r'Joomla! ([0-9.]+)', "body"),
    ],
    "Magento": [
        (r'Magento[,\s]+([0-9.]+)', "header"),
        (r'version/[0-9.]+', "static url"),
    ],
    "Ghost": [
        (r'<meta name="generator" content="Ghost ([0-9.]+)"', "meta generator"),
        (r'Ghost ([0-9.]+)', "body"),
    ],
}


class CmsScanner(BaseScanner):
    SCANNER_NAME = "CMS Security Scanner"
    _SCANNER_KEY = "cms"

    def run(self) -> list:
        self.log("INFO", f"[CMS] Fingerprinting CMS and common vulnerabilities on {self.target}...")
        base_url = self.target.rstrip("/")

        body, status, _ = self._make_request(
            self.target,
            timeout=10,
            return_response_obj=True,
        )
        if status == 0:
            self.log("WARNING", "[CMS] Could not reach target.")
            return self.vulns

        detected_cms = set()
        for cms_name, tests in CMS_FINGERPRINTS.items():
            for path, expected in tests:
                test_url = base_url + path
                test_body, test_status, _ = self._make_request(
                    test_url,
                    timeout=5,
                    return_response_obj=True,
                )
                if test_status in (200, 401, 403) and test_body and expected in test_body:
                    # PHASE 1: Suppress SPA catch-all responses for 200 status
                    if test_status == 200 and self._is_baseline(test_status, test_body):
                        self.log("INFO", f"[CMS] SUPPRESSED (baseline match): {test_url}")
                        continue
                    if cms_name not in detected_cms:
                        detected_cms.add(cms_name)
                        self.log("INFO", f"[CMS] Detected {cms_name} via {path}")
                    self._report(cms_name, path, test_status)

        if detected_cms:
            for cms_name in detected_cms:
                version = self._detect_version(body, cms_name)
                if version:
                    self.log("INFO", f"[CMS] {cms_name} version detected: {version}")
                    self.add_vuln(
                        title=f"{cms_name} Version Detected: {version}",
                        severity="Low",
                        category="CMS Fingerprint",
                        cvss_score=0.0,
                        description=f"The {cms_name} installation was detected with version {version}.",
                        remediation="Ensure the CMS is kept up to date with the latest security patches.",
                        evidence=f"Version: {version}",
                        confidence="Confirmed",
                    )

                    cves = find_cves(cms_name, version)
                    if cves:
                        cve_ids = [c["cve"] for c in cves]
                        self.log("WARNING", f"[CMS] Known CVEs for {cms_name} {version}: {', '.join(cve_ids)}")
                        self.add_vuln(
                            title=f"Known CVEs for {cms_name} {version}",
                            severity="High", category="CMS Vulnerability", cvss_score=max(c["cvss"] for c in cves),
                            description=f"Version {version} of {cms_name} has {len(cves)} known CVE(s): {', '.join(cve_ids)}.",
                            remediation=f"Upgrade {cms_name} to the latest version.",
                            evidence=f"CVEs: {', '.join(cve_ids)}",
                            confidence="Confirmed",
                            cve_ids=cve_ids,
                        )

        if not self.vulns:
            self.log("SUCCESS", "[CMS] No vulnerable/exposed CMS endpoints detected.")
        return self.vulns

    def _detect_version(self, body, cms_name):
        patterns = CMS_VERSION_PATTERNS.get(cms_name, [])
        for pattern, source in patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                return m.group(1)
        return self.vulns
    def _report(self, cms_name, path, status):
        if "xmlrpc.php" in path:
            self.add_vuln(
                title=f"{cms_name} XML-RPC API Exposed",
                severity="Medium",
                category="CMS Vulnerability",
                cvss_score=5.3,
                description=f"The `{cms_name}` XML-RPC endpoint is accessible at `{path}`. "
                    "This endpoint is frequently abused for brute-force attacks and Pingback SSRF attacks.",
                remediation="Disable XML-RPC by deleting `xmlrpc.php` or blocking it via `.htaccess` / Nginx config if not actively used.",
                confidence="Confirmed",
                response_details=f"HTTP {status}",
            )
        elif "wp-json/wp/v2/users" in path:
            self.add_vuln(
                title=f"{cms_name} REST API User Enumeration",
                severity="Medium",
                category="Information Disclosure",
                cvss_score=5.3,
                description=f"The `{cms_name}` REST API is exposing registered usernames at `{path}`. "
                    "This assists attackers in brute-forcing administrator accounts.",
                remediation="Restrict access to the REST API endpoints or use a plugin to disable user enumeration.",
                confidence="Confirmed",
                response_details=f"HTTP {status}",
            )
        else:
            self.log("INFO", f"[CMS] Exposed {cms_name} admin/login path: {path} (HTTP {status})")
            self.add_vuln(
                title=f"Exposed {cms_name} Admin/Login Panel",
                severity="Low",
                category="Attack Surface",
                cvss_score=0.0,
                description=f"A `{cms_name}` installation was detected with an exposed panel at `{path}`.",
                remediation="Ensure strong passwords and Two-Factor Authentication (2FA) are enabled.",
                response_details=f"HTTP {status}",
            )
