"""
admin_panel_scanner.py — Admin Panel & Exposed Dashboard Scanner
================================================================
PHASE 1: Baseline filtering added — only reports panels that are NOT the
         site's generic SPA catch-all response.
PHASE 2: Content-signature validation for product-specific panels.

Probes a targeted wordlist of admin, monitoring, and developer dashboards
that are often left exposed. More targeted than the generic directory scanner.
"""
import urllib.request, urllib.error
from scanners.base_scanner import BaseScanner
from scanners.core.signatures import matches_signature

ADMIN_PATHS = [
    # Generic admin panels
    "/admin", "/admin/", "/admin/login", "/admin/dashboard",
    "/_admin", "/administrator", "/admincp", "/admin1", "/admin2",
    "/backend", "/backend/login", "/manage", "/management",
    "/control", "/controlpanel", "/cp", "/cpanel",
    # PHP tooling
    "/phpmyadmin", "/pma", "/phpMyAdmin", "/phpmyadmin/", "/mysql",
    "/adminer", "/adminer.php", "/db", "/database",
    # Python/Django
    "/django-admin", "/django/admin", "/_admin/",
    # Java / Spring / JEE
    "/manager", "/manager/html", "/host-manager", "/console",
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings", "/actuator/info",
    "/jolokia", "/jolokia/list", "/druid", "/druid/login.html",
    # CI/CD & DevOps
    "/jenkins", "/jenkins/", "/jenkins/login",
    "/gitlab", "/gitlab/users/sign_in",
    "/sonarqube", "/sonar",
    # Monitoring / Observability
    "/grafana", "/grafana/login",
    "/kibana", "/kibana/app/kibana",
    "/prometheus", "/metrics", "/_prometheus/metrics",
    "/jaeger", "/zipkin",
    # Messaging & Queues
    "/rabbitmq", "/rabbitmq-management",
    "/activemq", "/activemq/admin",
    "/kafka", "/kafka-ui",
    # Container / Cloud
    "/portainer", "/rancher", "/kubernetes",
    "/_cluster/health", "/_cat/nodes",  # Elasticsearch
    # CMS / CRM
    "/wp-admin", "/wp-login.php",
    "/typo3", "/typo3/backend",
    "/joomla/administrator", "/index.php?option=com_admin",
    # Misc
    "/setup", "/setup.php", "/install", "/install.php",
    "/config", "/config.php", "/.env", "/server-status",
    "/server-info", "/status", "/info.php", "/phpinfo.php",
]

ADMIN_KEYWORDS = [
    "login", "dashboard", "admin", "username", "password",
    "sign in", "control panel", "management", "welcome back",
    "<form", "Log In", "Sign In",
]

# Map paths → signature keys for product-specific validation
_PATH_SIG_MAP: dict[str, str] = {
    "/jenkins":           "jenkins",
    "/jenkins/":          "jenkins",
    "/jenkins/login":     "jenkins",
    "/grafana":           "grafana",
    "/grafana/login":     "grafana",
    "/kibana":            "kibana",
    "/kibana/app/kibana": "kibana",
    "/prometheus":        "prometheus",
    "/phpmyadmin":        "phpmyadmin",
    "/pma":               "phpmyadmin",
    "/phpMyAdmin":        "phpmyadmin",
    "/phpmyadmin/":       "phpmyadmin",
    "/adminer":           "adminer",
    "/adminer.php":       "adminer",
    "/phpinfo.php":       "phpinfo",
    "/info.php":          "phpinfo",
    "/wp-login.php":      "wp_login",
    "/wp-admin":          "wp_login",
    "/_cluster/health":   "elasticsearch",
    "/actuator":          "spring_actuator",
    "/actuator/health":   "spring_actuator",
    "/actuator/env":      "spring_actuator_env",
    "/portainer":         "portainer",
}


class AdminPanelScanner(BaseScanner):
    SCANNER_NAME = "Admin Panel & Dashboard Scanner"
    _SCANNER_KEY = "admin_panel"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[AdminPanel] Probing {len(ADMIN_PATHS)} admin/dashboard paths on {self.target}...")
        base = self.target.rstrip("/")
        found = []

        for path in ADMIN_PATHS:
            url = base + path
            status, body = self._probe(url)

            if status == 200 and body is not None:
                # PHASE 1: Suppress if response is the site's SPA/404 catch-all
                if self._is_baseline(status, body):
                    self.log("INFO", f"[AdminPanel] SUPPRESSED (baseline match, {len(body)}b): {url}")
                    continue

                # Minimum content threshold — avoid near-empty redirect bodies
                if len(body) < 200:
                    self.log("INFO", f"[AdminPanel] SKIPPED (body too small, {len(body)}b): {url}")
                    continue

                # PHASE 2: Product-specific signature check
                sig_key = _PATH_SIG_MAP.get(path)
                if sig_key:
                    if not matches_signature(sig_key, body, log_fn=lambda m: self.log("INFO", m), url=url):
                        continue
                else:
                    # Generic admin check: must contain admin keywords AND a form element
                    body_lower = body.lower()
                    has_keyword = any(kw.lower() in body_lower for kw in ADMIN_KEYWORDS)
                    has_form = "<form" in body_lower
                    if not (has_keyword and has_form):
                        self.log("INFO", f"[AdminPanel] SKIPPED (no keyword+form match): {url}")
                        continue

                found.append((path, status, len(body)))
                self.log("WARNING", f"[AdminPanel] FOUND: {url} ({status}, {len(body)}b)")

            elif status in (401, 403):
                # Access denied — still confirms presence of a panel
                found.append((path, status, 0))
                self.log("INFO", f"[AdminPanel] Protected (HTTP {status}): {url}")

        if found:
            public = [(p, s, b) for p, s, b in found if s == 200]
            protected = [(p, s, b) for p, s, b in found if s in (401, 403)]

            if public:
                self.add_vuln(
                    title=f"Unauthenticated Admin Panels Found ({len(public)})",
                    severity="Critical",
                    category="Exposed Admin Panel",
                    cvss_score=9.8,
                    confidence="Confirmed",
                    description=(
                        f"The following admin/dashboard endpoints are publicly accessible (HTTP 200) "
                        f"without authentication:\n\n" +
                        "\n".join(f"- `{base + p}` ({b} bytes)" for p, s, b in public[:10])
                    ),
                    remediation=(
                        "1. Immediately restrict admin panels to internal IPs / VPN only.\n"
                        "2. Require MFA on all administrative interfaces.\n"
                        "3. Remove development tools (phpMyAdmin, Adminer) from production.\n"
                        "4. Disable Spring Actuator endpoints: management.endpoints.enabled-by-default=false"
                    ),
                    evidence=f"{len(public)} unauthenticated admin path(s) found, verified against site baseline.",
                )
            if protected:
                self.add_vuln(
                    title=f"Admin Panels Discovered But Access-Controlled ({len(protected)})",
                    severity="Medium",
                    category="Exposed Admin Panel",
                    cvss_score=5.3,
                    confidence="Likely",
                    description=(
                        f"Admin panels exist but return 401/403:\n\n" +
                        "\n".join(f"- `{base + p}` (HTTP {s})" for p, s, b in protected[:10]) +
                        "\n\nWhile protected, their existence aids attacker reconnaissance "
                        "and they remain vulnerable to credential stuffing."
                    ),
                    remediation=(
                        "Restrict admin paths to internal networks. Return 404 (not 403) "
                        "for admin paths when accessed externally to reduce information disclosure."
                    ),
                )
        else:
            self.log("SUCCESS", "[AdminPanel] No admin panels or dashboards found.")
        return self.vulns

    def _probe(self, url):
        try:
            req = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=4, context=self.get_ssl_context()) as r:
                return r.status, r.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception as e:
            self.log("ERROR", f"[AdminPanel] _probe error: {e}")
            return 0, ""
