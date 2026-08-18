"""
subdomain_scanner.py — Discovers subdomains via crt.sh and hunts for Takeovers.
"""
import requests
import json
import dns.resolver
import subprocess
import os
import shutil
from scanners.base_scanner import BaseScanner

TAKEOVER_SIGNATURES = {
    "github.io": "There isn't a GitHub Pages site here.",
    "s3.amazonaws.com": "NoSuchBucket",
    "s3-website": "NoSuchBucket",
    "herokuapp.com": "No such app",
    "myshopify.com": "Sorry, this shop is currently unavailable.",
    "wpengine.com": "The site you were looking for couldn't be found.",
    "pantheonsite.io": "The edge router is unable to route the requested request.",
    "zendesk.com": "Help Center Closed",
    "azurewebsites.net": "Error 404",
    "cloudapp.net": "No such app",
    "appspot.com": "Error 404",
    "herokudns.com": "No such app",
    "herokussl.com": "No such app",
    "netlify.app": "Page not found",
    "vercel.app": "Page not found",
    "now.sh": "Page not found",
    "bitbucket.io": "Repository not found",
    "gitlab.io": "Project not found",
    "surge.sh": "Project not found",
    "pages.cloudflare.com": "Error 1004",
    "workers.dev": "404 Not Found",
    "deno.dev": "Not Found",
    "fly.dev": "Not Found",
    "railway.app": "Not Found",
    "render.com": "Not Found",
    "elasticbeanstalk.com": "404 Not Found",
    "cloudfront.net": "404 Not Found",
    "fastly.com": "Fastly error",
    "cloudfunctions.net": "404 Not Found",
    "firebaseapp.com": "Site not found",
    "firebaseio.com": "null",
    "webflow.io": "404 Not Found",
    "wixsite.com": "404 Not Found",
    "squarespace.com": "404 Not Found",
    "wordpress.com": "Do you want to register",
    "blogspot.com": "Blog not found",
    "tumblr.com": "Nothing here",
    "ghost.io": "404 Not Found",
    "hubspot.com": "Page not found",
    "unbouncepages.com": "Page not found",
    "instapage.com": "Page not found",
    "leadpages.net": "Page not found",
    "kajabi.com": "Page not found",
    "teachable.com": "Page not found",
    "thinkific.com": "Page not found",
    "podia.com": "Page not found",
    "uservoice.com": "Page not found",
    "freshdesk.com": "Page not found",
    "intercom.com": "Page not found",
    "drift.com": "Page not found",
    "crisp.chat": "Page not found",
    "tawk.to": "Page not found",
    "typeform.com": "Page not found",
    "paperform.co": "Page not found",
    "jotform.com": "Page not found",
    "formstack.com": "Page not found",
    "wufoo.com": "Page not found",
    "cognitoforms.com": "Page not found",
    "formsite.com": "Page not found",
    "surveygizmo.com": "Page not found",
    "qualtrics.com": "Page not found",
    "survey monkey.com": "Page not found",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "email", "ftp", "sftp", "ssh", "vpn", "remote", "api", "dev", "staging", "test", "uat",
    "prod", "production", "live", "admin", "administrator", "dashboard", "panel", "portal", "console",
    "blog", "news", "media", "static", "assets", "cdn", "img", "images", "video", "videos", "audio",
    "docs", "documentation", "wiki", "help", "support", "kb", "knowledgebase", "faq", "forum",
    "shop", "store", "cart", "checkout", "payment", "billing", "account", "login", "signin", "signup", "register",
    "secure", "auth", "oauth", "sso", "identity", "token", "session", "cookie", "cache",
    "db", "database", "mysql", "postgres", "mongodb", "redis", "elasticsearch", "solr", "search",
    "jenkins", "ci", "cd", "build", "deploy", "git", "svn", "repo", "repository", "code",
    "monitor", "metrics", "logs", "log", "analytics", "stats", "statistics", "report", "reporting",
    "ns1", "ns2", "ns3", "ns4", "dns", "mx", "smtp", "pop", "pop3", "imap",
    "m", "mobile", "app", "application", "web", "webmail", "webdisk", "cpanel", "whm",
    "beta", "alpha", "demo", "sandbox", "lab", "labs", "experimental", "poc", "proof",
    "internal", "private", "public", "external", "partner", "vendor", "client", "customer",
    "hr", "finance", "legal", "marketing", "sales", "support", "it", "ops", "devops",
    "staging1", "staging2", "dev1", "dev2", "test1", "test2", "prod1", "prod2",
    "us-east", "us-west", "eu-west", "eu-central", "ap-south", "ap-northeast",
    "lb", "loadbalancer", "proxy", "gateway", "firewall", "ids", "ips",
    "backup", "archive", "old", "legacy", "v1", "v2", "v3", "version1", "version2",
    "status", "health", "ping", "heartbeat", "uptime", "monitoring",
]


class SubdomainScanner(BaseScanner):
    SCANNER_NAME = "Subdomain Enumeration & Takeover Hunter"
    _SCANNER_KEY = "subdomain"

    def brute_force_subdomains(self):
        self.log("INFO", "[Subdomains] Starting subdomain brute-forcing...")
        found_subdomains = set()

        for sub in COMMON_SUBDOMAINS[:50]:
            full_domain = f"{sub}.{self.domain}"
            try:
                dns.resolver.resolve(full_domain, 'A')
                found_subdomains.add(full_domain)
                self.log("INFO", f"[Subdomains] Found via brute-force: {full_domain}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
                pass
            except Exception as e:
                self.log("ERROR", f"[Subdomains] DNS resolve error: {e}")

        return found_subdomains

    def check_dns_records(self, subdomain):
        try:
            try:
                ns_answers = dns.resolver.resolve(subdomain, 'NS')
                ns_servers = [rdata.target.to_text() for rdata in ns_answers]
                if len(ns_servers) > 0:
                    self.log("INFO", f"[Subdomains] {subdomain} NS: {', '.join(ns_servers[:3])}")
            except Exception as e:
                self.log("ERROR", f"[Subdomains] NS record check error: {e}")

            try:
                mx_answers = dns.resolver.resolve(subdomain, 'MX')
                mx_servers = [rdata.exchange.to_text() for rdata in mx_answers]
                if len(mx_servers) > 0:
                    self.log("INFO", f"[Subdomains] {subdomain} MX: {', '.join(mx_servers[:3])}")
            except Exception as e:
                self.log("ERROR", f"[Subdomains] MX record check error: {e}")

            try:
                txt_answers = dns.resolver.resolve(subdomain, 'TXT')
                txt_records = [rdata.to_text() for rdata in txt_answers]
                if len(txt_records) > 0:
                    for txt in txt_records:
                        if "v=spf1" in txt:
                            self.log("INFO", f"[Subdomains] {subdomain} SPF: {txt[:80]}")
                        elif "v=dkim" in txt:
                            self.log("INFO", f"[Subdomains] {subdomain} DKIM: {txt[:80]}")
            except Exception as e:
                self.log("ERROR", f"[Subdomains] TXT record check error: {e}")

        except Exception as e:
            self.log("ERROR", f"[Subdomains] DNS records check error: {e}")

    def check_takeover(self, subdomain):
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                cname = rdata.target.to_text().lower().rstrip('.')

                for service, error_signature in TAKEOVER_SIGNATURES.items():
                    if service in cname:
                        try:
                            body, status, _ = self._make_request(
                                f"http://{subdomain}",
                                timeout=5,
                                return_response_obj=True,
                            )
                            if body and error_signature in body:
                                self.log("CRITICAL", f"[Subdomains] TAKEOVER FOUND: {subdomain} points to unclaimed {service}")
                                self.add_vuln(
                                    title=f"Subdomain Takeover ({service})",
                                    severity="Critical", category="Configuration", cvss_score=9.1,
                                    description=f"The subdomain `{subdomain}` has a CNAME record pointing to `{cname}`, but the service at that destination is unclaimed. An attacker can register this service and completely hijack the subdomain.",
                                    remediation=f"Immediately remove the dangling CNAME record for `{subdomain}` from your DNS zone file, or claim the resource at `{service}`.",
                                    confidence="Confirmed",
                                    evidence=f"CNAME: {cname}, Response contains: {error_signature}",
                                )
                        except Exception as e:
                            self.log("ERROR", f"[Subdomains] Takeover HTTP check error: {e}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            pass
        except Exception as e:
            self.log("ERROR", f"[Subdomains] Takeover check error: {e}")

    def _check_http_subdomains(self, subdomains):
        self.log("INFO", "[Subdomains] Probing discovered subdomains via HTTP...")
        requests_list = []
        for sub in subdomains:
            for scheme in ("http", "https"):
                url = f"{scheme}://{sub}"
                requests_list.append({"url": url, "timeout": 5, "_subdomain": sub, "_scheme": scheme})

        results = self._make_async_requests(requests_list, max_workers=15)

        live_subs = set()
        for req, body, status in results:
            sub = req.get("_subdomain", "")
            scheme = req.get("_scheme", "")
            if status != 0:
                live_subs.add(sub)
                self.log("SUCCESS", f"[Subdomains] Live HTTP: {scheme}://{sub} (HTTP {status})")

        if live_subs:
            self.log("SUCCESS", f"[Subdomains] {len(live_subs)} subdomains are live via HTTP/HTTPS.")
        return live_subs

    def _run_subfinder(self):
        self.log("INFO", "[Subdomains] Running Subfinder v2 for passive discovery...")
        found_subdomains = set()

        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        local_subfinder = os.path.join(project_root, "Tools", "subfinder.exe")
        subfinder_path = local_subfinder if os.path.exists(local_subfinder) else shutil.which("subfinder") or shutil.which("subfinder.exe")

        if not subfinder_path:
            self.log("WARNING", "[Subfinder] 'subfinder' binary not found. Skipping Subfinder recon.")
            return found_subdomains

        try:
            cmd = [
                subfinder_path,
                "-d",       self.domain,
                "-silent",  # only output subdomains
                "-timeout", "30",           # per-source timeout in seconds
            ]
            self.log("INFO", f"[Subfinder] Command: subfinder -d {self.domain} -silent")

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=150,  # 2.5 min overall timeout
                encoding="utf-8",
                errors="replace",
            )

            for line in process.stdout.splitlines():
                sub = line.strip().lower()
                # Only accept valid subdomain lines (ends with target domain, no spaces)
                if sub.endswith(self.domain) and " " not in sub and len(sub) > len(self.domain):
                    found_subdomains.add(sub)

            if found_subdomains:
                self.log("SUCCESS", f"[Subfinder] Discovered {len(found_subdomains)} subdomains.")
            else:
                self.log("INFO", "[Subfinder] No subdomains discovered.")

        except subprocess.TimeoutExpired:
            self.log("WARNING", "[Subfinder] Scan timed out after 2.5 minutes.")
        except Exception as e:
            self.log("ERROR", f"[Subfinder] Execution failed: {e}")

        return found_subdomains


    def _run_amass(self):
        self.log("INFO", "[Subdomains] Running Amass v5 for passive subdomain discovery...")
        found_subdomains = set()

        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        local_amass = os.path.join(project_root, "Tools", "amass_windows_amd64", "amass.exe")
        amass_path = local_amass if os.path.exists(local_amass) else shutil.which("amass") or shutil.which("amass.exe")

        if not amass_path:
            self.log("WARNING", "[Amass] 'amass' binary not found. Skipping Amass recon.")
            return found_subdomains

        try:
            # Amass v5 uses 'subs' subcommand (v4 used 'enum -passive')
            cmd = [
                amass_path,
                "subs",
                "-d", self.domain,
                "-silent",      # suppress banner/progress
            ]
            self.log("INFO", f"[Amass] Command: amass subs -d {self.domain} -silent")

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=240,  # 4 min max for passive enumeration
                encoding="utf-8",
                errors="replace",
            )

            # Amass v5 writes subdomains to stdout, one per line
            all_output = (process.stdout or "") + (process.stderr or "")
            for line in all_output.splitlines():
                sub = line.strip().lower()
                # Filter: must end with target domain, no spaces, not a log/info line
                if (sub.endswith(self.domain)
                        and " " not in sub
                        and not sub.startswith("[")
                        and len(sub) > len(self.domain)):
                    found_subdomains.add(sub)

            if found_subdomains:
                self.log("SUCCESS", f"[Amass] Discovered {len(found_subdomains)} subdomains.")
            else:
                self.log("INFO", "[Amass] No new subdomains discovered via passive enumeration.")

        except subprocess.TimeoutExpired:
            self.log("WARNING", "[Amass] Scan timed out after 4 minutes.")
        except Exception as e:
            self.log("ERROR", f"[Amass] Execution failed: {e}")

        return found_subdomains


    def run(self):
        self.log("INFO", f"[Subdomains] Enumerating subdomains for {self.domain}...")
        all_subdomains = set()

        self.log("INFO", "[Subdomains] Querying Certificate Transparency logs via crt.sh...")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        _max_crtsh_attempts = 2
        for _attempt in range(_max_crtsh_attempts):
            try:
                resp = requests.get(url, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()

                    for entry in data:
                        name_value = entry.get('name_value', '').lower()
                        if name_value:
                            for sub in name_value.split('\n'):
                                sub = sub.strip()
                                if sub.endswith(self.domain) and not sub.startswith('*'):
                                    all_subdomains.add(sub)

                    self.log("SUCCESS", f"[Subdomains] Found {len(all_subdomains)} subdomains via Certificate Transparency.")
                else:
                    self.log("WARNING", f"[Subdomains] crt.sh returned HTTP {resp.status_code}.")
                break  # Success — no retry needed

            except requests.RequestException as e:
                if _attempt < _max_crtsh_attempts - 1:
                    self.log("WARNING", f"[Subdomains] crt.sh attempt {_attempt+1} failed ({e}), retrying in 3s...")
                    import time as _time
                    _time.sleep(3)
                else:
                    self.log("WARNING", f"[Subdomains] Failed to query crt.sh after {_max_crtsh_attempts} attempts: {e}")
            except Exception as e:
                self.log("WARNING", f"[Subdomains] crt.sh returned invalid JSON or unexpected error: {e}")
                break

        brute_subdomains = self.brute_force_subdomains()
        all_subdomains.update(brute_subdomains)

        subfinder_subdomains = self._run_subfinder()
        all_subdomains.update(subfinder_subdomains)

        amass_subdomains = self._run_amass()
        all_subdomains.update(amass_subdomains)

        if all_subdomains:
            self.log("SUCCESS", f"[Subdomains] Total subdomains found: {len(all_subdomains)}")

            preview = list(all_subdomains)[:10]
            for sub in preview:
                self.log("INFO", f"  - {sub}")

            if len(all_subdomains) > 10:
                self.log("INFO", f"  ... and {len(all_subdomains) - 10} more.")

            self.add_vuln(
                title=f"Subdomain Enumeration Disclosure",
                severity="Low", category="Reconnaissance", cvss_score=0.0,
                description=f"Discovered {len(all_subdomains)} active or historical subdomains for {self.domain} via Certificate Transparency logs and brute-forcing.",
                remediation="Ensure all subdomains are actively maintained and patched. Remove unused subdomains from DNS.",
                confidence="Confirmed",
            )

            self.log("INFO", "[Subdomains] Analyzing DNS records for discovered subdomains...")
            for sub in list(all_subdomains)[:20]:
                self.check_dns_records(sub)

            self.log("INFO", "[Subdomains] Probing discovered subdomains via HTTP...")
            self._check_http_subdomains(list(all_subdomains))

            self.log("INFO", "[Subdomains] Checking for subdomain takeover vulnerabilities...")
            for sub in all_subdomains:
                self.check_takeover(sub)

        else:
            self.log("SUCCESS", f"[Subdomains] No subdomains found for {self.domain}.")

        return self.vulns
