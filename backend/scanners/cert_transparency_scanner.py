"""
cert_transparency_scanner.py — Certificate Transparency Scanner
"""
import json, urllib.request
from scanners.base_scanner import BaseScanner

class CertTransparencyScanner(BaseScanner):
    SCANNER_NAME = "Certificate Transparency Scanner"
    _SCANNER_KEY = "cert_transparency"
    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[CertTransp] Querying crt.sh for {self.domain}...")
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            req = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=15, context=self.get_ssl_context()) as r:
                data = json.loads(r.read().decode("utf-8", errors="ignore"))
        except Exception as e:
            self.log("WARNING", f"[CertTransp] crt.sh query failed: {e}")
            return self.vulns

        if not data:
            self.log("INFO", "[CertTransp] No CT log entries found.")
            return self.vulns

        # Extract unique subdomains
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip().lower()
                if line and line != self.domain and self.domain in line:
                    subdomains.add(line)

        if len(subdomains) > 5:
            self.add_vuln(
                title=f"Certificate Transparency: {len(subdomains)} Subdomains Discovered",
                severity="Low", category="Reconnaissance", cvss_score=0.0,
                description=f"CT logs reveal {len(subdomains)} subdomains for `{self.domain}`:\n\n" +
                    "\n".join(f"- `{s}`" for s in sorted(subdomains)[:30]),
                remediation="Audit all discovered subdomains. Decommission unused ones. "
                    "Use wildcard certs sparingly as they expose the full scope of your infrastructure.")

        # Check for expired certs
        from datetime import datetime, timezone
        expired = []
        for entry in data[:50]:
            try:
                not_after = entry.get("not_after", "")
                exp_date = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                if exp_date < datetime.now(timezone.utc):
                    cn = entry.get("common_name", "unknown")
                    if cn not in [e[0] for e in expired]:
                        expired.append((cn, not_after))
            except Exception as e:
                self.log("ERROR", f"[CertTransp] entry parsing error: {e}")
                continue

        if expired:
            self.add_vuln(
                title=f"Expired Certificates Found ({len(expired)})",
                severity="Low", category="Certificate Management", cvss_score=3.5,
                description=f"Expired certificates in CT logs:\n\n" +
                    "\n".join(f"- `{cn}` expired {d}" for cn, d in expired[:10]),
                remediation="Renew or revoke expired certificates. Use automated renewal (Let's Encrypt, certbot).")

        self.log("SUCCESS", f"[CertTransp] Found {len(subdomains)} subdomains, {len(expired)} expired certs.")
        return self.vulns
