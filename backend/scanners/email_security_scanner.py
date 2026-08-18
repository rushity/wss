"""
email_security_scanner.py — Email Security (SPF/DKIM/DMARC) Scanner
"""
import re, ssl, socket
from scanners.base_scanner import BaseScanner

try:
    import dns.resolver as dns_resolver
except ImportError:
    dns_resolver = None

class EmailSecurityScanner(BaseScanner):
    SCANNER_NAME = "Email Security Scanner"
    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[EmailSec] Auditing SPF/DKIM/DMARC for {self.domain}...")
        if not dns_resolver:
            self.log("WARNING", "[EmailSec] dnspython not installed. Skipping.")
            return self.vulns
        self._check_spf()
        self._check_dmarc()
        self._check_dkim()
        if not self.vulns:
            self.log("SUCCESS", "[EmailSec] Email security records look good.")
        return self.vulns

    def _resolve(self, name, rtype):
        try:
            return [str(r) for r in dns_resolver.resolve(name, rtype)]
        except Exception:
            return []

    def _check_spf(self):
        txts = self._resolve(self.domain, "TXT")
        spf = [t for t in txts if "v=spf1" in t.lower()]
        if not spf:
            self.add_vuln(title="Missing SPF Record", severity="Medium",
                category="Email Security", cvss_score=5.3,
                description=f"No SPF record found for `{self.domain}`. Without SPF, anyone can "
                    "send emails appearing to be from your domain (email spoofing).",
                remediation="Add a TXT record: v=spf1 include:_spf.google.com ~all")
        else:
            record = spf[0]
            if "+all" in record:
                self.add_vuln(title="SPF Record Uses +all (Permits All Senders)", severity="High",
                    category="Email Security", cvss_score=7.4,
                    description=f"SPF record `{record}` uses `+all`, allowing any server to send "
                        "email on behalf of this domain.",
                    remediation="Change +all to ~all (softfail) or -all (hardfail).")
            elif "~all" not in record and "-all" not in record:
                self.add_vuln(title="SPF Record Missing Fail Mechanism", severity="Low",
                    category="Email Security", cvss_score=3.5,
                    description=f"SPF: `{record}` lacks ~all or -all enforcement.",
                    remediation="Append -all to enforce strict SPF.")

    def _check_dmarc(self):
        txts = self._resolve(f"_dmarc.{self.domain}", "TXT")
        dmarc = [t for t in txts if "v=dmarc1" in t.lower()]
        if not dmarc:
            self.add_vuln(title="Missing DMARC Record", severity="Medium",
                category="Email Security", cvss_score=5.3,
                description=f"No DMARC record at `_dmarc.{self.domain}`. DMARC tells receiving "
                    "servers how to handle SPF/DKIM failures.",
                remediation="Add: _dmarc.yourdomain.com TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com\"")
        else:
            record = dmarc[0]
            if "p=none" in record.lower():
                self.add_vuln(title="DMARC Policy Set to 'none' (No Enforcement)", severity="Medium",
                    category="Email Security", cvss_score=5.3,
                    description=f"DMARC: `{record}` — policy `p=none` only monitors; it does not "
                        "reject or quarantine spoofed emails.",
                    remediation="Upgrade to p=quarantine or p=reject after monitoring period.")

    def _check_dkim(self):
        selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]
        found = False
        for sel in selectors:
            txts = self._resolve(f"{sel}._domainkey.{self.domain}", "TXT")
            if any("v=dkim1" in t.lower() or "p=" in t for t in txts):
                found = True
                self.log("SUCCESS", f"[EmailSec] DKIM record found: {sel}._domainkey.{self.domain}")
                break
        if not found:
            self.add_vuln(title="No DKIM Record Found (Common Selectors)", severity="Low",
                category="Email Security", cvss_score=3.5,
                description=f"No DKIM record found for common selectors on `{self.domain}`. "
                    "DKIM cryptographically signs emails to prevent tampering.",
                remediation="Configure DKIM signing on your email server and publish the public key.")
