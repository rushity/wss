"""
whois_scanner.py — WHOIS / DNS reconnaissance module.
Requires: pip install python-whois dnspython (dnspython optional)
"""
import socket, threading
from scanners.base_scanner import BaseScanner


def _run_with_timeout(func, timeout=10):
    """Run a callable in a thread with a hard timeout. Returns (result, error)."""
    result = [None]
    error  = [None]

    def wrapper():
        try:
            result[0] = func()
        except Exception as e:
            error[0] = e

    t = threading.Thread(target=wrapper, daemon=True)
    t.start()
    t.join(timeout=timeout)

    if t.is_alive():
        return None, TimeoutError(f"Operation timed out after {timeout}s")
    return result[0], error[0]


class WhoisScanner(BaseScanner):
    SCANNER_NAME = "WHOIS / DNS Recon Scanner"

    def run(self):
        self.log("INFO", f"[WHOIS] Starting DNS/WHOIS reconnaissance on {self.domain}...")
        self._dns_checks()
        self._whois_check()
        return self.vulns

    def _dns_checks(self):
        # A Record
        try:
            socket.setdefaulttimeout(10)
            ip = socket.gethostbyname(self.domain)
            self.log("SUCCESS", f"[DNS] A Record resolved: {self.domain} -> {ip}")
        except socket.gaierror as e:
            self.log("WARNING", f"[DNS] DNS resolution FAILED for {self.domain}: {e}")
            self.add_vuln(
                title="DNS Resolution Failure",
                severity="High", category="DNS/WHOIS", cvss_score=7.5,
                description=f"The domain '{self.domain}' could not be resolved to an IP address. This may indicate a misconfigured DNS record or a domain that no longer exists.",
                remediation="Verify your DNS A/AAAA records are correctly configured with your registrar or DNS provider.",
            )
            return
        except Exception as e:
            self.log("WARNING", f"[DNS] DNS lookup error: {e}")
            return

        # MX Record check via DNS lookup
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(self.domain, "MX", lifetime=8)
            for r in mx_records:
                self.log("INFO", f"[DNS] MX Record: {r.exchange} (priority {r.preference})")
        except ImportError:
            self.log("DEBUG", "[DNS] dnspython not installed -- skipping MX check.")
        except Exception as e:
            self.log("DEBUG", f"[DNS] MX lookup: {e}")

        # Check for open DNS zone transfer (AXFR) - information disclosure
        try:
            import dns.zone, dns.query
            z = dns.zone.from_xfr(dns.query.xfr(ip, self.domain, timeout=5))
            if z:
                self.log("CRITICAL", f"[DNS] DNS Zone Transfer ALLOWED from {ip}!")
                self.add_vuln(
                    title="DNS Zone Transfer Allowed (AXFR)",
                    severity="High", category="DNS/WHOIS", cvss_score=7.5,
                    description=f"The DNS server at {ip} allows unrestricted zone transfer requests (AXFR). "
                                "This reveals all DNS records, internal hostnames, and network topology to attackers.",
                    remediation="Restrict zone transfers to authorised secondary nameservers only:\n"
                                "  BIND: allow-transfer { trusted-secondaries; };\n"
                                "  PowerDNS: disable-axfr=yes",
                )
        except ImportError:
            pass
        except Exception as e:
            err_msg = str(e).strip()
            if err_msg:
                self.log("DEBUG", f"[WHOIS] Zone transfer error (expected if secured): {err_msg}")
            self.log("SUCCESS", "[DNS] Zone Transfer (AXFR): Not allowed.")

    def _whois_check(self):
        try:
            import whois  # type: ignore[import-untyped]
        except ImportError:
            self.log("DEBUG", "[WHOIS] python-whois not installed -- skipping WHOIS check. Run: pip install python-whois")
            self.log("INFO", "[WHOIS] DNS/WHOIS recon complete.")
            return

        self.log("INFO", "[WHOIS] Running WHOIS lookup (10s timeout)...")
        w, err = _run_with_timeout(lambda: whois.whois(self.domain), timeout=10)

        if err:
            self.log("WARNING", f"[WHOIS] WHOIS lookup failed/timed out: {err}")
            self.log("INFO", "[WHOIS] DNS/WHOIS recon complete.")
            return

        if w is None:
            self.log("WARNING", "[WHOIS] WHOIS returned no data.")
            self.log("INFO", "[WHOIS] DNS/WHOIS recon complete.")
            return

        try:
            registrar    = w.get("registrar", "Unknown")
            creation     = w.get("creation_date")
            expiration   = w.get("expiration_date")
            name_servers = w.get("name_servers", [])

            if isinstance(creation, list):    creation   = creation[0]
            if isinstance(expiration, list):  expiration = expiration[0]
            if isinstance(name_servers, list): name_servers = name_servers[:3]

            self.log("INFO", f"[WHOIS] Registrar: {registrar}")
            self.log("INFO", f"[WHOIS] Created: {creation}")
            self.log("INFO", f"[WHOIS] Expires: {expiration}")
            self.log("INFO", f"[WHOIS] Nameservers: {name_servers}")

            # Domain expiry warning
            if expiration:
                from datetime import datetime, timezone
                exp = expiration.replace(tzinfo=timezone.utc) if hasattr(expiration, "replace") else expiration
                try:
                    now = datetime.now(timezone.utc)
                    days_left = (exp - now).days
                    if days_left < 30:
                        self.log("WARNING", f"[WHOIS] Domain expires in {days_left} days!")
                        self.add_vuln(
                            title=f"Domain Registration Expiring Soon ({days_left} Days)",
                            severity="High", category="DNS/WHOIS", cvss_score=7.5,
                            description=f"The domain '{self.domain}' registration expires in {days_left} days ({exp.date()}). "
                                        "If not renewed, the domain becomes available for registration by attackers (domain hijacking).",
                            remediation="Renew the domain registration immediately through your registrar. Enable auto-renewal to prevent accidental expiry.",
                        )
                    else:
                        self.log("SUCCESS", f"[WHOIS] Domain valid for {days_left} more days.")
                except Exception as e:
                    self.log("ERROR", f"[WHOIS] Expiry calculation error: {e}")
        except Exception as e:
            self.log("DEBUG", f"[WHOIS] Error parsing WHOIS data: {e}")

        self.log("INFO", "[WHOIS] DNS/WHOIS recon complete.")
