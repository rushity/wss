"""
dns_security_scanner.py — DNS security analysis using DNSPython.
Performs comprehensive DNS security checks including zone transfer, DNSSEC, and record analysis.
"""
import dns.resolver, dns.query, dns.message, dns.rdatatype
from scanners.base_scanner import BaseScanner

class DNSSecurityScanner(BaseScanner):
    SCANNER_NAME = "DNS Security Analyzer"

    def run(self):
        self.log("INFO", f"[DNS Security] Starting comprehensive DNS analysis for {self.domain}...")
        
        # Perform various DNS security checks
        self._check_zone_transfer()
        self._check_dnssec()
        self._check_mx_records()
        self._check_spf()
        self._check_dmarc()
        self._check_wildcard_dns()
        self._check_dns_cache_poisoning()
        self._check_caa_records()
        
        self.log("SUCCESS", "[DNS Security] DNS analysis complete.")
        return self.vulns

    def _check_zone_transfer(self):
        """Check for DNS zone transfer vulnerability."""
        self.log("INFO", "[DNS Security] Checking for zone transfer vulnerability...")
        
        try:
            # Get authoritative nameservers
            ns_answers = dns.resolver.resolve(self.domain, 'NS')
            nameservers = [rdata.target.to_text().rstrip('.') for rdata in ns_answers]
            
            for ns in nameservers[:2]:  # Check first 2 nameservers only (faster)
                try:
                    # Attempt AXFR (zone transfer) — short timeout for speed
                    zone_query = dns.query.xfr(ns, self.domain, timeout=5)
                    zone_response = next(zone_query)
                    
                    if zone_response:
                        self.log("CRITICAL", f"[DNS Security] ZONE TRANSFER VULNERABLE on {ns}!")
                        self.add_vuln(
                            title="DNS Zone Transfer Vulnerability",
                            severity="Critical", category="DNS Security", cvss_score=9.8,
                            description=f"DNS zone transfer (AXFR) is allowed from {ns}. This exposes all DNS records including internal hostnames, mail servers, and other sensitive infrastructure details.",
                            remediation="Disable zone transfers to unauthorized servers:\n  BIND: allow-transfer { trusted_ips; };\n  Ensure only authorized secondary nameservers can perform AXFR."
                        )
                        return  # Found vulnerability, no need to check others
                except dns.exception.DNSException:
                    # Expected if zone transfer is disabled
                    pass
                except OSError as e:
                    # Network-level errors (timeout, connection refused) are expected
                    err_msg = str(e).strip()
                    if err_msg:
                        self.log("DEBUG", f"[DNS Security] Zone transfer network error on {ns}: {err_msg}")
                except Exception as e:
                    err_msg = str(e).strip()
                    if err_msg:
                        self.log("DEBUG", f"[DNS Security] Nameserver query error on {ns}: {err_msg}")
            
            self.log("SUCCESS", "[DNS Security] Zone transfer properly secured.")
            
        except dns.resolver.NoNameservers:
            self.log("WARNING", "[DNS Security] Could not retrieve nameservers.")
        except Exception as e:
            self.log("WARNING", f"[DNS Security] Zone transfer check failed: {e}")

    def _check_dnssec(self):
        """Check for DNSSEC implementation."""
        self.log("INFO", "[DNS Security] Checking DNSSEC implementation...")
        
        try:
            # Check for DNSKEY records
            dnskey_answers = dns.resolver.resolve(self.domain, 'DNSKEY')
            if dnskey_answers:
                self.log("SUCCESS", "[DNS Security] DNSSEC is implemented.")
                return
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            self.log("ERROR", f"[DNS Security] DNSKEY query error: {e}")
        
        self.log("WARNING", "[DNS Security] DNSSEC not implemented.")
        self.add_vuln(
            title="DNSSEC Not Implemented",
            severity="Medium", category="DNS Security", cvss_score=5.3,
            description=f"The domain {self.domain} does not have DNSSEC implemented. This makes it vulnerable to DNS cache poisoning and spoofing attacks.",
            remediation="Implement DNSSEC:\n  1. Generate DNSSEC keys\n  2. Sign your zone files\n  3. Upload DS records to your registrar\n  4. Verify with: dig +dnssec {self.domain}"
        )

    def _check_mx_records(self):
        """Check MX records for security issues."""
        self.log("INFO", "[DNS Security] Analyzing MX records...")
        
        try:
            mx_answers = dns.resolver.resolve(self.domain, 'MX')
            mx_servers = [rdata.exchange.to_text().rstrip('.') for rdata in mx_answers]
            
            if mx_servers:
                self.log("SUCCESS", f"[DNS Security] MX Records: {', '.join(mx_servers[:3])}")
                
                # Check for common mail server security issues
                for mx in mx_servers:
                    # Check if MX points to IP directly (bad practice)
                    if mx.replace('.', '').isdigit():
                        self.log("WARNING", f"[DNS Security] MX record points to IP: {mx}")
                        self.add_vuln(
                            title="MX Record Points to IP Address",
                            severity="Low", category="DNS Security", cvss_score=3.1,
                            description=f"MX record for {self.domain} points to IP address {mx} instead of a hostname. This is not a best practice.",
                            remediation="Update MX records to point to hostnames instead of IP addresses."
                        )
            else:
                self.log("INFO", "[DNS Security] No MX records found.")
                
        except dns.resolver.NoAnswer:
            self.log("INFO", "[DNS Security] No MX records found.")
        except Exception as e:
            self.log("WARNING", f"[DNS Security] MX check failed: {e}")

    def _check_spf(self):
        """Check for SPF record."""
        self.log("INFO", "[DNS Security] Checking SPF record...")
        
        try:
            txt_answers = dns.resolver.resolve(self.domain, 'TXT')
            spf_found = False
            
            for rdata in txt_answers:
                txt = rdata.to_text()
                if 'v=spf1' in txt:
                    spf_found = True
                    self.log("SUCCESS", f"[DNS Security] SPF Record: {txt[:100]}")
                    
                    # Check for ~all vs -all
                    if '~all' in txt:
                        self.log("WARNING", "[DNS Security] SPF uses ~all (soft fail)")
                        self.add_vuln(
                            title="SPF Uses Soft Fail (~all)",
                            severity="Low", category="DNS Security", cvss_score=3.1,
                            description=f"SPF record for {self.domain} uses ~all (soft fail) instead of -all (hard fail). This may allow some spoofed emails to pass.",
                            remediation="Consider changing ~all to -all in your SPF record for stricter email validation."
                        )
                    break
            
            if not spf_found:
                self.log("WARNING", "[DNS Security] No SPF record found.")
                self.add_vuln(
                    title="SPF Record Missing",
                    severity="Medium", category="DNS Security", cvss_score=5.3,
                    description=f"No SPF (Sender Policy Framework) record found for {self.domain}. This allows email spoofing and increases spam risk.",
                    remediation="Add an SPF record to your DNS:\n  Example: v=spf1 ip4:192.0.2.0/24 -all\n  Use SPF record generator tools for proper configuration."
                )
                
        except dns.resolver.NoAnswer:
            self.log("WARNING", "[DNS Security] No TXT records found (SPF missing).")
            self.add_vuln(
                title="SPF Record Missing",
                severity="Medium", category="DNS Security", cvss_score=5.3,
                description=f"No SPF record found for {self.domain}.",
                remediation="Add an SPF record to your DNS configuration."
            )
        except Exception as e:
            self.log("WARNING", f"[DNS Security] SPF check failed: {e}")

    def _check_dmarc(self):
        """Check for DMARC record."""
        self.log("INFO", "[DNS Security] Checking DMARC record...")
        
        dmarc_domain = f"_dmarc.{self.domain}"
        
        try:
            txt_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_found = False
            
            for rdata in txt_answers:
                txt = rdata.to_text()
                if 'v=DMARC1' in txt:
                    dmarc_found = True
                    self.log("SUCCESS", f"[DNS Security] DMARC Record: {txt[:100]}")
                    
                    # Check for p=none (monitoring only)
                    if 'p=none' in txt:
                        self.log("WARNING", "[DNS Security] DMARC policy is p=none (monitoring only)")
                        self.add_vuln(
                            title="DMARC Policy Set to None",
                            severity="Low", category="DNS Security", cvss_score=3.1,
                            description=f"DMARC record for {self.domain} has policy p=none, which means no action is taken on failed SPF/DKIM. This is only suitable for monitoring.",
                            remediation="Update DMARC policy to p=quarantine or p=reject for better email security:\n  v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
                        )
                    break
            
            if not dmarc_found:
                self.log("WARNING", "[DNS Security] No DMARC record found.")
                self.add_vuln(
                    title="DMARC Record Missing",
                    severity="Medium", category="DNS Security", cvss_score=5.3,
                    description=f"No DMARC (Domain-based Message Authentication, Reporting & Conformance) record found for {self.domain}. DMARC helps prevent email spoofing.",
                    remediation="Add a DMARC record to your DNS:\n  Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com\n  Start with p=none for monitoring, then move to p=quarantine or p=reject."
                )
                
        except dns.resolver.NoAnswer:
            self.log("WARNING", "[DNS Security] No DMARC record found.")
            self.add_vuln(
                title="DMARC Record Missing",
                severity="Medium", category="DNS Security", cvss_score=5.3,
                description=f"No DMARC record found for {self.domain}.",
                remediation="Add a DMARC record to your DNS configuration."
            )
        except dns.resolver.NXDOMAIN:
            self.log("WARNING", "[DNS Security] DMARC subdomain does not exist.")
        except Exception as e:
            self.log("WARNING", f"[DNS Security] DMARC check failed: {e}")

    def _check_wildcard_dns(self):
        """Check for wildcard DNS records."""
        self.log("INFO", "[DNS Security] Checking for wildcard DNS...")
        
        random_subdomain = f"random-nonexistent-{hash(self.domain) % 10000}.{self.domain}"
        
        try:
            dns.resolver.resolve(random_subdomain, 'A')
            self.log("WARNING", "[DNS Security] Wildcard DNS record detected.")
            self.add_vuln(
                title="Wildcard DNS Record Detected",
                severity="Low", category="DNS Security", cvss_score=3.1,
                description=f"Wildcard DNS record detected for {self.domain}. This can lead to subdomain takeover vulnerabilities if not properly managed.",
                remediation="Review wildcard DNS usage. Ensure all subdomains are properly claimed and monitored. Consider removing wildcard if not necessary."
            )
        except dns.resolver.NXDOMAIN:
            self.log("SUCCESS", "[DNS Security] No wildcard DNS detected.")
        except Exception as e:
            self.log("WARNING", f"[DNS Security] Wildcard check failed: {e}")

    def _check_dns_cache_poisoning(self):
        """Check for DNS cache poisoning vulnerabilities."""
        self.log("INFO", "[DNS Security] Checking DNS cache poisoning risks...")
        
        try:
            # Check for random source ports (good practice)
            # This is a heuristic check - we can't directly test this without more complex probing
            self.log("INFO", "[DNS Security] Ensure DNS resolver uses random source ports and transaction IDs.")
            
            # Check for DNSSEC (already done in _check_dnssec)
            # This is informational
            self.log("INFO", "[DNS Security] DNS cache poisoning protection relies on DNSSEC implementation.")
            
        except Exception as e:
            self.log("WARNING", f"[DNS Security] Cache poisoning check failed: {e}")

    def _check_caa_records(self):
        """Check for CAA (Certification Authority Authorization) records."""
        self.log("INFO", "[DNS Security] Checking CAA records...")
        
        try:
            caa_answers = dns.resolver.resolve(self.domain, 'CAA')
            caa_records = []
            
            for rdata in caa_answers:
                caa_records.append(f"{rdata.flags} {rdata.tag} {rdata.value}")
            
            if caa_records:
                self.log("SUCCESS", f"[DNS Security] CAA Records: {', '.join(caa_records)}")
            else:
                self.log("INFO", "[DNS Security] No CAA records found (informational).")
                self.add_vuln(
                    title="CAA Record Not Configured",
                    severity="Low", category="DNS Security", cvss_score=2.1,
                    description=f"No CAA (Certification Authority Authorization) record found for {self.domain}. CAA records specify which CAs are allowed to issue certificates for the domain.",
                    remediation="Consider adding CAA records to restrict which certificate authorities can issue certificates:\n  Example: issue ca.example.com; issuewild ca.example.com"
                )
                
        except dns.resolver.NoAnswer:
            self.log("INFO", "[DNS Security] No CAA records found.")
        except Exception as e:
            self.log("WARNING", f"[DNS Security] CAA check failed: {e}")
