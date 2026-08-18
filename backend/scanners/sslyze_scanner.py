"""
sslyze_scanner.py — Deep SSL/TLS analysis using the sslyze Python library.
Requires: pip install sslyze
"""
from scanners.base_scanner import BaseScanner
from utils.fingerprint_db import find_cves

class SslyzeScanner(BaseScanner):
    SCANNER_NAME = "SSLyze TLS/SSL Scanner"

    def run(self):
        self.log("INFO", f"[SSLyze] Starting SSL/TLS deep analysis on {self.domain}...")

        if not self.target.startswith("https://"):
            self.log("WARNING", "[SSLyze] Target is not HTTPS — running basic TLS check via socket.")
            self._check_no_https()
            return self.vulns

        try:
            from sslyze import (
                Scanner, ServerNetworkLocation, ServerScanRequest,
                ScanCommandAttemptStatusEnum
            )
            from sslyze.plugins.scan_commands import ScanCommand
            from sslyze.errors import ConnectionToServerFailed
        except ImportError:
            self.log("WARNING", "[SSLyze] sslyze not installed. Run: pip install sslyze")
            self._fallback_ssl_check()
            return self.vulns

        try:
            location = ServerNetworkLocation(hostname=self.domain, port=443)
            request  = ServerScanRequest(
                server_location=location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.ROBOT,
                    ScanCommand.TLS_FALLBACK_SCSV,
                    ScanCommand.OPENSSL_CCS_INJECTION,
                    ScanCommand.SESSION_RENEGOTIATION,
                    ScanCommand.HTTP_HEADERS,
                    ScanCommand.TLS_COMPRESSION,
                    ScanCommand.TLS_1_3_EARLY_DATA,
                },
            )

            scanner = Scanner()
            scanner.queue_scans([request])

            for result in scanner.get_results():
                self._process_result(result, ScanCommand, ScanCommandAttemptStatusEnum)

        except Exception as e:
            self.log("WARNING", f"[SSLyze] Scan failed: {e}. Falling back to basic check.")
            self._fallback_ssl_check()

        return self.vulns

    # ------------------------------------------------------------------
    def _process_result(self, result, ScanCommand, StatusEnum):
        from datetime import datetime, timezone

        # --- Certificate Info ---
        cert_attempt = result.scan_result.certificate_info
        if cert_attempt.status == StatusEnum.COMPLETED:
            r = cert_attempt.result
            for dep in r.certificate_deployments:
                chain = dep.received_certificate_chain
                if not chain:
                    continue
                leaf = chain[0]
                subject = leaf.subject.rfc4514_string()
                not_after = leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc") else leaf.not_valid_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days

                self.log("SUCCESS", f"[SSLyze] Certificate subject: {subject}")
                self.log("SUCCESS", f"[SSLyze] Certificate expires: {not_after.strftime('%Y-%m-%d')} ({days_left} days)")

                if days_left < 0:
                    self.log("CRITICAL", "[SSLyze] Certificate has EXPIRED!")
                    self.add_vuln(
                        title="Expired SSL/TLS Certificate",
                        severity="Critical", category="SSL/TLS", cvss_score=9.1,
                        description=f"The SSL/TLS certificate for {self.domain} expired on {not_after.strftime('%Y-%m-%d')}. All connections are untrusted.",
                        remediation="Renew the certificate immediately. Use Let's Encrypt for free automated renewal:\n  certbot renew --force-renewal",
                    )
                elif days_left < 14:
                    self.log("WARNING", f"[SSLyze] Certificate expiring SOON: {days_left} days!")
                    self.add_vuln(
                        title=f"SSL/TLS Certificate Expiring Soon ({days_left} Days)",
                        severity="High", category="SSL/TLS", cvss_score=7.5,
                        description=f"The certificate expires in {days_left} days. Browsers will display security warnings when it expires.",
                        remediation="Renew now: certbot renew\nConsider automating renewal with a cron job or certbot timer.",
                    )
                elif days_left < 30:
                    self.log("WARNING", f"[SSLyze] Certificate expiring in {days_left} days.")
                    self.add_vuln(
                        title=f"SSL/TLS Certificate Expiring in {days_left} Days",
                        severity="Medium", category="SSL/TLS", cvss_score=5.3,
                        description=f"Certificate expires on {not_after.strftime('%Y-%m-%d')}. Plan renewal to avoid service disruption.",
                        remediation="Schedule certificate renewal. certbot renew handles this automatically if configured.",
                    )
                else:
                    self.log("SUCCESS", f"[SSLyze] Certificate valid for {days_left} more days.")

                # Chain trust
                if not dep.verified_certificate_chain:
                    self.log("WARNING", "[SSLyze] Certificate chain is NOT trusted / incomplete!")
                    self.add_vuln(
                        title="Untrusted or Incomplete SSL Certificate Chain",
                        severity="High", category="SSL/TLS", cvss_score=7.4,
                        description="The server's certificate chain cannot be verified by a trusted root CA. Browsers will show a security warning.",
                        remediation="Install the full certificate chain including intermediates. Download the CA bundle from your certificate provider.",
                    )
                else:
                    self.log("SUCCESS", "[SSLyze] Certificate chain fully trusted.")
        else:
            self.log("WARNING", f"[SSLyze] Certificate scan failed: {cert_attempt.error_reason if hasattr(cert_attempt, 'error_reason') else 'unknown'}")

        # --- Deprecated Protocol Detection ---
        deprecated = {
            "SSL 2.0": result.scan_result.ssl_2_0_cipher_suites,
            "SSL 3.0": result.scan_result.ssl_3_0_cipher_suites,
            "TLS 1.0": result.scan_result.tls_1_0_cipher_suites,
            "TLS 1.1": result.scan_result.tls_1_1_cipher_suites,
        }
        for proto_name, attempt in deprecated.items():
            if attempt.status == StatusEnum.COMPLETED:
                if attempt.result.accepted_cipher_suites:
                    self.log("WARNING", f"[SSLyze] Deprecated protocol ENABLED: {proto_name}")
                    severity = "Critical" if "SSL" in proto_name else "High"
                    cvss     = 9.1 if "SSL" in proto_name else 7.4
                    self.add_vuln(
                        title=f"Deprecated Protocol Enabled: {proto_name}",
                        severity=severity, category="SSL/TLS", cvss_score=cvss,
                        description=f"The server accepts {proto_name} connections, which are cryptographically broken and vulnerable to POODLE, BEAST, and other protocol-downgrade attacks.",
                        remediation=f"Disable {proto_name} in your web server configuration.\n"
                                    "  Nginx: ssl_protocols TLSv1.2 TLSv1.3;\n"
                                    "  Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
                    )
                else:
                    self.log("SUCCESS", f"[SSLyze] {proto_name}: Disabled ✔")

        # Modern TLS check
        tls12_attempt = result.scan_result.tls_1_2_cipher_suites
        tls13_attempt = result.scan_result.tls_1_3_cipher_suites
        tls12_ok = tls12_attempt.status == StatusEnum.COMPLETED and bool(tls12_attempt.result.accepted_cipher_suites)
        tls13_ok = tls13_attempt.status == StatusEnum.COMPLETED and bool(tls13_attempt.result.accepted_cipher_suites)
        if tls12_ok: self.log("SUCCESS", "[SSLyze] TLS 1.2: Supported ✔")
        if tls13_ok: self.log("SUCCESS", "[SSLyze] TLS 1.3: Supported ✔")
        if not tls12_ok and not tls13_ok:
            self.log("WARNING", "[SSLyze] Neither TLS 1.2 nor TLS 1.3 is supported!")
            self.add_vuln(
                title="Modern TLS Protocol Not Supported",
                severity="High", category="SSL/TLS", cvss_score=7.5,
                description="The server does not support TLS 1.2 or TLS 1.3. Clients may be unable to establish secure connections.",
                remediation="Enable TLS 1.2 and TLS 1.3:\n  Nginx: ssl_protocols TLSv1.2 TLSv1.3;\n  Apache: SSLProtocol TLSv1.2 TLSv1.3",
            )

        # --- Heartbleed ---
        hb = result.scan_result.heartbleed
        if hb.status == StatusEnum.COMPLETED:
            if hb.result.is_vulnerable_to_heartbleed:
                self.log("CRITICAL", "[SSLyze] HEARTBLEED VULNERABILITY DETECTED! (CVE-2014-0160)")
                self.add_vuln(
                    title="Heartbleed Vulnerability (CVE-2014-0160)",
                    severity="Critical", category="SSL/TLS", cvss_score=9.8,
                    description="The server is vulnerable to Heartbleed. Attackers can read server memory, exposing private keys, session tokens, and plaintext data.",
                    remediation="Upgrade OpenSSL to 1.0.1g or later immediately. Reissue all SSL certificates and revoke the old ones. Reset all session cookies and user passwords.",
                )
            else:
                self.log("SUCCESS", "[SSLyze] Heartbleed: Not vulnerable ✔")

        # --- ROBOT ---
        robot = result.scan_result.robot
        if robot.status == StatusEnum.COMPLETED:
            robot_result = str(robot.result.robot_result).upper()
            if "NOT_VULNERABLE" in robot_result:
                self.log("SUCCESS", "[SSLyze] ROBOT Attack: Not vulnerable ✔")
            elif "VULNERABLE" in robot_result:
                self.log("CRITICAL", "[SSLyze] ROBOT Attack vulnerability detected!")
                self.add_vuln(
                    title="ROBOT Attack Vulnerability (RSA Key Decryption)",
                    severity="High", category="SSL/TLS", cvss_score=7.5,
                    description="The server is vulnerable to the ROBOT attack (Return Of Bleichenbacher's Oracle Threat). Attackers can perform RSA decryption and signature operations.",
                    remediation="Disable RSA key exchange cipher suites. Use ECDHE or DHE cipher suites only:\n  ssl_ciphers 'ECDH+AESGCM:DH+AESGCM:!RSA!aNULL:!MD5:!DSS';",
                )
            else:
                self.log("SUCCESS", "[SSLyze] ROBOT Attack: Not vulnerable ✔")

        # --- OpenSSL CCS Injection ---
        ccs = result.scan_result.openssl_ccs_injection
        if ccs.status == StatusEnum.COMPLETED:
            if ccs.result.is_vulnerable_to_ccs_injection:
                self.log("CRITICAL", "[SSLyze] OpenSSL CCS Injection detected! (CVE-2014-0224)")
                self.add_vuln(
                    title="OpenSSL CCS Injection (CVE-2014-0224)",
                    severity="High", category="SSL/TLS", cvss_score=7.4,
                    description="The server is vulnerable to OpenSSL ChangeCipherSpec injection, allowing MitM attacks to intercept and decrypt traffic.",
                    remediation="Update OpenSSL to version 0.9.8za, 1.0.0m, 1.0.1h or later.",
                )
            else:
                self.log("SUCCESS", "[SSLyze] OpenSSL CCS Injection: Not vulnerable ✔")

        # --- TLS Compression ---
        compression = result.scan_result.tls_compression
        if compression.status == StatusEnum.COMPLETED:
            # sslyze ≥ 5.x renamed / removed `supports_tls_compression` on
            # CompressionScanResult.  Use hasattr to stay compatible.
            comp_result = compression.result
            if hasattr(comp_result, "supports_tls_compression"):
                tls_compressed = comp_result.supports_tls_compression
            else:
                # Fallback: inspect repr for the "True" indicator
                tls_compressed = "True" in repr(comp_result)

            if tls_compressed:
                self.log("CRITICAL", "[SSLyze] TLS Compression enabled! (CRIME/BREACH vulnerability)")
                self.add_vuln(
                    title="TLS Compression Enabled (CRIME/BREACH)",
                    severity="High", category="SSL/TLS", cvss_score=7.5,
                    description="TLS compression is enabled, making the server vulnerable to CRIME and BREACH attacks that can decrypt HTTPS traffic.",
                    remediation="Disable TLS compression:\n  Nginx: ssl off;\n  Apache: SSLCompression off",
                )
            else:
                self.log("SUCCESS", "[SSLyze] TLS Compression: Disabled ✔")


        # --- TLS 1.3 Early Data ---
        early_data = result.scan_result.tls_1_3_early_data
        if early_data.status == StatusEnum.COMPLETED:
            if early_data.result.supports_early_data:
                self.log("WARNING", "[SSLyze] TLS 1.3 Early Data (0-RTT) enabled")
                self.add_vuln(
                    title="TLS 1.3 Early Data (0-RTT) Enabled",
                    severity="Medium", category="SSL/TLS", cvss_score=5.3,
                    description="TLS 1.3 Early Data (0-RTT) is enabled, which may allow replay attacks on sensitive requests.",
                    remediation="Consider disabling 0-RTT for applications that handle sensitive data:\n  Nginx: ssl_early_data off;\n  Apache: SSLInsecureRenegotiation off",
                )
            else:
                self.log("SUCCESS", "[SSLyze] TLS 1.3 Early Data: Disabled ✔")

        # --- HTTP Headers ---
        http_headers = result.scan_result.http_headers
        if http_headers.status == StatusEnum.COMPLETED:
            headers = getattr(http_headers.result, "http_headers_parsed", None) or getattr(http_headers.result, "headers", None)
            if headers:
                self.log("INFO", "[SSLyze] HTTP Headers via TLS:")
                for header_name, header_value in headers.items():
                    self.log("INFO", f"[SSLyze]   {header_name}: {header_value[:80]}")
                
                # Check for HSTS
                if "strict-transport-security" in [h.lower() for h in headers.keys()]:
                    self.log("SUCCESS", "[SSLyze] HSTS header present")
                else:
                    self.log("WARNING", "[SSLyze] HSTS header missing")
                    self.add_vuln(
                        title="HSTS Header Missing",
                        severity="Medium", category="SSL/TLS", cvss_score=5.3,
                        description="HTTP Strict Transport Security (HSTS) header is not present, allowing SSL stripping attacks.",
                        remediation="Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    )

        tls_techs = ["HTTP/2", "TLS", "SSL", "OpenSSL"]
        for tls_tech in tls_techs:
            cves = find_cves(tls_tech)
            if cves:
                cve_ids = [c["cve"] for c in cves]
                self.log("WARNING", f"[SSLyze] Known CVEs for {tls_tech}: {', '.join(cve_ids)}")
                self.add_vuln(
                    title=f"Known TLS/Crypto CVEs: {', '.join(cve_ids)}",
                    severity="High", category="SSL/TLS", cvss_score=max(c["cvss"] for c in cves),
                    description=f"The following CVEs affect {tls_tech}: {', '.join(cve_ids)}.",
                    remediation="Update affected software to the latest version.",
                    evidence=f"CVEs: {', '.join(cve_ids)}",
                    confidence="Confirmed",
                    cve_ids=cve_ids,
                )

        self.log("INFO", f"[SSLyze] SSL/TLS analysis complete. {len(self.vulns)} issue(s) detected.")

    # ------------------------------------------------------------------
    def _check_no_https(self):
        self.add_vuln(
            title="Insecure HTTP Protocol / No HTTPS",
            severity="High", category="SSL/TLS", cvss_score=7.5,
            description=f"The target {self.target} does not use HTTPS. All traffic including credentials, session tokens, and data is transmitted in plaintext and vulnerable to interception.",
            remediation="Obtain an SSL/TLS certificate (free via Let's Encrypt) and configure your web server to redirect all HTTP traffic to HTTPS:\n  Nginx: return 301 https://$host$request_uri;\n  Apache: Redirect permanent / https://yourdomain.com/",
        )

    def _fallback_ssl_check(self):
        import ssl, socket
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    expiry = cert.get("notAfter", "Unknown")
                    self.log("SUCCESS", f"[SSLyze] SSL/TLS connected. Protocol: {proto}. Cert expires: {expiry}")
                    if proto in ("SSLv3", "TLSv1", "TLSv1.1"):
                        self.log("WARNING", f"[SSLyze] Deprecated protocol in use: {proto}")
                        self.add_vuln(
                            title=f"Deprecated TLS Protocol: {proto}",
                            severity="High", category="SSL/TLS", cvss_score=7.4,
                            description=f"Server negotiated {proto} which is deprecated and cryptographically broken.",
                            remediation="Disable deprecated TLS protocols. Enable TLS 1.2 and TLS 1.3 only.",
                        )
        except ssl.SSLError as e:
            self.log("WARNING", f"[SSLyze] SSL error: {e}")
            self.add_vuln(
                title="SSL/TLS Handshake Failure",
                severity="High", category="SSL/TLS", cvss_score=7.5,
                description=f"SSL/TLS handshake with {self.domain} failed: {str(e)}. This may indicate a misconfigured certificate or unsupported protocol.",
                remediation="Verify your SSL certificate is valid, properly installed, and the server supports at least TLS 1.2.",
            )
        except Exception as e:
            self.log("WARNING", f"[SSLyze] Basic SSL check error: {e}")
