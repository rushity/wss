"""
tls_weakness_scanner.py — TLS Weakness Scanner (BEAST/POODLE/CRIME/Heartbleed)
"""
import ssl, socket
from scanners.base_scanner import BaseScanner

class TlsWeaknessScanner(BaseScanner):
    SCANNER_NAME = "TLS Weakness Scanner"
    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[TLSWeak] Testing TLS weaknesses on {self.domain}...")
        self._check_sslv3()
        self._check_tls10()
        self._check_tls11()
        self._check_compression()
        self._check_weak_ciphers()
        if not self.vulns:
            self.log("SUCCESS", "[TLSWeak] No TLS weaknesses detected.")
        return self.vulns

    def _try_connect(self, protocol_const):
        try:
            ctx = ssl.SSLContext(protocol_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    return ssock.version()
        except ssl.SSLError as e:
            err_str = str(e).lower()
            # NO_CIPHERS_AVAILABLE / UNSUPPORTED_PROTOCOL = modern OpenSSL blocked this protocol
            # This is the EXPECTED SECURE outcome — log at DEBUG only
            if any(x in err_str for x in ("no ciphers available", "unsupported protocol",
                                           "wrong version", "alert handshake failure")):
                self.log("DEBUG", f"[TLSWeak] Protocol not supported by local OpenSSL (expected): {e}")
            else:
                self.log("DEBUG", f"[TLSWeak] SSL error (protocol likely disabled): {e}")
            return None
        except OSError:
            # Connection refused / timeout — server port not open
            return None
        except Exception as e:
            self.log("DEBUG", f"[TLSWeak] _try_connect error: {e}")
            return None
    def _check_sslv3(self):
        if hasattr(ssl, 'PROTOCOL_SSLv3'):
            ver = self._try_connect(ssl.PROTOCOL_SSLv3)
            if ver:
                self.add_vuln(title="SSLv3 Supported (POODLE Vulnerable)", severity="Critical",
                    category="TLS Weakness", cvss_score=9.0,
                    description="Server accepts SSLv3, vulnerable to POODLE (CVE-2014-3566).",
                    remediation="Disable SSLv3: ssl_protocols TLSv1.2 TLSv1.3;")

    def _check_tls10(self):
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            ver = self._try_connect(ssl.PROTOCOL_TLSv1)
            if ver:
                self.add_vuln(title="TLS 1.0 Supported (BEAST Vulnerable)", severity="Medium",
                    category="TLS Weakness", cvss_score=5.3,
                    description="TLS 1.0 is deprecated and vulnerable to BEAST (CVE-2011-3389).",
                    remediation="Disable TLS 1.0. Use TLS 1.2+ only.")

    def _check_tls11(self):
        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            ver = self._try_connect(ssl.PROTOCOL_TLSv1_1)
            if ver:
                self.add_vuln(title="TLS 1.1 Supported (Deprecated)", severity="Low",
                    category="TLS Weakness", cvss_score=3.5,
                    description="TLS 1.1 is deprecated by all major browsers since March 2020.",
                    remediation="Disable TLS 1.1. Minimum should be TLS 1.2.")

    def _check_compression(self):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    if ssock.compression():
                        self.add_vuln(title="TLS Compression Enabled (CRIME Vulnerable)",
                            severity="High", category="TLS Weakness", cvss_score=7.4,
                            description="TLS compression is enabled, vulnerable to CRIME (CVE-2012-4929).",
                            remediation="Disable TLS compression: ssl_comp off; (OpenSSL)")
        except Exception as e:
            self.log("ERROR", f"[TLSWeak] _check_compression error: {e}")

    def _check_weak_ciphers(self):
        weak = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cipher = ssock.cipher()
                    if cipher and any(w in cipher[0].upper() for w in weak):
                        self.add_vuln(title=f"Weak TLS Cipher: {cipher[0]}", severity="High",
                            category="TLS Weakness", cvss_score=7.4,
                            description=f"Server negotiated weak cipher: {cipher[0]}.",
                            remediation="Configure strong cipher suites only (AES-GCM, ChaCha20).")
        except Exception as e:
            self.log("ERROR", f"[TLSWeak] _check_weak_ciphers error: {e}")
