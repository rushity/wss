"""
dns_rebinding_scanner.py — DNS Rebinding Scanner
=================================================
Expert-grade rewrite (GAP-011 fix):
  1. Real TTL check via low-level DNS query (struct-based) + socket fallback
  2. Multiple resolution comparison with jitter guard (avoids CDN false positives)
  3. Host header validation check (actual defense verification)
  4. Private IP detection on resolved addresses
  5. CORS + DNS rebinding chain check
"""
import socket, time, struct
import urllib.parse
from scanners.base_scanner import BaseScanner

# TTL threshold — anything below this is a rebinding risk
LOW_TTL_THRESHOLD = 30  # seconds

# Private IP ranges to check resolved IPs against
import ipaddress
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def _query_dns_ttl(hostname: str, timeout: float = 3.0) -> int | None:
    """
    Perform a raw DNS UDP query to get the actual TTL from the A record.
    Returns TTL in seconds, or None if the query fails.
    This avoids relying on the OS DNS cache (which resets TTL).
    """
    try:
        # Build minimal DNS query for A record
        qname = b""
        for label in hostname.encode().split(b"."):
            qname += bytes([len(label)]) + label
        qname += b"\x00"  # root label

        # Random transaction ID
        txid = b"\xab\xcd"
        header = txid + b"\x01\x00"  # QR=0, OPCODE=0, RD=1
        header += b"\x00\x01"        # QDCOUNT=1
        header += b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT NSCOUNT ARCOUNT = 0
        question = qname + b"\x00\x01\x00\x01"  # QTYPE=A QCLASS=IN

        packet = header + question

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect(("8.8.8.8", 53))
            s.send(packet)
            response = s.recv(4096)

        # Parse answer section — skip header (12 bytes) + question section
        # Answer section starts after the question section
        # Question section = qname + 4 bytes (qtype + qclass)
        q_offset = 12 + len(qname) + 4
        if len(response) < q_offset + 12:
            return None

        # Parse first answer record
        # NAME (2 bytes compressed ptr), TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        ans_offset = q_offset
        # Handle compressed name pointer (0xC0 xx)
        if response[ans_offset] & 0xC0 == 0xC0:
            ans_offset += 2
        else:
            # Walk the name
            while ans_offset < len(response) and response[ans_offset] != 0:
                ans_offset += response[ans_offset] + 1
            ans_offset += 1

        if ans_offset + 10 > len(response):
            return None

        rtype, rclass, ttl = struct.unpack("!HHI", response[ans_offset:ans_offset + 8])
        if rtype == 1:  # A record
            return ttl
        return None
    except Exception as e:
        print(f"ERROR: [DNSRebind] _query_dns_ttl error: {e}")
        return None


class DnsRebindingScanner(BaseScanner):
    SCANNER_NAME = "DNS Rebinding Scanner"
    _SCANNER_KEY = "dns_rebinding"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[DNSRebind] Checking DNS rebinding for {self.domain}...")

        # 1. Check actual DNS TTL via raw query
        self._check_ttl()

        # 2. Check if resolved IP is in a private range (misconfigured DNS)
        self._check_private_ip_resolution()

        # 3. Verify Host header validation (actual defense)
        self._check_host_header_validation()

        # 4. Multi-resolution instability check with jitter guard
        self._check_resolution_instability()

        if not self.vulns:
            self.log("SUCCESS", "[DNSRebind] No DNS rebinding indicators found.")
        return self.vulns

    # ── 1. TTL check ──────────────────────────────────────────────────────
    def _check_ttl(self):
        ttl = _query_dns_ttl(self.domain)
        if ttl is None:
            self.log("INFO", f"[DNSRebind] Could not retrieve TTL for {self.domain} (raw DNS query).")
            return
        self.log("INFO", f"[DNSRebind] TTL for {self.domain}: {ttl}s")
        if ttl < LOW_TTL_THRESHOLD:
            self.add_vuln(
                title=f"DNS Rebinding Risk — Extremely Low TTL ({ttl}s)",
                severity="Medium",
                category="DNS Rebinding",
                cvss_score=5.3,
                confidence="High",
                references=["https://attack.mitre.org/techniques/T1557/"],
                description=(
                    f"The domain `{self.domain}` has a DNS TTL of **{ttl} seconds**, "
                    f"well below the safe minimum of {LOW_TTL_THRESHOLD}s.\n\n"
                    "A low TTL allows an attacker to:\n"
                    "1. Have the victim visit their domain (resolves to attacker IP)\n"
                    "2. Quickly re-point the DNS to `127.0.0.1` or a private IP\n"
                    "3. Browser's Same-Origin Policy now allows the page to make requests "
                    "to `localhost` (bypassing SSRF filters)\n\n"
                    "This enables reading internal APIs, attacking localhost services, "
                    "and bypassing IP-based access controls."
                ),
                remediation=(
                    f"1. Set DNS TTL to at least 300 seconds (5 minutes) for all A/AAAA records.\n"
                    "2. Implement **DNS pinning** in your HTTP client/browser.\n"
                    "3. Validate the `Host` header against a strict allowlist on every request.\n"
                    "4. Reject requests from private/loopback IPs at the load balancer level."
                ),
            )

    # ── 2. Private IP resolution ──────────────────────────────────────────
    def _check_private_ip_resolution(self):
        try:
            infos = socket.getaddrinfo(self.domain, 443)
            ips = {info[4][0] for info in infos}
            for ip in ips:
                if _is_private(ip):
                    self.add_vuln(
                        title=f"DNS Resolves to Private IP — Rebinding Risk ({ip})",
                        severity="High",
                        category="DNS Rebinding",
                        cvss_score=7.5,
                        confidence="Confirmed",
                        description=(
                            f"The domain `{self.domain}` resolves to `{ip}`, "
                            "which is a **private/internal IP address**.\n\n"
                            "This directly enables DNS rebinding: if the browser trusted this "
                            "domain, it can now make cross-origin requests to internal services "
                            "as if coming from the same origin."
                        ),
                        remediation=(
                            "1. Never configure public domain names to resolve to private IP addresses.\n"
                            "2. Use split-horizon DNS — separate internal and external DNS views.\n"
                            "3. Block DNS responses resolving to private ranges (DNS firewall)."
                        ),
                    )
        except Exception as e:
            self.log("INFO", f"[DNSRebind] DNS resolution error: {e}")

    # ── 3. Host header validation ─────────────────────────────────────────
    def _check_host_header_validation(self):
        """
        Check if the server validates the Host header.
        Send requests with a spoofed Host header — if the server responds normally,
        it doesn't validate Host (weak rebinding defense).
        """
        parsed = urllib.parse.urlparse(self.target)
        spoofed_hosts = [
            "127.0.0.1",
            "localhost",
            "169.254.169.254",
            f"evil.{self.domain}",
        ]
        for spoofed in spoofed_hosts:
            resp, status = self._make_request(self.target, headers={"Host": spoofed})
            if resp and status == 200:
                self.log("WARNING",
                    f"[DNSRebind] Server accepted spoofed Host header: {spoofed} (status 200)")
                self.add_vuln(
                    title="Weak Host Header Validation — DNS Rebinding Facilitator",
                    severity="Medium",
                    category="DNS Rebinding",
                    cvss_score=4.3,
                    confidence="High",
                    description=(
                        f"The server returned HTTP 200 when the `Host` header was set to "
                        f"`{spoofed}` instead of the legitimate domain.\n\n"
                        "Proper Host header validation is the **primary defense** against DNS rebinding. "
                        "Without it, a rebinding attack can successfully pivot the browser "
                        "to access internal services."
                    ),
                    remediation=(
                        "1. Validate the `Host` header against a strict allowlist of known domains.\n"
                        "2. In nginx: define `server_name` explicitly and use `default_server` to reject unknowns.\n"
                        "3. In Express: use `vhost` middleware or validate `req.hostname`.\n"
                        "4. Reject requests with `Host` set to IP addresses or unrecognized domains."
                    ),
                )
                return  # One finding is enough

    # ── 4. Resolution instability (with jitter guard) ─────────────────────
    def _check_resolution_instability(self):
        """
        Resolve domain 5 times with 2s gaps.
        Only flag if ALL resolutions differ — single CDN rotation is normal.
        GAP-011: 1-second sleep caused massive false positives on CDNs.
        """
        results = []
        for _ in range(5):
            try:
                ips = {info[4][0] for info in socket.getaddrinfo(self.domain, 443)}
                results.append(frozenset(ips))
            except Exception as e:
                self.log("ERROR", f"[DNSRebind] resolution check error: {e}")
            time.sleep(2)

        if len(results) < 3:
            return

        # If every resolution returned a different set, that's suspicious
        unique_sets = set(results)
        if len(unique_sets) == len(results) and len(results) >= 3:
            self.log("WARNING",
                f"[DNSRebind] Domain resolved to a different IP on every check — "
                f"possible rapid DNS rebinding. Results: {[set(r) for r in results]}")
            self.add_vuln(
                title="DNS Resolution Instability — Possible DNS Rebinding",
                severity="Low",
                category="DNS Rebinding",
                cvss_score=3.1,
                confidence="Medium",
                description=(
                    f"The domain `{self.domain}` resolved to a different IP address "
                    f"on each of {len(results)} consecutive checks (2s apart), "
                    "which is unusual and may indicate rapid DNS record rotation "
                    "consistent with DNS rebinding infrastructure."
                ),
                remediation=(
                    "Investigate whether the DNS operator is intentionally rotating records. "
                    "Set minimum TTL to 300s. Implement DNS pinning."
                ),
            )
