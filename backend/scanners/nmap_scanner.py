"""
nmap_scanner.py — Real Nmap port/service scanner using subprocess + XML parsing.
Requires: nmap binary in PATH (https://nmap.org/download.html)
"""
import subprocess, shutil, xml.etree.ElementTree as ET
from scanners.base_scanner import BaseScanner

RISKY_PORTS = {
    21:    ("FTP",          "High",     7.5, "FTP transmits credentials in plaintext. Vulnerable to sniffing and brute-force."),
    23:    ("Telnet",       "Critical", 9.1, "Telnet is unencrypted. All data including credentials sent in cleartext."),
    25:    ("SMTP",         "Medium",   5.3, "Open SMTP relay can be abused for spam and email spoofing."),
    53:    ("DNS",          "Medium",   5.9, "DNS exposed publicly. Risk of amplification/reflection DDoS if misconfigured."),
    110:   ("POP3",         "Medium",   5.0, "POP3 may expose email credentials in cleartext without STARTTLS."),
    445:   ("SMB",          "Critical", 9.8, "SMB exposed. Vulnerable to EternalBlue (MS17-010) and ransomware propagation."),
    1433:  ("MSSQL",        "High",     7.8, "MSSQL port exposed. Risk of brute-force and xp_cmdshell abuse."),
    3306:  ("MySQL",        "High",     7.8, "MySQL exposed to internet. Risk of brute-force and data exfiltration."),
    3389:  ("RDP",          "High",     8.1, "RDP exposed. Vulnerable to brute-force and BlueKeep (CVE-2019-0708)."),
    5432:  ("PostgreSQL",   "High",     7.8, "PostgreSQL publicly accessible. Risk of direct database compromise."),
    5900:  ("VNC",          "High",     8.0, "VNC remote desktop exposed. Often uses weak or no authentication."),
    6379:  ("Redis",        "Critical", 9.8, "Redis has no auth by default. Full data exposure and RCE risk."),
    8080:  ("HTTP-Alt",     "Medium",   5.3, "Alt HTTP port may expose admin panels or staging services."),
    9200:  ("Elasticsearch","Critical", 9.8, "Elasticsearch exposed without auth. Index data publicly readable/writable."),
    27017: ("MongoDB",      "Critical", 9.8, "MongoDB no-auth default. Full database publicly exposed."),
}

class NmapScanner(BaseScanner):
    SCANNER_NAME = "Nmap Port & Service Scanner"

    def __init__(self, scan_id, target, domain, mode="standard", **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self.mode = mode

    def _build_cmd(self):
        base = ["nmap", "-sT", "-oX", "-", "--open"]
        if self.mode == "quick":
            return base + ["-T4", "--top-ports", "100", "-sV", "--version-intensity", "2",
                           "--host-timeout", "30s", "--max-retries", "1", self.domain]
        elif self.mode == "standard":
            return base + ["-T4", "--top-ports", "1000", "-sV", "--version-intensity", "5",
                           "--host-timeout", "120s", self.domain]
        else:  # deep
            return base + ["-T3", "-p-", "-sV", "--script=vuln,banner,http-title",
                           "--script-timeout", "30s", self.domain]

    def run(self):
        self.log("INFO", f"[Nmap] Starting {self.mode.upper()} port scan on {self.domain}...")
        if not shutil.which("nmap"):
            self.log("WARNING", "[Nmap] 'nmap' not found in PATH. Install from https://nmap.org and restart backend.")
            return self.vulns

        cmd = self._build_cmd()
        self.log("DEBUG", f"[Nmap] Command: {' '.join(cmd)}")

        # Aggressive process timeout per mode
        mode_timeouts = {"quick": 45, "standard": 180, "deep": 900}
        timeout = mode_timeouts.get(self.mode, 180)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if not proc.stdout.strip():
                self.log("WARNING", f"[Nmap] No output. Stderr: {proc.stderr[:200] if proc.stderr else 'none'}")
                return self.vulns
            self._parse_xml(proc.stdout)
        except subprocess.TimeoutExpired:
            self.log("WARNING", "[Nmap] Scan timed out — partial results used.")
        except FileNotFoundError:
            self.log("WARNING", "[Nmap] nmap binary missing. Skipping.")
        except Exception as e:
            self.log("WARNING", f"[Nmap] Error: {e}")
        return self.vulns

    def _parse_xml(self, xml_data):
        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError as e:
            self.log("WARNING", f"[Nmap] XML parse error: {e}")
            return

        open_ports = []
        for host in root.findall("host"):
            st = host.find("status")
            if st is None or st.get("state") != "up":
                continue
            addr_el = host.find("address[@addrtype='ipv4']")
            ip = addr_el.get("addr") if addr_el is not None else self.domain
            self.log("SUCCESS", f"[Nmap] Host UP: {ip}")

            ports_el = host.find("ports")
            if ports_el is None:
                self.log("INFO", "[Nmap] No open ports on this host.")
                continue

            for port_el in ports_el.findall("port"):
                port_num = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                svc_el   = port_el.find("service")
                svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                svc_prod = svc_el.get("product", "") if svc_el is not None else ""
                svc_ver  = svc_el.get("version", "") if svc_el is not None else ""
                banner   = f"{svc_prod} {svc_ver}".strip() or svc_name
                open_ports.append(port_num)

                if port_num in RISKY_PORTS:
                    label, severity, cvss, desc = RISKY_PORTS[port_num]
                    lvl = "CRITICAL" if cvss >= 9.0 else "WARNING"
                    self.log(lvl, f"[Nmap] ⚠ Port {port_num}/{protocol} ({label}) OPEN | Banner: {banner} | Risk: {severity}")
                    self.add_vuln(
                        title=f"Exposed Service: Port {port_num} ({label})",
                        severity=severity, category="Port Scan", cvss_score=cvss,
                        description=desc + (f" Detected banner: '{banner}'." if banner != svc_name else ""),
                        remediation=(
                            f"Block port {port_num} at firewall level:\n"
                            f"  UFW: sudo ufw deny {port_num}/tcp\n"
                            f"  iptables: iptables -A INPUT -p tcp --dport {port_num} -j DROP\n"
                            "Place admin services (DB, RDP, VNC) behind a VPN."
                        ),
                    )
                elif port_num in (80, 443):
                    self.log("SUCCESS", f"[Nmap] ✔ Port {port_num}/{protocol} ({svc_name}) OPEN | {banner}")
                else:
                    self.log("WARNING", f"[Nmap] Port {port_num}/{protocol} ({svc_name}) OPEN | {banner} — verify intent.")
                    self.add_vuln(
                        title=f"Unexpected Open Port: {port_num} ({svc_name})",
                        severity="Low", category="Port Scan", cvss_score=3.1,
                        description=f"Port {port_num}/{protocol} ({svc_name}) is publicly reachable. Banner: '{banner}'. Each exposed port increases attack surface.",
                        remediation=f"If port {port_num} is not required externally, block it at the firewall and audit your security group ruleset.",
                    )

                for script in port_el.findall("script"):
                    s_id  = script.get("id", "")
                    s_out = script.get("output", "")
                    if "VULNERABLE" in s_out.upper() or "CVE-" in s_out.upper():
                        self.log("CRITICAL", f"[Nmap NSE] {s_id} on port {port_num}: {s_out[:200]}")
                        self.add_vuln(
                            title=f"NSE Vulnerability: {s_id} (Port {port_num})",
                            severity="High", category="Port Scan", cvss_score=7.5,
                            description=f"Nmap NSE script '{s_id}' detected a vulnerability on port {port_num}. Output: {s_out[:600]}",
                            remediation="Apply vendor security patches for the identified CVE. Remove or restrict the service if not critical.",
                        )

        if not open_ports:
            self.log("INFO", "[Nmap] No open ports detected or host did not respond.")
        else:
            self.log("SUCCESS", f"[Nmap] Scan complete — {len(open_ports)} open port(s): {open_ports}")
