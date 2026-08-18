"""
nikto_scanner.py
----------------
Integration wrapper for Nikto scanner. 
Attempts to run the official perl-based Nikto scanner via subprocess if available.
Otherwise, runs a high-fidelity Python-based CGI, backup, and admin panel scanner
as fallback heuristics.
"""
import subprocess
import shutil
import os
import requests
import urllib.parse
import urllib3
from scanners.base_scanner import BaseScanner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# High-fidelity list of paths mimicking common Nikto test findings
NIKTO_FALLBACK_CHECKS = [
    # 1. CGI Scripts / Vulnerable paths
    {
        "path": "/cgi-bin/test.cgi",
        "indicator": "test",
        "title": "Exposed test CGI script",
        "severity": "Medium",
        "cvss": 5.0,
        "category": "CGI Scanning",
        "description": "A test CGI script was found exposed in `/cgi-bin/test.cgi`. Attackers can use test scripts to disclose system environment details or exploit poorly written bash execution.",
        "remediation": "Delete all test CGI scripts from production directories."
    },
    {
        "path": "/cgi-bin/printenv",
        "indicator": "HTTP_USER_AGENT",
        "title": "Exposed printenv CGI script",
        "severity": "Medium",
        "cvss": 5.3,
        "category": "Information Disclosure",
        "description": "The `printenv` script was found exposed. It displays all server environment variables, which can disclose path layouts, system credentials, or internal configuration.",
        "remediation": "Remove or restrict access to `/cgi-bin/printenv`."
    },
    
    # 2. Exposed Admin Consoles / Management Interfaces
    {
        "path": "/phpmyadmin/",
        "indicator": "db_details",
        "title": "Exposed phpMyAdmin Interface",
        "severity": "High",
        "cvss": 7.5,
        "category": "Information Disclosure",
        "description": "An exposed phpMyAdmin installation was found. This tool allows direct MySQL database administration. If weak credentials are used, attackers can compromise the entire database.",
        "remediation": "Restrict access to phpMyAdmin by IP address, require multi-factor authentication, or disable public access."
    },
    {
        "path": "/wp-login.php",
        "indicator": "user_login",
        "title": "Exposed WordPress Login Panel",
        "severity": "Low",
        "cvss": 3.0,
        "category": "Administrative Interface",
        "description": "WordPress login interface `/wp-login.php` was detected. This allows brute-force attacks against administrator accounts.",
        "remediation": "Protect login endpoints with rate limiting, CAPTCHAs, or IP-based access controls."
    },
    {
        "path": "/admin/",
        "indicator": "login",
        "title": "Exposed Admin Portal",
        "severity": "Medium",
        "cvss": 4.0,
        "category": "Administrative Interface",
        "description": "An administrative login interface was located at `/admin/`.",
        "remediation": "Apply strong passwords, multi-factor authentication, and IP restricts."
    },
    {
        "path": "/manager/html",
        "indicator": "Tomcat",
        "title": "Exposed Apache Tomcat Manager Interface",
        "severity": "High",
        "cvss": 8.0,
        "category": "Administrative Interface",
        "description": "An exposed Apache Tomcat manager console was found. If accessed with default credentials (e.g., admin/admin), attackers can upload custom WAR files to execute code.",
        "remediation": "Restrict access to Tomcat Manager and ensure strong credentials are configured."
    },

    # 3. Sensitive / Backup Files
    {
        "path": "/.env",
        "indicator": "DB_PASSWORD",
        "title": "Exposed Environment File (.env)",
        "severity": "Critical",
        "cvss": 10.0,
        "category": "Information Disclosure",
        "description": "The application's `.env` configuration file is publicly accessible. This file typically contains database credentials, API keys, mail server logins, and encryption secrets.",
        "remediation": "Configure your web server to deny access to all hidden files. Move the `.env` file outside the public HTML directory."
    },
    {
        "path": "/.git/config",
        "indicator": "[core]",
        "title": "Exposed Git Repository",
        "severity": "Critical",
        "cvss": 9.8,
        "category": "Information Disclosure",
        "description": "The server exposes the Git source control directory. Attackers can reconstruct the application's source code, exposing proprietary logic and embedded credentials.",
        "remediation": "Deny all HTTP requests targeting the `/.git` directory."
    },
    {
        "path": "/config.json",
        "indicator": "database",
        "title": "Exposed Configuration File (config.json)",
        "severity": "High",
        "cvss": 7.5,
        "category": "Information Disclosure",
        "description": "A `config.json` file containing sensitive settings or parameters was found publicly readable.",
        "remediation": "Restrict access to configuration files or store secrets in the environment."
    },
    {
        "path": "/backup.zip",
        "indicator": "PK\x03\x04",
        "title": "Exposed Backup Archive",
        "severity": "High",
        "cvss": 7.5,
        "category": "Information Disclosure",
        "description": "A backup archive file `/backup.zip` was detected, which could contain system source files, logs, or databases.",
        "remediation": "Remove backup files from the web root immediately."
    },
    {
        "path": "/db.sqlite",
        "indicator": "SQLite format 3",
        "title": "Exposed SQLite Database File",
        "severity": "High",
        "cvss": 8.0,
        "category": "Information Disclosure",
        "description": "An exposed SQLite database file `/db.sqlite` was found, exposing the application database directly.",
        "remediation": "Move database files outside of the public web root directory."
    },

    # 4. Info Disclosure / Info leak pages
    {
        "path": "/phpinfo.php",
        "indicator": "phpinfo()",
        "title": "Exposed PHP Info Page",
        "severity": "Medium",
        "cvss": 5.0,
        "category": "Information Disclosure",
        "description": "The PHP configuration info page `/phpinfo.php` is exposed, revealing server paths, OS version, PHP compilation settings, and loaded extensions.",
        "remediation": "Remove the `phpinfo.php` file from production servers."
    },
    {
        "path": "/info.php",
        "indicator": "PHP Version",
        "title": "Exposed PHP Info Page (Alternative path)",
        "severity": "Medium",
        "cvss": 5.0,
        "category": "Information Disclosure",
        "description": "PHP configuration details were found exposed via `/info.php`.",
        "remediation": "Remove the `info.php` file."
    },
    {
        "path": "/server-status",
        "indicator": "Apache Server Status",
        "title": "Exposed Apache Server Status",
        "severity": "Medium",
        "cvss": 5.0,
        "category": "Information Disclosure",
        "description": "The Apache mod_status page `/server-status` is open, exposing active client IPs, requested paths, and CPU usage details.",
        "remediation": "Disable mod_status or restrict access to localhost only."
    }
]

class NiktoScanner(BaseScanner):
    SCANNER_NAME = "Nikto Web Vulnerability Scanner"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self.timeout = kwargs.get("timeout", 12)  # FIX: 5s was too short for slow/filtered hosts
        self.headers = {"User-Agent": "LarShield/2.0 NiktoScanner"}
        if self.auth_headers:
            self.headers.update(self.auth_headers)

    def run(self):
        self.log("INFO", f"[Nikto] Starting Nikto security assessment on {self.target}...")

        # 1. Attempt to find nikto binary or perl launcher
        nikto_bin = shutil.which("nikto") or shutil.which("nikto.pl")
        
        if nikto_bin:
            self.log("INFO", f"[Nikto] Found local Nikto installation at {nikto_bin}")
            self._run_native_nikto(nikto_bin)
        else:
            self.log("WARNING", "[Nikto] Native Nikto / Perl binary was not found in PATH.")
            self.log("INFO", "[Nikto] Running Python CGI & path audit heuristics (Fallback Mode).")
            self._run_fallback_heuristics()

        self.log("SUCCESS", f"[Nikto] Security assessment complete. {len(self.vulns)} issue(s) detected.")
        return self.vulns

    def _run_native_nikto(self, bin_path):
        """Runs the native perl/executable Nikto using subprocess."""
        try:
            # Output in CSV or JSON format if supported
            temp_output = f"nikto_out_{self.scan_id}.json"
            
            cmd = [
                bin_path,
                "-h", self.target,
                "-Format", "json",
                "-o", temp_output,
                "-Display", "D"
            ]
            
            self.log("INFO", f"[Nikto] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if os.path.exists(temp_output):
                import json
                with open(temp_output, 'r') as f:
                    data = json.load(f)
                    # Process findings...
                    for item in data.get("vulnerabilities", []):
                        title = item.get("msg", "Nikto Alert")
                        severity = "Medium" # Default mapping
                        self.add_vuln(
                            title=f"Nikto: {title}",
                            severity=severity,
                            category="Vulnerable Resource",
                            cvss_score=6.0,
                            description=f"Path: {item.get('url', '')}\nMethod: {item.get('method', 'GET')}\n\nDescription: {title}",
                            remediation="Please patch or disable the affected resource/service."
                        )
                try:
                    os.remove(temp_output)
                except Exception as e:
                    self.log("ERROR", f"[Nikto] Failed to remove temp file: {e}")
            else:
                # Fallback if JSON output not generated: parse stdout text
                self.log("INFO", "[Nikto] Parsing stdout raw output...")
                for line in result.stdout.splitlines():
                    if "+ " in line:
                        finding = line.replace("+ ", "").strip()
                        self.add_vuln(
                            title="Nikto Alert",
                            severity="Medium",
                            category="Information Disclosure",
                            cvss_score=5.0,
                            description=finding,
                            remediation="Verify finding validity and patch the web server configuration."
                        )
        except Exception as e:
            self.log("WARNING", f"[Nikto] Subprocess execution failed: {e}. Falling back to heuristics.")
            self._run_fallback_heuristics()

    def _run_fallback_heuristics(self):
        """Simulates Nikto's signature-based CGI and sensitive file detection."""
        base_url = self.target.rstrip("/")
        
        for check in NIKTO_FALLBACK_CHECKS:
            target_url = base_url + check["path"]
            try:
                self.log("INFO", f"[Nikto] Probing: {check['path']}")
                response = requests.get(
                    target_url, 
                    headers=self.headers, 
                    timeout=self.timeout, 
                    verify=False,
                    allow_redirects=False # Prevent redirection to landing/home page from masking 404s
                )
                
                # Verify status code 200 (or sometimes 403 if it requires auth but indicates resource exists)
                if response.status_code == 200:
                    body = response.text
                    indicator = check["indicator"]
                    
                    # If check indicator matches (or is empty to indicate status check only)
                    if not indicator or indicator in body:
                        self.log("CRITICAL" if check["severity"] in ("High", "Critical") else "WARNING", 
                                 f"[Nikto] DETECTED: {check['title']} at {check['path']}")
                        
                        self.add_vuln(
                            title=f"Nikto Fallback: {check['title']}",
                            severity=check["severity"],
                            category=check["category"],
                            cvss_score=check["cvss"],
                            description=f"{check['description']}\n\nURL Tested: {target_url}",
                            remediation=check["remediation"]
                        )
            except Exception as e:
                self.log("ERROR", f"[Nikto] Fallback check error: {e}")
                continue

if __name__ == "__main__":
    from scanners.nikto_scanner import NiktoScanner
    
    print("=== Running direct test of NiktoScanner (Fallback Mode) ===")
    scanner = NiktoScanner(
        scan_id="direct-test-nikto",
        target="http://httpbin.org",
        domain="httpbin.org"
    )
    
    # Custom logger for console output
    def console_log(level, msg):
        print(f"[{level}] {msg}")
    scanner.log = console_log
    
    findings = scanner.run()
    print("\n=== Scan Complete ===")
    print(f"Vulnerabilities found: {len(findings)}")
    for vuln in findings:
        print(f" - [{vuln['severity']}] {vuln['title']}")
