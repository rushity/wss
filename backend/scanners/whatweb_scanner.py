"""
whatweb_scanner.py — Technology fingerprinting using WhatWeb tool.
Requires: whatweb binary in PATH (https://github.com/urbanadventurer/WhatWeb)
"""
import subprocess, shutil, json
from scanners.base_scanner import BaseScanner

class WhatWebScanner(BaseScanner):
    SCANNER_NAME = "WhatWeb Technology Fingerprinting"

    def run(self):
        self.log("INFO", f"[WhatWeb] Starting technology fingerprinting on {self.domain}...")
        
        if not shutil.which("whatweb"):
            self.log("WARNING", "[WhatWeb] 'whatweb' not found in PATH. Using fallback header/body fingerprinting.")
            self._fallback_fingerprint()
            return self.vulns

        # Build WhatWeb command with JSON output
        cmd = [
            "whatweb",
            "--color=never",
            "--log-json=-",
            "--no-errors",
            self.domain
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if not proc.stdout.strip():
                self.log("WARNING", f"[WhatWeb] No output. Stderr: {proc.stderr[:200] if proc.stderr else 'none'}")
                return self.vulns

            self._parse_json(proc.stdout)

        except subprocess.TimeoutExpired:
            self.log("WARNING", "[WhatWeb] Scan timed out.")
        except FileNotFoundError:
            self.log("WARNING", "[WhatWeb] whatweb binary missing. Skipping.")
        except Exception as e:
            self.log("WARNING", f"[WhatWeb] Error: {e}")

        return self.vulns

    def _parse_json(self, json_data):
        try:
            # WhatWeb JSON output is line-delimited JSON
            technologies = set()
            detected = []
            
            for line in json_data.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    detected.append(data)
                except json.JSONDecodeError:
                    continue

            if not detected:
                self.log("INFO", "[WhatWeb] No technologies detected.")
                return

            for item in detected:
                target = item.get("target", self.domain)
                plugins = item.get("plugins", {})
                
                self.log("INFO", f"[WhatWeb] Target: {target}")
                
                for plugin_name, plugin_data in plugins.items():
                    if isinstance(plugin_data, dict):
                        version = plugin_data.get("version", "")
                        if version:
                            technologies.add(f"{plugin_name} {version}")
                            self.log("SUCCESS", f"[WhatWeb] Detected: {plugin_name} {version}")
                        else:
                            technologies.add(plugin_name)
                            self.log("SUCCESS", f"[WhatWeb] Detected: {plugin_name}")

            if technologies:
                tech_list = ", ".join(sorted(technologies))
                self.log("SUCCESS", f"[WhatWeb] Fingerprint complete. Technologies: {tech_list}")
                
                self.add_vuln(
                    title="Technology Fingerprinting Disclosure",
                    severity="Low", category="Fingerprinting", cvss_score=0.0,
                    description=f"WhatWeb detected the following technologies on {self.domain}: {tech_list}. This information aids attackers in identifying applicable CVEs and attack vectors.",
                    remediation="Minimize information disclosure by removing version numbers from HTTP headers and error pages. Keep all technologies updated to latest stable versions."
                )
            else:
                self.log("INFO", "[WhatWeb] No specific technologies identified.")

        except Exception as e:
            self.log("WARNING", f"[WhatWeb] JSON parse error: {e}")

    def _fallback_fingerprint(self):
        try:
            from utils.fingerprint_db import match_tech
            body, status, headers = self._make_request(self.target, return_response_obj=True)
            if not body and not headers:
                return
            
            headers_dict = {k: v for k, v in headers.items()} if headers else {}
            techs = match_tech(body or "", headers_dict)
            
            if techs:
                tech_names = [f"{t['name']} {t.get('version', '')}".strip() for t in techs]
                tech_list = ", ".join(sorted(set(tech_names)))
                self.log("SUCCESS", f"[WhatWeb Fallback] Technologies: {tech_list}")
                self.add_vuln(
                    title="Technology Fingerprinting Disclosure (Fallback)",
                    severity="Low", category="Fingerprinting", cvss_score=0.0,
                    description=f"Basic fingerprinting detected the following technologies on {self.domain}: {tech_list}. This information aids attackers in identifying applicable CVEs and attack vectors.",
                    remediation="Minimize information disclosure by removing version numbers from HTTP headers and error pages. Keep all technologies updated to latest stable versions."
                )
            else:
                self.log("INFO", "[WhatWeb Fallback] No specific technologies identified.")
        except Exception as e:
            self.log("WARNING", f"[WhatWeb Fallback] Error: {e}")
