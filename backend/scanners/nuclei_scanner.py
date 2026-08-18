"""
nuclei_scanner.py — ProjectDiscovery Nuclei v3 Integration
===========================================================
Runs Nuclei v3 with local templates bundled in Tools/nuclei-templates/.
Falls back to Python heuristics if binary is absent.

FIXES (July 2026):
  - Use -t flag to point to bundled templates dir (avoids internet update on every scan)
  - Remove broken -update-templates flag (v3 API changed)
  - Add -duc flag to disable auto-update checks (silent mode)
  - Add -timeout flag per-request
  - Capture stderr for better error reporting
  - Show Nuclei version in log
"""
import subprocess
import json
import os
import shutil
from scanners.base_scanner import BaseScanner

# Severity → CVSS fallback mapping
SEVERITY_CVSS = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.3,
    "low":      3.1,
    "info":     1.0,
    "unknown":  5.0,
}

class NucleiScanner(BaseScanner):
    SCANNER_NAME = "ProjectDiscovery Nuclei (Advanced Template Scanner)"
    _SCANNER_KEY = "nuclei"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self.severity = kwargs.get("severity", "critical,high,medium")

    def _find_nuclei(self):
        """Find nuclei binary — prefers bundled Tools/nuclei.exe."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        local_nuclei = os.path.join(project_root, "Tools", "nuclei.exe")
        if os.path.exists(local_nuclei):
            return local_nuclei
        return shutil.which("nuclei") or shutil.which("nuclei.exe")

    def _find_templates_dir(self):
        """Find bundled nuclei-templates directory."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        local_templates = os.path.join(project_root, "Tools", "nuclei-templates")
        if os.path.isdir(local_templates):
            return local_templates
        # Fallback to default nuclei templates path
        appdata = os.environ.get("APPDATA", "")
        default = os.path.join(appdata, "nuclei", "templates")
        if os.path.isdir(default):
            return default
        return None

    def run(self):
        self.log("INFO", f"[Nuclei] Initializing Nuclei v3 scanning on {self.target}...")

        nuclei_path = self._find_nuclei()

        if not nuclei_path:
            self.log("WARNING", "[Nuclei] nuclei binary not found in Tools/ or PATH. Running fallback heuristics.")
            self._fallback_heuristics()
            return self.vulns

        templates_dir = self._find_templates_dir()
        if not templates_dir:
            self.log("WARNING", "[Nuclei] nuclei-templates directory not found. Running fallback heuristics.")
            self._fallback_heuristics()
            return self.vulns

        self.log("INFO", f"[Nuclei] Binary: {nuclei_path}")
        self.log("INFO", f"[Nuclei] Templates: {templates_dir}")
        self.log("INFO", f"[Nuclei] Severity filter: {self.severity}")

        try:
            # Build Nuclei v3 command
            # -duc = disable update check (no internet required)
            # -t   = point to local templates dir
            # -rl  = rate limit (requests/sec) to avoid overwhelming target
            # -timeout = per-request timeout in seconds
            cmd = [
                nuclei_path,
                "-u",        self.target,
                "-severity", self.severity,
                "-t",        templates_dir,
                "-jsonl",                    # JSONL output (one JSON per line)
                "-silent",                   # suppress banner
                "-duc",                      # disable update check
                "-timeout",  "10",           # 10s per-request timeout
                "-rl",       "20",           # max 20 req/s rate limit
                "-c",        "10",           # 10 concurrent templates
                "-no-interactsh",            # disable OOB interactsh (avoids external calls)
            ]

            self.log("INFO", f"[Nuclei] Executing: nuclei -u {self.target} -severity {self.severity}")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            findings_count = 0
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    name          = info.get("name", "Unknown Nuclei Finding")
                    sev_raw       = info.get("severity", "medium").lower()
                    severity_str  = sev_raw.capitalize()
                    desc          = info.get("description", "No description provided by template.")
                    remediation   = info.get("remediation", "Review the affected endpoint and apply the recommended patch.")
                    matched_at    = data.get("matched-at", self.target)
                    template_id   = data.get("template-id", "")
                    cvss_raw      = info.get("classification", {}).get("cvss-score") or 0.0

                    # Use template CVSS if present, fallback by severity
                    cvss = float(cvss_raw) if cvss_raw else SEVERITY_CVSS.get(sev_raw, 5.0)

                    cwe_list  = info.get("classification", {}).get("cwe-id", []) or []
                    cve_list  = info.get("classification", {}).get("cve-id", []) or []
                    refs_list = info.get("reference", []) or []

                    log_level = "CRITICAL" if sev_raw in ("critical",) else "WARNING"
                    self.log(log_level, f"[Nuclei] [{severity_str.upper()}] {name} — {matched_at[:80]}")
                    findings_count += 1

                    self.add_vuln(
                        title=f"Nuclei: {name}",
                        severity=severity_str,
                        category="Nuclei Template Match",
                        cvss_score=cvss,
                        description=(
                            f"{desc}\n\n"
                            f"**Matched at:** `{matched_at}`\n"
                            f"**Template:** `{template_id}`"
                        ),
                        remediation=remediation or "Apply the recommended patch for this vulnerability.",
                        evidence=f"Template: {template_id}, Matched: {matched_at}",
                        payload=data.get("matched-at", ""),
                        cwe_ids=cwe_list,
                        cve_ids=cve_list,
                        references=refs_list[:5],
                        confidence="High",
                    )
                except (json.JSONDecodeError, ValueError, KeyError):
                    pass  # Non-JSON lines (e.g. progress info) — skip

            # Wait for process to finish
            try:
                _, stderr = process.communicate(timeout=600)
                if stderr:
                    for err_line in stderr.splitlines():
                        if err_line.strip() and "[ERR]" in err_line:
                            self.log("WARNING", f"[Nuclei] {err_line.strip()}")
            except subprocess.TimeoutExpired:
                process.kill()
                self.log("WARNING", "[Nuclei] Scan timed out after 10 minutes. Partial results collected.")

            self.log(
                "SUCCESS" if findings_count == 0 else "WARNING",
                f"[Nuclei] Scan complete. {findings_count} finding(s) detected.",
            )

        except FileNotFoundError:
            self.log("WARNING", f"[Nuclei] Binary not executable: {nuclei_path}. Running fallback.")
            self._fallback_heuristics()
        except Exception as e:
            self.log("WARNING", f"[Nuclei] Execution error: {e}. Running fallback.")
            self._fallback_heuristics()

        return self.vulns

    def _fallback_heuristics(self):
        """High-signal heuristic checks when Nuclei binary is unavailable."""
        self.log("INFO", "[Nuclei-Fallback] Running Python-based heuristic checks...")

        checks = [
            # (path, indicator_string, title, severity, cvss, desc, remediation)
            (
                "/.git/config",
                "[core]",
                "Exposed Git Repository (.git/config)",
                "Critical", 9.8,
                "The server exposes its .git directory. Attackers can reconstruct the entire source code, "
                "including embedded credentials, API keys, and application secrets.",
                "Configure web server to deny all requests to hidden directories. "
                "Add `Deny from all` in Apache or `location ~ /\\. { deny all; }` in Nginx.",
            ),
            (
                "/.env",
                "=",
                "Exposed .env Environment File",
                "Critical", 10.0,
                "The .env configuration file is publicly accessible. It typically contains database passwords, "
                "API keys, mail credentials, and encryption secrets — total infrastructure compromise risk.",
                "Move the .env file outside the public web root. Block access to dotfiles in web server config.",
            ),
            (
                "/phpinfo.php",
                "phpinfo()",
                "Exposed PHP Info Page",
                "Medium", 5.3,
                "phpinfo() reveals PHP version, loaded extensions, server paths, and compile-time settings. "
                "This information assists attackers in crafting targeted exploits.",
                "Delete phpinfo.php from production. Never deploy debug scripts to production servers.",
            ),
            (
                "/backup.zip",
                None,
                "Exposed Backup Archive",
                "High", 7.5,
                "A backup archive is publicly accessible, potentially containing source code, databases, and credentials.",
                "Remove all backup files from the web root. Store backups outside the document root.",
            ),
            (
                "/.DS_Store",
                None,
                "Exposed macOS .DS_Store File",
                "Low", 3.1,
                ".DS_Store files reveal directory structure and file names of the development machine.",
                "Add .DS_Store to .gitignore and configure web server to deny access to hidden files.",
            ),
        ]

        for path, indicator, title, severity, cvss, desc, remediation in checks:
            url = f"{self.target.rstrip('/')}{path}"
            try:
                body, status = self._make_request(url, timeout=8)
                if status == 200 and body:
                    if indicator is None or indicator in body:
                        self.log("WARNING", f"[Nuclei-Fallback] DETECTED: {title} at {path}")
                        self.add_vuln(
                            title=f"Nuclei-Fallback: {title}",
                            severity=severity,
                            category="Sensitive File Exposure",
                            cvss_score=cvss,
                            description=f"{desc}\n\nDetected at: `{url}`",
                            remediation=remediation,
                            evidence=f"HTTP 200 from {url}",
                            payload=path,
                            confidence="Confirmed",
                        )
            except Exception as e:
                self.log("ERROR", f"[Nuclei-Fallback] Check error for {path}: {e}")

        self.log("INFO", f"[Nuclei-Fallback] Complete. {len(self.vulns)} finding(s).")
