"""
git_exposure_scanner.py — Git Repository Exposure Scanner
==========================================================
Checks for publicly accessible .git directories and version control artifacts
that could expose source code, commit history, credentials, and configuration.

Checks:
  - .git/HEAD, .git/config, .git/COMMIT_EDITMSG, .git/index
  - .gitignore, .gitmodules, .gitattributes
  - Common VCS metadata files (SVN, Mercurial)
  - Source code backup files
  - CI/CD configuration leaks
"""
import re, urllib.request, urllib.error
from scanners.base_scanner import BaseScanner
from scanners.core.signatures import matches_signature

# Format: (path, expected_content_regex, display_name, severity, cvss)
GIT_PROBES = [
    ("/.git/HEAD",          r"ref:\s*refs/heads/",   "Git HEAD reference",         "Critical", 9.8),
    ("/.git/config",        r"\[core\]|\[remote",    "Git repository config",      "Critical", 9.8),
    ("/.git/COMMIT_EDITMSG",r".*",                   "Git commit message",         "High",     8.5),
    ("/.git/index",         r"DIRC",                 "Git index (binary)",         "Critical", 9.8),
    ("/.git/FETCH_HEAD",    r".*",                   "Git FETCH_HEAD",             "High",     8.0),
    ("/.git/packed-refs",   r"refs/",                "Git packed refs",            "High",     8.0),
    ("/.git/logs/HEAD",     r"commit|checkout",      "Git reflog",                 "High",     8.0),
    ("/.gitignore",         r".*",                   ".gitignore file",            "Medium",   5.3),
    ("/.gitmodules",        r"\[submodule",          ".gitmodules (submodule list)","High",    7.5),
    ("/.gitattributes",     r".*",                   ".gitattributes",             "Low",      3.1),
    # SVN
    ("/.svn/entries",       r"https?://|svn://",     "SVN entries file",           "High",     8.0),
    ("/.svn/wc.db",         r"SQLite",               "SVN working copy DB",        "Critical", 9.0),
    # Mercurial
    ("/.hg/hgrc",           r"\[paths\]",            "Mercurial config",           "High",     8.0),
    # CI / CD secrets
    ("/.travis.yml",        r"language:|script:",    "Travis CI config",           "Medium",   5.3),
    ("/.env",               r"[A-Z_]+=",             ".env file (env variables)",  "Critical", 9.9),
    ("/.env.local",         r"[A-Z_]+=",             ".env.local file",            "Critical", 9.9),
    ("/.env.production",    r"[A-Z_]+=",             ".env.production file",       "Critical", 9.9),
    ("/Dockerfile",         r"FROM |RUN |CMD ",      "Dockerfile exposed",         "Medium",   5.3),
    ("/docker-compose.yml", r"services:|version:",   "docker-compose config",      "Medium",   5.8),
    ("/Jenkinsfile",        r"pipeline|stage",       "Jenkinsfile exposed",        "Medium",   5.3),
    ("/.github/workflows/", r"on:|jobs:",            "GitHub Actions workflows",   "Low",      3.5),
    # Backup / source files
    ("/backup.sql",         r"INSERT INTO|CREATE TABLE","SQL dump exposed",        "Critical", 9.9),
    ("/dump.sql",           r"INSERT INTO|CREATE TABLE","SQL dump exposed",        "Critical", 9.9),
    ("/config.php.bak",     r".*",                   "PHP config backup",          "High",     8.5),
    ("/wp-config.php.bak",  r".*",                   "WordPress config backup",    "Critical", 9.8),
]


class GitExposureScanner(BaseScanner):
    SCANNER_NAME = "Git / VCS Exposure Scanner"
    _SCANNER_KEY = "git_exposure"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    # ------------------------------------------------------------------
    def run(self) -> list:
        self.log("INFO",
            f"[GitExposure] Probing {len(GIT_PROBES)} VCS/backup paths on {self.target}...")

        base = self.target.rstrip("/")
        found = 0

        for path, pattern, display, severity, cvss in GIT_PROBES:
            url  = f"{base}{path}"
            body, status = self._probe(url)
            if body is None:
                continue

            # PHASE 1: Suppress if response is the site's SPA/404 catch-all
            if self._is_baseline(status, body):
                self.log("INFO", f"[GitExposure] SUPPRESSED (baseline match): {url}")
                continue

            if status == 200 and re.search(pattern, body, re.S | re.I):
                found += 1
                self.log("CRITICAL" if severity == "Critical" else "WARNING",
                    f"[GitExposure] EXPOSED: {display} at {url}")
                masked = body[:300].replace("\n", " ")
                self.add_vuln(
                    title=f"Exposed VCS/Config File: {display}",
                    severity=severity,
                    category="Information Disclosure",
                    cvss_score=cvss,
                    description=(
                        f"The file `{url}` is publicly accessible (HTTP 200).\n\n"
                        f"**Resource type:** {display}\n\n"
                        f"**Preview (first 300 chars):**\n```\n{masked}\n```\n\n"
                        "Exposed version control metadata can reveal:\n"
                        "- Full source code reconstruction from pack files\n"
                        "- Hardcoded credentials and API keys in commit history\n"
                        "- Internal infrastructure hostnames and paths\n"
                        "- Business logic and proprietary algorithms"
                    ),
                    remediation=(
                        f"1. Immediately block access to `{path}` in your web server:\n"
                        "   Nginx:  location ~ /\\.git { deny all; return 404; }\n"
                        "   Apache: RedirectMatch 404 /\\.git\n"
                        "2. Rotate any credentials found in git history immediately.\n"
                        "3. Use `git filter-branch` or BFG Repo Cleaner to purge secrets.\n"
                        "4. Add VCS directories to your web server deny rules globally.\n"
                        "5. Use a WAF rule to block /.git, /.svn, /.env paths."
                    ),
                )
            elif status == 200:
                self.log("INFO", f"[GitExposure] {url} returned 200 but content mismatch")
            else:
                self.log("INFO", f"[GitExposure] {url} -> HTTP {status}")

        if found == 0:
            self.log("SUCCESS", "[GitExposure] No exposed VCS/backup files detected")
        else:
            self.log("WARNING", f"[GitExposure] {found} exposed resource(s) found!")

        return self.vulns

    # ------------------------------------------------------------------
    def _probe(self, url: str) -> tuple:
        try:
            headers = {"User-Agent": "LarShield/2.0 GitExposure-Probe"}
            headers.update(self.auth_headers or {})
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=6, context=self.get_ssl_context()) as r:
                return r.read().decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e:
            return "", e.code
        except Exception as e:
            self.log("ERROR", f"[GitExposure] Fetch error: {e}")
            return None, 0
