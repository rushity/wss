"""
dependency_scanner.py — JavaScript / Backend Dependency Vulnerability Scanner
==============================================================================
Detects outdated and vulnerable client-side libraries by:
  1. Parsing package.json / composer.json / requirements.txt if exposed
  2. Fingerprinting loaded JS libraries from HTML source (jQuery, React, etc.)
  3. Comparing detected versions against a built-in known-vulnerable version database
  4. Detecting missing Subresource Integrity (SRI) on external scripts
"""
import re, json, urllib.request, urllib.error
from packaging import version as pkg_version
from scanners.base_scanner import BaseScanner

# ── Known-vulnerable version ranges ────────────────────────────────────────
# Format: library_name -> [(max_vulnerable_version, CVE, severity, cvss, description)]
VULN_DB = {
    "jquery": [
        ("1.12.4", "CVE-2015-9251",  "Medium", 6.1, "XSS via jQuery.htmlPrefilter"),
        ("3.4.9",  "CVE-2019-11358", "Medium", 6.1, "Prototype pollution in jQuery.extend"),
        ("3.6.0",  "CVE-2020-23064", "Medium", 6.9, "XSS via HTML parsing"),
    ],
    "bootstrap": [
        ("3.4.1", "CVE-2019-8331",  "Medium", 6.1, "XSS in tooltip/popover data-template"),
        ("4.3.0", "CVE-2018-14042", "Medium", 6.1, "XSS via data-target attribute"),
    ],
    "angularjs": [
        ("1.8.3", "CVE-2022-25869", "Medium", 6.1, "XSS in $sanitize"),
        ("1.6.9", "CVE-2019-14863", "Medium", 6.1, "Angular template injection"),
    ],
    "lodash": [
        ("4.17.20", "CVE-2021-23337", "High", 7.2, "Command injection via template"),
        ("4.17.15", "CVE-2020-28500", "Medium", 5.3, "ReDoS in toNumber"),
        ("4.17.10", "CVE-2019-10744", "Critical", 9.1, "Prototype pollution"),
    ],
    "moment": [
        ("2.29.3", "CVE-2022-24785", "High", 7.5, "Path traversal in locale loading"),
        ("2.29.1", "CVE-2022-31129", "High", 7.5, "ReDoS in string-to-date parsing"),
    ],
    "axios": [
        ("0.21.1", "CVE-2021-3749", "High", 7.5, "Server-side request forgery via SSRF bypass"),
    ],
    "d3": [
        ("5.16.0", "CVE-2021-23490", "Medium", 5.3, "Prototype pollution"),
    ],
    "react": [
        ("16.13.0", "CVE-2018-6341", "Medium", 6.1, "XSS via dangerouslySetInnerHTML"),
    ],
    "vue": [
        ("2.6.14", "CVE-2022-23912", "Medium", 5.3, "ReDoS"),
    ],
}

# JS fingerprint patterns: (regex in src/content, library_name, version_capture_group)
JS_FINGERPRINTS = [
    (re.compile(r'jquery[.-]?(\d+\.\d+\.\d+)', re.I),    "jquery"),
    (re.compile(r'bootstrap[.-]?(\d+\.\d+\.\d+)', re.I), "bootstrap"),
    (re.compile(r'angular[.-]?(\d+\.\d+\.\d+)', re.I),   "angularjs"),
    (re.compile(r'lodash[.-]?(\d+\.\d+\.\d+)', re.I),    "lodash"),
    (re.compile(r'moment[.-]?(\d+\.\d+\.\d+)', re.I),    "moment"),
    (re.compile(r'axios[.-]?(\d+\.\d+\.\d+)', re.I),     "axios"),
    (re.compile(r'react[.-]?(\d+\.\d+\.\d+)', re.I),     "react"),
    (re.compile(r'vue[.-]?(\d+\.\d+\.\d+)', re.I),       "vue"),
    (re.compile(r'd3[.-]?v?(\d+\.\d+\.\d+)', re.I),      "d3"),
]

# Inline version variables: jQuery.fn.jquery, $.fn.jquery, etc.
INLINE_VER_RE = {
    "jquery": re.compile(r'jQuery\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
    "react":  re.compile(r'ReactDOM\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
    "vue":    re.compile(r'Vue\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
}

EXPOSED_MANIFESTS = [
    ("/package.json",       "json", "node"),
    ("/composer.json",      "json", "php"),
    ("/requirements.txt",   "text", "python"),
    ("/Gemfile.lock",       "text", "ruby"),
    ("/go.sum",             "text", "go"),
]


class DependencyScanner(BaseScanner):
    SCANNER_NAME = "Dependency Vulnerability Scanner"
    _SCANNER_KEY = "dependency"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._detected: dict = {}   # library -> version
        self._reported: set  = set()

    # ------------------------------------------------------------------
    def run(self) -> list:
        self.log("INFO", f"[Deps] Starting dependency vulnerability scan on {self.target}...")
        try:
            html, script_urls = self._fetch_page()
            self._fingerprint_from_html(html, script_urls)
            self._check_manifest_exposure()
            self._check_sri(html)
            self._audit_detected()
        except Exception as e:
            self.log("WARNING", f"[Deps] Error: {e}")

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[Deps] Complete. Detected {len(self._detected)} lib(s). "
            f"{len(self.vulns)} issue(s) found.",
        )
        return self.vulns

    # ------------------------------------------------------------------
    def _fetch_page(self) -> tuple:
        req = urllib.request.Request(self.target,
            headers={"User-Agent": "LarShield/2.0 Dep-Scanner"})
        with urllib.request.urlopen(req, timeout=8, context=self.get_ssl_context()) as r:
            html = r.read().decode("utf-8", errors="ignore")
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        return html, scripts

    # ------------------------------------------------------------------
    def _fingerprint_from_html(self, html: str, script_urls: list):
        # Check script src URLs
        all_text = html + "\n" + "\n".join(script_urls)
        for pat, lib in JS_FINGERPRINTS:
            m = pat.search(all_text)
            if m:
                ver = m.group(1)
                if lib not in self._detected:
                    self._detected[lib] = ver
                    self.log("INFO", f"[Deps] Detected: {lib} v{ver}")

        # Check inline version variables in JS content
        for script_url in script_urls[:8]:
            try:
                full_url = self._resolve_url(script_url)
                req = urllib.request.Request(full_url,
                    headers={"User-Agent": "LarShield/2.0 Dep-Scanner"})
                with urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context()) as r:
                    js = r.read().decode("utf-8", errors="ignore")
                for lib, ver_re in INLINE_VER_RE.items():
                    vm = ver_re.search(js)
                    if vm and lib not in self._detected:
                        self._detected[lib] = vm.group(1)
                        self.log("INFO", f"[Deps] Detected (inline): {lib} v{vm.group(1)}")
            except Exception as e:
                self.log("ERROR", f"[Deps] Inline detection error: {e}")
                continue

    # ------------------------------------------------------------------
    def _check_manifest_exposure(self):
        base = self.target.rstrip("/")
        for path, fmt, ecosystem in EXPOSED_MANIFESTS:
            url  = f"{base}{path}"
            body, status = self._probe(url)
            if status == 200 and body:
                self.add_vuln(
                    title=f"Exposed Dependency Manifest: {path}",
                    severity="Medium",
                    category="Information Disclosure",
                    cvss_score=5.3,
                    description=f"The {ecosystem} dependency manifest `{url}` is publicly "
                        "accessible. This reveals the exact library versions in use, "
                        "allowing targeted exploitation of known CVEs.",
                    remediation=f"Block access to `{path}` in your web server config:\n"
                        "Nginx: location = /package.json { deny all; return 404; }",
                )
                # Also parse versions from manifest
                if fmt == "json":
                    try:
                        data = json.loads(body)
                        deps = {**data.get("dependencies",{}), **data.get("devDependencies",{})}
                        for lib, ver_str in deps.items():
                            clean_ver = ver_str.lstrip("^~>=<")
                            lib_key   = lib.lower().split("/")[-1]
                            if lib_key in VULN_DB and lib_key not in self._detected:
                                self._detected[lib_key] = clean_ver
                    except Exception as e:
                        self.log("ERROR", f"[Deps] Manifest JSON parse error: {e}")

    # ------------------------------------------------------------------
    def _check_sri(self, html: str):
        ext_scripts = re.findall(
            r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>', html, re.I)
        missing_sri = [s for s in ext_scripts if "integrity=" not in s.lower()]
        if missing_sri:
            self.add_vuln(
                title=f"Subresource Integrity (SRI) Missing on {len(missing_sri)} External Script(s)",
                severity="Medium",
                category="Supply Chain Security",
                cvss_score=5.9,
                description=f"Found {len(missing_sri)} external `<script>` tag(s) without "
                    "`integrity=` attributes. Without SRI, if the CDN is compromised or the "
                    "file is modified, malicious code executes in users' browsers silently.\n\n"
                    f"Example: `{missing_sri[0][:200]}`",
                remediation="Add integrity and crossorigin attributes to all external scripts:\n"
                    '<script src="https://cdn.example.com/lib.js" '
                    'integrity="sha384-..." crossorigin="anonymous"></script>\n'
                    "Generate SRI hashes at: https://www.srihash.org/",
            )
        else:
            self.log("SUCCESS", "[Deps] All external scripts have SRI attributes")

    # ------------------------------------------------------------------
    def _audit_detected(self):
        for lib, detected_ver in self._detected.items():
            if lib not in VULN_DB:
                continue
            try:
                dv = pkg_version.parse(detected_ver)
            except Exception as e:
                self.log("ERROR", f"[Deps] Version parse error for {lib}: {e}")
                continue

            for max_vuln_ver, cve, severity, cvss, desc in VULN_DB[lib]:
                try:
                    mv = pkg_version.parse(max_vuln_ver)
                except Exception as e:
                    self.log("ERROR", f"[Deps] Version parse error for {max_vuln_ver}: {e}")
                    continue
                key = f"{lib}:{cve}"
                if dv <= mv and key not in self._reported:
                    self._reported.add(key)
                    self.log("WARNING",
                        f"[Deps] VULNERABLE: {lib} v{detected_ver} <= v{max_vuln_ver} ({cve})")
                    self.add_vuln(
                        title=f"Vulnerable Library: {lib} v{detected_ver} ({cve})",
                        severity=severity,
                        category="Vulnerable Dependencies",
                        cvss_score=cvss,
                        description=f"The detected version of **{lib}** (`v{detected_ver}`) "
                            f"is at or below the vulnerable version `v{max_vuln_ver}`.\n\n"
                            f"**CVE:** {cve}\n**Impact:** {desc}\n\n"
                            "An attacker can exploit this known vulnerability via client-side attacks.",
                        remediation=f"Update {lib} to the latest stable version.\n"
                            f"See: https://nvd.nist.gov/vuln/detail/{cve}",
                    )

    # ------------------------------------------------------------------
    def _probe(self, url: str) -> tuple:
        try:
            req = urllib.request.Request(url,
                headers={"User-Agent": "LarShield/2.0 Dep-Scanner"})
            with urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context()) as r:
                return r.read().decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e:
            return "", e.code
        except Exception as e:
            self.log("ERROR", f"[Deps] Probe error: {e}")
            return None, 0

    def _resolve_url(self, src: str) -> str:
        if src.startswith("//"):
            return f"https:{src}"
        if src.startswith("/"):
            return f"{self.target.rstrip('/')}{src}"
        if not src.startswith("http"):
            return f"{self.target.rstrip('/')}/{src}"
        return src
