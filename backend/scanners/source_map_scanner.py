"""
source_map_scanner.py — Source Map Exposure Scanner
====================================================
Expert-grade rewrite (GAP-015 fix):
  1. Discovers .js.map files by checking common JS bundles
  2. Downloads and parses map file content
  3. Extracts and reports: server-side paths, internal package names,
     secret patterns (API keys, tokens, credentials), Git repo URLs
  4. Reports severity based on content sensitivity
  5. Checks /sourceMappingURL= comments in loaded JS files
"""
import re, json, urllib.parse
from scanners.base_scanner import BaseScanner

# Common JS bundle names to probe for source maps
JS_BUNDLE_PATTERNS = [
    "/static/js/main.js",
    "/static/js/app.js",
    "/static/js/bundle.js",
    "/static/js/index.js",
    "/assets/js/app.js",
    "/assets/index.js",
    "/js/app.js",
    "/js/main.js",
    "/dist/bundle.js",
    "/dist/app.js",
    "/build/static/js/main.chunk.js",
    "/build/static/js/2.chunk.js",
    "/app.js",
    "/bundle.js",
    "/main.js",
]

# Regex to find sourceMappingURL in JS
SOURCEMAP_URL_RE = re.compile(
    r'//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)', re.I
)

# Internal path patterns to flag in source map content
SERVER_PATH_PATTERNS = [
    re.compile(r'/(?:home|var|usr|opt|app|srv|root|etc)/[\w/.\-]+'),
    re.compile(r'[A-Z]:\\[\w\\.\-]+'),   # Windows paths
    re.compile(r'/Users/[\w/.\-]+'),      # macOS dev paths
    re.compile(r'C:/[\w/.\-]+'),
]

# Internal package / company-specific patterns
INTERNAL_PKG_RE = re.compile(
    r'["\'](@[a-z0-9_-]+/[a-z0-9_-]+-(?:internal|private|sdk|core|lib)[^"\']*)["\']',
    re.I
)

# Secret patterns to search in decompiled source
SECRET_PATTERNS = [
    (re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.I), "API Key"),
    (re.compile(r'(?:secret|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I), "Secret/Password"),
    (re.compile(r'(AKIA[0-9A-Z]{16})', re.I), "AWS Access Key"),
    (re.compile(r'(sk-[a-zA-Z0-9]{40,})'), "OpenAI API Key"),
    (re.compile(r'(?:token|access_token|auth_token)\s*[=:]\s*["\']([A-Za-z0-9._\-]{20,})["\']', re.I), "Token"),
    (re.compile(r'(?:private[_-]?key|privateKey)\s*[=:]\s*["\']([^"\']{20,})["\']', re.I), "Private Key"),
    (re.compile(r'(ghp_[A-Za-z0-9]{36})'), "GitHub Personal Access Token"),
    (re.compile(r'(xox[baprs]-[A-Za-z0-9\-]{10,})'), "Slack Token"),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "Private Key (PEM)"),
]

# Internal Git repo URL patterns
GIT_REPO_RE = re.compile(
    r'((?:https?://|git@)(?:github\.com|gitlab\.com|bitbucket\.org|'
    r'[a-z0-9\-]+\.internal|[a-z0-9\-]+\.corp|[a-z0-9\-]+\.company)[:/][^\s"\'<>]+)',
    re.I
)


class SourceMapScanner(BaseScanner):
    SCANNER_NAME = "Source Map Exposure Scanner"
    _SCANNER_KEY = "source_map"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[SourceMap] Scanning for exposed source maps on {self.target}...")
        parsed = urllib.parse.urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Fetch page and look for <script src> tags and sourceMappingURL
        self._scan_page_for_maps(base)

        # 2. Probe common bundle paths for .js.map
        for js_path in JS_BUNDLE_PATTERNS:
            map_url = base + js_path + ".map"
            self._check_map_url(map_url, js_path + ".map")

        if not self.vulns:
            self.log("SUCCESS", "[SourceMap] No exposed source maps found.")
        return self.vulns

    # ── Page scan ─────────────────────────────────────────────────────────
    def _scan_page_for_maps(self, base: str):
        html, status = self._make_request(self.target)
        if not html: return

        # Find all <script src> tags
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        for src in script_srcs[:10]:
            js_url = src if src.startswith("http") else base + src
            # Fetch the JS file and look for sourceMappingURL comment
            js_body, _ = self._make_request(js_url)
            if not js_body: continue

            matches = SOURCEMAP_URL_RE.findall(js_body)
            for map_ref in matches:
                if map_ref.startswith("http"):
                    map_url = map_ref
                else:
                    map_url = js_url.rsplit("/", 1)[0] + "/" + map_ref
                self._check_map_url(map_url, map_ref)

    # ── Check a single map URL ────────────────────────────────────────────
    def _check_map_url(self, map_url: str, label: str):
        body, status = self._make_request(map_url)
        if not body or status not in (200, 206):
            return

        # PHASE 1: Suppress if response is the site's SPA/404 catch-all
        if self._is_baseline(status, body):
            self.log("INFO", f"[SourceMap] SUPPRESSED (baseline match): {map_url}")
            return

        # Verify it's actually a source map (JSON with "sources" key)
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            # Not valid JSON — not a source map
            return

        if "sources" not in data and "mappings" not in data:
            return

        self.log("WARNING", f"[SourceMap] Exposed source map: {map_url}")

        # Analyze content for sensitive information
        sources  = data.get("sources", [])
        content  = body  # Full map content for secret scanning

        findings = []

        # 1. Server-side paths
        for src in sources:
            if not src: continue
            for patt in SERVER_PATH_PATTERNS:
                if patt.search(src):
                    findings.append(f"Server path in sources: `{src}`")
                    break

        # 2. Internal package names
        for match in INTERNAL_PKG_RE.finditer(content):
            findings.append(f"Internal package: `{match.group(1)}`")

        # 3. Secrets in sourcesContent
        for src_content in data.get("sourcesContent", []):
            if not src_content: continue
            for pattern, label_s in SECRET_PATTERNS:
                m = pattern.search(src_content)
                if m:
                    # Mask the value in the log
                    findings.append(f"Potential {label_s} in decompiled source")
                    break

        # 4. Git repo URLs
        for match in GIT_REPO_RE.finditer(content):
            findings.append(f"Git repo URL: `{match.group(1)}`")

        severity    = "High"   if findings else "Medium"
        confidence  = "Confirmed"
        cvss        = 7.5      if findings else 5.3

        finding_text = "\n".join(f"  - {f}" for f in findings[:10]) if findings else \
            "  - No sensitive data detected in map content (exposure risk still exists)"

        self.add_vuln(
            title=f"Source Map Exposed — {label}",
            severity=severity,
            category="Information Disclosure",
            cvss_score=cvss,
            confidence=confidence,
            references=[
                "https://developer.mozilla.org/en-US/docs/Tools/Debugger/How_to/Use_a_source_map",
                "https://owasp.org/www-community/vulnerabilities/Improper_Error_Handling",
            ],
            description=(
                f"JavaScript source map exposed at: `{map_url}`\n\n"
                f"**{len(sources)} source files** decompilable. Sensitive content found:\n"
                f"{finding_text}\n\n"
                "Exposed source maps allow attackers to:\n"
                "- Reconstruct the original application source code\n"
                "- Discover internal paths, infrastructure details, and credentials\n"
                "- Understand business logic to find vulnerabilities faster\n"
                "- Identify internal package names and software stack"
            ),
            remediation=(
                "1. **Remove source maps from production builds** — configure bundler to not output `.map` files.\n"
                "2. If source maps are needed for error tracking: serve them only to authenticated Sentry/Datadog.\n"
                "3. In webpack: set `devtool: false` in production config.\n"
                "4. Restrict `.map` file access at CDN/nginx level: `deny all;` for `*.map` files.\n"
                "5. Rotate any credentials found in source map content immediately."
            ),
            evidence=f"{len(sources)} source files exposed. {len(findings)} sensitive items found.",
        )
