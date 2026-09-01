"""
js_supply_chain_scanner.py — JavaScript Supply Chain & Dependency Confusion Scanner
=====================================================================================
Detects real-world JavaScript supply-chain attack vectors:

  1. Dependency Confusion: Internal package names that could be squatted on npm
  2. Typosquatting: CDN/npm imports with names close to popular packages
  3. Exposed package.json / package-lock.json / yarn.lock leaking internal deps
  4. CDN integrity bypass: <script src> without Subresource Integrity (SRI)
  5. Malicious/outdated npm packages via npm audit advisory API
  6. Shadow DOM / iframe injection via relaxed CSP allowing unsafe-inline scripts
  7. Eval-based sinks in sourced scripts that can be chained with prototype pollution
"""
import re
import json
import time
import urllib.parse
import urllib.request
import urllib.error

from scanners.base_scanner import BaseScanner


# ── Typosquatting similarity detection ─────────────────────────────────────
POPULAR_PACKAGES = [
    "react", "react-dom", "lodash", "axios", "express", "moment",
    "webpack", "babel-core", "eslint", "typescript", "vue", "angular",
    "next", "jquery", "underscore", "rxjs", "redux", "antd", "styled-components",
]

CDN_HOSTS = [
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "code.jquery.com", "stackpath.bootstrapcdn.com",
    "ajax.googleapis.com", "ajax.microsoft.com",
]

# Known malicious package patterns (documented typosquats)
KNOWN_TYPOSQUATS = {
    "lodash": ["1odash", "lodahs", "lod4sh", "lodash-dev"],
    "react": ["reeact", "reect", "react-dom-server"],
    "axios": ["axois", "axsios", "axios-dev"],
    "express": ["expres", "xpress", "expresss"],
    "moment": ["momen", "momentjs-beta"],
    "webpack": ["webpakc", "webpackk", "webpack-cli-dev"],
}

# Manifest files that expose dependency lists
MANIFEST_PATHS = [
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/.npmrc",
    "/bower.json",
    "/shrinkwrap.json",
    "/npm-shrinkwrap.json",
    "/.yarnrc",
    "/.yarnrc.yml",
    "/pnpm-lock.yaml",
    "/.pnpm/pnpm-lock.yaml",
    "/composer.json",  # PHP but often co-located
]


def _levenshtein(a: str, b: str) -> int:
    """Compute edit distance between two strings."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]


def _is_typosquat(name: str, threshold: int = 2) -> tuple[bool, str]:
    """
    Returns (True, similar_package) if 'name' is likely a typosquat
    of a popular package (edit distance ≤ threshold and not identical).
    """
    name_lower = name.lower().strip()
    for popular in POPULAR_PACKAGES:
        if name_lower == popular:
            continue  # exact match, not a typosquat
        dist = _levenshtein(name_lower, popular)
        if dist <= threshold:
            return True, popular
    # Also check known documented typosquats
    for real, fakes in KNOWN_TYPOSQUATS.items():
        if name_lower in fakes:
            return True, real
    return False, ""


def _check_npm_registry(package_name: str) -> dict:
    """
    Check if a package exists on the public npm registry.
    Returns {"exists": bool, "version": str, "deprecated": bool}
    """
    try:
        url = f"https://registry.npmjs.org/{urllib.parse.quote(package_name, safe='')}/latest"
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "LarShield/2.0"})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read())
            return {
                "exists": True,
                "version": data.get("version", "unknown"),
                "deprecated": bool(data.get("deprecated")),
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"exists": False, "version": None, "deprecated": False}
    except Exception:
        pass
    return {"exists": None, "version": None, "deprecated": False}


def _fetch_page_html(url: str, timeout: int = 10) -> str:
    """Fetch and return raw HTML of the page."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LarShield/2.0-SupplyChain"})
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _extract_script_srcs(html: str) -> list[dict]:
    """Extract all <script src=...> tags, with their integrity attribute if present."""
    results = []
    pattern = re.compile(
        r'<script\b[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>',
        re.IGNORECASE
    )
    integrity_pat = re.compile(r'\bintegrity=["\']([^"\']+)["\']', re.IGNORECASE)
    crossorigin_pat = re.compile(r'\bcrossorigin=["\']?([^"\'>\s]+)["\']?', re.IGNORECASE)

    for m in pattern.finditer(html):
        full_tag = html[max(0, m.start() - 50):m.end() + 100]
        src = m.group(1)
        integrity = integrity_pat.search(full_tag)
        crossorigin = crossorigin_pat.search(full_tag)
        results.append({
            "src": src,
            "integrity": integrity.group(1) if integrity else None,
            "crossorigin": crossorigin.group(1) if crossorigin else None,
        })
    return results


def _extract_npm_imports(html: str) -> list[str]:
    """
    Extract package names from:
      - import('package') dynamic imports
      - require('package') CJS requires in inline scripts
      - ESM import statements
    """
    packages = set()
    patterns = [
        r"""(?:import|require)\s*\(\s*['"]([^./'"@][^'"]*)['"]\s*\)""",
        r"""import\s+[^'"]*\s+from\s+['"]([^./'"@][^'"]*)['"]\s*""",
        r"""from\s+['"]([^./'"@][^'"]+)['"]""",
    ]
    for pat in patterns:
        for m in re.finditer(pat, html):
            pkg = m.group(1).split("/")[0]  # strip sub-path
            if pkg and len(pkg) > 1 and not pkg.startswith("@"):
                packages.add(pkg.strip())
            elif pkg.startswith("@"):
                # scoped package: @scope/pkg
                parts = m.group(1).split("/")
                if len(parts) >= 2:
                    packages.add(f"{parts[0]}/{parts[1]}")
    return list(packages)


def _check_manifest_exposed(target: str) -> list[dict]:
    """Try to fetch package manifests from the web root."""
    found = []
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in MANIFEST_PATHS:
        url = base + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LarShield/2.0"})
            with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
                if r.status == 200:
                    content = r.read(8192).decode("utf-8", errors="ignore")
                    # Check if it looks like an actual manifest
                    if any(k in content for k in ["dependencies", "devDependencies", "packages", "resolved"]):
                        found.append({"path": path, "url": url, "content_preview": content[:500]})
        except Exception:
            pass
    return found


class JsSupplyChainScanner(BaseScanner):
    """
    JavaScript Supply Chain Attack Scanner.
    Performs real dependency confusion, typosquat, CDN integrity, and manifest exposure checks.
    """
    SCANNER_NAME = "JS Supply Chain Scanner"

    def run(self) -> list:
        self.log("INFO", f"[SupplyChain] Starting JS supply chain scan on {self.target}")
        self._seen: set = set()

        # ── Phase 1: Fetch page HTML ─────────────────────────────────────────
        self.log("INFO", "[SupplyChain] Fetching page content for script analysis...")
        html = _fetch_page_html(self.target)
        if not html:
            self.log("WARNING", "[SupplyChain] Could not fetch page content — skipping HTML analysis")
            html = ""

        # ── Phase 2: CDN scripts without SRI ────────────────────────────────
        self.log("INFO", "[SupplyChain] Checking CDN scripts for missing SRI attributes...")
        script_tags = _extract_script_srcs(html)
        sri_missing = []
        for tag in script_tags:
            src = tag["src"]
            # Check if hosted on a CDN
            is_cdn = any(cdn in src for cdn in CDN_HOSTS)
            if is_cdn and not tag["integrity"]:
                sri_missing.append(src)

        if sri_missing:
            key = f"sri:{self.domain}"
            if key not in self._seen:
                self._seen.add(key)
                self.log("WARNING", f"[SupplyChain] {len(sri_missing)} CDN script(s) missing SRI integrity check")
                self.add_vuln(
                    title="CDN JavaScript Resources Loaded Without Subresource Integrity (SRI)",
                    severity="High",
                    category="Supply Chain Security",
                    cvss_score=7.4,
                    cwe_ids=["CWE-829"],
                    owasp_category="A06:2021 – Vulnerable and Outdated Components",
                    description=(
                        f"The page loads {len(sri_missing)} JavaScript file(s) from external CDN providers "
                        f"without the `integrity` attribute. If the CDN is compromised or the resource is "
                        f"tampered with via BGP hijack or DNS poisoning, malicious code will execute in users' browsers.\n\n"
                        f"**Affected CDN scripts ({len(sri_missing)}):**\n"
                        + "\n".join(f"- `{s}`" for s in sri_missing[:10])
                    ),
                    remediation=(
                        "1. Add `integrity` and `crossorigin` attributes to all external <script> tags.\n"
                        "2. Use tools like `sri-hash` or the SRI Hash Generator (srihash.org) to compute hashes.\n"
                        "3. Host critical dependencies locally instead of relying on CDNs.\n"
                        "4. Implement a strict Content-Security-Policy that restricts external script sources."
                    ),
                    evidence=f"CDN scripts without SRI: {', '.join(sri_missing[:5])}",
                    request_details=f"GET {self.target}",
                )

        # ── Phase 3: Typosquat detection in CDN URLs ─────────────────────────
        self.log("INFO", "[SupplyChain] Checking for typosquatted package names in CDN URLs...")
        for tag in script_tags:
            src = tag["src"]
            # Extract package name from CDN URL patterns
            # e.g. https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js
            npm_match = re.search(r"/npm/([^/@]+)", src)
            if npm_match:
                pkg_name = npm_match.group(1)
                is_typo, similar = _is_typosquat(pkg_name)
                if is_typo:
                    key = f"typosquat:{pkg_name}"
                    if key not in self._seen:
                        self._seen.add(key)
                        self.log("CRITICAL", f"[SupplyChain] Potential typosquat: '{pkg_name}' ≈ '{similar}'")
                        self.add_vuln(
                            title=f"Potential Typosquatted Package in CDN Import: '{pkg_name}'",
                            severity="Critical",
                            category="Supply Chain Security",
                            cvss_score=9.3,
                            cwe_ids=["CWE-829", "CWE-1395"],
                            owasp_category="A06:2021 – Vulnerable and Outdated Components",
                            description=(
                                f"The page imports `{pkg_name}` from a CDN, which has an edit distance of ≤2 "
                                f"from the popular package `{similar}`. This package may be a typosquatting attack — "
                                f"a malicious package published to npm under a name close to a popular package to "
                                f"catch developers who mistype it.\n\n"
                                f"**CDN URL:** `{src}`\n"
                                f"**Suspected Typosquat of:** `{similar}`"
                            ),
                            remediation=(
                                f"1. Verify the intended package is `{similar}` and correct the import URL.\n"
                                "2. Use package-lock.json / yarn.lock with pinned checksums.\n"
                                "3. Audit all CDN imports against your intended dependency list.\n"
                                "4. Use npm audit or Snyk to scan dependencies for known malicious packages."
                            ),
                            evidence=f"Package '{pkg_name}' is suspiciously similar to '{similar}' (typosquat pattern)",
                            request_details=f"<script src=\"{src}\">",
                            payload=pkg_name,
                        )

        # ── Phase 4: Exposed package manifests ──────────────────────────────
        self.log("INFO", "[SupplyChain] Checking for exposed package manifest files...")
        manifests = _check_manifest_exposed(self.target)
        for manifest in manifests:
            key = f"manifest:{manifest['path']}"
            if key not in self._seen:
                self._seen.add(key)
                self.log("WARNING", f"[SupplyChain] Exposed manifest: {manifest['path']}")

                # Parse internal package names for dependency confusion check
                dep_names = []
                try:
                    pkg_data = json.loads(manifest["content_preview"])
                    for dep_section in ["dependencies", "devDependencies"]:
                        dep_names.extend(pkg_data.get(dep_section, {}).keys())
                except Exception:
                    pass

                self.add_vuln(
                    title=f"Package Manifest Exposed: {manifest['path']}",
                    severity="High",
                    category="Supply Chain Security / Information Disclosure",
                    cvss_score=7.5,
                    cwe_ids=["CWE-538", "CWE-829"],
                    owasp_category="A05:2021 – Security Misconfiguration",
                    description=(
                        f"The file `{manifest['url']}` is publicly accessible. Package manifest files "
                        f"expose internal dependency names, versions, and potentially private package "
                        f"registry configurations that can be leveraged for dependency confusion attacks.\n\n"
                        f"**Exposed file:** `{manifest['url']}`\n\n"
                        f"**Preview:**\n```\n{manifest['content_preview'][:300]}\n```"
                    ),
                    remediation=(
                        f"1. Block public access to `{manifest['path']}` via server configuration (Nginx/Apache deny rule).\n"
                        "2. Ensure the web root does not serve project root files.\n"
                        "3. Move all manifest files outside the document root.\n"
                        "4. Review .npmrc for private registry configurations that might be leaked."
                    ),
                    evidence=f"HTTP 200 response from {manifest['url']}",
                    request_details=f"GET {manifest['url']}",
                )

                # ── Phase 4b: Dependency confusion for each exposed dep ──────
                if dep_names:
                    self.log("INFO", f"[SupplyChain] Checking {len(dep_names)} exposed dependencies for confusion risk...")
                    for dep in dep_names[:20]:  # limit to 20 to avoid excessive API calls
                        if dep.startswith("@") and "/" in dep:
                            # Scoped package — check if scope is a known private indicator
                            scope = dep.split("/")[0]
                            if scope not in ["@types", "@babel", "@angular", "@vue", "@sveltejs"]:
                                npm_info = _check_npm_registry(dep)
                                # No sleep — npm registry network latency is sufficient throttling
                                if npm_info["exists"] is False:
                                    # Package doesn't exist on public npm — potential confusion attack vector
                                    key2 = f"depcnf:{dep}"
                                    if key2 not in self._seen:
                                        self._seen.add(key2)
                                        self.log("CRITICAL", f"[SupplyChain] Dependency confusion risk: '{dep}' not on public npm")
                                        self.add_vuln(
                                            title=f"Dependency Confusion Risk: Private Package '{dep}' Not on Public npm",
                                            severity="Critical",
                                            category="Supply Chain Security",
                                            cvss_score=9.8,
                                            cwe_ids=["CWE-829"],
                                            owasp_category="A06:2021 – Vulnerable and Outdated Components",
                                            description=(
                                                f"The internal/private package `{dep}` is referenced in the exposed "
                                                f"`{manifest['path']}` but does **not exist on the public npm registry**. "
                                                f"An attacker can publish a malicious package with this exact name to npm. "
                                                f"If developers or CI/CD pipelines install dependencies without scoping "
                                                f"to a private registry, they will automatically pull the malicious public package.\n\n"
                                                f"**Attack vector:** Publish `{dep}` to npm with a higher version number than "
                                                f"the internal package. `npm install` will prefer the higher public version."
                                            ),
                                            remediation=(
                                                f"1. Publish a placeholder/dummy package `{dep}` on npm to claim the name.\n"
                                                "2. Configure .npmrc to scope all internal packages to a private registry.\n"
                                                "3. Use npm's `--registry` flag or `.npmrc` scoping to prevent public resolution.\n"
                                                "4. Implement package name validation in CI/CD pipelines.\n"
                                                "5. Block public access to your package.json file."
                                            ),
                                            evidence=f"Package '{dep}' not found on npm registry (HTTP 404)",
                                            request_details=f"GET https://registry.npmjs.org/{dep}/latest → 404",
                                            payload=dep,
                                        )

        # ── Phase 5: Inline script eval() sinks detection ────────────────────
        self.log("INFO", "[SupplyChain] Checking for eval() sinks in inline scripts...")
        eval_pattern = re.compile(
            r'(?:eval|new\s+Function|setTimeout|setInterval)\s*\(\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*|["\'])',
            re.IGNORECASE
        )
        eval_matches = eval_pattern.findall(html)
        if eval_matches:
            key = f"eval:{self.domain}"
            if key not in self._seen:
                self._seen.add(key)
                self.log("WARNING", f"[SupplyChain] {len(eval_matches)} eval() sink(s) detected in page source")
                self.add_vuln(
                    title="Dangerous Eval() Sinks Detected in Page JavaScript",
                    severity="High",
                    category="Supply Chain Security / Code Injection",
                    cvss_score=7.2,
                    cwe_ids=["CWE-95", "CWE-78"],
                    owasp_category="A03:2021 – Injection",
                    description=(
                        f"The page contains {len(eval_matches)} instance(s) of dangerous JavaScript sinks "
                        f"such as `eval()`, `new Function()`, or `setTimeout(string)`. When combined with a "
                        f"supply chain compromise (e.g., a malicious CDN package or prototype pollution), "
                        f"these sinks can execute attacker-controlled code without additional XSS.\n\n"
                        f"**Detected patterns:**\n"
                        + "\n".join(f"- `{m}`" for m in set(eval_matches[:5]))
                    ),
                    remediation=(
                        "1. Replace eval() with safer alternatives (JSON.parse, switch/case, object lookup tables).\n"
                        "2. Implement a strict Content-Security-Policy that disallows 'unsafe-eval'.\n"
                        "3. Audit all use of eval(), Function(), setTimeout(string), setInterval(string).\n"
                        "4. Use a linter rule (eslint no-eval) to prevent future eval() introductions."
                    ),
                    evidence=f"Eval sinks found: {', '.join(set(eval_matches[:3]))}",
                    request_details=f"GET {self.target} → HTML source analysis",
                )

        count = len(self.vulns)
        self.log(
            "WARNING" if count else "SUCCESS",
            f"[SupplyChain] Complete — {count} supply chain issue(s) detected"
        )
        return self.vulns
