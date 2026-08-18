"""
swagger_scanner.py — Swagger/OpenAPI Exposure Scanner
======================================================
Expert-grade rewrite (GAP-021 fix):
  1. Discover Swagger/OpenAPI/GraphQL docs at common paths
  2. Check if endpoints require authentication (unauthenticated access = critical)
  3. Parse OpenAPI spec to find endpoints marked security:[] (no auth)
  4. Flag deprecated API versions (/v1 alongside /v3)
  5. Identify internal/admin endpoints in the spec
  6. Check for sensitive info in API descriptions/examples
"""
import json, re, urllib.parse
from scanners.base_scanner import BaseScanner

# Common API documentation paths to probe
API_DOC_PATHS = [
    # Swagger UI
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger",
    "/api/swagger-ui",
    # OpenAPI spec files
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/api/docs",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/api/v3/swagger.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/openapi.json",
    # Redoc
    "/redoc",
    "/docs",
    "/api/redoc",
    # Spring Boot
    "/v2/api-docs",
    "/v3/api-docs",
    # Django DRF
    "/api/schema/",
    "/api/schema/swagger-ui/",
    "/api/schema/redoc/",
    # FastAPI
    "/openapi.json",
    "/docs",
    # Express / Hapi
    "/documentation",
    "/swagger/docs/v1",
]

# Sensitive endpoint patterns in API specs
ADMIN_ENDPOINT_PATTERNS = [
    r"/admin", r"/internal", r"/debug", r"/system",
    r"/management", r"/actuator", r"/_", r"/metrics",
    r"/health", r"/env", r"/config", r"/console",
]

# Sensitive info patterns in spec description/examples
SPEC_SENSITIVE_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS Access Key"),
    (re.compile(r'(sk-[a-zA-Z0-9]{40,})'), "OpenAI Key"),
    (re.compile(r'password.*?[:\s]+["\']([^"\']{6,})["\']', re.I), "Password in example"),
    (re.compile(r'Authorization.*?Bearer\s+([A-Za-z0-9._\-]{20,})'), "Bearer token in example"),
    (re.compile(r'(?:secret|token).*?[:\s]+["\']([A-Za-z0-9._\-]{16,})["\']', re.I), "Secret in example"),
]


class SwaggerScanner(BaseScanner):
    SCANNER_NAME = "Swagger/OpenAPI Exposure Scanner"
    _SCANNER_KEY = "swagger"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[Swagger] Scanning {self.target} for API documentation exposure...")
        parsed = urllib.parse.urlparse(self.target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        found_specs = []

        for path in API_DOC_PATHS:
            url = base + path
            body, status = self._make_request(url)
            if not body or status not in (200, 206):
                continue

            # PHASE 1: Suppress if response is the site's SPA/404 catch-all
            if self._is_baseline(status, body):
                self.log("INFO", f"[Swagger] SUPPRESSED (baseline match): {url}")
                continue

            # Check if it looks like an API doc or spec
            is_ui  = self._is_swagger_ui(body)
            is_spec = self._is_openapi_spec(body)

            if not (is_ui or is_spec):
                continue

            self.log("WARNING", f"[Swagger] API docs found: {url}")

            # Check if accessible without auth (most critical finding)
            self._check_unauthenticated_access(url, path, body, status)

            if is_spec:
                try:
                    spec = json.loads(body)
                except Exception as e:
                    self.log("ERROR", f"[Swagger] JSON parse error: {e}")
                    spec = None

                if spec:
                    found_specs.append((url, spec))
                    self._analyze_spec(url, spec)

        if not self.vulns and not found_specs:
            self.log("SUCCESS", "[Swagger] No exposed API documentation found.")
        elif not self.vulns:
            self.log("INFO", "[Swagger] API docs found but no critical issues detected.")
        return self.vulns

    # ── UI / Spec detection ───────────────────────────────────────────────
    def _is_swagger_ui(self, body: str) -> bool:
        return any(kw in body for kw in [
            "swagger-ui", "SwaggerUI", "Swagger UI", "Redoc",
            "api-docs", "openapi", "ReDoc"
        ])

    def _is_openapi_spec(self, body: str) -> bool:
        body_l = body.strip()
        if body_l.startswith("{"):
            try:
                data = json.loads(body_l)
                return "swagger" in data or "openapi" in data or "paths" in data
            except Exception as e:
                self.log("ERROR", f"[Swagger] _is_openapi_spec error: {e}")
                return False
        if body_l.startswith("swagger:") or body_l.startswith("openapi:"):
            return True
        return False

    # ── Unauthenticated access check ──────────────────────────────────────
    def _check_unauthenticated_access(self, url: str, path: str, body: str, status: int):
        """
        GAP-021 FIX: Check if API docs accessible without auth headers.
        If we got a 200 WITHOUT auth headers, this is the critical finding.
        """
        # Make request without auth headers to confirm unauthenticated access
        import urllib.request, urllib.error
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LarShield/2.0"})
            with urllib.request.urlopen(req, timeout=8, context=self.get_ssl_context()) as r:
                unauth_body = r.read().decode("utf-8", errors="ignore")
                unauth_status = r.status
        except urllib.error.HTTPError as e:
            unauth_status = e.code
            unauth_body = ""
        except Exception as e:
            self.log("ERROR", f"[Swagger] _check_unauthenticated_access error: {e}")
            unauth_status = 0
            unauth_body = ""

        if unauth_status == 200 and self._is_swagger_ui(unauth_body or body):
            self.add_vuln(
                title=f"Unauthenticated API Documentation Exposed — `{path}`",
                severity="High",
                category="Information Disclosure",
                cvss_score=7.5,
                confidence="Confirmed",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-assets-management/",
                ],
                description=(
                    f"**API documentation is accessible without authentication** at `{url}`.\n\n"
                    "Exposed API docs allow attackers to:\n"
                    "- Enumerate all API endpoints, parameters, and data models\n"
                    "- Identify authentication bypass or hidden endpoints\n"
                    "- Understand the API contract to craft targeted attacks\n"
                    "- Find deprecated versions (`/v1`) with weaker security than production"
                ),
                remediation=(
                    "1. Require authentication to access API documentation in production.\n"
                    "2. Disable Swagger UI entirely in production — use it only in development.\n"
                    "3. If needed in production, restrict to internal IPs or VPN users only.\n"
                    "4. Use `@SecurityRequirement` annotations to mark all endpoints as requiring auth."
                ),
                evidence=f"HTTP {unauth_status} returned for {url} without auth headers.",
            )

    # ── Spec analysis ─────────────────────────────────────────────────────
    def _analyze_spec(self, url: str, spec: dict):
        self._check_unauthenticated_endpoints(url, spec)
        self._check_admin_endpoints(url, spec)
        self._check_deprecated_versions(url, spec)
        self._check_sensitive_examples(url, spec)

    def _check_unauthenticated_endpoints(self, url: str, spec: dict):
        """Find endpoints with security: [] (explicitly no auth required)."""
        paths = spec.get("paths", {})
        no_auth_eps = []

        for path_key, path_item in paths.items():
            for method in ["get", "post", "put", "delete", "patch"]:
                op = path_item.get(method, {})
                security = op.get("security", None)
                # security: [] means explicitly no auth
                if security is not None and security == []:
                    no_auth_eps.append(f"{method.upper()} {path_key}")

        if no_auth_eps:
            self.add_vuln(
                title=f"API Endpoints With No Authentication Required ({len(no_auth_eps)} found)",
                severity="High",
                category="Authentication",
                cvss_score=7.5,
                confidence="High",
                description=(
                    f"The OpenAPI spec at `{url}` defines **{len(no_auth_eps)} endpoint(s)** "
                    "with `security: []` (no authentication required):\n\n"
                    + "\n".join(f"- `{ep}`" for ep in no_auth_eps[:15])
                    + ("\n- _(and more...)_" if len(no_auth_eps) > 15 else "")
                ),
                remediation=(
                    "1. Audit each `security: []` endpoint and confirm they should be public.\n"
                    "2. Add appropriate security schemes to endpoints that should be protected.\n"
                    "3. Implement global security requirements in the spec's top-level `security` array."
                ),
            )

    def _check_admin_endpoints(self, url: str, spec: dict):
        """Find internal/admin endpoints exposed in the spec."""
        paths  = list(spec.get("paths", {}).keys())
        found  = [p for p in paths if any(re.search(patt, p, re.I) for patt in ADMIN_ENDPOINT_PATTERNS)]

        if found:
            self.add_vuln(
                title=f"Internal/Admin API Endpoints in Public Spec ({len(found)} found)",
                severity="Medium",
                category="Information Disclosure",
                cvss_score=5.3,
                confidence="High",
                description=(
                    f"The OpenAPI spec exposes **{len(found)} administrative/internal endpoint(s)**:\n\n"
                    + "\n".join(f"- `{p}`" for p in found[:10])
                ),
                remediation=(
                    "1. Remove internal/admin endpoints from public-facing API specs.\n"
                    "2. Maintain separate internal API specs behind authentication.\n"
                    "3. Tag admin endpoints and filter them from public spec generation."
                ),
            )

    def _check_deprecated_versions(self, url: str, spec: dict):
        """Check if older API versions are mentioned."""
        paths = list(spec.get("paths", {}).keys())
        versions = set(re.findall(r'/v(\d+)/', " ".join(paths) + " " + url))
        if len(versions) > 1:
            self.add_vuln(
                title=f"Multiple API Versions Detected in Spec — Deprecated Version Risk",
                severity="Low",
                category="API Security",
                cvss_score=3.1,
                confidence="Medium",
                description=(
                    f"Multiple API versions found: v{', v'.join(sorted(versions))}. "
                    "Deprecated versions often lack the security controls of current versions "
                    "(rate limiting, auth, input validation) and are common targets."
                ),
                remediation=(
                    "1. Decommission deprecated API versions (/v1, /v2 if /v3 is current).\n"
                    "2. Return 410 Gone for all deprecated version endpoints.\n"
                    "3. Redirect clients to the latest API version."
                ),
            )

    def _check_sensitive_examples(self, url: str, spec: dict):
        """Check spec content for credentials in examples."""
        spec_str = json.dumps(spec)
        for pattern, label in SPEC_SENSITIVE_PATTERNS:
            m = pattern.search(spec_str)
            if m:
                self.add_vuln(
                    title=f"Sensitive Data in API Spec Examples — {label}",
                    severity="High",
                    category="Information Disclosure",
                    cvss_score=7.5,
                    confidence="High",
                    description=(
                        f"A **{label}** was found in the API specification at `{url}`.\n\n"
                        "Developers sometimes use real credentials in example requests, "
                        "which are then exposed in public API docs."
                    ),
                    remediation=(
                        "1. Replace all real credentials in spec examples with placeholder values.\n"
                        "2. Rotate any real credentials found immediately.\n"
                        "3. Run secret scanning on your spec files in CI/CD."
                    ),
                )
                break
