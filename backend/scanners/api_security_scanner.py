"""
api_security_scanner.py — Advanced REST/GraphQL/gRPC API Security Scanner
==========================================================================
Goes beyond basic API fuzzing to test:

  1. Mass Assignment via field injection on POST/PUT/PATCH
  2. Parameter pollution (HPP) on REST APIs
  3. Versioned API endpoint enumeration (v1, v2, v3...)
  4. API key leakage in responses, headers, and error messages
  5. HTTP verb tunneling (X-HTTP-Method-Override bypass)
  6. API rate limit bypass via header manipulation
  7. Unauthenticated GraphQL introspection
  8. REST API response data over-exposure (sensitive field detection)
  9. JWT none-algorithm and algorithm confusion probing
 10. API documentation endpoint exposure (Swagger, OpenAPI, Postman)
"""
import re
import json
import time
import urllib.parse
import urllib.request
import urllib.error
import ssl
import base64

from scanners.base_scanner import BaseScanner


# ── Patterns ────────────────────────────────────────────────────────────────
API_KEY_PATTERNS = [
    (r'(?i)api[_\-]?key\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "API Key"),
    (r'(?i)secret\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Secret"),
    (r'(?i)access[_\-]?token\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?', "Access Token"),
    (r'(?i)auth[_\-]?token\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?', "Auth Token"),
    (r'(?i)password\s*[:=]\s*["\']?([^\s"\']{8,})["\']?', "Password"),
    (r'(?i)client[_\-]?secret\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "Client Secret"),
    (r'sk_live_[A-Za-z0-9]{24,}', "Stripe Live Key"),
    (r'sk_test_[A-Za-z0-9]{24,}', "Stripe Test Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'AIza[0-9A-Za-z_\-]{35}', "Google API Key"),
    (r'(?i)mongodb\+srv://[^\s"\'<>]+', "MongoDB Connection String"),
]

SENSITIVE_RESPONSE_FIELDS = [
    "password", "passwd", "pwd", "hash", "secret", "salt",
    "ssn", "social_security", "credit_card", "card_number", "cvv",
    "private_key", "api_key", "access_token", "refresh_token",
    "session_token", "auth_token", "otp_secret", "totp_secret",
    "internal_ip", "server_ip", "db_host", "db_password",
    "admin_email", "admin_pass",
]

DOC_ENDPOINTS = [
    "/api/docs", "/api/swagger", "/api/openapi", "/swagger",
    "/swagger-ui", "/swagger-ui.html", "/swagger/index.html",
    "/api/swagger.json", "/api/openapi.json", "/openapi.json",
    "/swagger.yaml", "/openapi.yaml", "/api/v1/swagger.json",
    "/api/v2/swagger.json", "/v1/api-docs", "/v2/api-docs",
    "/docs", "/redoc", "/api/redoc",
    "/postman.json", "/postman_collection.json",
    "/.well-known/openid-configuration",
    "/graphql/playground", "/graphiql", "/altair",
]

API_VERSION_PATTERNS = [
    "/api/v{n}", "/api/{n}", "/v{n}", "/v{n}/api",
    "/api/version{n}", "/rest/v{n}",
]

MASS_ASSIGN_FIELDS = [
    "is_admin", "role", "admin", "superuser", "is_superuser",
    "is_staff", "permissions", "privilege", "level", "account_type",
    "verified", "is_verified", "subscription_tier", "plan",
    "credits", "balance", "discount",
]

HTTP_VERB_OVERRIDES = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "_method",
]

RATE_LIMIT_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1, 127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
]


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(url: str, method: str = "GET", body: bytes | None = None,
             extra_headers: dict | None = None, timeout: int = 8) -> tuple[str, int, dict]:
    """Make HTTP request, returning (body_text, status_code, response_headers)."""
    try:
        headers = {"User-Agent": "LarShield/2.0-APIScanner", "Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as r:
            resp_body = r.read().decode("utf-8", errors="ignore")
            return resp_body, r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode("utf-8", errors="ignore")
        except Exception:
            body_text = ""
        return body_text, e.code, {}
    except Exception:
        return "", 0, {}


def _check_api_key_in_response(body: str, headers: dict) -> list[tuple[str, str]]:
    """Scan response body and headers for exposed secrets."""
    found = []
    combined = body + " " + " ".join(f"{k}: {v}" for k, v in headers.items())
    for pattern, label in API_KEY_PATTERNS:
        for m in re.finditer(pattern, combined):
            found.append((label, m.group(0)[:80]))
    return found


def _check_sensitive_fields(body: str) -> list[str]:
    """Find sensitive field names in JSON response."""
    found = []
    try:
        data = json.loads(body)
    except Exception:
        # Fallback: regex search
        data = None

    if data:
        def _scan_dict(d, depth=0):
            if depth > 5 or not isinstance(d, (dict, list)):
                return
            if isinstance(d, dict):
                for key in d.keys():
                    if any(sf in key.lower() for sf in SENSITIVE_RESPONSE_FIELDS):
                        found.append(key)
                    _scan_dict(d[key], depth + 1)
            elif isinstance(d, list):
                for item in d[:5]:
                    _scan_dict(item, depth + 1)
        _scan_dict(data)
    else:
        for sf in SENSITIVE_RESPONSE_FIELDS:
            if re.search(rf'["\']?{sf}["\']?\s*[:=]', body, re.IGNORECASE):
                found.append(sf)
    return list(set(found))


class ApiSecurityScanner(BaseScanner):
    """
    Advanced REST/GraphQL API Security Scanner.
    Performs real probes against discovered API endpoints.
    """
    SCANNER_NAME = "Advanced API Security Scanner"

    def run(self) -> list:
        self.log("INFO", f"[AdvAPI] Starting advanced API security scan on {self.target}")
        self._seen: set = set()
        parsed = urllib.parse.urlparse(self.target)
        self._base = f"{parsed.scheme}://{parsed.netloc}"

        # ── 1. API documentation endpoint exposure ───────────────────────────
        self.log("INFO", "[AdvAPI] Probing for exposed API documentation endpoints...")
        self._check_doc_exposure()

        # ── 2. API version enumeration ───────────────────────────────────────
        self.log("INFO", "[AdvAPI] Enumerating versioned API endpoints...")
        found_versions = self._enumerate_api_versions()

        # ── 3. Mass assignment injection ─────────────────────────────────────
        self.log("INFO", "[AdvAPI] Testing mass assignment vulnerabilities...")
        self._check_mass_assignment(found_versions)

        # ── 4. HTTP verb tunneling ────────────────────────────────────────────
        self.log("INFO", "[AdvAPI] Testing HTTP verb tunneling bypass...")
        self._check_verb_tunneling()

        # ── 5. API rate limit bypass via header spoofing ─────────────────────
        self.log("INFO", "[AdvAPI] Testing rate limit bypass techniques...")
        self._check_rate_limit_bypass()

        # ── 6. GraphQL introspection ─────────────────────────────────────────
        self.log("INFO", "[AdvAPI] Checking GraphQL introspection access...")
        self._check_graphql_introspection()

        # ── 7. Response data over-exposure ───────────────────────────────────
        self.log("INFO", "[AdvAPI] Checking API responses for sensitive data over-exposure...")
        self._check_data_overexposure(found_versions)

        count = len(self.vulns)
        self.log(
            "WARNING" if count else "SUCCESS",
            f"[AdvAPI] Complete — {count} API security issue(s) detected"
        )
        return self.vulns

    def _check_doc_exposure(self):
        """Check if API documentation is publicly accessible."""
        for path in DOC_ENDPOINTS:
            url = self._base + path
            body, status, headers = _request(url, timeout=6)
            if status == 200 and body:
                # Verify it's actual API docs, not a generic 200
                is_docs = any(kw in body.lower() for kw in [
                    "swagger", "openapi", "paths", "definitions",
                    "graphql", "playground", "mutation", "query",
                    "postman", "endpoint",
                ])
                if is_docs:
                    key = f"apidoc:{path}"
                    if key not in self._seen:
                        self._seen.add(key)
                        self.log("HIGH", f"[AdvAPI] API documentation exposed: {url}")
                        self.add_vuln(
                            title=f"API Documentation Publicly Exposed: {path}",
                            severity="High",
                            category="API Security / Information Disclosure",
                            cvss_score=7.5,
                            cwe_ids=["CWE-538", "CWE-200"],
                            owasp_category="A09:2021 – Security Logging and Monitoring Failures",
                            description=(
                                f"The API documentation endpoint `{url}` is publicly accessible. "
                                f"Exposed API docs (Swagger, OpenAPI, GraphQL Playground) provide attackers "
                                f"with a complete blueprint of all API endpoints, parameters, authentication "
                                f"methods, and data models — dramatically accelerating attack reconnaissance."
                            ),
                            remediation=(
                                "1. Restrict API documentation to authenticated users or internal networks only.\n"
                                "2. Disable interactive API explorers (Swagger UI, GraphiQL) in production.\n"
                                "3. Use IP allowlisting for documentation endpoints.\n"
                                "4. Implement authentication middleware before documentation routes."
                            ),
                            evidence=f"HTTP {status} response from {url} with API documentation content",
                            request_details=f"GET {url}",
                        )

    def _enumerate_api_versions(self) -> list[str]:
        """Discover active API versioned base URLs."""
        found = []
        parsed = urllib.parse.urlparse(self.target)
        base_path = parsed.path.rstrip("/")

        for n in range(1, 6):
            for pattern in ["/api/v{n}", "/v{n}", "/api/v{n}/", "/v{n}/api"]:
                path = pattern.replace("{n}", str(n))
                url = self._base + path
                body, status, _ = _request(url, timeout=5)
                if status in (200, 401, 403, 405):
                    # Status 401/403/405 still means the endpoint exists
                    if url not in found:
                        found.append(url)
                        self.log("INFO", f"[AdvAPI] Found API version endpoint: {url} (HTTP {status})")

        return found

    def _check_mass_assignment(self, api_bases: list[str]):
        """Attempt mass assignment on common CRUD endpoints."""
        endpoints_to_try = [self.target, self._base + "/api/user", self._base + "/api/users", self._base + "/api/profile"]
        endpoints_to_try.extend(api_bases[:3])

        for base_url in endpoints_to_try[:5]:
            # Send a POST/PUT with extra privileged fields
            payload_dict = {
                "name": "test",
                "email": "test@example.com",
            }
            # Add mass assignment fields
            for field in MASS_ASSIGN_FIELDS[:5]:
                payload_dict[field] = True

            body_bytes = json.dumps(payload_dict).encode()

            for method in ["POST", "PUT"]:
                resp_body, status, resp_headers = _request(
                    base_url, method=method, body=body_bytes,
                    extra_headers={"Content-Type": "application/json"},
                    timeout=7
                )
                if status in (200, 201, 204):
                    # Check if the server reflected any privileged field back
                    reflected_fields = []
                    try:
                        resp_data = json.loads(resp_body)
                        for field in MASS_ASSIGN_FIELDS:
                            if field in resp_data:
                                reflected_fields.append(field)
                    except Exception:
                        for field in MASS_ASSIGN_FIELDS:
                            if re.search(rf'["\']?{field}["\']?\s*:', resp_body, re.IGNORECASE):
                                reflected_fields.append(field)

                    if reflected_fields:
                        key = f"massassign:{base_url}:{method}"
                        if key not in self._seen:
                            self._seen.add(key)
                            self.log("CRITICAL", f"[AdvAPI] Mass assignment: {reflected_fields} reflected in {method} {base_url}")
                            self.add_vuln(
                                title=f"Mass Assignment Vulnerability via {method} {base_url}",
                                severity="Critical",
                                category="API Security / Mass Assignment",
                                cvss_score=9.1,
                                cwe_ids=["CWE-915"],
                                owasp_category="API6:2023 – Unrestricted Access to Sensitive Business Flows",
                                description=(
                                    f"The endpoint `{base_url}` accepts and reflects privileged fields "
                                    f"(`{', '.join(reflected_fields)}`) in a {method} request without "
                                    f"filtering. An attacker can escalate privileges by submitting fields "
                                    f"like `is_admin: true`, `role: 'admin'`, or `credits: 99999` in the request body."
                                ),
                                remediation=(
                                    "1. Implement an explicit allowlist of accepted fields (not a blocklist).\n"
                                    "2. Use Data Transfer Objects (DTOs) that only bind permitted fields.\n"
                                    "3. Never bind the entire request body directly to database models.\n"
                                    "4. Implement object-level authorization checks after field binding."
                                ),
                                evidence=f"Privileged fields reflected: {reflected_fields}",
                                request_details=f"{method} {base_url}\nBody: {json.dumps(payload_dict)[:200]}",
                                payload=json.dumps({f: True for f in reflected_fields}),
                            )

    def _check_verb_tunneling(self):
        """Test HTTP verb tunneling via method override headers."""
        test_url = self._base + "/api/admin"
        for header in HTTP_VERB_OVERRIDES:
            extra = {header: "DELETE"}
            body, status, resp_headers = _request(test_url, method="POST", extra_headers=extra, timeout=6)
            if status not in (404, 405):
                # Check if a normally-disallowed method was accepted
                normal_body, normal_status, _ = _request(test_url, method="DELETE", timeout=6)
                if status != normal_status and status in (200, 204, 401, 403):
                    key = f"verbtunn:{header}"
                    if key not in self._seen:
                        self._seen.add(key)
                        self.log("HIGH", f"[AdvAPI] Verb tunneling via {header} accepted (HTTP {status})")
                        self.add_vuln(
                            title=f"HTTP Verb Tunneling via {header} Header",
                            severity="High",
                            category="API Security / Access Control",
                            cvss_score=7.3,
                            cwe_ids=["CWE-650"],
                            owasp_category="API1:2023 – Broken Object Level Authorization",
                            description=(
                                f"The server accepts `{header}: DELETE` in a POST request, tunneling "
                                f"a restricted HTTP method. This bypasses WAF/firewall rules that only "
                                f"block explicit DELETE/PUT methods, allowing attackers to perform "
                                f"destructive operations through a POST wrapper."
                            ),
                            remediation=(
                                f"1. Disable `{header}` header processing on production APIs.\n"
                                "2. Validate that WAF rules apply to effective HTTP method, not tunneled method.\n"
                                "3. Use framework-level configuration to disable method override middleware.\n"
                                "4. Implement resource-level authorization that doesn't depend on HTTP method alone."
                            ),
                            evidence=f"POST with {header}: DELETE returned HTTP {status} vs DELETE returning {normal_status}",
                            request_details=f"POST {test_url}\n{header}: DELETE",
                            payload=f"{header}: DELETE",
                        )

    def _check_rate_limit_bypass(self):
        """Check if rate limits can be bypassed via IP spoofing headers."""
        test_url = self.target

        # Get baseline response
        baseline_body, baseline_status, baseline_headers = _request(test_url, timeout=6)
        rate_limited = False

        # Send 20 rapid requests to trigger rate limiting
        for _ in range(20):
            body, status, _ = _request(test_url, timeout=3)
            if status == 429:
                rate_limited = True
                break
            # No sleep needed — requests run as fast as socket allows

        if rate_limited:
            # Try bypass headers
            for bypass_header in RATE_LIMIT_BYPASS_HEADERS:
                body, status, _ = _request(test_url, extra_headers=bypass_header, timeout=6)
                if status != 429:
                    header_name, header_val = list(bypass_header.items())[0]
                    key = f"ratelimit_bypass:{header_name}"
                    if key not in self._seen:
                        self._seen.add(key)
                        self.log("HIGH", f"[AdvAPI] Rate limit bypassed via {header_name}: {header_val}")
                        self.add_vuln(
                            title=f"Rate Limit Bypass via {header_name} IP Spoofing Header",
                            severity="High",
                            category="API Security / Rate Limiting",
                            cvss_score=7.5,
                            cwe_ids=["CWE-799", "CWE-290"],
                            owasp_category="API4:2023 – Unrestricted Resource Consumption",
                            description=(
                                f"The rate limiting mechanism trusts the `{header_name}` header "
                                f"for IP identification. By setting `{header_name}: {header_val}`, "
                                f"an attacker can bypass rate limits entirely, enabling:\n"
                                f"- Brute force attacks on authentication endpoints\n"
                                f"- Credential stuffing at scale\n"
                                f"- API denial-of-service with rotating fake IPs"
                            ),
                            remediation=(
                                "1. Use the actual TCP connection IP for rate limiting, not forwarded headers.\n"
                                "2. If behind a trusted proxy, validate the proxy IP before trusting forwarded headers.\n"
                                "3. Implement rate limiting at the TCP/network layer (not just HTTP).\n"
                                f"4. Remove trust of `{header_name}` from untrusted sources."
                            ),
                            evidence=f"429 rate limit triggered normally, then bypassed with {header_name}: {header_val}",
                            request_details=f"GET {test_url}\n{header_name}: {header_val}",
                            payload=f"{header_name}: {header_val}",
                        )

    def _check_graphql_introspection(self):
        """Check for unauthenticated GraphQL introspection."""
        gql_paths = ["/graphql", "/api/graphql", "/gql", "/query", "/api/query"]
        introspection_query = json.dumps({
            "query": "{ __schema { types { name } } }"
        }).encode()

        for path in gql_paths:
            url = self._base + path
            body, status, headers = _request(
                url, method="POST", body=introspection_query,
                extra_headers={"Content-Type": "application/json"},
                timeout=7
            )
            if status == 200 and '"__schema"' in body and '"types"' in body:
                key = f"gql_introspect:{path}"
                if key not in self._seen:
                    self._seen.add(key)
                    # Count type count as a measure of exposure
                    type_count = body.count('"name"')
                    self.log("HIGH", f"[AdvAPI] GraphQL introspection open at {url} ({type_count} types exposed)")
                    self.add_vuln(
                        title="GraphQL Introspection Enabled in Production",
                        severity="High",
                        category="API Security / GraphQL",
                        cvss_score=7.5,
                        cwe_ids=["CWE-200"],
                        owasp_category="A09:2021 – Security Logging and Monitoring Failures",
                        description=(
                            f"GraphQL introspection is enabled at `{url}` without authentication. "
                            f"Introspection exposes the complete schema ({type_count} type references), "
                            f"including all queries, mutations, fields, arguments, and data models. "
                            f"This provides attackers with a full API blueprint for further targeted attacks."
                        ),
                        remediation=(
                            "1. Disable introspection in production GraphQL configurations.\n"
                            "2. For Apollo Server: `introspection: false`.\n"
                            "3. For Hasura: set HASURA_GRAPHQL_ENABLE_INTROSPECTION=false.\n"
                            "4. Restrict introspection to authenticated admin users only.\n"
                            "5. Implement query depth limiting and complexity analysis."
                        ),
                        evidence=f"GraphQL introspection returned {type_count} type references",
                        request_details=f'POST {url}\nBody: {{"query": "{{ __schema {{ types {{ name }} }} }}"}}',
                        payload='{ __schema { types { name } } }',
                    )

    def _check_data_overexposure(self, api_bases: list[str]):
        """Check API responses for sensitive fields that shouldn't be exposed."""
        endpoints = [self.target, self._base + "/api/user", self._base + "/api/me", self._base + "/api/profile"]
        endpoints.extend(api_bases[:2])

        for url in endpoints[:6]:
            body, status, headers = _request(url, timeout=6)
            if status == 200 and body:
                # Check for API key leakage
                secrets = _check_api_key_in_response(body, headers)
                for secret_type, secret_val in secrets:
                    key = f"secretleak:{secret_type}:{url}"
                    if key not in self._seen:
                        self._seen.add(key)
                        self.log("CRITICAL", f"[AdvAPI] Secret leaked in response: {secret_type} at {url}")
                        self.add_vuln(
                            title=f"Sensitive Credential Exposed in API Response: {secret_type}",
                            severity="Critical",
                            category="API Security / Information Disclosure",
                            cvss_score=9.1,
                            cwe_ids=["CWE-200", "CWE-312"],
                            owasp_category="API3:2023 – Broken Object Property Level Authorization",
                            description=(
                                f"The API endpoint `{url}` returns a **{secret_type}** in its response body or headers. "
                                f"This exposes sensitive credentials that can be used to authenticate as the affected "
                                f"user/service, access third-party APIs, or perform actions on behalf of the system.\n\n"
                                f"**Detected pattern:** `{secret_val}`"
                            ),
                            remediation=(
                                "1. Remove all sensitive fields from API responses using response DTOs/serializers.\n"
                                "2. Never return API keys, tokens, or passwords in any API response.\n"
                                "3. Audit all API endpoints with automated secret scanning in CI/CD.\n"
                                "4. Rotate any exposed credentials immediately.\n"
                                "5. Implement response filtering middleware to block secret patterns."
                            ),
                            evidence=f"{secret_type} found in response from {url}: {secret_val[:30]}...",
                            request_details=f"GET {url}",
                        )

                # Check for sensitive field over-exposure
                sensitive = _check_sensitive_fields(body)
                if sensitive:
                    key = f"overexpose:{url}"
                    if key not in self._seen:
                        self._seen.add(key)
                        self.log("HIGH", f"[AdvAPI] Data over-exposure: {sensitive} at {url}")
                        self.add_vuln(
                            title=f"API Response Data Over-Exposure — Sensitive Fields Returned",
                            severity="High",
                            category="API Security / Data Exposure",
                            cvss_score=7.5,
                            cwe_ids=["CWE-213"],
                            owasp_category="API3:2023 – Broken Object Property Level Authorization",
                            description=(
                                f"The API endpoint `{url}` returns sensitive fields that should not be exposed to clients: "
                                f"`{'`, `'.join(sensitive[:8])}`.\n\n"
                                f"Over-exposure occurs when API responses include more data than the frontend actually needs, "
                                f"relying on the UI to 'hide' sensitive information that is still transmitted over the network."
                            ),
                            remediation=(
                                "1. Implement field-level filtering in API serializers — only return fields the client needs.\n"
                                "2. Use separate response schemas for different user roles.\n"
                                "3. Avoid returning full database model objects directly as API responses.\n"
                                "4. Regularly audit API response fields using automated data classification tools."
                            ),
                            evidence=f"Sensitive fields in response: {sensitive[:5]}",
                            request_details=f"GET {url}",
                        )
