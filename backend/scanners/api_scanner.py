import urllib.request, urllib.error, urllib.parse, ssl, json
from scanners.base_scanner import BaseScanner
from utils.fuzzer_engine import ContextAwareFuzzer

class ApiScanner(BaseScanner):
    SCANNER_NAME = "API & GraphQL Introspection Scanner"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        self._headers = {"User-Agent": "LarShield/2.0 API-Analyzer", "Content-Type": "application/json"}
        if self.auth_headers:
            self._headers.update(self.auth_headers)
        self.base_url = target.rstrip("/")
        self._fuzzer = ContextAwareFuzzer(self._api_fuzzer_req)

    def _api_fuzzer_req(self, url, params, headers=None):
        data = urllib.parse.urlencode(params).encode("utf-8") if params else None
        merged = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            merged.update(headers)
        body, status = self._make_request(url, method="POST", data=data, headers=merged, timeout=8)
        return body or "", status

    def _get(self, path):
        url = f"{self.base_url}{path}"
        try:
            req = urllib.request.Request(url, headers=self._headers)
            with urllib.request.urlopen(req, timeout=5, context=self._ctx) as resp:
                return resp.read().decode("utf-8", errors="ignore"), resp.status
        except urllib.error.HTTPError as e:
            return e.read().decode("utf-8", errors="ignore") if e.fp else "", e.code
        except Exception as e:
            self.log("ERROR", f"[API] GET error: {e}")
            return "", 0

    def _post(self, path, payload):
        url = f"{self.base_url}{path}"
        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers=self._headers, method='POST')
            with urllib.request.urlopen(req, timeout=5, context=self._ctx) as resp:
                return resp.read().decode("utf-8", errors="ignore"), resp.status
        except urllib.error.HTTPError as e:
            return e.read().decode("utf-8", errors="ignore") if e.fp else "", e.code
        except Exception as e:
            self.log("ERROR", f"[API] POST error: {e}")
            return "", 0

    def check_swagger(self):
        self.log("INFO", "[API] Hunting for exposed Swagger/OpenAPI documentation...")
        paths = ["/swagger-ui.html", "/api-docs", "/v2/api-docs", "/openapi.json", "/api/swagger.json", "/docs"]
        for path in paths:
            body, status = self._get(path)
            if status == 200 and ("swagger" in body.lower() or "openapi" in body.lower()):
                self.log("CRITICAL", f"[API] Exposed API documentation found at {path}")
                self.add_vuln(
                    title="Exposed API Documentation (Swagger/OpenAPI)",
                    severity="High",
                    category="Information Disclosure",
                    cvss_score=7.5,
                    description=f"Unauthenticated API documentation was discovered at `{path}`. Attackers can use this to map out the entire backend infrastructure, discover hidden endpoints, and find injection vectors.",
                    remediation="Restrict access to API documentation endpoints in production environments using IP whitelisting or robust authentication."
                )
                break

    def check_graphql(self):
        self.log("INFO", "[API] Testing GraphQL endpoints for Introspection vulnerabilities...")
        endpoints = ["/graphql", "/api/graphql", "/v1/graphql"]
        introspection_query = {
            "query": "{ __schema { types { name fields { name } } } }"
        }
        
        for path in endpoints:
            body, status = self._post(path, introspection_query)
            if status == 200 and "__schema" in body:
                self.log("CRITICAL", f"[API] GraphQL Introspection enabled at {path}")
                self.add_vuln(
                    title="GraphQL Introspection Query Enabled",
                    severity="Critical",
                    category="API Security",
                    cvss_score=9.1,
                    description=f"The GraphQL endpoint at `{path}` allows Introspection queries. An attacker dumped the entire database schema, including all types, mutations, and hidden fields. This completely exposes the application's internal data structures.",
                    remediation="Disable GraphQL introspection in your production environment. In Apollo Server, set `introspection: false`."
                )
                break

    def _fuzz_api_params(self):
        swagger_paths = ["/api-docs", "/v2/api-docs", "/openapi.json", "/api/swagger.json"]
        swagger_spec = None
        for path in swagger_paths:
            body, status = self._get(path)
            if status == 200 and body:
                try:
                    swagger_spec = json.loads(body)
                    break
                except json.JSONDecodeError:
                    continue

        if swagger_spec:
            paths = swagger_spec.get("paths", {})
            for endpoint, methods in paths.items():
                url = f"{self.base_url}{endpoint}"
                for method, details in methods.items():
                    if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        continue
                    params = {}
                    for param in details.get("parameters", []):
                        if param.get("in") in ("query", "formData"):
                            params[param["name"]] = str(param.get("default", "test"))
                    if not params:
                        continue
                    self.log("INFO", f"[API] Context-aware fuzzing {endpoint} ({len(params)} params)")
                    self._fuzzer.fuzz(url, params)
                    baseline_body, _ = self._make_request(url, timeout=8)
                    baseline_length = len(baseline_body or "")
                    anomalies = self._fuzzer.anomalies(baseline_length)
                    for anom in anomalies:
                        self.log("WARNING", f"[API] Fuzzer anomaly at {endpoint}: {anom['param']} mutation={anom['mutation']} status={anom['status']}")
                        self.add_vuln(
                            title=f"API Injection — {anom['param']} ({anom['mutation']})",
                            severity="High",
                            category="Injection",
                            cvss_score=7.5,
                            description=(
                                f"API endpoint {endpoint} parameter '{anom['param']}' "
                                f"(classified as '{anom['type']}') returned an anomalous response "
                                f"when mutated with '{anom['mutation']}' (value: {anom['value']}). "
                                f"HTTP {anom['status']}, response length {anom['length']}."
                            ),
                            remediation="Validate and sanitize all API input parameters. Use parameterized queries, input type enforcement, and proper output encoding.",
                            cwe_ids=["CWE-20"],
                            owasp_category="A03:2021 – Injection",
                        )
        else:
            common_api_params = ["id", "q", "search", "query", "page", "limit", "offset", "sort", "filter",
                                 "token", "key", "secret", "user", "email", "name", "status", "type", "role"]
            params = {p: "test" for p in common_api_params}
            self.log("INFO", "[API] No swagger spec found; fuzzing common API parameters on base URL")
            self._fuzzer.fuzz(self.base_url, params)
            baseline_body, _ = self._make_request(self.target, timeout=8)
            baseline_length = len(baseline_body or "")
            anomalies = self._fuzzer.anomalies(baseline_length)
            for anom in anomalies:
                self.log("WARNING", f"[API] Fuzzer anomaly: {anom['param']} mutation={anom['mutation']} status={anom['status']}")
                self.add_vuln(
                    title=f"API Injection — {anom['param']} ({anom['mutation']})",
                    severity="High",
                    category="Injection",
                    cvss_score=7.5,
                    description=(
                        f"Common API parameter '{anom['param']}' (classified as '{anom['type']}') "
                        f"returned an anomalous response when mutated with '{anom['mutation']}' "
                        f"(value: {anom['value']}). HTTP {anom['status']}, response length {anom['length']}."
                    ),
                    remediation="Validate and sanitize all API input parameters. Use parameterized queries, input type enforcement, and proper output encoding.",
                    cwe_ids=["CWE-20"],
                    owasp_category="A03:2021 – Injection",
                )

    def run(self):
        self.log("INFO", f"[API] Starting Advanced API analysis on {self.target}...")
        self.check_swagger()
        self.check_graphql()
        self._fuzz_api_params()
        self.log("SUCCESS" if not self.vulns else "WARNING", "[API] Analysis complete.")
        return self.vulns
