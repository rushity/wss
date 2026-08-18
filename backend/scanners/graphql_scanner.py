"""
graphql_scanner.py — GraphQL Security Scanner
==============================================
Advanced GraphQL vulnerability detection module.

This scanner:
  1. Identifies GraphQL endpoints
  2. Performs introspection to discover schema
  3. Tests for GraphQL-specific vulnerabilities
  4. Detects information disclosure via introspection
  5. Tests for query depth limiting and DoS vulnerabilities
  6. Checks for authorization bypass in GraphQL queries
  7. Multi-stage detection: probe endpoint, then confirm vulnerabilities
"""
import urllib.request, urllib.error, urllib.parse, re, json
from scanners.base_scanner import BaseScanner
from utils.fuzzer_engine import ContextAwareFuzzer

GRAPHQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/graphiql", "/api/graphiql",
    "/graphql.php", "/graphql/api", "/v1/graphql", "/v2/graphql",
    "/gql", "/api/gql", "/query", "/api/query",
    "/console/graphql", "/graphql/console", "/playground",
    "/api/v1/graphql", "/api/v2/graphql",
]

GRAPHQL_INDICATORS = [
    r"graphql", r"GraphQL", r"query\s+\w+", r"mutation\s+\w+",
    r"subscription\s+\w+", r"__schema", r"__type", r"__typename",
]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name fields { name type { name kind } } }
    mutationType { name fields { name type { name kind } } }
    subscriptionType { name fields { name type { name kind } } }
    types { name kind description fields { name type { name kind } } }
  }
}
"""

BATCHING_QUERY = """
[
  { "query": "{ __typename }" },
  { "query": "{ __typename }" },
  { "query": "{ __typename }" },
  { "query": "{ __typename }" },
  { "query": "{ __typename }" }
]
"""

DEEP_NESTED_QUERY = """
{
  __schema {
    queryType { fields { name type { fields { name type { fields { name type { fields { name type { fields { name } } } } } } } } }
  }
}
"""

ALIAS_QUERY = """
query {
  a1: __typename
  a2: __typename
  a3: __typename
  a4: __typename
  a5: __typename
  a6: __typename
  a7: __typename
  a8: __typename
  a9: __typename
  a10: __typename
}
"""

SQLI_GQL_QUERY = """
query {
  __typename
  search(query: "' OR '1'='1")
}
"""

TEST_QUERIES = {
    "introspection": INTROSPECTION_QUERY,
    "basic_query": "{ __typename }",
    "nested_query": DEEP_NESTED_QUERY,
    "mutation_test": "mutation { __typename }",
    "batching": BATCHING_QUERY,
    "alias_spam": ALIAS_QUERY,
    "sqli_test": SQLI_GQL_QUERY,
}

ERROR_PATTERNS = [
    r"GraphQL error", r"Cannot query field", r"Cannot return null",
    r"Variable", r"Syntax Error", r"Parse error", r"Validation error",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax", r"mysql_fetch", r"ORA-[0-9]{5}", r"PostgreSQL",
    r"SQLite", r"unclosed quotation mark", r"quoted string not properly terminated",
    r"division by zero", r"syntax error at or near", r"Unclosed",
]


class GraphqlScanner(BaseScanner):
    SCANNER_NAME = "GraphQL Security Scanner"
    _SCANNER_KEY = "graphql"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._headers = {
            "User-Agent": "LarShield/2.0 GraphQL Scanner",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.auth_headers:
            self._headers.update(self.auth_headers)
        self._tested_endpoints = 0
        self._vulns_found = 0
        self._fuzzer = ContextAwareFuzzer(self._gql_fuzzer_req)

    def _gql_fuzzer_req(self, url, params, headers=None):
        variables = {}
        for key, val in params.items():
            variables[key] = val
        payload_dict = {"query": "query($vars: JSON!) { __typename }", "variables": variables}
        encoded = json.dumps(payload_dict).encode("utf-8")
        merged = {"Content-Type": "application/json"}
        if headers:
            merged.update(headers)
        body, status = self._make_request(url, method="POST", data=encoded, headers=merged, timeout=8)
        return body or "", status

    def _make_gql_request(self, url, query, variables=None, timeout=8):
        """Send a GraphQL query and return the response."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        encoded = json.dumps(payload).encode("utf-8")
        body, status = self._make_request(
            url, method="POST", data=encoded,
            headers=self._headers, timeout=timeout,
        )
        return body, status

    def _detect_graphql_endpoint(self, url):
        """Check if a URL is a GraphQL endpoint."""
        try:
            body, status = self._make_request(url)
            if body:
                for indicator in GRAPHQL_INDICATORS:
                    if re.search(indicator, body, re.IGNORECASE):
                        return True, "GET"

            body, status = self._make_gql_request(url, TEST_QUERIES["basic_query"])
            if body:
                try:
                    response_json = json.loads(body)
                    if "data" in response_json or "errors" in response_json:
                        return True, "POST"
                except json.JSONDecodeError:
                    pass

                for indicator in GRAPHQL_INDICATORS:
                    if re.search(indicator, body, re.IGNORECASE):
                        return True, "POST"
        except Exception as e:
            self.log("ERROR", f"[GraphQL] Error detecting endpoint {url}: {e}")

        return False, None

    def _test_introspection(self, url):
        """Test if introspection is enabled (information disclosure)."""
        try:
            body, status = self._make_gql_request(url, TEST_QUERIES["introspection"])
            if not body:
                return False

            try:
                response_json = json.loads(body)
                if "data" in response_json:
                    data = response_json["data"]
                    if "__schema" in data or "__type" in data:
                        self._vulns_found += 1
                        self.log("CRITICAL", "[GraphQL] Introspection is ENABLED — Full schema disclosure!")

                        schema = data.get("__schema", {})
                        types = schema.get("types", [])
                        query_fields = schema.get("queryType", {}).get("fields", [])
                        mutation_fields = schema.get("mutationType", {}).get("fields", [])

                        self.log("INFO", f"[GraphQL] Schema contains {len(types)} types, "
                                         f"{len(query_fields)} query fields, {len(mutation_fields)} mutation fields")

                        self.add_vuln(
                            title="GraphQL — Introspection Enabled",
                            severity="High",
                            category="Information Disclosure",
                            cvss_score=7.5,
                            description=(
                                f"GraphQL introspection is enabled at {url}.\n"
                                f"Discovered schema contains:\n"
                                f"- {len(types)} types\n"
                                f"- {len(query_fields)} query fields\n"
                                f"- {len(mutation_fields)} mutation fields\n\n"
                                f"Introspection exposes the entire GraphQL schema, including "
                                f"all queries, mutations, types, and their relationships. "
                                f"This information can be used by attackers to craft targeted attacks."
                            ),
                            remediation=(
                                "1. DISABLE introspection in production:\n"
                                "   - Apollo Server: introspection: false in config\n"
                                "   - GraphQL Yoga: disableIntrospection: true\n"
                                "   - Graphene: disable_introspection = True\n"
                                "2. Use environment-specific configuration\n"
                                "3. Implement proper authentication and authorization\n"
                                "4. Monitor for introspection queries in logs"
                            ),
                            evidence=json.dumps({k: v for k, v in data.items() if k == "__schema"}, indent=2)[:500],
                            payload="Introspection query (see evidence)",
                            request_details=f"URL: {url}",
                            response_details=f"Schema: {len(types)} types, {len(query_fields)} queries, {len(mutation_fields)} mutations",
                            confidence="Confirmed",
                        )
                        return True
            except json.JSONDecodeError:
                pass
        except Exception as e:
            self.log("ERROR", f"[GraphQL] Error testing introspection: {e}")

        return False

    def _test_query_depth(self, url):
        """Test for query depth limiting (DoS prevention)."""
        try:
            body, status = self._make_gql_request(url, TEST_QUERIES["nested_query"], timeout=15)
            if not body:
                return False

            try:
                response_json = json.loads(body)
                if "data" in response_json and response_json["data"]:
                    self.log("WARNING", "[GraphQL] Query depth limiting may not be configured")

                    self.add_vuln(
                        title="GraphQL — Missing Query Depth Limiting",
                        severity="Medium",
                        category="Denial of Service",
                        cvss_score=5.3,
                        description=(
                            f"GraphQL endpoint at {url} accepted deeply nested queries without depth limiting. "
                            "This can lead to denial of service attacks through complex nested queries."
                        ),
                        remediation=(
                            "1. IMPLEMENT query depth limiting:\n"
                            "   - Apollo Server: maxDepth or validation rules\n"
                            "   - Set reasonable depth limits (e.g., 5-10 levels)\n"
                            "2. Implement query complexity analysis\n"
                            "3. Use query whitelisting for production"
                        ),
                        evidence="Deeply nested query returned data successfully",
                        payload=TEST_QUERIES["nested_query"][:200],
                        request_details=f"URL: {url}",
                        response_details="Query executed without depth limit enforcement",
                        confidence="Confirmed",
                    )
                    return True
            except json.JSONDecodeError:
                pass
        except Exception as e:
            self.log("ERROR", f"[GraphQL] Error testing query depth: {e}")

        return False

    def _test_batching_attack(self, url):
        """Test for batching attack vulnerabilities (batched queries bypassing rate limits)."""
        try:
            body, status = self._make_gql_request(
                url, TEST_QUERIES["batching"],
                timeout=15,
            )
            if not body:
                return False

            try:
                response_json = json.loads(body)
                if isinstance(response_json, list) and len(response_json) >= 5:
                    self._vulns_found += 1
                    self.log("WARNING",
                             f"[GraphQL] Batching is supported — {len(response_json)} batched queries accepted at {url}")

                    self.add_vuln(
                        title="GraphQL — Batching Attack Possible",
                        severity="High",
                        category="Denial of Service",
                        cvss_score=7.5,
                        description=(
                            f"GraphQL endpoint at {url} supports query batching.\n"
                            f"Accepted {len(response_json)} batched queries in a single request.\n\n"
                            f"Impact: Attackers can bypass rate limiting by sending multiple "
                            f"operations in a single request, making brute-force attacks, "
                            f"enumeration, and DoS more effective."
                        ),
                        remediation=(
                            "1. Implement rate limiting per operation, not per request.\n"
                            "2. Limit the number of operations allowed per batch request.\n"
                            "3. Use cost-based analysis to limit batch complexity.\n"
                            "4. Consider disabling batching if not required."
                        ),
                        evidence=f"Batched query returned {len(response_json)} results",
                        payload="Batched query with 5 operations",
                        request_details=f"URL: {url}",
                        response_details=f"{len(response_json)} operations accepted",
                        confidence="Confirmed",
                    )
                    return True
            except (json.JSONDecodeError, TypeError):
                pass
        except Exception as e:
            self.log("ERROR", f"[GraphQL] Error testing batching attack: {e}")

        return False

    def _test_alias_dos(self, url):
        """Test for alias-based DoS attacks (many aliases consuming resources)."""
        try:
            body, status = self._make_gql_request(url, TEST_QUERIES["alias_spam"], timeout=15)
            if not body:
                return False

            try:
                response_json = json.loads(body)
                if "data" in response_json:
                    data = response_json["data"]
                    alias_count = sum(1 for k in data if k.startswith("a"))
                    if alias_count >= 8:
                        self._vulns_found += 1
                        self.log("WARNING",
                                 f"[GraphQL] Alias-based DoS possible at {url} — {alias_count} aliases accepted")

                        self.add_vuln(
                            title="GraphQL — Alias-Based DoS Possible",
                            severity="Medium",
                            category="Denial of Service",
                            cvss_score=5.0,
                            description=(
                                f"GraphQL endpoint at {url} accepted {alias_count} aliases in a single query.\n"
                                f"Attackers can use many aliases to amplify resource consumption.\n\n"
                                f"Aliases allow the same field to be queried multiple times under different names, "
                                f"bypassing query depth limits while consuming significant server resources."
                            ),
                            remediation=(
                                "1. Implement query complexity/cost analysis.\n"
                                "2. Limit the number of aliases allowed per query.\n"
                                "3. Use rate limiting based on field resolution cost.\n"
                                "4. Consider using persisted queries in production."
                            ),
                            evidence=f"{alias_count} aliases accepted",
                            payload="Alias-based amplification query",
                            request_details=f"URL: {url}",
                            response_details=f"Accepted {alias_count} aliases",
                            confidence="Confirmed",
                        )
                        return True
            except json.JSONDecodeError:
                pass
        except Exception as e:
            self.log("ERROR", f"[GraphQL] Error testing alias DoS: {e}")

        return False

    def _test_graphql_sqli(self, url):
        """Test for SQL injection via GraphQL query parameters."""
        try:
            sqli_query = TEST_QUERIES["sqli_test"]
            body, status = self._make_gql_request(url, sqli_query, timeout=15)
            if not body:
                return False

            try:
                response_json = json.loads(body)
                # Check for SQL errors in response
                errors = response_json.get("errors", [])
                error_str = json.dumps(errors)
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, error_str, re.IGNORECASE):
                        self._vulns_found += 1
                        self.log("CRITICAL",
                                 f"[GraphQL] SQL Injection via GraphQL at {url}! "
                                 f"Pattern matched: {pattern}")

                        self.add_vuln(
                            title="GraphQL — SQL Injection via GraphQL Parameters",
                            severity="Critical",
                            category="Injection",
                            cvss_score=9.8,
                            description=(
                                f"A SQL injection vulnerability was detected via GraphQL at {url}.\n"
                                f"The GraphQL endpoint appears to pass user input directly to SQL queries.\n"
                                f"Pattern matched: {pattern}\n\n"
                                f"Impact: Attackers can extract, modify, or delete database contents, "
                                f"potentially leading to complete database compromise."
                            ),
                            remediation=(
                                "1. Use parameterized queries / prepared statements.\n"
                                "2. Implement input validation and sanitization.\n"
                                "3. Use an ORM/ODM with proper injection protections.\n"
                                "4. Implement least-privilege database access.\n"
                                "5. Regularly audit and test for injection vulnerabilities."
                            ),
                            evidence=f"SQL error pattern matched: {pattern}",
                            payload=SQLI_GQL_QUERY,
                            request_details=f"URL: {url}",
                            response_details=f"Error message: {error_str[:200]}",
                            confidence="Confirmed" if any(re.search(p, error_str, re.IGNORECASE) for p in SQLI_ERROR_PATTERNS) else "Medium",
                        )
                        return True
            except json.JSONDecodeError:
                pass
        except Exception as e:
            self.log("ERROR", f"[GraphQL] Error testing SQLi: {e}")

        return False

    def _test_graphql_params_fuzz(self, url):
        try:
            body, status = self._make_gql_request(url, TEST_QUERIES["introspection"])
            if not body:
                return
            data = json.loads(body)
            schema = data.get("data", {}).get("__schema", {})
            query_type = schema.get("queryType", {})
            fields = query_type.get("fields", []) if query_type else []
            params = {}
            for field in fields:
                for arg in field.get("args", []):
                    params[arg["name"]] = "test"
            mutation_type = schema.get("mutationType", {})
            if mutation_type:
                for field in mutation_type.get("fields", []):
                    for arg in field.get("args", []):
                        params[arg["name"]] = "test"
            if not params:
                params = {"query": "test", "id": "1", "filter": "test"}
            self.log("INFO", f"[GraphQL] Context-aware fuzzing {len(params)} parameter(s) at {url}")
            self._fuzzer.fuzz(url, params)
            baseline_body, _ = self._make_gql_request(url, TEST_QUERIES["basic_query"])
            baseline_length = len(baseline_body or "")
            anomalies = self._fuzzer.anomalies(baseline_length)
            for anom in anomalies:
                self._vulns_found += 1
                self.log("WARNING", f"[GraphQL] Fuzzer anomaly: {anom['param']} mutation={anom['mutation']} status={anom['status']}")
                self.add_vuln(
                    title=f"GraphQL — Parameter Injection ({anom['param']})",
                    severity="High",
                    category="Injection",
                    cvss_score=7.5,
                    description=(
                        f"GraphQL parameter '{anom['param']}' (classified as '{anom['type']}') "
                        f"at {url} returned an anomalous response when mutated with "
                        f"'{anom['mutation']}' (value: {anom['value']}). "
                        f"HTTP {anom['status']}, response length {anom['length']}."
                    ),
                    remediation="Validate and sanitize all GraphQL argument inputs. Use parameterized queries, input type enforcement, and proper output encoding.",
                    cwe_ids=["CWE-20"],
                    owasp_category="A03:2021 – Injection",
                )
        except Exception as e:
            self.log("ERROR", f"[GraphQL] Error in param fuzzing: {e}")

    def _test_authorization(self, url):
        """Test for authorization bypass in GraphQL."""
        try:
            test_query = """
            {
              __schema {
                queryType {
                  fields { name args { name type { name } } }
                }
              }
            }
            """

            body, status = self._make_gql_request(url, test_query)
            if not body:
                return False

            try:
                response_json = json.loads(body)
                if "data" in response_json:
                    data = response_json["data"]
                    if "__schema" in data:
                        fields = data["__schema"].get("queryType", {}).get("fields", [])
                        sensitive_fields = []
                        for field in fields:
                            field_name = field.get("name", "").lower()
                            if any(s in field_name for s in ["user", "password", "secret", "key", "token", "admin"]):
                                sensitive_fields.append(field.get("name"))

                        if sensitive_fields:
                            self.log("WARNING", f"[GraphQL] Discovered potentially sensitive fields: {sensitive_fields}")
                            self.add_vuln(
                                title="GraphQL — Sensitive Field Exposure",
                                severity="Medium",
                                category="Information Disclosure",
                                cvss_score=5.5,
                                description=(
                                    f"GraphQL schema exposes potentially sensitive fields: {', '.join(sensitive_fields)}. "
                                    "These fields may contain sensitive information that should be protected."
                                ),
                                remediation=(
                                    "1. Review and restrict field access based on user roles\n"
                                    "2. Implement field-level authorization\n"
                                    "3. Use custom resolvers with proper access checks\n"
                                    "4. Audit schema for sensitive data exposure"
                                ),
                                evidence=f"Sensitive fields: {', '.join(sensitive_fields)}",
                                payload="Schema field discovery query",
                                request_details=f"URL: {url}",
                                response_details=f"Fields found: {[f.get('name') for f in fields[:10]]}",
                                confidence="High",
                            )
                            return True
            except json.JSONDecodeError:
                pass
        except Exception as e:
            self.log("ERROR", f"[GraphQL] Error testing authorization: {e}")

        return False

    def _discover_graphql_endpoints(self):
        """Discover GraphQL endpoints."""
        endpoints = []
        base_url = self.target.rstrip("/")

        for path in GRAPHQL_ENDPOINTS:
            url = f"{base_url}{path}"
            is_graphql, method = self._detect_graphql_endpoint(url)
            if is_graphql:
                endpoints.append((url, method))
                self.log("INFO", f"[GraphQL] Discovered GraphQL endpoint: {url} ({method})")

        is_graphql, method = self._detect_graphql_endpoint(self.target)
        if is_graphql:
            endpoints.append((self.target, method))
            self.log("INFO", f"[GraphQL] Main URL is GraphQL endpoint: {self.target} ({method})")

        return endpoints

    def run(self):
        self.log("INFO", f"[GraphQL] Starting GraphQL security scanning on {self.target}...")

        try:
            # Step 1: Discover GraphQL endpoints
            self.log("INFO", "[GraphQL] Discovering GraphQL endpoints...")
            endpoints = self._discover_graphql_endpoints()
            self.log("INFO", f"[GraphQL] Found {len(endpoints)} GraphQL endpoint(s)")

            if not endpoints:
                self.log("INFO", "[GraphQL] No GraphQL endpoints detected")
                return self.vulns

            # Step 2: Test each endpoint
            for url, method in endpoints:
                self._tested_endpoints += 1
                self.log("INFO", f"[GraphQL] Testing endpoint: {url}")

                if self._test_introspection(url):
                    pass

                self._test_query_depth(url)

                self._test_authorization(url)

                self._test_batching_attack(url)

                self._test_alias_dos(url)

                self._test_graphql_sqli(url)

                self._test_graphql_params_fuzz(url)

        except Exception as e:
            self.log("ERROR", f"[GraphQL] Unexpected error during scan: {e}")

        self.log("SUCCESS" if not self.vulns else "WARNING",
                 f"[GraphQL] Complete — {self._tested_endpoints} endpoint(s) tested | "
                 f"{self._vulns_found} vulnerability/vulnerabilities found")
        return self.vulns
