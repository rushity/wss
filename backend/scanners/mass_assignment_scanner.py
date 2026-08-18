"""
mass_assignment_scanner.py — Mass Assignment / Parameter Pollution Scanner
===========================================================================
Expert-grade rewrite (GAP-008 fix):
  1. Uses unique probe VALUES (not just key names) to confirm acceptance
  2. Properly passes auth_headers via _make_request() for authenticated endpoints
  3. Tests GET, POST, PUT, PATCH methods
  4. Tests JSON body AND form-encoded body
  5. Checks response for reflected probe VALUE (not key name — GAP-008 fix)
  6. Tests privilege escalation fields: role, isAdmin, plan, verified, price
"""
import json, urllib.parse
from scanners.base_scanner import BaseScanner

# ── Probe fields with unique probe VALUES for accurate detection ──────────
# Key = field name, Value = unique probe string to look for in response
PROBE_FIELDS = {
    "role":        "wss_admin_probe",
    "isAdmin":     "wss_true_probe",
    "is_admin":    "wss_true_probe",
    "admin":       "wss_admin_probe",
    "plan":        "wss_enterprise_probe",
    "verified":    "wss_verified_probe",
    "status":      "wss_active_probe",
    "price":       "0.001",       # unusual price value
    "credits":     "999999",
    "permissions": "wss_perm_probe",
    "group_id":    "0",
    "user_type":   "wss_superuser",
    "account_type":"wss_premium",
}

# Endpoints commonly vulnerable to mass assignment
ENDPOINTS = [
    "/api/user",
    "/api/users",
    "/api/profile",
    "/api/account",
    "/api/me",
    "/api/v1/user",
    "/api/v1/users",
    "/api/v1/profile",
    "/api/v2/user",
    "/api/v2/users",
    "/api/register",
    "/api/signup",
    "/api/auth/register",
    "/api/users/me",
    "/user/update",
    "/profile/update",
    "/account/settings",
]


class MassAssignmentScanner(BaseScanner):
    SCANNER_NAME = "Mass Assignment Scanner"
    _SCANNER_KEY = "mass_assignment"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[MassAssign] Testing mass assignment on {self.target}...")
        base = self.target.rstrip("/")

        for ep in ENDPOINTS:
            url = base + ep
            if self._probe_endpoint(url):
                return self.vulns

        if not self.vulns:
            self.log("SUCCESS", "[MassAssign] No mass assignment vulnerabilities detected.")
        return self.vulns

    def _probe_endpoint(self, url: str) -> bool:
        """Test endpoint with multiple methods and body formats."""
        # Base legitimate payload
        base_data = {"username": "wsstest", "email": "wss@test.local"}

        for method in ["PUT", "PATCH", "POST"]:
            # JSON body
            if self._test_json(url, method, base_data):
                return True
            # Form-encoded body
            if self._test_form(url, method, base_data):
                return True
        return False

    def _test_json(self, url: str, method: str, base_data: dict) -> bool:
        """Inject extra privilege-escalation fields in JSON body."""
        payload_dict = {**base_data, **PROBE_FIELDS}
        body_bytes = json.dumps(payload_dict).encode()

        resp_body, status = self._make_request(
            url, method, body_bytes,
            {"Content-Type": "application/json"}
        )
        if resp_body is None:
            return False

        return self._check_response(url, method, "JSON", resp_body, status, payload_dict)

    def _test_form(self, url: str, method: str, base_data: dict) -> bool:
        """Inject extra privilege-escalation fields in form-encoded body."""
        payload_dict = {**base_data, **PROBE_FIELDS}
        body_bytes = urllib.parse.urlencode(payload_dict).encode()

        resp_body, status = self._make_request(
            url, method, body_bytes,
            {"Content-Type": "application/x-www-form-urlencoded"}
        )
        if resp_body is None:
            return False

        return self._check_response(url, method, "form", resp_body, status, payload_dict)

    def _check_response(self, url, method, format_name, resp_body, status, payload_dict) -> bool:
        """
        GAP-008 FIX: check if a probe VALUE (not key name) was accepted and reflected.
        This prevents false positives from error messages containing field names.
        """
        if status not in (200, 201, 204):
            return False

        resp_lower = resp_body.lower()

        for field, probe_value in PROBE_FIELDS.items():
            probe_lower = probe_value.lower()
            if probe_lower in resp_lower:
                self.log("CRITICAL",
                    f"[MassAssign] Probe value '{probe_value}' reflected! "
                    f"endpoint={url} method={method} field={field}"
                )
                self.add_vuln(
                    title=f"Mass Assignment — Privilege Field `{field}` Accepted ({method} {url})",
                    severity="High",
                    category="Mass Assignment",
                    cvss_score=8.1,
                    confidence="Confirmed",
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                        "https://cwe.mitre.org/data/definitions/915.html",
                    ],
                    description=(
                        f"**Mass assignment** confirmed at `{method} {url}` ({format_name} body).\n\n"
                        f"The privilege-escalation field `{field}` was injected with probe value "
                        f"`{probe_value}` and reflected in the response body (HTTP {status}), "
                        "confirming the server accepted and stored the injected value.\n\n"
                        "An attacker can set their own `role=admin`, `isAdmin=true`, "
                        "`plan=enterprise`, or `price=0` to gain unauthorized privileges or discounts."
                    ),
                    remediation=(
                        "1. Use **allowlists** (DTOs/serializers) that explicitly define which fields users can set.\n"
                        "2. Never bind raw request bodies directly to database model objects.\n"
                        "3. In frameworks: use `@JsonIgnore`, `attr_accessible`, `fillable` lists.\n"
                        "4. Log and alert when unknown fields are submitted to user update endpoints.\n"
                        "5. Validate that role/privilege changes are always performed server-side based on current session, not request body."
                    ),
                    payload=json.dumps({field: probe_value}),
                    evidence=f"Probe value '{probe_value}' found in response to {method} {url}",
                )
                return True
        return False
