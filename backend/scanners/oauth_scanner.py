
"""
oauth_scanner.py — OAuth / OpenID Connect Security Scanner
============================================================
Audits OAuth and OIDC implementations for common misconfigurations:
  - Missing state parameter (CSRF)
  - Open redirect_uri (token theft)
  - Missing PKCE for public clients
  - Token leakage in URL fragments
  - Discovery of .well-known endpoints
  - Redirect URI bypass and referer leakage
"""
import re, json, urllib.parse
from scanners.base_scanner import BaseScanner
from utils.callback import build_callback_url

OIDC_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/auth/realms/master/.well-known/openid-configuration",
]


class OauthScanner(BaseScanner):
    SCANNER_NAME = "OAuth / OIDC Security Scanner"
    _SCANNER_KEY = "oauth"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[OAuth] Scanning OAuth/OIDC configuration on {self.target}...")
        base = self.target.rstrip("/")

        for path in OIDC_DISCOVERY_PATHS:
            url = base + path
            body, status = self._make_request(url)
            if status == 200 and body:
                self.log("INFO", f"[OAuth] Found OIDC endpoint: {url}")
                self._audit_discovery(url, body)

        html, status = self._make_request(self.target)
        if html:
            self._audit_html_oauth(html)
            self._test_redirect_uri_bypass(html)
            self._test_csrf_callback(html)
            self._test_token_leakage_referer(html)
            self._test_redirect_uri_callback_bypass(html)
            self._test_pkce_downgrade(html)

        if not self.vulns:
            self.log("SUCCESS", "[OAuth] No OAuth/OIDC issues detected (or no OAuth in use).")
        return self.vulns

    def _audit_discovery(self, url: str, body: str):
        try:
            config = json.loads(body)
        except Exception as e:
            self.log("ERROR", f"[OAuth] _audit_discovery JSON parse error: {e}")
            return

        auth_ep = config.get("authorization_endpoint", "")
        if auth_ep.startswith("http://"):
            self.add_vuln(
                title="OAuth Authorization Endpoint Uses HTTP (Not HTTPS)",
                severity="Critical",
                category="OAuth Misconfiguration",
                cvss_score=9.1,
                description=f"The OIDC discovery document at `{url}` exposes an authorization "
                    f"endpoint over plain HTTP: `{auth_ep}`. Tokens and auth codes will be "
                    f"transmitted in cleartext.",
                remediation="All OAuth endpoints must use HTTPS. Update the authorization_endpoint URL.",
                evidence=f"authorization_endpoint: {auth_ep}",
                confidence="Confirmed",
                cwe_ids=["CWE-862"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

        code_challenge = config.get("code_challenge_methods_supported", [])
        if not code_challenge or "S256" not in code_challenge:
            self.add_vuln(
                title="OAuth Server Does Not Support PKCE (S256)",
                severity="Medium",
                category="OAuth Misconfiguration",
                cvss_score=5.3,
                description=f"The OIDC discovery at `{url}` does not advertise PKCE (S256) support. "
                    f"Without PKCE, public clients (SPAs, mobile apps) are vulnerable to authorization "
                    f"code interception attacks.",
                remediation="Enable PKCE on the OAuth server and require code_challenge_method=S256 "
                    "for all public client flows.",
                evidence=f"code_challenge_methods_supported: {code_challenge}",
                confidence="Confirmed",
                cwe_ids=["CWE-862"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

        grants = config.get("grant_types_supported", [])
        if "implicit" in grants:
            self.add_vuln(
                title="OAuth Implicit Flow Enabled (Deprecated)",
                severity="Medium",
                category="OAuth Misconfiguration",
                cvss_score=5.3,
                description="The OAuth server still supports the `implicit` grant type, which "
                    "exposes access tokens in URL fragments and browser history.",
                remediation="Disable implicit grant. Use Authorization Code + PKCE instead.",
                evidence=f"grant_types_supported includes implicit: {grants}",
                confidence="Confirmed",
                cwe_ids=["CWE-862"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )

        self.add_vuln(
            title=f"OIDC Discovery Document Exposed: {url}",
            severity="Low",
            category="OAuth",
            cvss_score=0.0,
            description=f"An OpenID Connect discovery document is publicly accessible at `{url}`. "
                f"While standard, it reveals the full OAuth infrastructure layout.",
            remediation="Ensure all advertised endpoints enforce proper authentication and rate limiting.",
            cwe_ids=["CWE-862"],
            owasp_category="A07:2021 – Identification and Authentication Failures",
        )

    def _audit_html_oauth(self, html: str):
        oauth_links = re.findall(
            r'href=["\']([^"\']*(?:oauth|authorize|auth/login|connect/authorize)[^"\']*)["\']',
            html, re.I)

        for link in oauth_links[:5]:
            parsed = urllib.parse.urlparse(link)
            params = urllib.parse.parse_qs(parsed.query)

            if "state" not in params:
                self.add_vuln(
                    title="OAuth Flow Missing `state` Parameter (CSRF)",
                    severity="High",
                    category="OAuth Misconfiguration",
                    cvss_score=7.4,
                    description=f"An OAuth authorization link was found without a `state` parameter:\n"
                        f"`{link[:200]}`\n\nWithout `state`, the OAuth flow is vulnerable to CSRF — "
                        f"an attacker can force a victim to authenticate under the attacker's account.",
                    remediation="Include a cryptographically random `state` parameter in every OAuth "
                        "authorization request and validate it on the callback.",
                    evidence=f"OAuth link without state: {link[:200]}",
                    confidence="High",
                    cwe_ids=["CWE-862"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )

            redirect_uri = params.get("redirect_uri", [""])[0]
            if redirect_uri and not redirect_uri.startswith(("https://" + self.domain, "http://" + self.domain)):
                self.add_vuln(
                    title="OAuth redirect_uri Points to External Domain",
                    severity="High",
                    category="OAuth Misconfiguration",
                    cvss_score=7.4,
                    description=f"The OAuth `redirect_uri` parameter points outside the application domain:\n"
                        f"`{redirect_uri}`\n\nAn attacker can manipulate this to steal authorization codes.",
                    remediation="Strictly validate redirect_uri on the server against a pre-registered allowlist.",
                    evidence=f"redirect_uri: {redirect_uri}",
                    confidence="High",
                    cwe_ids=["CWE-862"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )

    def _test_redirect_uri_bypass(self, html: str):
        oauth_links = re.findall(
            r'href=["\']([^"\']*(?:oauth|authorize|connect/authorize)[^"\']*)["\']',
            html, re.I)
        open_redirect_tricks = [
            lambda u: u + "?redirect_uri=https://evil.com%2F" + self.domain,
            lambda u: u.replace("redirect_uri=", "redirect_uri=https://evil.com/?"),
            lambda u: u + "&redirect_uri=https://evil.com",
        ]
        for link in oauth_links[:3]:
            parsed = urllib.parse.urlparse(link)
            params = urllib.parse.parse_qs(parsed.query)
            redirect_uri = params.get("redirect_uri", [""])[0]
            if not redirect_uri:
                continue
            for trick in open_redirect_tricks:
                test_url = trick(link)
                resp, status = self._make_request(test_url)
                if resp and "evil.com" in resp:
                    self.add_vuln(
                        title="OAuth Redirect URI Bypass via Parameter Injection",
                        severity="High",
                        category="OAuth Misconfiguration",
                        cvss_score=7.8,
                        description=f"OAuth redirect_uri can be bypassed via parameter injection. "
                            f"Test URL: `{test_url[:200]}`. Attacker can redirect auth codes to their own server.",
                        remediation="Perform strict server-side validation of redirect_uri against a "
                            "pre-registered allowlist. Do not accept partial matches or URL fragments.",
                        evidence=f"Bypass URL reflected evil.com: {test_url[:200]}",
                        confidence="High",
                        cwe_ids=["CWE-862"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )

    def _test_redirect_uri_callback_bypass(self, html: str):
        """Test redirect URI bypass using build_callback_url for OOB detection."""
        callback_url = build_callback_url("/oauth-test")
        oauth_links = re.findall(
            r'href=["\']([^"\']*(?:oauth|authorize|connect/authorize)[^"\']*)["\']',
            html, re.I)
        for link in oauth_links[:2]:
            parsed = urllib.parse.urlparse(link)
            params = urllib.parse.parse_qs(parsed.query)
            if "redirect_uri" in params:
                test_url = link.replace(params["redirect_uri"][0], callback_url)
                resp, status = self._make_request(test_url)
                if resp and status < 400:
                    self.add_vuln(
                        title="OAuth Redirect URI Bypass via Callback URL Injection",
                        severity="Critical",
                        category="OAuth Misconfiguration",
                        cvss_score=9.1,
                        description=f"OAuth redirect_uri can be replaced with an attacker-controlled "
                            f"callback URL: `{callback_url}`. This allows full authorization code theft.",
                        remediation="Validate redirect_uri strictly against a pre-registered allowlist. "
                            "Reject any redirect_uri not matching the registered pattern.",
                        evidence=f"Callback URL {callback_url} accepted as redirect_uri",
                        payload=test_url[:200],
                        request_details=f"GET {test_url[:200]}",
                        response_details=f"HTTP {status}",
                        confidence="Confirmed",
                        cwe_ids=["CWE-862"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return

    def _test_csrf_callback(self, html: str):
        oauth_links = re.findall(
            r'href=["\']([^"\']*(?:oauth|authorize|connect/authorize)[^"\']*)["\']',
            html, re.I)
        for link in oauth_links[:3]:
            parsed = urllib.parse.urlparse(link)
            params = urllib.parse.parse_qs(parsed.query)
            if "state" not in params and "response_type" in params:
                self.add_vuln(
                    title="OAuth Callback CSRF — Missing state Parameter",
                    severity="Critical",
                    category="OAuth Misconfiguration",
                    cvss_score=8.0,
                    description=f"OAuth authorization request missing `state` parameter makes the "
                        f"callback endpoint vulnerable to CSRF. An attacker can initiate an auth flow, "
                        f"then trick the victim into completing it, linking the victim's account to "
                        f"the attacker's session.",
                    remediation="Always include and validate a cryptographically random `state` parameter "
                        "in the OAuth authorization request and callback.",
                    evidence=f"Missing state in: {link[:200]}",
                    confidence="High",
                    cwe_ids=["CWE-862"],
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                )

    def _test_pkce_downgrade(self, html: str):
        """Test for PKCE downgrade by removing code_challenge from authorization request."""
        oauth_links = re.findall(
            r'href=["\']([^"\']*(?:oauth|authorize|connect/authorize)[^"\']*)["\']',
            html, re.I)
        for link in oauth_links[:2]:
            parsed = urllib.parse.urlparse(link)
            params = urllib.parse.parse_qs(parsed.query)
            if "code_challenge" in params:
                # Remove code challenge to test PKCE downgrade
                clean_params = {k: v for k, v in params.items() if k != "code_challenge" and k != "code_challenge_method"}
                new_query = urllib.parse.urlencode(clean_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                resp, status = self._make_request(test_url)
                if resp and status < 400:
                    self.add_vuln(
                        title="OAuth PKCE Downgrade Possible",
                        severity="High",
                        category="OAuth Misconfiguration",
                        cvss_score=8.0,
                        description=f"OAuth authorization request accepted without the `code_challenge` "
                            f"parameter, indicating PKCE can be downgraded. Without PKCE, authorization "
                            f"codes can be intercepted on public clients.",
                        remediation="1. Require code_challenge on all authorization requests.\n"
                            "2. Reject requests that omit code_challenge for public clients.\n"
                            "3. Enforce code_challenge_method=S256 on the server.",
                        evidence="Authorization request succeeded without code_challenge parameter",
                        payload=test_url[:200],
                        request_details=f"GET {test_url[:200]}",
                        response_details=f"HTTP {status}",
                        confidence="High",
                        cwe_ids=["CWE-862"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )
                    return

    def _test_token_leakage_referer(self, html: str):
        token_patterns = re.findall(
            r'(?:access_token|id_token|token)=([^&\s"\']{10,})',
            html, re.I)
        if token_patterns:
            self.add_vuln(
                title="OAuth Token Leakage via Referer Header",
                severity="High",
                category="OAuth Misconfiguration",
                cvss_score=6.5,
                description=f"OAuth tokens found in URLs within the page. When users navigate away, "
                    f"the Referer header will leak these tokens to external sites.\n"
                    f"Sample tokens: `{token_patterns[0][:50]}...`",
                remediation="Use fragment (#) instead of query string (?) for token transmission. "
                    "Set Referrer-Policy: no-referrer on all pages.",
                evidence=f"Token pattern found in URL: {token_patterns[0][:50]}",
                payload=token_patterns[0][:50],
                confidence="Confirmed",
                cwe_ids=["CWE-862"],
                owasp_category="A07:2021 – Identification and Authentication Failures",
            )
