import re, math
from html.parser import HTMLParser
from collections import Counter
from scanners.base_scanner import BaseScanner


class JSExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.js_urls = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            for name, value in attrs:
                if name == "src" and value:
                    self.js_urls.append(value)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_FP_CONTEXT_KEYWORDS = (
    "data:image", "data:font", "srcset", "blob:https", "cdn-cgi",
    "oEmbed", "oembed", "media.instagram", "fbcdn", "akamaized",
    "cloudflare", "w3.org", "schema.org", "xmlns", "svg", "gzip",
    "content-type", "etag", "cache-control",
)

_MIN_ENTROPY_FOR_GENERIC = 3.5


def _is_likely_fp(match: str, context: str) -> bool:
    low_ctx = context.lower()
    for kw in _FP_CONTEXT_KEYWORDS:
        if kw in low_ctx:
            return True
    return False


_SIGNATURES = [
    ("Stripe Live Secret Key",        r"sk_live_[0-9a-zA-Z]{24,}",                   None, []),
    ("Stripe Restricted Key",         r"rk_live_[0-9a-zA-Z]{24,}",                   None, []),
    ("Stripe Publishable Key",        r"pk_live_[0-9a-zA-Z]{24,}",                   None, []),
    ("AWS Access Key ID",             r"AKIA[0-9A-Z]{16}",                            None, []),
    ("Google API Key",                r"AIza[0-9A-Za-z\-_]{35}",                      None, []),
    ("Google Cloud Service Account",  r'"type":\s*"service_account"',                 None, []),
    ("JSON Web Token",                r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]{20,}", None, []),
    ("Slack Bot Token",               r"xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}",   None, []),
    ("Slack Webhook URL",             r"https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24}", None, []),
    ("GitHub Personal Access Token",  r"ghp_[a-zA-Z0-9]{36}",                         None, []),
    ("GitHub OAuth Token",            r"gho_[a-zA-Z0-9]{36}",                         None, []),
    ("GitLab Personal Access Token",  r"glpat-[a-zA-Z0-9_-]{20}",                    None, []),
    ("SendGrid API Key",              r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",   None, []),
    ("Shopify API Key",               r"shp[a-zA-Z0-9]{32}",                          None, []),
    ("Discord Bot Token",             r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",    None, []),
    ("Telegram Bot Token",            r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",               None, []),
    ("Firebase Service Account",      r'"firebase-adminsdk-[a-z0-9]+@[a-z0-9-]+\.iam\.gserviceaccount\.com"', None, []),
    ("PostgreSQL Connection String",  r"postgresql://[a-zA-Z0-9_:%@.-]+:[0-9]+/[a-zA-Z0-9_]+", None, []),
    ("MySQL Connection String",       r"mysql://[a-zA-Z0-9_:%@.-]+:[0-9]+/[a-zA-Z0-9_]+",      None, []),
    ("MongoDB Connection String",     r"mongodb(\+srv)?://[a-zA-Z0-9_:%@.-]+",                  None, []),
    ("Redis Connection String",       r"redis://[a-zA-Z0-9_:%@.-]+:[0-9]+",                     None, []),
    ("Mailgun API Key",               r"key-[a-zA-Z0-9]{32}",                          None, []),
    ("Square Sandbox Token",          r"sandbox-[a-zA-Z0-9]{22}",                     None, []),
    ("DigitalOcean API Key",          r"doo_v_[a-f0-9]{64}",                          None, []),
    ("RSA Private Key",               r"-----BEGIN RSA PRIVATE KEY-----",              None, []),
    ("DSA Private Key",               r"-----BEGIN DSA PRIVATE KEY-----",              None, []),
    ("EC Private Key",                r"-----BEGIN EC PRIVATE KEY-----",               None, []),
    ("OpenSSH Private Key",           r"-----BEGIN OPENSSH PRIVATE KEY-----",         None, []),
    ("PGP Private Key",               r"-----BEGIN PGP PRIVATE KEY BLOCK-----",       None, []),
    ("AWS MFA ARN",                   r"arn:aws:iam::[0-9]{12}:mfa/[a-zA-Z0-9]+",     None, []),
    ("AWS S3 Bucket URL",             r"s3://[a-zA-Z0-9._-]+",                        None, []),
    ("AWS Lambda ARN",                r"arn:aws:lambda:[a-z0-9-]+:[0-9]{12}:function:[a-zA-Z0-9_-]+", None, []),
    ("Docker Registry Auth",          r'"auths":\s*{',                                 None, []),
    ("Twilio Account SID",            r"\bAC[a-zA-Z0-9]{32}\b",                       None, ["twilio", "TWILIO"]),
    ("Twilio API Key",                r"\bSK[a-zA-Z0-9]{32}\b",                       None, ["twilio", "TWILIO"]),
    ("AWS Secret Access Key",         r"[A-Za-z0-9/+=]{40}",                    4.2, ["aws_secret", "AWS_SECRET", "secretAccessKey", "SecretAccessKey"]),
    ("Azure Storage Account Key",     r"[a-zA-Z0-9/+]{86}==",                   4.5, ["storageAccount", "storage_account", "AccountKey", "azure"]),
    ("Heroku API Key",                r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", None, ["heroku", "HEROKU"]),
    ("OpenAI API Key",                r"sk-[a-zA-Z0-9]{20,}",                   4.0, ["openai", "OPENAI", "sk-"]),
    ("npm Token",                     r"npm_[a-zA-Z0-9]{36}",                        None, []),
    ("GitLab CI Job Token",           r"glci-[a-zA-Z0-9]{20,}",                      None, []),
    ("New Relic API Key",             r"NRAK-[A-Z0-9]{27}",                           None, []),
    ("PagerDuty API Key",             r"pdy_[a-zA-Z0-9]{20}",                         None, []),
    ("Terraform API Token",           r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_]{64,}", None, ["terraform", "TERRAFORM", "atlasv1"]),
    ("Grafana API Key",               r"eyJrIjoi[a-zA-Z0-9]{16,}",                    None, []),
    ("SonarQube Token",               r"squ_[0-9a-f]{40}",                            None, []),
    ("Docker Hub Token",              r"dckr_pat_[a-zA-Z0-9\-_]{26,}",               None, []),
    ("Facebook Access Token",         r"EAACEdEose0cBA[a-zA-Z0-9]{20,}",              None, []),
    ("Google OAuth Client ID",        r"[0-9]{12,}\-[a-zA-Z0-9_]{32,}\.apps\.googleusercontent\.com", None, []),
    ("Google OAuth Client Secret",    r"GOCSPX-[a-zA-Z0-9\-_]{28}",                    None, []),
    ("Alibaba Cloud Key",             r"LTAI[a-zA-Z0-9]{12,}",                         None, []),
    ("Mailchimp API Key",             r"[a-f0-9]{32}-us[0-9]{1,2}",                   None, []),
    ("Slack Access Token",            r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-f0-9]{32}", None, []),
    ("HubSpot API Key",               r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", None, ["hubspot", "HUBSPOT"]),
    ("Datadog API Key",               r"[a-f0-9]{32}",                          4.5, ["datadog", "DATADOG", "DD_API_KEY"]),
    ("Bitbucket App Password",        r"[a-zA-Z0-9]{32}",                       4.2, ["bitbucket", "BITBUCKET", "app_password"]),
    ("CircleCI Token",                r"[a-f0-9]{40}",                          4.2, ["circleci", "CIRCLECI"]),
]


class SecretsScanner(BaseScanner):
    SCANNER_NAME = "Embedded Secrets & JS Analyzer"
    _SCANNER_KEY = "secrets"

    def run(self):
        self.log("INFO", f"[Secrets] Analyzing client-side assets on {self.target} for leaked secrets...")

        html_body, html_status, html_headers = self._make_request(
            self.target,
            headers={"User-Agent": "LarShield/2.0 Secret-Hunter"},
            timeout=10,
            return_response_obj=True,
        )
        if html_status == 0:
            self.log("WARNING", "[Secrets] Could not fetch target page.")
            return self.vulns

        parser = JSExtractor()
        parser.feed(html_body)

        sources = [(self.target, html_body)]
        for js_url in parser.js_urls[:10]:
            if js_url.startswith("//"):
                full_url = f"https:{js_url}"
            elif js_url.startswith("/"):
                full_url = f"{self.target.rstrip('/')}{js_url}"
            elif not js_url.startswith("http"):
                full_url = f"{self.target.rstrip('/')}/{js_url}"
            else:
                full_url = js_url
            js_body, js_status, _ = self._make_request(
                full_url,
                headers={"User-Agent": "LarShield/2.0 Secret-Hunter"},
                timeout=8,
                return_response_obj=True,
            )
            if js_status != 0 and js_body:
                sources.append((full_url, js_body))

        reported: set[tuple] = set()

        for source_url, content in sources:
            for sig_name, pattern, min_entropy, kw_ctx in _SIGNATURES:
                compiled = re.compile(pattern)
                for m in compiled.finditer(content):
                    match_val = m.group(0)

                    if min_entropy is not None:
                        if _entropy(match_val) < min_entropy:
                            continue

                    if kw_ctx:
                        start = max(0, m.start() - 120)
                        end = min(len(content), m.end() + 120)
                        surrounding = content[start:end]
                        if not any(kw in surrounding for kw in kw_ctx):
                            continue

                    start_ctx = max(0, m.start() - 80)
                    end_ctx = min(len(content), m.end() + 80)
                    ctx_slice = content[start_ctx:end_ctx]
                    if _is_likely_fp(match_val, ctx_slice):
                        continue

                    masked = (
                        match_val[:5] + "***" + match_val[-5:]
                        if len(match_val) > 10 else "***"
                    )
                    dedup_key = (sig_name, masked)
                    if dedup_key in reported:
                        continue
                    reported.add(dedup_key)

                    self.log("CRITICAL", f"[Secrets] Found {sig_name} in {source_url}!")
                    self.add_vuln(
                        title=f"Hardcoded {sig_name} Leak",
                        severity="Critical",
                        category="Information Disclosure",
                        cvss_score=9.5,
                        description=(
                            f"A sensitive API key or token ({sig_name}) was found hardcoded "
                            f"in client-side code at `{source_url}`.\n\n"
                            f"Leaked value (masked): `{masked}`\n\n"
                            "Attackers can extract this key and use it to impersonate your "
                            "application, steal data, or incur massive billing charges."
                        ),
                        remediation=(
                            "1. Immediately revoke and rotate the compromised key.\n"
                            "2. Move secret-bearing API calls to your backend server.\n"
                            "3. Never bundle secrets in frontend env vars "
                            "(REACT_APP_*, VITE_*) — they are embedded in the JS bundle."
                        ),
                        evidence=f"Source: {source_url}",
                        confidence="Confirmed",
                        cwe_ids=["CWE-798"],
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                    )

        status = "SUCCESS" if not self.vulns else "WARNING"
        self.log(status, "[Secrets] Analysis complete.")
        return self.vulns
