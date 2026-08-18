"""
__init__.py — Scanner pipeline dispatcher.
Maps scan_type -> ordered list of scanner module classes.
"""
from .headers_scanner          import HeadersScanner
from .nmap_scanner             import NmapScanner
from .sslyze_scanner           import SslyzeScanner
from .tech_scanner             import TechScanner
from .whois_scanner            import WhoisScanner
from .fuzzer_scanner           import FuzzerScanner
from .path_traversal_scanner   import PathTraversalScanner
from .nikto_scanner            import NiktoScanner
from .subdomain_scanner        import SubdomainScanner
from .waf_scanner              import WafScanner
from .cors_scanner             import CorsScanner
from .robots_scanner           import RobotsScanner
from .directory_scanner        import DirectoryScanner
from .zap_scanner              import ZapScanner
from .nuclei_scanner           import NucleiScanner
from .api_scanner              import ApiScanner
from .secrets_scanner          import SecretsScanner
from .cloud_scanner            import CloudScanner
from .cve_scanner              import CveScanner
from .xxe_scanner              import XxeScanner
from .ssrf_scanner             import SsrfScanner
from .jwt_scanner              import JwtScanner
from .idor_scanner             import IdorScanner
from .graphql_scanner          import GraphqlScanner
from .race_condition_scanner   import RaceConditionScanner
from .request_smuggling_scanner import RequestSmugglingScanner
from .business_logic_scanner   import BusinessLogicScanner
from .sql_injection_scanner    import SqlInjectionScanner
from .websocket_scanner        import WebsocketScanner
from .rate_limiting_scanner    import RateLimitingScanner
from .whatweb_scanner          import WhatWebScanner
from .dns_security_scanner     import DNSSecurityScanner
from .custom_website_scanner   import CustomWebsiteScanner
# ── Batch 1 (added previously) ────────────────────────────────────────────
from .ssti_scanner             import SstiScanner
from .open_redirect_scanner    import OpenRedirectScanner
from .cookie_scanner           import CookieScanner
from .csrf_scanner             import CsrfScanner
from .lfi_scanner              import LfiScanner
# ── Batch 2 (new) ─────────────────────────────────────────────────────────
from .auth_scanner             import AuthScanner
from .session_scanner          import SessionScanner
from .csp_scanner              import CspScanner
from .clickjacking_scanner     import ClickjackingScanner
from .git_exposure_scanner     import GitExposureScanner
from .dependency_scanner       import DependencyScanner
from .attack_surface_scanner   import AttackSurfaceScanner
from .compliance_scanner       import ComplianceScanner
from .ai_remediation_scanner   import AiRemediationScanner

# ── Batch 3: High Priority Gaps ───────────────────────────────────────────
from .subdomain_takeover_scanner import SubdomainTakeoverScanner
from .host_header_scanner      import HostHeaderScanner
from .deserialization_scanner  import DeserializationScanner
from .command_injection_scanner import CommandInjectionScanner
from .crlf_scanner             import CrlfScanner
from .cms_scanner              import CmsScanner
from .file_upload_scanner      import FileUploadScanner

# ── Batch 4: Medium Priority ──────────────────────────────────────────────
from .nosql_scanner             import NosqlScanner
from .cache_poisoning_scanner   import CachePoisoningScanner
from .oauth_scanner             import OauthScanner
from .prototype_pollution_scanner import PrototypePollutionScanner
from .source_map_scanner        import SourceMapScanner
from .swagger_scanner           import SwaggerScanner
from .email_security_scanner    import EmailSecurityScanner
from .xpath_scanner             import XpathScanner

# ── Batch 5: Lower Priority ───────────────────────────────────────────────
from .broken_link_scanner       import BrokenLinkScanner
from .sri_scanner               import SriScanner
from .mfa_bypass_scanner        import MfaBypassScanner
from .mass_assignment_scanner   import MassAssignmentScanner
from .http_pollution_scanner    import HttpPollutionScanner
from .dns_rebinding_scanner     import DnsRebindingScanner
from .exif_scanner              import ExifScanner
from .tls_weakness_scanner      import TlsWeaknessScanner
from .cert_transparency_scanner import CertTransparencyScanner
from .redos_scanner             import RedosScanner

# ── Batch 6: New Distinct Attack Vectors ─────────────────────────────────
from .dom_xss_scanner           import DomXssScanner
from .saml_scanner              import SamlScanner
from .web_cache_deception_scanner import WebCacheDeceptionScanner
from .http_method_tampering_scanner import HttpMethodTamperingScanner
from .bypass_403_scanner        import Bypass403Scanner
from .ldap_scanner              import LdapScanner
from .blind_xss_scanner         import BlindXssScanner
from .admin_panel_scanner       import AdminPanelScanner

# ── Batch 7: Client-Side & Logic Gaps ────────────────────────────────────
from .csti_scanner              import CstiScanner
from .postmessage_scanner       import PostmessageScanner
from .password_reset_scanner    import PasswordResetScanner
from .cache_control_scanner     import CacheControlScanner
from .second_order_scanner      import SecondOrderScanner
from .webrtc_leak_scanner       import WebrtcLeakScanner
from .service_worker_scanner    import ServiceWorkerScanner

# ── Batch 8: Advanced Attack Techniques ──────────────────────────────────
from .http2_desync_scanner       import Http2DesyncScanner
from .js_supply_chain_scanner    import JsSupplyChainScanner
from .api_security_scanner       import ApiSecurityScanner

# ---------------------------------------------------------------------------
# Pipeline definitions — order matters, runs top-to-bottom
# AiRemediationScanner always runs LAST (post-processor)
# ---------------------------------------------------------------------------
PIPELINES = {
    # ── Quick: fast, non-intrusive checks (~2 min) ─────────────────────────
    "Quick": [
        ("headers",       HeadersScanner,      {}),
        ("nmap",          NmapScanner,         {"mode": "quick"}),
        ("sslyze",        SslyzeScanner,       {}),
        ("tech",          TechScanner,         {}),
        ("whois",         WhoisScanner,        {}),
        ("waf",           WafScanner,          {}),
        ("dns_security",  DNSSecurityScanner,  {}),
        ("cookies",       CookieScanner,       {}),
        ("csp",           CspScanner,          {}),
        ("clickjacking",  ClickjackingScanner, {}),
        ("git_exposure",  GitExposureScanner,  {}),
        ("compliance",    ComplianceScanner,   {}),
        ("ai_remediation",AiRemediationScanner,{}),
    ],

    # ── Advanced: core vulnerability audit (~10-20 min) ────────────────────────
    "Advanced": [
        ("headers",          HeadersScanner,        {}),
        ("nmap",             NmapScanner,           {"mode": "standard"}),
        ("sslyze",           SslyzeScanner,         {}),
        ("tech",             TechScanner,           {}),
        ("whois",            WhoisScanner,          {}),
        ("waf",              WafScanner,            {}),
        ("dns_security",     DNSSecurityScanner,    {}),
        ("cookies",          CookieScanner,         {}),
        ("csp",              CspScanner,            {}),
        ("clickjacking",     ClickjackingScanner,   {}),
        ("git_exposure",     GitExposureScanner,    {}),
        ("compliance",       ComplianceScanner,     {}),
        ("whatweb",          WhatWebScanner,        {}),
        ("cors",             CorsScanner,           {}),
        ("robots",           RobotsScanner,         {}),
        ("auth",             AuthScanner,           {}),
        ("session",          SessionScanner,        {}),
        ("dependency",       DependencyScanner,     {}),
        ("fuzzer",           FuzzerScanner,         {}),
        ("path_traversal",   PathTraversalScanner,  {}),
        ("lfi",              LfiScanner,            {}),
        ("nikto",            NiktoScanner,          {}),
        ("sql_injection",    SqlInjectionScanner,   {}),
        ("subdom",           SubdomainScanner,      {}),
        ("custom_website",   CustomWebsiteScanner,  {}),
        ("attack_surface",   AttackSurfaceScanner,  {}),
        ("api",              ApiScanner,            {}),
        ("cloud",            CloudScanner,          {}),
        ("secrets",          SecretsScanner,        {}),
        ("cve",              CveScanner,            {}),
        ("ssrf",             SsrfScanner,           {}),
        ("jwt",              JwtScanner,            {}),
        ("csrf",             CsrfScanner,           {}),
        ("open_redirect",    OpenRedirectScanner,   {}),
        ("rate_limiting",    RateLimitingScanner,   {}),
        ("ai_remediation",   AiRemediationScanner,  {}),
    ],

    # ── Deep: exhaustive + ZAP active (~2 h) ──────────────────────────────
    "Deep": [
        ("headers",           HeadersScanner,        {}),
        ("nmap",              NmapScanner,           {"mode": "deep"}),
        ("sslyze",            SslyzeScanner,         {}),
        ("tech",              TechScanner,           {}),
        ("whatweb",           WhatWebScanner,        {}),
        ("whois",             WhoisScanner,          {}),
        ("dns_security",      DNSSecurityScanner,    {}),
        ("cookies",           CookieScanner,         {}),
        ("csp",               CspScanner,            {}),
        ("clickjacking",      ClickjackingScanner,   {}),
        ("cors",              CorsScanner,           {}),
        ("robots",            RobotsScanner,         {}),
        ("directory",         DirectoryScanner,      {}),
        ("waf",               WafScanner,            {}),
        ("auth",              AuthScanner,           {}),
        ("session",           SessionScanner,        {}),
        ("git_exposure",      GitExposureScanner,    {}),
        ("dependency",        DependencyScanner,     {}),
        ("fuzzer",            FuzzerScanner,         {"red_team": True}),
        ("path_traversal",    PathTraversalScanner,  {}),
        ("lfi",               LfiScanner,            {}),
        ("nikto",             NiktoScanner,          {}),
        ("subdom",            SubdomainScanner,      {}),
        ("custom_website",    CustomWebsiteScanner,  {}),
        ("attack_surface",    AttackSurfaceScanner,  {}),
        ("api",               ApiScanner,            {}),
        ("cloud",             CloudScanner,          {}),
        ("secrets",           SecretsScanner,        {}),
        ("cve",               CveScanner,            {}),
        ("xxe",               XxeScanner,            {}),
        ("ssrf",              SsrfScanner,           {}),
        ("jwt",               JwtScanner,            {}),
        ("ssti",              SstiScanner,           {}),
        ("csrf",              CsrfScanner,           {}),
        ("open_redirect",     OpenRedirectScanner,   {}),
        ("idor",              IdorScanner,           {}),
        ("graphql",           GraphqlScanner,        {}),
        ("race_condition",    RaceConditionScanner,  {}),
        ("request_smuggling", RequestSmugglingScanner,{}),
        ("business_logic",    BusinessLogicScanner,  {}),
        ("websocket",         WebsocketScanner,      {}),
        ("rate_limiting",     RateLimitingScanner,   {}),
        ("subdomain_takeover",SubdomainTakeoverScanner,{}),
        ("host_header",       HostHeaderScanner,     {}),
        ("deserialization",   DeserializationScanner,{}),
        ("command_injection", CommandInjectionScanner,{}),
        ("sql_injection",     SqlInjectionScanner,   {}),
        ("crlf",              CrlfScanner,           {}),
        ("cms",               CmsScanner,            {}),
        ("file_upload",       FileUploadScanner,     {}),
        ("nosql",             NosqlScanner,          {}),
        ("cache_poisoning",   CachePoisoningScanner, {}),
        ("oauth",             OauthScanner,          {}),
        ("prototype_pollution",PrototypePollutionScanner,{}),
        ("source_map",        SourceMapScanner,      {}),
        ("swagger",           SwaggerScanner,        {}),
        ("email_security",    EmailSecurityScanner,  {}),
        ("xpath",             XpathScanner,          {}),
        ("broken_link",       BrokenLinkScanner,     {}),
        ("sri",               SriScanner,            {}),
        ("mfa_bypass",        MfaBypassScanner,      {}),
        ("mass_assignment",   MassAssignmentScanner, {}),
        ("http_pollution",    HttpPollutionScanner,  {}),
        ("dns_rebinding",     DnsRebindingScanner,   {}),
        ("exif",              ExifScanner,           {}),
        ("tls_weakness",      TlsWeaknessScanner,    {}),
        ("cert_transparency", CertTransparencyScanner,{}),
        ("redos",             RedosScanner,          {}),
        ("dom_xss",           DomXssScanner,         {}),
        ("saml",              SamlScanner,           {}),
        ("cache_deception",   WebCacheDeceptionScanner,{}),
        ("http_methods",      HttpMethodTamperingScanner,{}),
        ("bypass_403",        Bypass403Scanner,      {}),
        ("ldap",              LdapScanner,           {}),
        ("blind_xss",         BlindXssScanner,       {}),
        ("admin_panel",       AdminPanelScanner,     {}),
        ("csti",              CstiScanner,           {}),
        ("postmessage",       PostmessageScanner,    {}),
        ("password_reset",    PasswordResetScanner,  {}),
        ("cache_control",     CacheControlScanner,   {}),
        ("second_order",      SecondOrderScanner,    {}),
        ("webrtc",            WebrtcLeakScanner,     {}),
        ("service_worker",    ServiceWorkerScanner,  {}),
        ("compliance",        ComplianceScanner,     {}),
        ("nuclei",            NucleiScanner,         {"severity": "critical,high,medium,low"}),
        ("zap",               ZapScanner,            {"mode": "active"}),
        # ── Advanced Techniques ────────────────────────────────
        ("h2_desync",         Http2DesyncScanner,    {}),
        ("js_supply_chain",   JsSupplyChainScanner,  {}),
        ("api_security",      ApiSecurityScanner,    {}),
        ("ai_remediation",    AiRemediationScanner,  {}),   # LAST
    ],

    # Legacy aliases
    "Standard": None,
    "Full":     None,
    "SSL":      None,
    "OWASP":    None,
    "Port":     None,
}

# Resolve aliases
PIPELINES["Standard"] = PIPELINES["Advanced"]
PIPELINES["Full"]     = PIPELINES["Advanced"]
PIPELINES["OWASP"]    = PIPELINES["Advanced"]
PIPELINES["Port"]     = [("nmap", NmapScanner, {"mode": "standard"})]
PIPELINES["SSL"]      = [
    ("sslyze",     SslyzeScanner,  {}),
    ("headers",    HeadersScanner, {}),
    ("csp",        CspScanner,     {}),
    ("clickjacking",ClickjackingScanner, {}),
]


CRAWLER_SCANNERS = frozenset({
    "fuzzer", "path_traversal", "lfi", "ssti",
    "open_redirect", "csrf", "attack_surface",
    "sql_injection",
})

SCAN_TYPE_DEFAULT_DEPTH = {
    "Quick":    3,
    "Advanced": 10,
    "Deep":     20,
    "Standard": 10,
}


# ---------------------------------------------------------------------------
# Phase definitions — controls execution order within each scan type.
# Each phase runs its modules CONCURRENTLY, phases run SEQUENTIALLY.
# AI remediation is always last; heavy tools (ZAP/Nuclei) are second-to-last.
# ---------------------------------------------------------------------------
SCAN_PHASES = {
    # ── Quick (2 phases, ~2 min total) ─────────────────────────────────────
    "Quick": [
        {
            "name": "Phase 1: Recon & Headers",
            "keys": {"headers", "nmap", "sslyze", "tech", "whois", "waf",
                     "dns_security", "git_exposure"},
        },
        {
            "name": "Phase 2: Config & Policy",
            "keys": {"cookies", "csp", "clickjacking", "compliance", "ai_remediation"},
        },
    ],

    # ── Advanced (4 phases, ~10-20 min total) ───────────────────────────────
    "Advanced": [
        {
            "name": "Phase 1: Recon & Fingerprinting",
            "keys": {"headers", "nmap", "sslyze", "tech", "whatweb", "whois",
                     "waf", "dns_security", "git_exposure", "cloud", "cve",
                     "robots", "cors"},
        },
        {
            "name": "Phase 2: Auth & Session",
            "keys": {"auth", "session", "cookies", "csp", "clickjacking",
                     "compliance", "dependency", "jwt", "csrf"},
        },
        {
            "name": "Phase 3: Injection & Crawl",
            "keys": {"sql_injection", "ssrf", "fuzzer", "path_traversal",
                     "lfi", "nikto", "open_redirect", "subdom",
                     "custom_website", "attack_surface", "api",
                     "secrets", "rate_limiting"},
        },
        {
            "name": "Phase 4: AI Analysis",
            "keys": {"ai_remediation"},
        },
    ],

    # ── Deep (8 phases, ~2h total) ─────────────────────────────────────────
    "Deep": [
        {
            "name": "Phase 1: Recon & Fingerprinting",
            "keys": {"headers", "nmap", "sslyze", "tech", "whatweb", "whois",
                     "dns_security", "waf", "cloud", "cve", "cert_transparency",
                     "robots", "tls_weakness", "exif", "source_map",
                     "email_security", "sri"},
        },
        {
            "name": "Phase 2: Auth, Session & Config",
            "keys": {"auth", "session", "cookies", "csp", "clickjacking",
                     "git_exposure", "dependency", "compliance", "cors",
                     "jwt", "oauth", "saml", "mfa_bypass", "password_reset"},
        },
        {
            "name": "Phase 3: Injection Attacks",
            "keys": {"sql_injection", "xxe", "ssrf", "ssti", "command_injection",
                     "nosql", "xpath", "ldap", "crlf", "lfi",
                     "path_traversal", "deserialization", "redos"},
        },
        {
            "name": "Phase 4: Crawl, Directory & Discovery",
            "keys": {"fuzzer", "directory", "subdom", "subdomain_takeover",
                     "attack_surface", "custom_website", "api", "swagger",
                     "nikto", "broken_link", "admin_panel", "cms",
                     "graphql", "api_security"},
        },
        {
            "name": "Phase 5: Logic, Access Control & Rate",
            "keys": {"idor", "csrf", "open_redirect", "business_logic",
                     "race_condition", "rate_limiting", "mass_assignment",
                     "bypass_403", "request_smuggling", "websocket",
                     "file_upload", "second_order"},
        },
        {
            "name": "Phase 6: Client-Side & Protocol",
            "keys": {"host_header", "http_methods", "http_pollution",
                     "cache_poisoning", "cache_deception", "cache_control",
                     "dom_xss", "blind_xss", "csti", "postmessage",
                     "prototype_pollution", "dns_rebinding", "h2_desync",
                     "js_supply_chain", "service_worker", "webrtc",
                     "secrets"},
        },
        {
            "name": "Phase 7: Heavy Scanners (ZAP & Nuclei)",
            "keys": {"nuclei", "zap"},
        },
        {
            "name": "Phase 8: AI Analysis",
            "keys": {"ai_remediation"},
        },
    ],
}

# Resolve aliases for phases
SCAN_PHASES["Standard"] = SCAN_PHASES["Advanced"]
SCAN_PHASES["Full"]     = SCAN_PHASES["Advanced"]
SCAN_PHASES["OWASP"]    = SCAN_PHASES["Advanced"]
SCAN_PHASES["SSL"]      = [
    {"name": "Phase 1: SSL/TLS Checks",
     "keys": {"sslyze", "headers", "csp", "clickjacking"}},
]
SCAN_PHASES["Port"] = [
    {"name": "Phase 1: Port Scan",
     "keys": {"nmap"}},
]


def get_phases(scan_type: str) -> list:
    """Return the ordered phase list for the given scan type."""
    return SCAN_PHASES.get(scan_type, SCAN_PHASES["Advanced"])


def get_pipeline(scan_type: str) -> list:
    """Return the scanner pipeline for the given scan_type string."""
    return PIPELINES.get(scan_type, PIPELINES["Advanced"])


def apply_scan_options(pipeline: list, scan_type: str, scan_options: dict | None) -> list:
    """Merge user scan options (crawl depth, exclusions, red-team) into pipeline kwargs."""
    options     = scan_options or {}
    crawl_depth = options.get("crawl_depth")
    if crawl_depth is None:
        crawl_depth = SCAN_TYPE_DEFAULT_DEPTH.get(scan_type, 10)
    else:
        crawl_depth = max(1, min(int(crawl_depth), 20))

    exclude_paths   = options.get("exclude_paths") or []
    enable_red_team = options.get("enable_red_team", False)

    updated = []
    for name, cls, kwargs in pipeline:
        merged = dict(kwargs)
        if name in CRAWLER_SCANNERS:
            merged["max_depth"]     = crawl_depth
            merged["exclude_paths"] = exclude_paths
        if name == "fuzzer" and (enable_red_team or merged.get("red_team")):
            merged["red_team"] = True
        updated.append((name, cls, merged))
    return updated


def build_scanner(name, cls, kwargs, scan_id, target, domain, auth_headers=None):
    """Instantiate a scanner with the correct kwargs."""
    return cls(scan_id=scan_id, target=target, domain=domain,
               auth_headers=auth_headers, **kwargs)
