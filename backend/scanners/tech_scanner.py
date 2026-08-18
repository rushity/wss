"""
tech_scanner.py — Technology fingerprinting via HTTP headers and HTML analysis.
Identifies web server, framework, CMS, CDN, and analytics technologies.
Checks identified versions against a built-in EOL (end-of-life) list.
No external dependencies required.
"""
import re
from scanners.base_scanner import BaseScanner
from utils.fingerprint_db import match_tech, find_cves

HEADER_SIGNATURES = [
    ("server",          "Web Server",   r"nginx/?(\S+)?",       "Nginx"),
    ("server",          "Web Server",   r"apache/?(\S+)?",      "Apache"),
    ("server",          "Web Server",   r"Microsoft-IIS/(\S+)", "IIS"),
    ("server",          "Web Server",   r"LiteSpeed",           "LiteSpeed"),
    ("server",          "Web Server",   r"Caddy",               "Caddy"),
    ("server",          "Web Server",   r"OpenResty",           "OpenResty"),
    ("server",          "Web Server",   r"Tengine",             "Tengine"),
    ("server",          "Web Server",   r"Gunicorn",            "Gunicorn"),
    ("server",          "Web Server",   r"uWSGI",               "uWSGI"),
    ("server",          "Web Server",   r"CherryPy",            "CherryPy"),
    ("server",          "Web Server",   r"Tomcat",              "Apache Tomcat"),
    ("server",          "Web Server",   r"TornadoServer",       "Tornado"),
    ("server",          "Web Server",   r"uvicorn",             "FastAPI/Starlette"),
    ("server",          "Web Server",   r"Bottle",              "Bottle"),
    ("server",          "Web Server",   r"cloudflare",          "Cloudflare"),
    ("server",          "Web Server",   r"Fly/[0-9]",           "Fly.io"),
    ("x-powered-by",   "Language",     r"PHP/(\S+)",           "PHP"),
    ("x-powered-by",   "Language",     r"Python/?(\S+)?",      "Python"),
    ("x-powered-by",   "Language",     r"Ruby/?(\S+)?",        "Ruby"),
    ("x-powered-by",   "Language",     r"Node\.js",            "Node.js"),
    ("x-powered-by",   "Language",     r"ASP\.NET",            "ASP.NET"),
    ("x-powered-by",   "Language",     r"Java",                "Java"),
    ("x-powered-by",   "Framework",    r"Express",             "Express.js"),
    ("x-powered-by",   "Framework",    r"Django/?(\S+)?",      "Django"),
    ("x-powered-by",   "Framework",    r"Flask",               "Flask"),
    ("x-powered-by",   "Framework",    r"Rails/?(\S+)?",       "Ruby on Rails"),
    ("x-powered-by",   "Framework",    r"Laravel",             "Laravel"),
    ("x-powered-by",   "Framework",    r"Symfony",             "Symfony"),
    ("x-powered-by",   "Framework",    r"Spring",              "Spring Framework"),
    ("x-powered-by",   "Framework",    r"Next\.js",            "Next.js"),
    ("x-powered-by",   "Framework",    r"Nuxt\.js",            "Nuxt.js"),
    ("x-powered-by",   "Framework",    r"Koa",                 "Koa"),
    ("x-powered-by",   "Framework",    r"Fastify",             "Fastify"),
    ("x-powered-by",   "Framework",    r"Hapi",                "Hapi"),
    ("x-powered-by",   "Framework",    r"Tornado",             "Tornado"),
    ("x-generator",    "CMS",          r"WordPress (\S+)",     "WordPress"),
    ("x-generator",    "CMS",          r"Joomla!",             "Joomla"),
    ("x-generator",    "CMS",          r"Drupal",              "Drupal"),
    ("x-generator",    "CMS",          r"Magento",             "Magento"),
    ("x-generator",    "CMS",          r"PrestaShop",          "PrestaShop"),
    ("x-generator",    "CMS",          r"Shopify",             "Shopify"),
    ("x-generator",    "CMS",          r"Wix",                 "Wix"),
    ("x-generator",    "CMS",          r"Squarespace",         "Squarespace"),
    ("x-drupal-cache", "CMS",          r".*",                  "Drupal"),
    ("x-varnish",      "Cache",        r".*",                  "Varnish Cache"),
    ("x-served-by",    "Cache",        r".*",                  "Varnish Cache"),
    ("cf-ray",         "CDN",          r".*",                  "Cloudflare"),
    ("x-amz-cf-id",    "CDN",          r".*",                  "Amazon CloudFront"),
    ("x-cache",        "CDN",          r".*",                  "Generic CDN/Cache"),
    ("x-akamai-transformed", "CDN",    r".*",                  "Akamai"),
    ("x-cdn",          "CDN",          r".*",                  "Generic CDN"),
    ("fastly-ssl",     "CDN",          r".*",                  "Fastly"),
    ("via",            "CDN",          r".*fastly.*",          "Fastly"),
    ("x-edge-location", "CDN",         r".*",                  "Akamai Edge"),
    ("x-aws-request-id", "Cloud",      r".*",                  "AWS"),
    ("x-google-app-engine", "Cloud",    r".*",                  "Google App Engine"),
    ("x-azure-ref",    "Cloud",        r".*",                  "Microsoft Azure"),
    ("cf-kv",          "Cloud",        r".*",                  "Cloudflare Workers KV"),
]

HTML_SIGNATURES = [
    (r"wp-content|wp-includes|WordPress",      "CMS",        "WordPress"),
    (r"/wp-json/",                             "CMS",        "WordPress REST API"),
    (r"Joomla!",                               "CMS",        "Joomla"),
    (r"Drupal\.settings",                      "CMS",        "Drupal"),
    (r"__VIEWSTATE",                           "Framework",  "ASP.NET WebForms"),
    (r"ng-version=\"([^\"]+)\"",               "Framework",  "Angular"),
    (r"react(?:\.min)?\.js|data-reactroot",    "Framework",  "React"),
    (r"vue(?:\.min)?\.js",                     "Framework",  "Vue.js"),
    (r"<meta[^>]*generator[^>]*WordPress",     "CMS",        "WordPress"),
    (r"jquery[.-](\d+\.\d+\.\d+)",            "Library",    "jQuery"),
    (r"bootstrap(?:\.min)?\.css",              "UI Library", "Bootstrap"),
    (r"googletagmanager\.com",                 "Analytics",  "Google Tag Manager"),
    (r"google-analytics\.com",                 "Analytics",  "Google Analytics"),
    (r"hotjar\.com",                           "Analytics",  "Hotjar"),
    (r"cdn\.shopify\.com",                     "E-Commerce", "Shopify"),
    (r"Magento",                               "E-Commerce", "Magento"),
    (r"PrestaShop",                            "E-Commerce", "PrestaShop"),
    (r"/s/[^/]+\.js",                          "E-Commerce", "Shopify"),
    (r"svelte(?:\.min)?\.js",                  "Framework",  "Svelte"),
    (r"ember(?:\.min)?\.js",                   "Framework",  "Ember.js"),
    (r"backbone(?:\.min)?\.js",                "Framework",  "Backbone.js"),
    (r"knockout(?:\.min)?\.js",                "Framework",  "Knockout.js"),
    (r"alpine(?:\.min)?\.js",                  "Framework",  "Alpine.js"),
    (r"htmx(?:\.min)?\.js",                    "Framework",  "HTMX"),
    (r"stimulus(?:\.min)?\.js",                "Framework",  "Stimulus"),
    (r"tailwind(?:\.min)?\.css",               "CSS Framework", "Tailwind CSS"),
    (r"bulma(?:\.min)?\.css",                  "CSS Framework", "Bulma"),
    (r"foundation(?:\.min)?\.css",             "CSS Framework", "Foundation"),
    (r"materialize(?:\.min)?\.css",            "CSS Framework", "Materialize"),
    (r"semantic(?:\.min)?\.css",               "CSS Framework", "Semantic UI"),
    (r"uikit(?:\.min)?\.css",                  "CSS Framework", "UIkit"),
    (r"material-design(?:\.min)?\.css",        "CSS Framework", "Material Design"),
    (r"fontawesome(?:\.min)?\.css",            "Icon Library", "Font Awesome"),
    (r"ionicons(?:\.min)?\.css",               "Icon Library", "Ionicons"),
    (r"material-icons",                        "Icon Library", "Material Icons"),
    (r"chart\.js",                             "Charting",   "Chart.js"),
    (r"d3(?:\.min)?\.js",                      "Charting",   "D3.js"),
    (r"plotly(?:\.min)?\.js",                  "Charting",   "Plotly"),
    (r"highcharts(?:\.min)?\.js",              "Charting",   "Highcharts"),
    (r"echarts(?:\.min)?\.js",                 "Charting",   "ECharts"),
    (r"moment(?:\.min)?\.js",                 "Date Library", "Moment.js"),
    (r"dayjs(?:\.min)?\.js",                   "Date Library", "Day.js"),
    (r"date-fns(?:\.min)?\.js",                "Date Library", "date-fns"),
    (r"lodash(?:\.min)?\.js",                  "Utility",    "Lodash"),
    (r"underscore(?:\.min)?\.js",              "Utility",    "Underscore.js"),
    (r"axios(?:\.min)?\.js",                   "HTTP Client", "Axios"),
    (r"fetch",                                 "HTTP Client", "Fetch API"),
    (r"graphql",                               "API",        "GraphQL"),
    (r"apollo",                                "API",        "Apollo GraphQL"),
    (r"relay",                                 "API",        "Relay GraphQL"),
    (r"swagger|openapi",                       "API",        "Swagger/OpenAPI"),
    (r"postman",                              "API",        "Postman"),
    (r"socket\.io(?:\.min)?\.js",              "Real-time",  "Socket.io"),
    (r"signalr",                              "Real-time",  "SignalR"),
    (r"pusher(?:\.min)?\.js",                 "Real-time",  "Pusher"),
    (r"firebase",                              "Backend",    "Firebase"),
    (r"supabase",                              "Backend",    "Supabase"),
    (r"amplify",                               "Backend",    "AWS Amplify"),
    (r"auth0",                                 "Auth",       "Auth0"),
    (r"okta",                                  "Auth",       "Okta"),
    (r"cognito",                               "Auth",       "AWS Cognito"),
    (r"firebaseauth",                          "Auth",       "Firebase Auth"),
    (r"recaptcha",                             "Captcha",    "reCAPTCHA"),
    (r"hcaptcha",                              "Captcha",    "hCaptcha"),
    (r"cloudflareturnstile",                  "Captcha",    "Cloudflare Turnstile"),
    (r"segment\.com",                          "Analytics",  "Segment"),
    (r"mixpanel",                              "Analytics",  "Mixpanel"),
    (r"amplitude",                             "Analytics",  "Amplitude"),
    (r"fullstory",                             "Analytics",  "FullStory"),
    (r"logrocket",                             "Analytics",  "LogRocket"),
    (r"clarity\.ms",                           "Analytics",  "Microsoft Clarity"),
    (r"optimizely",                            "A/B Testing", "Optimizely"),
    (r"vwo",                                   "A/B Testing", "VWO"),
    (r"abtasty",                               "A/B Testing", "AB Tasty"),
    (r"gtm\.js",                               "Analytics",  "Google Tag Manager"),
    (r"gtag\.js",                              "Analytics",  "Google Analytics 4"),
    (r"analytics\.js",                         "Analytics",  "Google Analytics"),
    (r"facebook\.net",                         "Social",     "Facebook SDK"),
    (r"twitter\.com",                          "Social",     "Twitter SDK"),
    (r"linkedin\.com",                         "Social",     "LinkedIn SDK"),
    (r"instagram\.com",                        "Social",     "Instagram SDK"),
    (r"pinterest\.com",                        "Social",     "Pinterest SDK"),
    (r"stripe\.com",                           "Payment",    "Stripe"),
    (r"paypal\.com",                           "Payment",    "PayPal"),
    (r"braintree",                             "Payment",    "Braintree"),
    (r"squareup\.com",                         "Payment",    "Square"),
    (r"adyen",                                 "Payment",    "Adyen"),
    (r"klarna",                                "Payment",    "Klarna"),
    (r"afterpay",                              "Payment",    "Afterpay"),
    (r"aws",                                   "Cloud",      "AWS"),
    (r"amazonaws\.com",                        "Cloud",      "AWS"),
    (r"googleapis\.com",                       "Cloud",      "Google Cloud"),
    (r"cloudfunctions\.net",                   "Cloud",      "Google Cloud Functions"),
    (r"firebaseio\.com",                       "Cloud",      "Firebase"),
    (r"azurewebsites\.net",                    "Cloud",      "Azure"),
    (r"azure\.net",                            "Cloud",      "Azure"),
    (r"herokuapp\.com",                        "Cloud",      "Heroku"),
    (r"vercel\.app",                          "Cloud",      "Vercel"),
    (r"netlify\.app",                          "Cloud",      "Netlify"),
    (r"cloudflare\.com",                       "Cloud",      "Cloudflare"),
    (r"fastly\.com",                           "Cloud",      "Fastly"),
    (r"akamai\.net",                           "Cloud",      "Akamai"),
    (r"cloudfront\.net",                       "Cloud",      "CloudFront"),
    (r"cloudinary\.com",                       "Media",      "Cloudinary"),
    (r"imgix\.net",                            "Media",      "Imgix"),
    (r"twimg\.com",                            "Media",      "Twitter Image CDN"),
    (r"fbcdn\.net",                            "Media",      "Facebook CDN"),
    (r"wp\.com",                               "CMS",        "WordPress.com"),
    (r"wixstatic\.com",                        "CMS",        "Wix"),
    (r"squarespace\.com",                      "CMS",        "Squarespace"),
    (r"weebly\.com",                          "CMS",        "Weebly"),
    (r"godaddy\.com",                          "Hosting",    "GoDaddy"),
    (r"bluehost\.com",                         "Hosting",    "Bluehost"),
    (r"hostgator\.com",                        "Hosting",    "HostGator"),
    (r"siteground\.com",                       "Hosting",    "SiteGround"),
    (r"webpackJsonp|__webpack_require__",       "Bundler",    "Webpack"),
    (r"vite(?:\.min)?\.js|/@vite/",           "Bundler",    "Vite"),
    (r"gatsby(?:\.min)?\.js",                  "Framework",  "Gatsby"),
    (r"<meta[^>]*generator[^>]*Jekyll",        "Framework",  "Jekyll"),
    (r"<meta[^>]*generator[^>]*Hugo",          "Framework",  "Hugo"),
    (r"docusaurus",                            "Framework",  "Docusaurus"),
    (r"yii\\.debug|yii\\.js",                   "Framework",  "Yii Framework"),
    (r"CAKEPHP|cake\.cookie|cake\.session",     "Framework",  "CakePHP"),
    (r"sails\.io\.js|__sails_io_sdk",          "Framework",  "Sails.js"),
    (r"adonis(?:\.min)?\.js",                  "Framework",  "AdonisJS"),
    (r"nest(?:\.min)?\.js|@nestjs",            "Framework",  "NestJS"),
    (r"umami\.js|umami\.is",                    "Analytics",  "Umami"),
    (r"plausible\.io",                         "Analytics",  "Plausible"),
    (r"cdn\.usefathom\.com",                   "Analytics",  "Fathom"),
    (r"mc\.yandex\.ru",                        "Analytics",  "Yandex Metrica"),
    (r"hm\.baidu\.com",                        "Analytics",  "Baidu Analytics"),
    (r"newrelic\.com|newrelic",               "Analytics",  "New Relic"),
    (r"sentry\.min\.js|sentry\.io",            "Error Tracking", "Sentry"),
    (r"datadoghq\.com.*rum",                   "Analytics",  "Datadog RUM"),
    (r"rollbar\.com|rollbar\.min\.js",          "Error Tracking", "Rollbar"),
    (r"bugsnag\.com|bugsnag\.min\.js",          "Error Tracking", "Bugsnag"),
    (r"clicky\.com",                           "Analytics",  "Clicky"),
    (r"matomo\.js|piwik\.js",                  "Analytics",  "Matomo"),
    (r"luckyorange\.com",                      "Analytics",  "Lucky Orange"),
    (r"heapanalytics\.com",                    "Analytics",  "Heap"),
    (r"crazyegg\.com",                         "Analytics",  "Crazy Egg"),
    (r"chartbeat\.js|chartbeat\.com",          "Analytics",  "Chartbeat"),
    (r"splunk\.com.*analytics",                "Analytics",  "Splunk"),
]

EOL_VERSIONS = {
    "PHP":       {"eol_before": "8.1", "desc": "PHP 7.x and below are end-of-life and no longer receive security patches."},
    "jQuery":    {"eol_before": "3.0", "desc": "jQuery versions below 3.x have known XSS and prototype pollution vulnerabilities."},
    "WordPress": {"eol_before": "6.0", "desc": "Older WordPress versions may contain unpatched vulnerabilities."},
    "Apache":    {"eol_before": "2.4", "desc": "Apache versions below 2.4 are end-of-life."},
    "Nginx":     {"eol_before": "1.18","desc": "Older Nginx versions may have unpatched vulnerabilities."},
    "Angular":   {"eol_before": "14.0","desc": "Older Angular versions may have unpatched vulnerabilities."},
    "React":     {"eol_before": "17.0","desc": "React versions below 17 have known issues."},
    "Drupal":    {"eol_before": "9.0", "desc": "Older Drupal versions may have unpatched vulnerabilities."},
    "Joomla":    {"eol_before": "4.0", "desc": "Older Joomla versions may have unpatched vulnerabilities."},
    "Magento":   {"eol_before": "2.4", "desc": "Older Magento versions may have unpatched vulnerabilities."},
}

EOL_VULNERABLE = {
    "PHP": {"min": "5.6", "max": "8.0"},
    "jQuery": {"min": "1.0", "max": "3.5"},
    "WordPress": {"min": "1.0", "max": "5.9"},
    "Apache": {"min": "1.0", "max": "2.3"},
    "Nginx": {"min": "0.1", "max": "1.17"},
}


class TechScanner(BaseScanner):
    SCANNER_NAME = "Technology Fingerprinting Scanner"
    _SCANNER_KEY = "tech"

    def run(self):
        self.log("INFO", f"[Tech] Fingerprinting technologies on {self.target}...")

        body, status, resp_headers = self._make_request(
            self.target,
            timeout=10,
            return_response_obj=True,
        )
        if status == 0:
            self.log("WARNING", f"[Tech] Could not reach target.")
            return self.vulns

        headers = {k.lower(): v for k, v in resp_headers.items()}
        self.log("INFO", f"[Tech] Response: HTTP {status} \u2014 analysing headers and HTML body...")
        detected = {}

        for hdr, category, pattern, tech_name in HEADER_SIGNATURES:
            val = headers.get(hdr, "")
            if val:
                m = re.search(pattern, val, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex else ""
                    detected[tech_name] = {"category": category, "version": version, "source": f"Header: {hdr}"}
                    self.log("INFO", f"[Tech] Detected [{category}]: {tech_name} {version} (via {hdr}: {val[:60]})")

        for pattern, category, tech_name in HTML_SIGNATURES:
            m = re.search(pattern, body, re.IGNORECASE) if body else None
            if m:
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                if tech_name not in detected:
                    detected[tech_name] = {"category": category, "version": version, "source": "HTML body"}
                    self.log("INFO", f"[Tech] Detected [{category}]: {tech_name} {version} (via HTML)")

        fp_matches = match_tech(body if body else "", headers)
        for fp in fp_matches:
            name = fp["name"]
            if name not in detected:
                detected[name] = {"category": fp["type"], "version": fp["version"], "source": "fingerprint_db"}
                self.log("INFO", f"[Tech] Detected [{fp['type']}]: {name} {fp['version']} (via fingerprint_db)")

        if not detected:
            self.log("INFO", "[Tech] No common technology signatures identified.")
            return self.vulns

        for tech_name, info in detected.items():
            version = info.get("version", "")
            if tech_name in EOL_VERSIONS and version:
                eol_info = EOL_VERSIONS[tech_name]
                try:
                    detected_parts = [int(x) for x in version.split(".")[:2]]
                    eol_parts = [int(x) for x in eol_info["eol_before"].split(".")[:2]]
                    if detected_parts < eol_parts:
                        self.log("WARNING", f"[Tech] EOL Version detected: {tech_name} {version}")
                        self.add_vuln(
                            title=f"Outdated / EOL Technology: {tech_name} {version}",
                            severity="High", category="Technology Fingerprint", cvss_score=7.5,
                            description=(
                                f"Version {version} of {tech_name} is detected, which is end-of-life. "
                                f"{eol_info['desc']}"
                            ),
                            remediation=f"Upgrade {tech_name} to the latest stable version immediately. "
                                        "Subscribe to security advisories for your technology stack.",
                            confidence="Confirmed",
                            evidence=f"Version string: {version}",
                        )
                except ValueError as e:
                    self.log("ERROR", f"[Tech] Version comparison error for {tech_name}: {e}")

        for tech_name, info in detected.items():
            version = info.get("version", "")
            cves = find_cves(tech_name, version)
            if cves:
                cve_ids = [c["cve"] for c in cves]
                self.log("WARNING", f"[Tech] Known CVEs for {tech_name} {version}: {', '.join(cve_ids)}")
                self.add_vuln(
                    title=f"Known Vulnerabilities: {tech_name} {version}",
                    severity="High", category="Technology Fingerprint", cvss_score=max(c["cvss"] for c in cves),
                    description=f"Version {version} of {tech_name} has {len(cves)} known CVE(s): {', '.join(cve_ids)}.",
                    remediation=f"Upgrade {tech_name} to the latest version to mitigate known CVEs.",
                    confidence="Confirmed",
                    evidence=f"CVEs: {', '.join(cve_ids)}",
                    cve_ids=cve_ids,
                )

        server_header = headers.get("server", "")
        if server_header and any(c.isdigit() for c in server_header):
            self.log("WARNING", f"[Tech] Detailed Server version exposed: {server_header}")
            self.add_vuln(
                title="Web Server Version Disclosed in 'Server' Header",
                severity="Low", category="Technology Fingerprint", cvss_score=3.1,
                description=f"The server header '{server_header}' reveals the exact web server software and version. This aids attackers in identifying applicable CVEs.",
                remediation="Suppress version information in your server config:\n  Nginx: server_tokens off;\n  Apache: ServerTokens Prod; ServerSignature Off",
                confidence="Confirmed",
                evidence=f"Server header: {server_header}",
            )

        tech_list = ", ".join(f"{n} ({v['category']})" for n, v in detected.items())
        self.log("SUCCESS", f"[Tech] Fingerprint complete. Detected: {tech_list}")
        return self.vulns
