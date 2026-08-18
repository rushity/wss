"""
waf_scanner.py — Web Application Firewall (WAF) Detection module.
Detects common WAFs via HTTP headers, response signatures, and attack probes.
"""
from scanners.base_scanner import BaseScanner
from utils.fingerprint_db import find_cves

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"server": ["cloudflare"], "cf-ray": [], "cf-request-id": []},
        "cookies": ["__cfduid", "cf_clearance", "cf_bm"]
    },
    "AWS WAF": {
        "headers": {"server": ["awselb", "amazon"], "x-amz-cf-id": [], "x-amz-request-id": []},
        "cookies": ["awsalbcors", "awsalb", "aws-elb"]
    },
    "Akamai": {
        "headers": {"server": ["akamai", "akamaighost", "akamaigt"], "x-akamai-transformed": []},
        "cookies": ["ak_bmsc", "akamai_cc"]
    },
    "Imperva / Incapsula": {
        "headers": {"x-iinfo": [], "x-cdn": ["incapsula"], "x-cdn-uc": []},
        "cookies": ["visid_incap", "incap_ses", "nlbi"]
    },
    "Sucuri": {
        "headers": {"server": ["sucuri/cloudproxy"], "x-sucuri-id": [], "x-sucuri-country": []},
        "cookies": ["sucuri_cloudproxy"]
    },
    "F5 BIG-IP": {
        "headers": {"server": ["big-ip", "f5"], "x-wa-profile": []},
        "cookies": ["bigipserver", "ts01", "f5_persistence"]
    },
    "Barracuda": {
        "headers": {"server": ["barracuda"], "x-barracuda": []},
        "cookies": ["barracuda"]
    },
    "Citrix": {
        "headers": {"server": ["citrix", "netscaler"], "x-citrix-appid": []},
        "cookies": ["citrix_ns_id", "ns_c"]
    },
    "Fortinet": {
        "headers": {"server": ["fortinet"], "x-fortinet": []},
        "cookies": ["fortinet"]
    },
    "Palo Alto": {
        "headers": {"server": ["palo alto"], "x-pan": []},
        "cookies": ["pan"]
    },
    "ModSecurity": {
        "headers": {"server": ["modsecurity"], "x-modsecurity": []},
        "cookies": ["modsecurity"]
    },
    "Radware": {
        "headers": {"server": ["radware"], "x-radware": []},
        "cookies": ["radware"]
    },
    "Trustwave": {
        "headers": {"server": ["trustwave"], "x-trustwave": []},
        "cookies": ["trustwave"]
    },
    "Wordfence": {
        "headers": {"server": ["wordfence"], "x-wordfence": []},
        "cookies": ["wordfence"]
    },
    "StackPath": {
        "headers": {"server": ["stackpath"], "x-stackpath": []},
        "cookies": ["stackpath"]
    },
    "Fastly": {
        "headers": {"server": ["fastly"], "x-fastly-request-id": [], "fastly-ssl": []},
        "cookies": ["fastly"]
    },
    "Azure Front Door": {
        "headers": {"server": ["azure front door"], "x-azure-ref": [], "x-fd-id": []},
        "cookies": ["afd"]
    },
    "Azure WAF": {
        "headers": {"server": ["azure waf"], "x-azure-waf": []},
        "cookies": ["azure"]
    },
    "Google Cloud Armor": {
        "headers": {"server": ["gcp"], "x-google-cloud-armor": []},
        "cookies": ["gcp"]
    },
    "Cloudflare Enterprise": {
        "headers": {"server": ["cloudflare"], "cf-chl-bypass": [], "cf-mitigated": []},
        "cookies": ["cf_chl_2", "cf_chl_prog"]
    },
    "Akamai Kona": {
        "headers": {"server": ["akamai"], "x-akamai-kona": []},
        "cookies": ["akamai_kona"]
    },
    "AWS Shield": {
        "headers": {"server": ["aws"], "x-aws-shield": []},
        "cookies": ["aws_shield"]
    },
    "AWS CloudFront": {
        "headers": {"server": ["cloudfront"], "x-amz-cf-id": [], "x-cache": []},
        "cookies": ["cloudfront"]
    },
    "Cloudbric": {
        "headers": {"server": ["cloudbric"], "x-cloudbric": []},
        "cookies": ["cloudbric"]
    },
    "Indusface": {
        "headers": {"server": ["indusface"], "x-indusface": []},
        "cookies": ["indusface"]
    },
    "A10 Networks": {
        "headers": {"server": ["a10"], "x-a10": []},
        "cookies": ["a10"]
    },
    "Brocade": {
        "headers": {"server": ["brocade"], "x-brocade": []},
        "cookies": ["brocade"]
    },
    "Cisco": {
        "headers": {"server": ["cisco"], "x-cisco": []},
        "cookies": ["cisco"]
    },
    "Juniper": {
        "headers": {"server": ["juniper"], "x-juniper": []},
        "cookies": ["juniper"]
    },
    "Check Point": {
        "headers": {"server": ["check point"], "x-checkpoint": []},
        "cookies": ["checkpoint"]
    },
    "SonicWALL": {
        "headers": {"server": ["sonicwall"], "x-sonicwall": []},
        "cookies": ["sonicwall"]
    },
    "WatchGuard": {
        "headers": {"server": ["watchguard"], "x-watchguard": []},
        "cookies": ["watchguard"]
    },
    "Sophos": {
        "headers": {"server": ["sophos"], "x-sophos": []},
        "cookies": ["sophos"]
    },
    "McAfee": {
        "headers": {"server": ["mcafee"], "x-mcafee": []},
        "cookies": ["mcafee"]
    },
    "Trend Micro": {
        "headers": {"server": ["trend micro"], "x-trend": []},
        "cookies": ["trend"]
    },
    "Symantec": {
        "headers": {"server": ["symantec"], "x-symantec": []},
        "cookies": ["symantec"]
    },
    "Qualys": {
        "headers": {"server": ["qualys"], "x-qualys": []},
        "cookies": ["qualys"]
    },
    "Rapid7": {
        "headers": {"server": ["rapid7"], "x-rapid7": []},
        "cookies": ["rapid7"]
    },
    "Tenable": {
        "headers": {"server": ["tenable"], "x-tenable": []},
        "cookies": ["tenable"]
    },
    "Reblaze": {
        "headers": {"server": ["reblaze"], "x-reblaze": []},
        "cookies": ["reblaze"]
    },
    "Wallarm": {
        "headers": {"server": ["wallarm"], "x-wallarm": []},
        "cookies": ["wallarm"]
    },
    "Signal Sciences": {
        "headers": {"server": ["signal sciences"], "x-sigsci": []},
        "cookies": ["sigsci"]
    },
    "Twilio": {
        "headers": {"server": ["twilio"], "x-twilio": []},
        "cookies": ["twilio"]
    },
    "EdgeCast": {
        "headers": {"server": ["edgecast"], "x-edgecast": []},
        "cookies": ["edgecast"]
    },
    "Highwinds": {
        "headers": {"server": ["highwinds"], "x-highwinds": []},
        "cookies": ["highwinds"]
    },
    "Level 3": {
        "headers": {"server": ["level3"], "x-level3": []},
        "cookies": ["level3"]
    },
    "Limelight": {
        "headers": {"server": ["limelight"], "x-limelight": []},
        "cookies": ["limelight"]
    },
    "CDNetworks": {
        "headers": {"server": ["cdnetworks"], "x-cdnetworks": []},
        "cookies": ["cdnetworks"]
    },
    "KeyCDN": {
        "headers": {"server": ["keycdn"], "x-keycdn": []},
        "cookies": ["keycdn"]
    },
    "BunnyCDN": {
        "headers": {"server": ["bunnycdn"], "x-bunnycdn": []},
        "cookies": ["bunnycdn"]
    },
    "CDN77": {
        "headers": {"server": ["cdn77"], "x-cdn77": []},
        "cookies": ["cdn77"]
    },
    "QUIC.cloud": {
        "headers": {"server": ["quic.cloud"], "x-quic": []},
        "cookies": ["quic"]
    },
    "WP Engine": {
        "headers": {"server": ["wpengine"], "x-wpe": []},
        "cookies": ["wpengine"]
    },
    "Kinsta": {
        "headers": {"server": ["kinsta"], "x-kinsta": []},
        "cookies": ["kinsta"]
    },
    "SiteGround": {
        "headers": {"server": ["siteground"], "x-siteground": []},
        "cookies": ["siteground"]
    },
    "Bluehost": {
        "headers": {"server": ["bluehost"], "x-bluehost": []},
        "cookies": ["bluehost"]
    },
    "GoDaddy": {
        "headers": {"server": ["godaddy"], "x-godaddy": []},
        "cookies": ["godaddy"]
    },
    "Network Solutions": {
        "headers": {"server": ["network solutions"], "x-netsol": []},
        "cookies": ["netsol"]
    },
}

WAF_PROBES = [
    ("/?id=1'+OR+'1'%3D'1", "SQLi Basic"),
    ("/?id=1+UNION+SELECT+1,2,3,4,5,6,7", "SQLi Union"),
    ("/?q=<script>alert(1)</script>", "XSS Basic"),
    ("/?q=<img+src=x+onerror=alert(1)>", "XSS Img OnError"),
    ("/../../../etc/passwd", "Path Traversal"),
    ("/?page=../../../etc/passwd", "Path Traversal Param"),
    ("/?cmd=;cat+/etc/passwd", "Command Injection"),
    ("/?exec=|id", "Cmd Exec Pipe"),
    ("/?file=php://filter/convert.base64-encode/resource=index", "File Inclusion"),
    ("/?redirect=http://evil.com", "Open Redirect"),
    ("/?search=<svg+onload=alert(1)>", "XSS SVG OnLoad"),
    ("/?id=(select+*+from+users)", "SQLi Subquery"),
]

WAF_BLOCK_PAGES = {
    "Cloudflare": [
        "Attention Required! | Cloudflare",
        "Just a moment...",
        "cf-browser-verification",
        "Cloudflare Ray ID:",
        "Please complete the security check to access",
    ],
    "AWS WAF": [
        "Request blocked",
        "AWS WAF",
        "waf-aws",
        "x-amzn-RequestId",
    ],
    "Akamai": [
        "Reference #",
        "AkamaiGHost",
        "Akamai",
    ],
    "ModSecurity": [
        "ModSecurity",
        "This error was generated by Mod_Security",
        "ModSecurity: Access denied",
    ],
    "F5 Networks": [
        "The requested URL was rejected",
        "F5 Networks",
        "F5 BIG-IP",
    ],
    "Imperva / Incapsula": [
        "Incapsula",
        "Blocked because of Web Application Firewall",
        "imperva",
    ],
    "Fortinet / FortiWeb": [
        "FortiWeb",
        "Fortinet",
        "Powered by Fortinet",
    ],
    "Barracuda": [
        "Barracuda.Networks",
        "Barracuda",
    ],
    "Sucuri": [
        "Sucuri WebSite Firewall",
        "cloudproxy",
        "Sucuri CloudProxy",
    ],
    "Wordfence": [
        "Wordfence",
        "Generated by Wordfence",
    ],
    "Comodo WAF": [
        "Comodo WAF",
        "Protected by Comodo",
    ],
    "Radware": [
        "Radware",
        "AppWall",
        "Radware AppWall",
    ],
    "NAXSI": [
        "Naxsi",
        "naxsi-waf",
    ],
    "SafeDog": [
        "SafeDog",
        "SafeDog WAF",
    ],
    "WebKnight": [
        "WebKnight",
        "WebKnight WAF",
    ],
    "Yundun": [
        "Yundun",
        "Yundun WAF",
    ],
    "360 WangZhan": [
        "360wzb",
        "360 WangZhan",
    ],
    "URLScan": [
        "Rejected by urlscan",
        "urlscan",
    ],
}


class WafScanner(BaseScanner):
    SCANNER_NAME = "WAF & CDN Detection"
    _SCANNER_KEY = "waf"

    def run(self):
        self.log("INFO", f"[WAF] Probing {self.target} for Web Application Firewalls...")
        detected_wafs = set()

        base_body, base_status, base_headers = self._make_request(
            self.target,
            timeout=10,
            return_response_obj=True,
        )
        if base_status == 0:
            self.log("WARNING", f"[WAF] Request failed, skipping WAF detection.")
            return self.vulns

        headers_lower = {k.lower(): v.lower() for k, v in base_headers.items()}

        for waf_name, sigs in WAF_SIGNATURES.items():
            for header, values in sigs.get("headers", {}).items():
                if header in headers_lower:
                    if not values:
                        detected_wafs.add(waf_name)
                    else:
                        for val in values:
                            if val in headers_lower[header]:
                                detected_wafs.add(waf_name)

        base_body_lower = base_body.lower() if base_body else ""

        for waf_name, signatures in WAF_BLOCK_PAGES.items():
            for sig in signatures:
                if sig.lower() in base_body_lower:
                    detected_wafs.add(waf_name)
                    break

        if detected_wafs:
            waf_list = ", ".join(sorted(detected_wafs))
            self.log("SUCCESS", f"[WAF] Detected protection: {waf_list}")
            self.add_vuln(
                title=f"WAF/CDN Detected: {waf_list}",
                severity="Low", category="Fingerprinting", cvss_score=0.0,
                description=f"The target is protected by or routed through the following WAF/CDN providers: {waf_list}. This may interfere with active vulnerability scanning and block malicious payloads.",
                remediation="Informational finding. No remediation required unless WAF bypass testing is explicitly authorized.",
                confidence="Confirmed",
            )

            for waf_name in sorted(detected_wafs):
                cves = find_cves(waf_name)
                if cves:
                    cve_ids = [c["cve"] for c in cves]
                    self.log("WARNING", f"[WAF] Known CVEs for {waf_name}: {', '.join(cve_ids)}")
                    self.add_vuln(
                        title=f"Known CVEs for WAF: {waf_name}",
                        severity="Medium", category="WAF Fingerprinting", cvss_score=max(c["cvss"] for c in cves),
                        description=f"The detected WAF product {waf_name} has known CVEs: {', '.join(cve_ids)}.",
                        remediation=f"Upgrade {waf_name} to the latest version.",
                        evidence=f"CVEs: {', '.join(cve_ids)}",
                        confidence="Confirmed",
                        cve_ids=cve_ids,
                    )
        else:
            self.log("SUCCESS", f"[WAF] No WAF signatures detected from baseline. Probing with attack payloads...")
            probe_detected = self._probe_waf()
            if probe_detected:
                waf_list = ", ".join(sorted(probe_detected))
                self.log("SUCCESS", f"[WAF] Detected WAF via probe blocking: {waf_list}")
                self.add_vuln(
                    title=f"WAF Detected via Attack Probes: {waf_list}",
                    severity="Low", category="Fingerprinting", cvss_score=0.0,
                    description=f"Attack probes were blocked by a WAF ({waf_list}). The WAF was identified by block page content analysis.",
                    remediation="Informational finding. No remediation required unless WAF bypass testing is explicitly authorized.",
                    confidence="High",
                )

                for waf_name in sorted(probe_detected):
                    cves = find_cves(waf_name)
                    if cves:
                        cve_ids = [c["cve"] for c in cves]
                        self.log("WARNING", f"[WAF] Known CVEs for {waf_name}: {', '.join(cve_ids)}")
                        self.add_vuln(
                            title=f"Known CVEs for WAF: {waf_name}",
                            severity="Medium", category="WAF Fingerprinting", cvss_score=max(c["cvss"] for c in cves),
                            description=f"The detected WAF product {waf_name} has known CVEs: {', '.join(cve_ids)}.",
                            remediation=f"Upgrade {waf_name} to the latest version.",
                            evidence=f"CVEs: {', '.join(cve_ids)}",
                            confidence="Confirmed",
                            cve_ids=cve_ids,
                        )
            else:
                self.log("SUCCESS", f"[WAF] No WAF detected via probes.")

        return self.vulns

    def _probe_waf(self):
        detected_wafs = set()

        for path, probe_name in WAF_PROBES:
            probe_url = self.target.rstrip("/") + path
            body, status, _ = self._make_request(
                probe_url,
                headers={"User-Agent": "LarShield/2.0"},
                timeout=5,
                return_response_obj=True,
            )
            if status in (403, 406, 429, 503) or (body and body.lower().strip() == ""):
                self.log("INFO", f"[WAF] Probe '{probe_name}' blocked (HTTP {status})")
                body_lower = body.lower() if body else ""
                for waf_name, signatures in WAF_BLOCK_PAGES.items():
                    for sig in signatures:
                        if sig.lower() in body_lower:
                            detected_wafs.add(waf_name)
                            break
                    if waf_name in detected_wafs:
                        break
            elif status == 200:
                pass
            else:
                self.log("INFO", f"[WAF] Probe '{probe_name}' returned HTTP {status}")

        return detected_wafs
