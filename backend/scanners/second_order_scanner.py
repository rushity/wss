"""
second_order_scanner.py — Second-Order Injection Scanner
"""
import re, json, urllib.request, urllib.error
from scanners.base_scanner import BaseScanner

MARKER = "WSS2OI"
SQLI_PAYLOADS = [f"{MARKER}' OR '1'='1", f"{MARKER}\"--", f"1; DROP TABLE--{MARKER}"]
XSS_PAYLOADS  = [f"<script>alert('{MARKER}')</script>", f"\">{MARKER}<svg onload=x>"]

class SecondOrderScanner(BaseScanner):
    SCANNER_NAME = "Second-Order Injection Scanner"
    _SCANNER_KEY = "second_order"
    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[SecondOrder] Testing second-order injection on {self.target}...")
        base = self.target.rstrip("/")

        # Phase 1: Store payloads in common write endpoints
        store_endpoints = [
            ("/api/register",   "POST", {"username": SQLI_PAYLOADS[0], "email": f"test@{self.domain}", "password": "Test1234!"}),
            ("/api/profile",    "PUT",  {"name": XSS_PAYLOADS[0], "bio": SQLI_PAYLOADS[1]}),
            ("/api/comment",    "POST", {"body": XSS_PAYLOADS[0], "post_id": "1"}),
            ("/api/feedback",   "POST", {"message": SQLI_PAYLOADS[0], "email": f"t@{self.domain}"}),
        ]

        stored_at = []
        for path, method, payload in store_endpoints:
            url = base + path
            status = self._write(url, method, payload)
            if status in (200, 201):
                stored_at.append((url, payload))
                self.log("INFO", f"[SecondOrder] Payload stored at {url}")

        if not stored_at:
            self.log("INFO", "[SecondOrder] No writable endpoints found for payload storage.")
            return self.vulns

        # Phase 2: Retrieve and check if payload appears in read endpoints
        read_endpoints = [
            "/api/users", "/api/admin/users", "/admin/users",
            "/api/comments", "/api/feedback", "/admin/dashboard",
        ]
        for path in read_endpoints:
            url = base + path
            body, status = self._read(url)
            if not body: continue
            if MARKER in body:
                # Determine type
                is_xss = any(p in body for p in XSS_PAYLOADS)
                is_sqli = any(err in body.lower() for err in
                    ["syntax error", "sql", "mysql", "sqlite", "ora-", "pg::"])
                title = "Second-Order XSS" if is_xss else "Second-Order SQLi" if is_sqli else "Second-Order Injection"
                sev = "Critical" if is_sqli else "High"
                self.add_vuln(
                    title=f"{title} — Payload Stored and Retrieved at {path}",
                    severity=sev,
                    category="Second-Order Injection",
                    cvss_score=9.0 if is_sqli else 7.5,
                    description=f"A payload stored via a write endpoint was retrieved unescaped at `{url}`. "
                        "This confirms second-order injection — the payload is not reflected immediately "
                        "but executes when an admin or other user views the stored data.",
                    remediation="1. Encode/escape ALL stored data at render time, not just at input.\n"
                        "2. Use parameterized queries for ALL database reads, not just writes.\n"
                        "3. Apply output encoding consistently regardless of data source.",
                )
                self.log("CRITICAL", f"[SecondOrder] {title} confirmed at {url}!")
                return self.vulns

        # If we stored but couldn't verify (no access to admin reads), report as potential
        if stored_at:
            self.add_vuln(
                title="Second-Order Injection Payloads Successfully Stored",
                severity="Low",
                category="Second-Order Injection",
                cvss_score=0.0,
                description="Marker payloads were accepted by write endpoints:\n\n" +
                    "\n".join(f"- `{url}`" for url, _ in stored_at) +
                    "\n\nManual verification required: check if these values appear unescaped in admin views.",
                remediation="Audit all admin views that render user-submitted data for proper output encoding.",
            )
        return self.vulns

    def _write(self, url, method, payload):
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(url, data=data, method=method,
                headers={"User-Agent": "LarShield/2.0", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context()) as r:
                return r.status
        except urllib.error.HTTPError as e: return e.code
        except Exception as e:
            self.log("ERROR", f"[SecondOrder] _write error: {e}")
            return 0

    def _read(self, url):
        try:
            req = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context()) as r:
                return r.read().decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e: return e.read().decode("utf-8", errors="ignore"), e.code
        except Exception as e:
            self.log("ERROR", f"[SecondOrder] _read error: {e}")
            return "", 0
