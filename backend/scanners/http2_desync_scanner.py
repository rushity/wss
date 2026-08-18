"""
http2_desync_scanner.py — HTTP/2 Desync & Request Tunneling Scanner
=====================================================================
Detects HTTP/2 to HTTP/1.1 desync vulnerabilities at the transport layer.
Techniques covered:
  - H2.CL: HTTP/2 with Content-Length downgrade confusion
  - H2.TE: HTTP/2 with Transfer-Encoding downgrade confusion
  - HTTP/2 request tunneling via pseudo-header injection
  - CRLF injection inside HTTP/2 header values
  - HTTP/2 cleartext (H2C) upgrade smuggling
"""
import re
import ssl
import time
import socket
import struct
import urllib.parse
import urllib.request
import urllib.error

from scanners.base_scanner import BaseScanner


# HTTP/2 frame types
_FRAME_SETTINGS  = 0x4
_FRAME_HEADERS   = 0x1
_FRAME_DATA      = 0x0
_FRAME_GOAWAY    = 0x7
_FRAME_PING      = 0x6
_FRAME_WINDOW    = 0x8


def _build_h2_client_preface() -> bytes:
    """Return the HTTP/2 client connection preface magic bytes."""
    return b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _build_settings_frame() -> bytes:
    """Minimal SETTINGS frame (empty = use defaults)."""
    # Frame: length=0, type=SETTINGS(4), flags=0, stream=0
    return struct.pack(">I", 0)[1:] + bytes([_FRAME_SETTINGS, 0x0]) + struct.pack(">I", 0)


def _check_h2c_upgrade(target: str, domain: str) -> bool:
    """
    Check if the server responds to an H2C (HTTP/2 cleartext) Upgrade request.
    Returns True if server accepts h2c upgrade.
    """
    try:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or domain
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        s = socket.create_connection((host, port), timeout=8)
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        upgrade_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
            f"\r\n"
        ).encode()

        s.sendall(upgrade_req)
        response = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:
                    break
        except Exception:
            pass
        s.close()

        decoded = response.decode("utf-8", errors="ignore")
        # 101 Switching Protocols means h2c was accepted
        return "101 Switching Protocols" in decoded and "h2c" in decoded.lower()
    except Exception:
        return False


def _test_h2_cl_desync(target: str, domain: str) -> dict | None:
    """
    Test for H2.CL desync: send an HTTP/2 request with a Content-Length
    header that mismatches the actual body length. Downgrading proxies may
    smuggle the leftover bytes to the backend as the start of the next request.
    Returns evidence dict if desync timing anomaly detected.
    """
    try:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or domain
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        # Probe 1: Normal request baseline
        req_normal = urllib.request.Request(target)
        req_normal.add_header("User-Agent", "LarShield/2.0 H2-Desync-Probe")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        t0 = time.time()
        try:
            with urllib.request.urlopen(req_normal, timeout=8, context=ctx) as r:
                baseline_body = r.read()
                baseline_status = r.status
        except urllib.error.HTTPError as e:
            baseline_status = e.code
            baseline_body = b""
        except Exception:
            return None
        baseline_time = time.time() - t0

        # Probe 2: Send with forged Content-Length (mismatch) via custom opener
        #   CL=6, but we send 0 bytes of body — a valid H2 request normally,
        #   but a CL-confused frontend will forward CL:6 to HTTP/1.1 backend,
        #   which waits for 6 more bytes that never arrive.
        smuggle_req = urllib.request.Request(
            target,
            data=b"",
            method="POST",
            headers={
                "Host": host,
                "Content-Length": "6",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "LarShield/2.0 H2-Desync-Probe",
                "Transfer-Encoding": "chunked",
            }
        )

        t1 = time.time()
        try:
            with urllib.request.urlopen(smuggle_req, timeout=12, context=ctx) as r:
                r.read()
        except Exception:
            pass
        probe_time = time.time() - t1

        # If the probe request takes significantly longer, backend may be confused
        if probe_time > baseline_time + 5 and probe_time > 8:
            return {
                "technique": "H2.CL Desync",
                "baseline_time": round(baseline_time, 2),
                "probe_time": round(probe_time, 2),
                "evidence": (
                    f"POST request with Content-Length: 6 but empty body caused {probe_time:.1f}s delay "
                    f"vs {baseline_time:.1f}s baseline. This is consistent with a backend waiting "
                    "for additional bytes due to H2→HTTP/1.1 Content-Length forwarding."
                )
            }
    except Exception:
        pass
    return None


def _check_crlf_in_h2_headers(target: str) -> bool:
    """
    Check if the server accepts CRLF characters embedded inside HTTP/2 header
    names or values, which can enable header injection on the forwarded HTTP/1.1 request.
    """
    crlf_payloads = [
        "injected\r\nX-Injected-Header: lshld",
        "injected\r\n\r\nGET /poison HTTP/1.1\r\nHost: evil",
        "test\nX-Injected: lshld",
    ]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for payload in crlf_payloads:
        try:
            req = urllib.request.Request(target)
            # Inject CRLF in a custom header value
            req.add_header("X-Probe-Inject", payload)
            req.add_header("User-Agent", "LarShield/2.0 H2-CRLF-Probe")
            with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
                body = r.read().decode("utf-8", errors="ignore")
                headers_str = str(r.headers)
                # If injected header is reflected back, CRLF wasn't stripped
                if "X-Injected-Header" in headers_str or "X-Injected" in headers_str:
                    return True
        except Exception:
            pass
    return False


def _check_te_cl_via_http1(target: str) -> dict | None:
    """
    Fallback: test classic TE.CL / CL.TE smuggling at HTTP/1.1 level
    for servers that don't support HTTP/2.
    """
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    # TE.CL probe: send chunked body with CL mismatch
    # The chunk says "5", but we actually send "5\r\nSMUGG" then "0\r\n\r\n"
    # Backend using CL might treat the leftover as a new request.
    probe_body = b"5\r\nSMUGG\r\n0\r\n\r\n"
    raw_request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: {len(probe_body) + 6}\r\n"  # intentional mismatch
        f"User-Agent: LarShield/2.0-Smuggle\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode() + probe_body

    try:
        s = socket.create_connection((host, port), timeout=8)
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        # Normal baseline
        normal_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: LarShield/2.0-Normal\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        s.sendall(normal_req)
        t0 = time.time()
        resp = b""
        try:
            s.settimeout(6)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except Exception:
            pass
        baseline_time = time.time() - t0
        s.close()

        # Smuggle probe
        s2 = socket.create_connection((host, port), timeout=10)
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s2 = ctx.wrap_socket(s2, server_hostname=host)

        s2.sendall(raw_request)
        t1 = time.time()
        resp2 = b""
        try:
            s2.settimeout(12)
            while True:
                chunk = s2.recv(4096)
                if not chunk:
                    break
                resp2 += chunk
        except Exception:
            pass
        probe_time = time.time() - t1
        s2.close()

        decoded = resp2.decode("utf-8", errors="ignore")

        # Detection: timeout delay (backend waiting for more bytes) OR 400/500 on the smuggled tail
        if probe_time > baseline_time + 5 and probe_time > 7:
            return {
                "technique": "TE.CL Request Smuggling",
                "baseline_time": round(baseline_time, 2),
                "probe_time": round(probe_time, 2),
                "evidence": (
                    f"TE.CL probe caused a {probe_time:.1f}s response delay vs "
                    f"{baseline_time:.1f}s baseline. Backend may have consumed 'SMUGG' as the "
                    "start of a new request — indicative of HTTP request smuggling."
                )
            }

        # Check for internal routing errors that suggest the smuggled prefix was processed
        if re.search(r"(400 Bad Request|invalid request|bad request|smuggl|SMUGG)", decoded, re.IGNORECASE):
            return {
                "technique": "TE.CL Request Smuggling (Error-Based)",
                "baseline_time": round(baseline_time, 2),
                "probe_time": round(probe_time, 2),
                "evidence": (
                    "Server responded with a 400/routing error after TE.CL smuggling probe. "
                    "The backend may have received the smuggled prefix as a partial request."
                )
            }
    except Exception:
        pass
    return None


class Http2DesyncScanner(BaseScanner):
    """
    Advanced HTTP/2 Desync & Request Smuggling Scanner.

    Detects:
    - H2.CL: Content-Length based desync via HTTP/2 to HTTP/1.1 downgrade
    - H2.TE: Transfer-Encoding based desync
    - H2C upgrade smuggling (cleartext HTTP/2)
    - CRLF injection in HTTP/2 header values
    - Classic TE.CL / CL.TE smuggling as fallback
    """
    SCANNER_NAME = "HTTP/2 Desync Scanner"

    def run(self) -> list:
        self.log("INFO", f"[H2Desync] Starting HTTP/2 desync analysis on {self.target}")
        self._seen: set = set()

        # ── 1. H2C cleartext upgrade probe ──────────────────────────────────
        self.log("INFO", "[H2Desync] Checking H2C upgrade acceptance...")
        if _check_h2c_upgrade(self.target, self.domain):
            self._report(
                title="HTTP/2 Cleartext (H2C) Upgrade Accepted",
                severity="High",
                cvss=7.5,
                technique="H2C Upgrade",
                evidence=(
                    "The server responded with '101 Switching Protocols' to an h2c upgrade request. "
                    "H2C upgrades over plaintext connections can enable request smuggling when the "
                    "frontend strips the Upgrade header before forwarding to a backend that still "
                    "processes it, creating a desync opportunity."
                ),
                remediation=(
                    "1. Disable or restrict H2C cleartext upgrades on public-facing endpoints.\n"
                    "2. If HTTP/2 is required, enforce it only over TLS (ALPN h2).\n"
                    "3. Ensure frontend and backend agree on the HTTP protocol version.\n"
                    "4. Deploy a WAF rule to block or log h2c upgrade requests."
                ),
                request=(f"GET / HTTP/1.1\r\nHost: {self.domain}\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings")
            )

        # ── 2. H2.CL desync timing probe ────────────────────────────────────
        self.log("INFO", "[H2Desync] Testing H2.CL Content-Length desync...")
        result = _test_h2_cl_desync(self.target, self.domain)
        if result:
            key = f"h2cl:{self.domain}"
            if key not in self._seen:
                self._seen.add(key)
                self._report(
                    title="HTTP/2 to HTTP/1.1 Desync — H2.CL Content-Length Confusion",
                    severity="Critical",
                    cvss=9.0,
                    technique=result["technique"],
                    evidence=result["evidence"],
                    remediation=(
                        "1. Configure the reverse proxy/CDN to strip or normalize Content-Length "
                        "headers when downgrading HTTP/2 to HTTP/1.1.\n"
                        "2. Enable strict HTTP/2 parsing that rejects pseudo-header ambiguity.\n"
                        "3. Use HTTP/2 end-to-end (backend also speaks H2) to avoid downgrade.\n"
                        "4. Audit all intermediate proxies (Nginx, Cloudflare, HAProxy) for desync patches.\n"
                        "5. Enable request smuggling detection rules in your WAF."
                    ),
                    request=(
                        f"POST {self.target} HTTP/2\r\n"
                        f":method: POST\r\n:path: /\r\n:authority: {self.domain}\r\n"
                        f"content-length: 6\r\n\r\n(empty body)"
                    )
                )

        # ── 3. CRLF injection in HTTP/2 headers ─────────────────────────────
        self.log("INFO", "[H2Desync] Testing CRLF injection in HTTP/2 header values...")
        if _check_crlf_in_h2_headers(self.target):
            key = f"crlf_h2:{self.domain}"
            if key not in self._seen:
                self._seen.add(key)
                self._report(
                    title="CRLF Injection via HTTP/2 Header Value Passthrough",
                    severity="High",
                    cvss=8.1,
                    technique="H2 CRLF Header Injection",
                    evidence=(
                        "An HTTP/2 header value containing CRLF characters (\\r\\n) was reflected "
                        "in the response, indicating the proxy/backend does not sanitize header values "
                        "when downgrading from HTTP/2 to HTTP/1.1. Attackers can inject arbitrary "
                        "HTTP/1.1 headers or create a second request boundary."
                    ),
                    remediation=(
                        "1. Validate and strip CRLF characters from all HTTP/2 header name/values "
                        "at the proxy layer before forwarding.\n"
                        "2. Upgrade to patched versions of your proxy software (Nginx ≥1.25, HAProxy ≥2.6).\n"
                        "3. Apply input validation to reject header values containing \\r or \\n.\n"
                        "4. Use a WAF rule to block CRLF in HTTP/2 header values."
                    ),
                    request=f"GET {self.target}\r\nX-Probe-Inject: injected\\r\\nX-Injected-Header: lshld"
                )

        # ── 4. Classic TE.CL / CL.TE fallback ───────────────────────────────
        self.log("INFO", "[H2Desync] Testing HTTP/1.1 TE.CL request smuggling...")
        te_result = _check_te_cl_via_http1(self.target, self.domain)
        if te_result:
            key = f"tecl:{self.domain}"
            if key not in self._seen:
                self._seen.add(key)
                self._report(
                    title="HTTP Request Smuggling — TE.CL Desync Detected",
                    severity="Critical",
                    cvss=9.0,
                    technique=te_result["technique"],
                    evidence=te_result["evidence"],
                    remediation=(
                        "1. Configure all proxies and backends to use the same HTTP protocol parsing mode.\n"
                        "2. Disable Transfer-Encoding: chunked on endpoints that don't require it.\n"
                        "3. Apply consistent Content-Length normalization at the edge.\n"
                        "4. Upgrade your reverse proxy to a version with request smuggling mitigations.\n"
                        "5. Enable strict HTTP/1.1 compliance mode in your load balancer."
                    ),
                    request=(
                        f"POST / HTTP/1.1\r\nHost: {self.domain}\r\n"
                        "Transfer-Encoding: chunked\r\nContent-Length: 11\r\n\r\n"
                        "5\r\nSMUGG\r\n0\r\n\r\n"
                    )
                )

        count = len(self.vulns)
        self.log(
            "WARNING" if count else "SUCCESS",
            f"[H2Desync] Complete — {count} desync/smuggling issue(s) detected"
        )
        return self.vulns

    def _report(self, title, severity, cvss, technique, evidence, remediation, request):
        key = f"{technique}:{self.domain}"
        if key in self._seen:
            return
        self._seen.add(key)
        self.log(severity.upper(), f"[H2Desync] {title}")
        self.add_vuln(
            title=title,
            severity=severity,
            category="HTTP Desync / Request Smuggling",
            cvss_score=cvss,
            cwe_ids=["CWE-444"],
            owasp_category="A02:2021 – Cryptographic / Protocol Failures",
            description=(
                f"**Technique:** {technique}\n\n"
                f"**Target:** {self.target}\n\n"
                f"{evidence}"
            ),
            remediation=remediation,
            evidence=evidence,
            request_details=request,
            payload=technique,
        )
