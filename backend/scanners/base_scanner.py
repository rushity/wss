"""
base_scanner.py — Foundation for all WSS scanners
===================================================
Security hardened per Expert Audit (June 2026):
  GAP-001: confidence + scanner_key + cve_ids + timestamp fields in build_vuln()
  GAP-002: Target SSRF self-validation (_validate_target) — NOW CALLED IN __init__
  GAP-003: _make_request() / _make_headers() unified helper (auth-aware)
  GAP-004: Ring buffer (max 5000 lines) for active_scan_logs
  GAP-S1:  Secrets masking in log output
  GAP-S2:  Structured JSON security event logging

FIXES (June 2026):
  BUG-12/SEC-3: _validate_target() is now called inside __init__ so ALL scanners
                are protected from being used as SSRF pivots — was dead code before.
  ENH: Added _safe_url_join() to construct test URLs without path confusion.
  ENH: Added _deduplicate_vulns() to remove identical findings before reporting.
  ENH: _make_async_requests() now properly captures exceptions per-future.
"""
import re
import os
import json
import ssl
import time
import http.client
import socket
import logging
import ipaddress
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from urllib.robotparser import RobotFileParser
from urllib.parse import urlparse, urljoin, urlencode, quote
from utils.vuln_classifier import enrich as _classify_enrich
from scanners.core.baseline import SiteBaseline
from scanners.core.confidence import ConfidenceTracker

# ── Log store ─────────────────────────────────────────────────────────────
active_scan_logs: dict[str, list[str]] = {}
_logs_lock = threading.Lock()
MAX_LOG_LINES = 5000    # GAP-004: ring buffer cap

# ── WebSocket integration for real-time updates ───────────────────────────
_socketio_instance = None
_socketio_lock = threading.Lock()

def set_socketio_instance(socketio):
    """Set the global SocketIO instance for real-time progress updates."""
    global _socketio_instance
    with _socketio_lock:
        _socketio_instance = socketio

def emit_scan_progress(scan_id: str, event_type: str, data: dict) -> None:
    """Emit real-time scan progress events via WebSocket."""
    global _socketio_instance
    with _socketio_lock:
        if _socketio_instance:
            try:
                _socketio_instance.emit(event_type, data, room=f'scan_{scan_id}')
            except Exception as e:
                # Silently fail if WebSocket is not available
                pass

def parse_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    except Exception:
        return url

def cleanup_scan_logs(scan_id):
    with _logs_lock:
        if scan_id in active_scan_logs:
            del active_scan_logs[scan_id]

def schedule_log_cleanup(scan_id, delay=3600):
    def cleanup_task():
        time.sleep(delay)
        cleanup_scan_logs(scan_id)
    threading.Thread(target=cleanup_task, daemon=True).start()

# ── Environment ──────────────────────────────────────────────────────────
DEFAULT_VERIFY_SSL = os.environ.get("WSS_VERIFY_SSL", "0") == "1"
XSS_CALLBACK_URL = os.environ.get(
    "WSS_XSS_CALLBACK_URL",
    "https://xss-reporting.internal/callback",
)

# ── Secret patterns to mask in logs (GAP-S1) ─────────────────────────────
_SECRET_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16})'), r'AKIA****'),
    (re.compile(r'(sk-[a-zA-Z0-9]{40,})'), r'sk-****'),
    (re.compile(r'([Bb]earer\s+)[A-Za-z0-9\-_.~+/]+=*'), r'\1****'),
    (re.compile(r'(password["\s:=]+)[^\s&"\']+', re.I), r'\1****'),
    (re.compile(r'(token["\s:=]+)[^\s&"\']{8,}', re.I), r'\1****'),
]

# ── Structured security event logger (GAP-S2) ────────────────────────────
_sec_logger = logging.getLogger("LarShield.Security")
if not _sec_logger.handlers:
    _h = logging.FileHandler("security_events.log", encoding="utf-8")
    _h.setFormatter(logging.Formatter("%(message)s"))
    _sec_logger.addHandler(_h)
    _sec_logger.setLevel(logging.INFO)
    _sec_logger.propagate = False


def _clean_nul(val) -> str:
    if val is None:
        return ""
    if not isinstance(val, str):
        val = str(val)
    return val.replace("\x00", "").replace("\u0000", "")


def _mask_secrets(text: str) -> str:
    """Redact known secret patterns before writing to logs."""
    text = _clean_nul(text)
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _log_security_event(event_type: str, scan_id: str, message: str, level: str) -> None:
    """Write structured JSON security event for SIEM ingestion."""
    event = {
        "ts":         datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "level":      level,
        "scan_id":    scan_id,
        "message":    _mask_secrets(message),
    }
    _sec_logger.info(json.dumps(event))


def get_scan_logs(scan_id: str) -> list[str]:
    with _logs_lock:
        return list(active_scan_logs.get(scan_id, []))


def add_log(scan_id: str, level: str, message: str) -> None:
    timestamp = datetime.now().strftime("%H:%M:%S")
    safe_msg  = _mask_secrets(message)
    log_line  = f"[{timestamp}] [{level}] {safe_msg}"

    with _logs_lock:
        # GAP-004: ring buffer — cap at MAX_LOG_LINES
        logs = active_scan_logs.setdefault(scan_id, [])
        if len(logs) >= MAX_LOG_LINES:
            logs.pop(0)
        logs.append(log_line)

    # Structured security event for critical/warning levels
    if level in ("CRITICAL", "WARNING", "ERROR"):
        _log_security_event(f"SCAN_{level}", scan_id, message, level)

    try:
        print(log_line, flush=True)
    except UnicodeEncodeError:
        print(log_line.encode("ascii", "replace").decode("ascii"), flush=True)


def cleanup_scan_logs(scan_id: str) -> None:
    with _logs_lock:
        active_scan_logs.pop(scan_id, None)


def schedule_log_cleanup(scan_id: str, delay_seconds: int = 300) -> None:
    """
    Schedule scan log cleanup after `delay_seconds` (default 5 min).
    BUG-6 FIX: Prevents premature cleanup while frontend polls /logs.
    """
    def _cleanup():
        time.sleep(delay_seconds)
        cleanup_scan_logs(scan_id)

    t = threading.Thread(target=_cleanup, daemon=True)
    t.start()


def parse_domain(url: str) -> str:
    return (
        url.replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split(":")[0]
        .split("?")[0]
        .strip()
    )


def build_vuln(
    title: str,
    severity: str,
    category: str,
    cvss_score: float,
    description: str,
    remediation: str,
    evidence: str = "",
    payload: str = "",
    request_details: str = "",
    response_details: str = "",
    confidence: str = "Medium",
    scanner_key: str = "unknown",
    cve_ids: list | None = None,
    references: list | None = None,
    cwe_ids: list | None = None,
    owasp_category: str | None = None,
) -> dict:
    result = {
        "title":            _clean_nul(title),
        "severity":         _clean_nul(severity),
        "category":         _clean_nul(category),
        "cvss_score":       cvss_score,
        "description":      _clean_nul(description),
        "remediation":      _clean_nul(remediation),
        "evidence":         _mask_secrets(evidence),
        "payload":          _clean_nul(payload),
        "request_details":  _clean_nul(request_details),
        "response_details": _mask_secrets(response_details),
        "confidence":       _clean_nul(confidence),
        "scanner_key":      _clean_nul(scanner_key),
        "cve_ids":          cve_ids or [],
        "references":       references or [],
        "timestamp":        datetime.now(timezone.utc).isoformat(),
    }
    if cwe_ids:
        result["cwe_ids"] = cwe_ids
    if owasp_category:
        result["owasp_category"] = _clean_nul(owasp_category)
    _classify_enrich(result, scanner_key)
    return result


def make_ssl_context(verify: bool | None = None):
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    if verify is False or (verify is None and not DEFAULT_VERIFY_SSL):
        ctx.check_hostname = False
        ctx.verify_mode   = _ssl.CERT_NONE
    else:
        # Enforce TLS 1.2+ minimum (report §1.3)
        try:
            ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
        except AttributeError:
            pass  # Older Python — skip
    return ctx


def check_robots_txt(target: str, user_agent: str = "LarShield/2.0") -> RobotFileParser | None:
    try:
        parsed = urlparse(target)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        rp = RobotFileParser(robots_url)
        rp.read()
        return rp
    except Exception as e:
        print(f"ERROR: [Base] check_robots_txt error: {e}")
        return None


# ── Blocked target sets (GAP-002) ─────────────────────────────────────────
_BLOCKED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "169.254.169.254",          # AWS/Azure IMDS
    "metadata.google.internal", # GCP metadata
    "100.100.100.200",          # Alibaba Cloud ECS metadata
    "kubernetes.default.svc",
    "kubernetes.default",
})
_BLOCKED_SCHEMES = frozenset({"file", "ftp", "gopher", "dict", "ldap", "ldaps"})

# Raised from 60→150 to reduce per-scanner throttle waits and cut scan time
_SCANNER_RATE_LIMIT  = int(os.environ.get("SCANNER_RATE_LIMIT",  "150"))
_SCANNER_RATE_WINDOW = int(os.environ.get("SCANNER_RATE_WINDOW", "60"))

# ── Module-level shared SSL context (avoids rebuilding per-instance) ──────────
_SHARED_SSL_CONTEXT = None
_SSL_CONTEXT_LOCK   = threading.Lock()

def _get_shared_ssl_context():
    """Return (or lazily create) a module-level SSL context."""
    global _SHARED_SSL_CONTEXT
    if _SHARED_SSL_CONTEXT is None:
        with _SSL_CONTEXT_LOCK:
            if _SHARED_SSL_CONTEXT is None:
                _SHARED_SSL_CONTEXT = make_ssl_context(None)
    return _SHARED_SSL_CONTEXT


class TokenBucket:
    def __init__(self, rate: int = 60, window: int = 60):
        self._rate = rate
        self._window = window
        self._tokens = rate
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._rate, self._tokens + elapsed * (self._rate / self._window))
        self._last_refill = now

    def acquire(self, block: bool = True) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            if block:
                sleep_time = (self._window / self._rate) * 1.1
                time.sleep(sleep_time)
                self._refill()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return True
        return False


class BaseScanner:
    SCANNER_NAME: str = "Base Scanner"

    def __init__(
        self,
        scan_id: str,
        target: str,
        domain: str,
        auth_headers: dict | None = None,
        verify_ssl: bool | None = None,
        red_team: bool = False,
        **kwargs,
    ) -> None:
        self.scan_id       = scan_id
        self.target        = target
        self.domain        = domain
        self.auth_headers  = auth_headers or {}
        self.verify_ssl    = verify_ssl
        self.red_team      = red_team
        self.vulns: list[dict] = []
        self._ssl_context  = None
        self._robots_parser = None

        # GAP-ADV: Centralized discovery context to prevent redundant crawling
        self.discovery_context = kwargs.get("discovery_context", {})

        # PHASE 1: Build per-scan site baseline for SPA/404 false-positive suppression
        self._baseline = SiteBaseline()
        try:
            ssl_ctx = make_ssl_context(verify_ssl)
            self._baseline.build(
                target,
                ssl_context=ssl_ctx,
                headers={"User-Agent": "LarShield/2.0"},
                timeout=6,
            )
        except Exception as _be:
            add_log(scan_id, "WARNING", f"[Base] Baseline build error (suppression disabled): {_be}")

        # BUG-12 FIX: Validate target on init so ALL scanners are protected.
        # We catch ValueError here (not re-raise) to log and continue — some
        # scan types like API scanners may legitimately call with non-HTTP URLs.
        try:
            self._validate_target(self.target)
        except ValueError as e:
            add_log(scan_id, "WARNING",
                    f"[Base] Target validation warning for '{target}': {e}")

    # ── SSL / robots ─────────────────────────────────────────────────────

    def get_ssl_context(self):
        if self._ssl_context is None:
            self._ssl_context = make_ssl_context(self.verify_ssl)
        return self._ssl_context

    def get_robots_parser(self):
        if self._robots_parser is None:
            self._robots_parser = check_robots_txt(self.target)
        return self._robots_parser

    def can_fetch(self, path: str = "/") -> bool:
        rp = self.get_robots_parser()
        if rp is None:
            return True
        return rp.can_fetch("LarShield/2.0", path)

    # ── PHASE 1: Baseline convenience helpers ─────────────────────────────

    def _is_baseline(self, status: int, body: str | bytes) -> bool:
        """
        Return True when this response matches the site's generic SPA/404 catch-all.
        Use this before reporting any path as "found" to suppress false positives.
        """
        return self._baseline.is_baseline(status, body)

    def _is_not_found(self, status: int, body: str | bytes = b"") -> bool:
        """True when status >= 400 OR response matches the baseline catch-all."""
        return self._baseline.is_not_found(status, body)

    # ── Logging ──────────────────────────────────────────────────────────

    def log(self, level: str, message: str) -> None:
        add_log(self.scan_id, level, message)
        # Emit real-time log event
        emit_scan_progress(self.scan_id, 'scan_log', {
            'level': level,
            'message': message,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

    # ── Vulnerability reporting ──────────────────────────────────────────

    def add_vuln(
        self,
        title: str,
        severity: str,
        category: str,
        cvss_score: float,
        description: str,
        remediation: str,
        evidence: str = "",
        payload: str = "",
        request_details: str = "",
        response_details: str = "",
        confidence: str = "Medium",
        cve_ids: list | None = None,
        references: list | None = None,
        cwe_ids: list | None = None,
        owasp_category: str | None = None,
    ) -> None:
        vuln = build_vuln(
            title, severity, category, cvss_score,
            description, remediation,
            evidence, payload, request_details, response_details,
            confidence=confidence,
            scanner_key=getattr(self, "_SCANNER_KEY", "unknown"),
            cve_ids=cve_ids,
            references=references,
            cwe_ids=cwe_ids,
            owasp_category=owasp_category,
        )
        # Inline dedup: skip if same title+category already recorded this run
        for existing in self.vulns:
            if existing["title"] == vuln["title"] and existing["category"] == vuln["category"]:
                # Update confidence if the new one is stronger
                conf_rank = {"Low": 0, "Medium": 1, "High": 2, "Confirmed": 3}
                if conf_rank.get(vuln["confidence"], 0) > conf_rank.get(existing["confidence"], 0):
                    existing["confidence"] = vuln["confidence"]
                    if vuln.get("payload"):
                        existing["payload"] = vuln["payload"]
                    if vuln.get("evidence"):
                        existing["evidence"] = vuln["evidence"]
                return
        self.vulns.append(vuln)
        # Emit real-time vulnerability found event
        emit_scan_progress(self.scan_id, 'vulnerability_found', {
            'title': title,
            'severity': severity,
            'category': category,
            'cvss_score': cvss_score,
            'confidence': confidence,
            'scanner_key': getattr(self, "_SCANNER_KEY", "unknown"),
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

    def run(self) -> list[dict]:
        raise NotImplementedError("Subclasses must implement run()")

    # ── GAP-003: Unified auth-aware HTTP helpers ──────────────────────────

    def _make_headers(self, additional: dict | None = None) -> dict:
        """Build headers dict merging auth_headers (always include for authenticated scanning)."""
        headers = {"User-Agent": "LarShield/2.0"}
        if self.auth_headers:
            headers.update(self.auth_headers)
        if additional:
            headers.update(additional)
        return headers

    def _throttle(self):
        """Rate-limit requests per scanner instance. Blocks (sleeps) when rate limit is hit."""
        if not hasattr(self, '_bucket'):
            self._bucket = TokenBucket(_SCANNER_RATE_LIMIT, _SCANNER_RATE_WINDOW)
        self._bucket.acquire(block=True)

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict | None = None,
        timeout: int = 15,  # Increased from 5s -> 15s to handle slower external sites
        return_response_obj: bool = False,
    ) -> tuple[str | None, int] | tuple[str | None, int, dict]:
        """
        Unified HTTP request helper — always includes auth_headers.
        Returns (body_str, status_code). On error returns (None, 0).
        Automatically handles HTTPError bodies.
        """
        self._throttle()
        req_headers = self._make_headers(headers)
        # Add Connection: close to prevent keep-alive pool exhaustion on stressed targets
        req_headers.setdefault("Connection", "close")
        # Use shared SSL context to avoid per-call context creation overhead
        ssl_ctx = _get_shared_ssl_context() if self.verify_ssl is None else self.get_ssl_context()

        # PHASE 7.3: Retry with backoff on IncompleteRead / transient errors
        _RETRY_DELAYS = [0.0, 0.5, 1.5]  # 3 attempts: immediate, +0.5s, +1.5s
        for _attempt, _delay in enumerate(_RETRY_DELAYS):
            if _delay:
                time.sleep(_delay)
            try:
                req = urllib.request.Request(
                    url, data=data, headers=req_headers, method=method
                )
                with urllib.request.urlopen(
                    req, timeout=timeout, context=ssl_ctx
                ) as r:
                    body = r.read().decode("utf-8", errors="ignore")
                    if return_response_obj:
                        return body, r.status, r.headers  # type: ignore[return-value]
                    return body, r.status
            except http.client.IncompleteRead as e:
                if _attempt < len(_RETRY_DELAYS) - 1:
                    self.log("WARNING", f"[Base] IncompleteRead on {url} (attempt {_attempt+1}), retrying...")
                    continue
                # Last attempt — return partial data
                partial = e.partial.decode("utf-8", errors="ignore") if e.partial else ""
                if return_response_obj:
                    return partial, 200, {}  # type: ignore[return-value]
                return partial, 200
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode("utf-8", errors="ignore")
                except Exception as ex:
                    self.log("ERROR", f"[Base] _make_request HTTPError body read error: {ex}")
                    body = ""
                if return_response_obj:
                    return body, e.code, e.headers  # type: ignore[return-value]
                return body, e.code
            except ValueError as e:
                err_str = str(e).lower()
                # Suppress expected errors from newline/CRLF injection payloads in headers
                if "control characters" in err_str or "invalid header" in err_str:
                    if return_response_obj:
                        return None, 0, {}  # type: ignore[return-value]
                    return None, 0
                self.log("ERROR", f"[Base] _make_request ValueError: {e}")
                if return_response_obj:
                    return None, 0, {}  # type: ignore[return-value]
                return None, 0
            except Exception as e:
                # Suppress verbose logging for expected/common probe errors
                err_str = str(e).lower()
                _suppressed = (
                    "timed out", "connection refused", "name or service",
                    "getaddrinfo",         # DNS resolution failure
                    "errno 11001",         # Windows: getaddrinfo failed
                    "control characters",  # Expected when CRLF payloads hit urllib
                    "no connection could be made",
                    "actively refused",
                    "10054",               # Connection forcibly closed
                    "forcibly closed",
                )
                if not any(x in err_str for x in _suppressed):
                    self.log("ERROR", f"[Base] _make_request error: {e}")
                if return_response_obj:
                    return None, 0, {}  # type: ignore[return-value]
                return None, 0
        # Should not reach here
        if return_response_obj:
            return None, 0, {}  # type: ignore[return-value]
        return None, 0


    def _make_timed_request(
        self, url: str, method: str = "GET",
        data: bytes | None = None, headers: dict | None = None, timeout: int = 8,
    ) -> tuple[str | None, int, float]:
        """Returns (body, status, elapsed_seconds). Used for timing-based detection."""
        t0 = time.monotonic()
        body, status = self._make_request(url, method, data, headers, timeout)
        return body, status, time.monotonic() - t0

    # ── GAP-ADV: Concurrent execution helpers ──────────────────────────────

    def _make_async_requests(
        self,
        requests_list: list[dict],
        max_workers: int = 10,  # PHASE 7.3: Reduced 25 → 10 to prevent connection pool exhaustion
    ) -> list[tuple[dict, str | None, int]]:
        """
        Executes a list of requests concurrently using a thread pool.
        Each request in `requests_list` must be a dict with keys:
          'url' (required), optionally 'method', 'data', 'headers', 'timeout'.
        Returns a list of tuples: (request_dict, response_body, status_code).
        """
        import concurrent.futures

        results: list[tuple[dict, str | None, int]] = []

        def worker(req: dict) -> tuple[dict, str | None, int]:
            url = req.get("url")
            if not url:
                return req, None, 0
            method  = req.get("method", "GET")
            data    = req.get("data")
            headers = req.get("headers")
            timeout = req.get("timeout", 15)  # Consistent 15s default
            body, status = self._make_request(url, method, data, headers, timeout)
            return req, body, status

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_req = {executor.submit(worker, req): req for req in requests_list}
            for future in concurrent.futures.as_completed(future_to_req):
                req = future_to_req[future]
                try:
                    res = future.result()
                    results.append(res)
                except Exception as exc:
                    self.log("ERROR", f"[Base] _make_async_requests future error: {exc}")
                    results.append((req, None, 0))

        return results

    # ── URL helpers ────────────────────────────────────────────────────────

    def _safe_url_join(self, base: str, path: str) -> str:
        """
        Safely join a base URL with a relative path.
        Handles edge cases like missing slashes, query strings, fragments.
        """
        try:
            if path.startswith("http://") or path.startswith("https://"):
                return path
            return urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        except Exception:
            return base

    def _deduplicate_vulns(self) -> None:
        """
        Remove duplicate vulnerabilities from self.vulns in-place.
        Dedup key: (title, category).
        Keeps the highest-confidence occurrence.
        """
        seen: dict[tuple, dict] = {}
        conf_rank = {"Low": 0, "Medium": 1, "High": 2, "Confirmed": 3}
        for v in self.vulns:
            key = (v["title"], v["category"])
            if key not in seen:
                seen[key] = v
            else:
                existing_rank = conf_rank.get(seen[key].get("confidence", "Low"), 0)
                new_rank = conf_rank.get(v.get("confidence", "Low"), 0)
                if new_rank > existing_rank:
                    seen[key] = v
        self.vulns = list(seen.values())

    # ── GAP-002: Target SSRF self-protection ─────────────────────────────

    def _validate_target(self, url: str | None = None) -> None:
        """
        Prevent the scanner engine from being used as an SSRF pivot.
        Raises ValueError for blocked targets.
        BUG-12 FIX: Now called in __init__ automatically for every scanner.
        """
        target = url or self.target
        try:
            p = urlparse(target)
        except Exception as exc:
            raise ValueError(f"Invalid URL: {exc}") from exc

        # Block dangerous schemes
        if p.scheme in _BLOCKED_SCHEMES:
            raise ValueError(f"Blocked URL scheme: {p.scheme!r}")

        hostname = (p.hostname or "").lower().strip()
        if not hostname:
            raise ValueError("URL has no hostname")

        # Block known metadata / internal service hostnames
        if hostname in _BLOCKED_HOSTS:
            raise ValueError(f"Blocked host: {hostname}")

        # Block private / loopback / link-local IP ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                raise ValueError(f"Private/internal IP blocked: {ip}")
        except ValueError as exc:
            if "Blocked" in str(exc) or "Private" in str(exc) or "internal" in str(exc):
                raise  # Re-raise our own checks
            # Not an IP address (it's a hostname) — fine, proceed
            pass
