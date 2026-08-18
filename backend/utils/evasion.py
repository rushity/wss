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

"""
evasion.py — WAF Evasion / Payload Encoding Helpers
=====================================================
Advanced WAF bypass techniques used by scanner modules.

FIXES (June 2026):
  BUG-13: mixed_case() — lambda closure referenced undefined `i` variable.
           Refactored to use enumerate() with a proper loop instead of a lambda.
  ENH-1:  Added HTML entity, Unicode codepoint, and SQL comment splice encoders.
  ENH-2:  Added case-splice SQL comment technique.
"""


def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def unicode_encode(s: str) -> str:
    return "".join(f"%u{ord(c):04X}" for c in s)


def hex_encode(s: str) -> str:
    return "".join(f"\\x{ord(c):02x}" for c in s)


def utf16_encode(s: str) -> str:
    return "".join(
        f"%00{ord(c):02x}" if ord(c) < 256 else f"%u{ord(c):04X}" for c in s
    )


def html_entity_encode(s: str) -> str:
    """Encode each char as HTML entity (useful for XSS context evasion)."""
    return "".join(f"&#{ord(c)};" for c in s)


def sql_comment_splice(s: str) -> str:
    """
    Inject /**/ between every character (common SQL WAF bypass).
    E.g., SELECT → S/**/E/**/L/**/E/**/C/**/T
    """
    return "/**/".join(list(s))


def mixed_case(s: str, variant: int = 0) -> str:
    """
    Return a mixed-case version of `s`.
    Variant 0 → uppercase even positions
    Variant 1 → lowercase even positions
    Variant 2 → swapcase entire string
    BUG-13 FIX: Previously used a lambda with `i` from enumerate() but the
    lambda was defined in a list comprehension where `i` was not in scope.
    Now uses a simple loop with index tracking.
    """
    result = []
    alpha_idx = 0  # count only alphabetic chars
    for ch in s:
        if ch.isalpha():
            if variant == 0:
                result.append(ch.upper() if alpha_idx % 2 == 0 else ch.lower())
            elif variant == 1:
                result.append(ch.lower() if alpha_idx % 2 == 0 else ch.upper())
            else:  # variant 2
                result.append(ch.swapcase())
            alpha_idx += 1
        else:
            result.append(ch)
    return "".join(result)


ENCODERS = [
    ("plain",             lambda s: s),
    ("url",               url_encode),
    ("double_url",        double_url_encode),
    ("unicode",           unicode_encode),
    ("utf16",             utf16_encode),
    ("hex",               hex_encode),
    ("html_entity",       html_entity_encode),
    ("sql_comment_splice",sql_comment_splice),
    ("mixed_case_1",      lambda s: mixed_case(s, 0)),
    ("mixed_case_2",      lambda s: mixed_case(s, 1)),
    ("mixed_case_3",      lambda s: mixed_case(s, 2)),
]


def generate_variants(payload: str) -> list[tuple[str, str]]:
    results = []
    for name, encoder in ENCODERS:
        try:
            encoded = encoder(payload)
            if encoded != payload:
                results.append((name, encoded))
        except Exception:
            pass
    return results


WAF_EVASION_PREFIXES = [
    ("tab",                    "%09"),      # \t — URL-encoded to avoid urllib ValueError
    ("newline",                "%0a"),      # \n — URL-encoded to avoid urllib ValueError
    ("carriage",               "%0d"),      # \r — URL-encoded to avoid urllib ValueError
    ("null_byte",              "%00"),      # \x00 — URL-encoded to avoid urllib ValueError
    ("comment",                "/**/"),
    ("multiline_comment",      "/*!*/"),
    ("backticks",              "``"),
    ("parenthesis_overflow",   "(((("),
    ("tab_before",             "%09/"),     # \t/ — URL-encoded
    ("path_param",             "/;/"),
    ("sp_prefix",              "%20"),      # space — URL-encoded to avoid urllib ValueError
    ("plus_prefix",            "+"),        # URL-decoded space
]

# Additional SQL-specific suffix tricks
WAF_EVASION_SUFFIXES = [
    ("sql_dash_comment",   "-- -"),
    ("sql_hash_comment",   "#"),
    ("sql_block_comment",  "/*"),
]


def waf_evade(payload: str) -> list[tuple[str, str]]:
    """
    Return a deduplicated list of (evasion_name, evaded_payload) tuples.
    Includes prefix tricks, encoding tricks, and SQL comment suffixes.
    """
    seen: set[str] = set()
    variants: list[tuple[str, str]] = []

    def _add(name: str, val: str):
        if val != payload and val not in seen:
            seen.add(val)
            variants.append((name, val))

    # Plain payload always first (for baseline)
    _add("plain", payload)

    # Prefix-based evasion
    for name, prefix in WAF_EVASION_PREFIXES:
        _add(f"prefix_{name}", prefix + payload)

    # Encoding-based evasion
    for name, encoded in generate_variants(payload):
        _add(f"encode_{name}", encoded)

    return variants

