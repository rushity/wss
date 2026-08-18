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

VULN_CLASSIFICATION = {
    "sql_injection": {
        "cwe_ids": ["CWE-89"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 9.8,
    },
    "blind_xss": {
        "cwe_ids": ["CWE-79"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 8.2,
    },
    "dom_xss": {
        "cwe_ids": ["CWE-79"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 8.2,
    },
    "command_injection": {
        "cwe_ids": ["CWE-78"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 9.8,
    },
    "ssti": {
        "cwe_ids": ["CWE-1336"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 9.8,
    },
    "xxe": {
        "cwe_ids": ["CWE-611"],
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cvss_base": 8.6,
    },
    "ssrf": {
        "cwe_ids": ["CWE-918"],
        "owasp_category": "A10:2021 – Server-Side Request Forgery",
        "cvss_base": 8.6,
    },
    "lfi": {
        "cwe_ids": ["CWE-22"],
        "owasp_category": "A01:2021 – Broken Access Control",
        "cvss_base": 7.5,
    },
    "path_traversal": {
        "cwe_ids": ["CWE-22"],
        "owasp_category": "A01:2021 – Broken Access Control",
        "cvss_base": 7.5,
    },
    "idor": {
        "cwe_ids": ["CWE-639"],
        "owasp_category": "A01:2021 – Broken Access Control",
        "cvss_base": 6.5,
    },
    "csrf": {
        "cwe_ids": ["CWE-352"],
        "owasp_category": "A01:2021 – Broken Access Control",
        "cvss_base": 5.3,
    },
    "jwt": {
        "cwe_ids": ["CWE-287", "CWE-345"],
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cvss_base": 7.5,
    },
    "auth": {
        "cwe_ids": ["CWE-287"],
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cvss_base": 7.3,
    },
    "session": {
        "cwe_ids": ["CWE-384", "CWE-613"],
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cvss_base": 6.8,
    },
    "open_redirect": {
        "cwe_ids": ["CWE-601"],
        "owasp_category": "A01:2021 – Broken Access Control",
        "cvss_base": 4.7,
    },
    "crlf": {
        "cwe_ids": ["CWE-93"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 7.3,
    },
    "request_smuggling": {
        "cwe_ids": ["CWE-444"],
        "owasp_category": "A04:2021 – Insecure Design",
        "cvss_base": 8.6,
    },
    "host_header": {
        "cwe_ids": ["CWE-644"],
        "owasp_category": "A04:2021 – Insecure Design",
        "cvss_base": 6.5,
    },
    "cache_poisoning": {
        "cwe_ids": ["CWE-644"],
        "owasp_category": "A04:2021 – Insecure Design",
        "cvss_base": 6.1,
    },
    "deserialization": {
        "cwe_ids": ["CWE-502"],
        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        "cvss_base": 9.8,
    },
    "nosql": {
        "cwe_ids": ["CWE-943"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 9.1,
    },
    "ldap": {
        "cwe_ids": ["CWE-90"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 9.1,
    },
    "file_upload": {
        "cwe_ids": ["CWE-434"],
        "owasp_category": "A04:2021 – Insecure Design",
        "cvss_base": 8.8,
    },
    "race_condition": {
        "cwe_ids": ["CWE-362"],
        "owasp_category": "A01:2021 – Broken Access Control",
        "cvss_base": 7.5,
    },
    "cors": {
        "cwe_ids": ["CWE-942"],
        "owasp_category": "A01:2021 – Broken Access Control",
        "cvss_base": 6.1,
    },
    "csp": {
        "cwe_ids": ["CWE-1021", "CWE-693"],
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cvss_base": 5.9,
    },
    "clickjacking": {
        "cwe_ids": ["CWE-1021"],
        "owasp_category": "A04:2021 – Insecure Design",
        "cvss_base": 4.3,
    },
    "cookie": {
        "cwe_ids": ["CWE-1004", "CWE-614"],
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cvss_base": 5.3,
    },
    "headers": {
        "cwe_ids": ["CWE-693"],
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cvss_base": 5.0,
    },
    "cache_control": {
        "cwe_ids": ["CWE-525"],
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cvss_base": 3.1,
    },
    "password_reset": {
        "cwe_ids": ["CWE-640"],
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cvss_base": 6.3,
    },
    "saml": {
        "cwe_ids": ["CWE-287"],
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cvss_base": 8.1,
    },
    "oauth": {
        "cwe_ids": ["CWE-862"],
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cvss_base": 7.5,
    },
    "prototype_pollution": {
        "cwe_ids": ["CWE-1321"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 8.2,
    },
    "mfa_bypass": {
        "cwe_ids": ["CWE-308"],
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cvss_base": 7.4,
    },
    "bypass_403": {
        "cwe_ids": ["CWE-290"],
        "owasp_category": "A01:2021 – Broken Access Control",
        "cvss_base": 5.3,
    },
    "http_method_tampering": {
        "cwe_ids": ["CWE-749"],
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cvss_base": 5.3,
    },
    "subdomain_takeover": {
        "cwe_ids": ["CWE-350"],
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cvss_base": 7.5,
    },
    "csti": {
        "cwe_ids": ["CWE-1336"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 8.6,
    },
    "postmessage": {
        "cwe_ids": ["CWE-345"],
        "owasp_category": "A04:2021 – Insecure Design",
        "cvss_base": 5.3,
    },
    "second_order": {
        "cwe_ids": ["CWE-89", "CWE-79"],
        "owasp_category": "A03:2021 – Injection",
        "cvss_base": 8.2,
    },
    "web_cache_deception": {
        "cwe_ids": ["CWE-444"],
        "owasp_category": "A04:2021 – Insecure Design",
        "cvss_base": 5.3,
    },
}


def classify(scanner_key: str) -> dict:
    return VULN_CLASSIFICATION.get(scanner_key, {
        "cwe_ids": ["CWE-1104"],
        "owasp_category": "A06:2021 – Vulnerable and Outdated Components",
        "cvss_base": 5.0,
    })


def enrich(vuln: dict, scanner_key: str) -> dict:
    cls = classify(scanner_key)
    vuln.setdefault("cwe_ids", cls["cwe_ids"])
    vuln.setdefault("owasp_category", cls["owasp_category"])
    if "cvss_score" not in vuln or vuln.get("cvss_score", 0) == 0:
        vuln["cvss_score"] = cls["cvss_base"]
    return vuln

