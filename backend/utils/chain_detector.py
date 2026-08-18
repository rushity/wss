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


CHAIN_RULES: list[dict] = [
    {
        "name": "SSRF → Cloud Metadata Credential Theft",
        "risk": "Critical",
        "cvss_bonus": 2.0,
        "conditions": [
            {"scanner_key": "ssrf", "severity": {"$in": ["High", "Critical"]}},
            {"scanner_key": "secrets", "category": "Cloud Credentials"},
        ],
    },
    {
        "name": "LFI → Remote Code Execution (log poisoning)",
        "risk": "Critical",
        "cvss_bonus": 1.5,
        "conditions": [
            {"scanner_key": "lfi", "severity": {"$in": ["High", "Critical"]}},
            {"scanner_key": "file_upload", "severity": "Medium"},
        ],
    },
    {
        "name": "XSS + CSRF → Full Account Takeover",
        "risk": "Critical",
        "cvss_bonus": 2.5,
        "conditions": [
            {"scanner_key": "blind_xss", "severity": {"$in": ["High", "Critical"]}},
            {"scanner_key": "csrf"},
        ],
    },
    {
        "name": "Open Redirect + OAuth Token Leakage",
        "risk": "High",
        "cvss_bonus": 1.0,
        "conditions": [
            {"scanner_key": "open_redirect"},
            {"scanner_key": "oauth"},
        ],
    },
    {
        "name": "Weak JWT + IDOR → Privilege Escalation",
        "risk": "Critical",
        "cvss_bonus": 2.0,
        "conditions": [
            {"scanner_key": "jwt"},
            {"scanner_key": "idor"},
        ],
    },
    {
        "name": "SQL Injection + File Upload → Web Shell",
        "risk": "Critical",
        "cvss_bonus": 2.5,
        "conditions": [
            {"scanner_key": "sql_injection"},
            {"scanner_key": "file_upload"},
        ],
    },
    {
        "name": "Broken Authentication + Weak Session → Account Takeover",
        "risk": "High",
        "cvss_bonus": 1.5,
        "conditions": [
            {"scanner_key": "auth"},
            {"scanner_key": "session"},
        ],
    },
    {
        "name": "Subdomain Takeover + XSS → Full Application Compromise",
        "risk": "Critical",
        "cvss_bonus": 2.0,
        "conditions": [
            {"scanner_key": "subdomain_takeover"},
            {"scanner_key": {"$in": ["blind_xss", "dom_xss"]}},
        ],
    },
    {
        "name": "SSTI + Path Traversal → Remote Code Execution",
        "risk": "Critical",
        "cvss_bonus": 2.5,
        "conditions": [
            {"scanner_key": "ssti"},
            {"scanner_key": "path_traversal"},
        ],
    },
    {
        "name": "CORS Misconfiguration + XSS → Cross-Origin Data Theft",
        "risk": "High",
        "cvss_bonus": 1.5,
        "conditions": [
            {"scanner_key": "cors", "severity": {"$in": ["High", "Critical"]}},
            {"scanner_key": {"$in": ["blind_xss", "dom_xss"]}},
        ],
    },
    {
        "name": "Race Condition + Coupon → Financial Loss",
        "risk": "High",
        "cvss_bonus": 1.0,
        "conditions": [
            {"scanner_key": "race_condition"},
            {"scanner_key": "business_logic"},
        ],
    },
    {
        "name": "Host Header Injection + Cache Poisoning → Widespread XSS",
        "risk": "Critical",
        "cvss_bonus": 2.5,
        "conditions": [
            {"scanner_key": "host_header"},
            {"scanner_key": "cache_poisoning"},
        ],
    },
    {
        "name": "NoSQL Injection + Authentication Bypass → Full Admin Access",
        "risk": "Critical",
        "cvss_bonus": 2.0,
        "conditions": [
            {"scanner_key": "nosql"},
            {"scanner_key": "auth"},
        ],
    },
    {
        "name": "Deserialization + Command Injection → Remote Code Execution",
        "risk": "Critical",
        "cvss_bonus": 2.5,
        "conditions": [
            {"scanner_key": "deserialization"},
            {"scanner_key": "command_injection"},
        ],
    },
    {
        "name": "Cookie Without Secure + Session Hijacking → Account Takeover",
        "risk": "High",
        "cvss_bonus": 1.0,
        "conditions": [
            {"scanner_key": "cookie"},
            {"scanner_key": "session"},
        ],
    },
]

EVIDENCE_EXTRACTORS: dict[str, list[str]] = {
    "ssrf": ["http://169.254", "imds", "metadata"],
    "lfi": ["root:", "etc/passwd", "boot.ini", "windows"],
    "sql_injection": ["SQL syntax", "mysql_fetch", "ORA-", "unclosed quotation"],
    "xss": ["<script>", "alert(", "onerror=", "onload="],
}


def detect_chains(vulns: list[dict]) -> list[dict]:
    chains = []
    keyed: dict[str, list[dict]] = {}
    for v in vulns:
        sk = v.get("scanner_key", "unknown")
        keyed.setdefault(sk, []).append(v)

    for rule in CHAIN_RULES:
        matched = []
        for cond in rule["conditions"]:
            sk_cond = cond.get("scanner_key", "")
            sev_cond = cond.get("severity", {})
            if isinstance(sk_cond, dict) and "$in" in sk_cond:
                candidates = []
                for alt_sk in sk_cond["$in"]:
                    candidates.extend(keyed.get(alt_sk, []))
            else:
                candidates = keyed.get(sk_cond, [])

            if not candidates:
                matched = []
                break

            if sev_cond and "$in" in sev_cond:
                candidates = [c for c in candidates if c.get("severity") in sev_cond["$in"]]

            if not candidates:
                matched = []
                break

            matched.extend(candidates[:2])

        if matched:
            combined_title = rule["name"]
            combined_desc = f"Attack chain detected: {rule['name']}\n\n"
            combined_desc += "Contributing findings:\n"
            base_cvss = 0.0
            for m in matched:
                combined_desc += f"  - {m.get('title', 'unknown')} ({m.get('severity', 'Info')})\n"
                base_cvss = max(base_cvss, m.get("cvss_score", 0))
            combined_cvss = min(base_cvss + rule.get("cvss_bonus", 0), 10.0)

            chains.append({
                "chain_name": rule["name"],
                "risk": rule.get("risk", "Medium"),
                "cvss_score": round(combined_cvss, 1),
                "description": combined_desc,
                "contributing_findings": matched,
                "remediation": "Each finding in this chain must be addressed. "
                "Attackers chain these weaknesses for maximum impact. "
                "Priority: fix the chain as a whole.",
            })

    return chains

