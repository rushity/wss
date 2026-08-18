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


FINGERPRINTS: list[dict] = [
    {"name": "WordPress", "regex": r'<meta name="generator" content="WordPress ([0-9.]+)"', "type": "CMS"},
    {"name": "Drupal", "regex": r'<meta name="Generator" content="Drupal ([0-9.]+)"', "type": "CMS"},
    {"name": "Joomla", "regex": r'<meta name="generator" content="Joomla! ([0-9.]+)"', "type": "CMS"},
    {"name": "jQuery", "regex": r'jquery[.-]v?([0-9.]+)(?:\.min)?\.js', "type": "JS Library"},
    {"name": "Bootstrap", "regex": r'bootstrap[.-]v?([0-9.]+)(?:\.min)?\.css', "type": "CSS Framework"},
    {"name": "React", "regex": r'react[.-]v?([0-9.]+)(?:\.min)?\.js|__REACT_DEVTOOLS_GLOBAL_HOOK__', "type": "JS Framework"},
    {"name": "Angular", "regex": r'angular[.-]v?([0-9.]+)(?:\.min)?\.js|ng-version="([0-9.]+)"', "type": "JS Framework"},
    {"name": "Vue.js", "regex": r'vue[.-]v?([0-9.]+)(?:\.min)?\.js|__VUE_DEVTOOLS_GLOBAL_HOOK__', "type": "JS Framework"},
    {"name": "Django", "regex": r'csrfmiddlewaretoken|__admin_media_prefix__', "type": "Python Web"},
    {"name": "Flask", "regex": r'flask|__gl××××××?', "type": "Python Web"},
    {"name": "Laravel", "regex": r'Laravel|__livewire', "type": "PHP Framework"},
    {"name": "Symfony", "regex": r'symfony|_sf2_attributes|_sf2_meta', "type": "PHP Framework"},
    {"name": "ASP.NET", "regex": r'__VIEWSTATE|__EVENTVALIDATION|X-AspNet-Version', "type": ".NET Web"},
    {"name": "Nginx", "regex": r'nginx(?:/([0-9.]+))?', "type": "Web Server"},
    {"name": "Apache", "regex": r'Apache(?:/([0-9.]+))?', "type": "Web Server"},
    {"name": "Cloudflare", "regex": r'cloudflare|__cfduid|cf-ray', "type": "CDN/WAF"},
    {"name": "AWS", "regex": r'aws|amazonaws\.com|x-amz-', "type": "Cloud"},
    {"name": "Google Cloud", "regex": r'googleapis\.com|gstatic\.com|cloudfront', "type": "Cloud"},
]

CVE_DATABASE: list[dict] = [
    {"cve": "CVE-2024-21626", "software": "Docker", "versions": {"<": "25.0.2"}, "severity": "Critical", "cvss": 9.9},
    {"cve": "CVE-2024-27198", "software": "JetBrains TeamCity", "versions": {"<": "2023.11.4"}, "severity": "Critical", "cvss": 9.8},
    {"cve": "CVE-2023-46604", "software": "Apache ActiveMQ", "versions": {"<": "5.18.3"}, "severity": "Critical", "cvss": 10.0},
    {"cve": "CVE-2023-50164", "software": "Apache Struts", "versions": {"<": "2.5.33"}, "severity": "Critical", "cvss": 9.8},
    {"cve": "CVE-2023-44487", "software": "HTTP/2", "versions": {}, "severity": "High", "cvss": 7.5},
    {"cve": "CVE-2023-22527", "software": "Atlassian Confluence", "versions": {"<": "8.5.4"}, "severity": "Critical", "cvss": 10.0},
    {"cve": "CVE-2023-46674", "software": "WordPress", "versions": {"<": "6.4.1"}, "severity": "High", "cvss": 8.3},
    {"cve": "CVE-2023-43786", "software": "Drupal", "versions": {"<": "10.1.6"}, "severity": "High", "cvss": 8.1},
    {"cve": "CVE-2023-51441", "software": "Apache Axis", "versions": {}, "severity": "Critical", "cvss": 9.8},
    {"cve": "CVE-2023-2986", "software": "WordPress", "versions": {"<": "6.3"}, "severity": "High", "cvss": 7.5},
    {"cve": "CVE-2023-5362", "software": "Joomla", "versions": {"<": "5.0.1"}, "severity": "Medium", "cvss": 5.3},
    {"cve": "CVE-2023-44487", "software": "nginx", "versions": {"<": "1.25.3"}, "severity": "High", "cvss": 7.5},
    {"cve": "CVE-2023-50447", "software": "Django", "versions": {"<": "5.0.1"}, "severity": "High", "cvss": 8.1},
    {"cve": "CVE-2023-34034", "software": "Spring", "versions": {"<": "6.0.14"}, "severity": "High", "cvss": 7.5},
    {"cve": "CVE-2023-38286", "software": "Apache", "versions": {"<": "2.4.57"}, "severity": "High", "cvss": 7.5},
]

TECH_EOL: dict[str, dict[str, str]] = {
    "jQuery": {"< 3.0": "EOL since 2019, known CVEs in 1.x/2.x"},
    "AngularJS": {"1.x": "EOL since Jan 2022, no security patches"},
    "Bootstrap": {"< 3.4": "EOL since 2019"},
    "WordPress": {"< 5.0": "Multiple known vulnerabilities"},
    "Drupal": {"< 8.0": "EOL, multiple known CVEs"},
    "Internet Explorer": {"any": "Browser EOL, no security support"},
}


def match_tech(body: str, headers: dict) -> list[dict]:
    results = []
    for fp in FINGERPRINTS:
        try:
            m = re.search(fp["regex"], body, re.I)
            if m:
                version = m.group(1) if m.lastindex and m.group(1) else m.group(0)
                eol_info = TECH_EOL.get(fp["name"], {}).get(version, "")
                results.append({
                    "name": fp["name"],
                    "version": version,
                    "type": fp["type"],
                    "eol": eol_info,
                })
        except Exception:
            pass
    for k, v in (headers or {}).items():
        if k.lower() == "server":
            results.append({"name": v, "version": "", "type": "Server Header", "eol": ""})
        if k.lower() == "x-powered-by":
            results.append({"name": v, "version": "", "type": "Powered-By", "eol": ""})
    return results


def find_cves(tech_name: str, version: str | None = None) -> list[dict]:
    matches = []
    for cve in CVE_DATABASE:
        if cve["software"].lower() not in tech_name.lower():
            continue
        if not cve["versions"]:
            matches.append(cve)
        elif version and cve["versions"].get("<"):
            try:
                if float(version) < float(cve["versions"]["<"]):
                    matches.append(cve)
            except ValueError:
                matches.append(cve)
    return matches

