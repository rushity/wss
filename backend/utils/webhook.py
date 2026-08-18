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


def send_webhook_alert(webhook_url, scan, vulnerabilities, crit_count, high_count):
    """
    Sends a formatted Discord/Slack compatible webhook payload summarizing the scan.
    """
    if not webhook_url:
        return

    score = scan.security_score
    status_color = 0x00FF00 # Green
    if crit_count > 0:
        status_color = 0xFF0000 # Red
    elif high_count > 0:
        status_color = 0xFFA500 # Orange

    embed = {
        "title": f"🚨 Security Scan Completed: {scan.target_url}",
        "description": f"Scan type **{scan.scan_type}** finished with a security score of **{score}/100**.",
        "color": status_color,
        "fields": [
            {"name": "Target", "value": scan.target_url, "inline": True},
            {"name": "Scan ID", "value": scan.id[:8], "inline": True},
            {"name": "Score", "value": str(score), "inline": True},
            {"name": "Critical", "value": str(crit_count), "inline": True},
            {"name": "High", "value": str(high_count), "inline": True},
            {"name": "Total Vulns", "value": str(len(vulnerabilities)), "inline": True},
        ],
        "footer": {"text": f"LarShield Web Security • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"}
    }

    # If criticals exist, add a snippet of the top finding
    if crit_count > 0:
        top_vuln = next((v for v in vulnerabilities if v.severity == "Critical"), None)
        if top_vuln:
            embed["fields"].append({
                "name": f"Top Finding: {top_vuln.title}",
                "value": top_vuln.description[:250] + "...",
                "inline": False
            })

    payload = {
        "username": "LarShield Alert System",
        "avatar_url": "https://i.imgur.com/4M34hi2.png", # Placeholder shield icon
        "embeds": [embed]
    }

    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        print(f"DEBUG: Webhook failed: {e}")

