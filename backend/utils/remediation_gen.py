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

TEMPLATES: dict[str, dict[str, str]] = {
    "sql_injection": {
        "python_flask": """from flask import request

def get_user(user_id):
    # BAD: direct string interpolation
    # cur.execute(f"SELECT * FROM users WHERE id = {user_id}")

    # GOOD: parameterized query
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cur.fetchone()""",
        "python_django": """# BAD: raw SQL
# User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")

# GOOD: ORM query
User.objects.filter(id=user_id).first()""",
        "node_express": """// BAD: string concatenation
// db.query(`SELECT * FROM users WHERE id = ${userId}`);

// GOOD: parameterized query
db.query('SELECT * FROM users WHERE id = $1', [userId]);""",
        "java_spring": """// BAD: string concatenation
// String sql = "SELECT * FROM users WHERE id = " + userId;

// GOOD: parameterized query with JDBC
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();""",
    },
    "xss": {
        "python_flask": """from flask import escape

# BAD: rendering raw input
# return f"<h1>Welcome {request.args.get('name')}</h1>"

# GOOD: escape output
name = escape(request.args.get('name', ''))
return f"<h1>Welcome {name}</h1>" """,
        "python_django": """# BAD: marking safe
# from django.utils.safestring import mark_safe
# return render(request, 'template.html', {'name': mark_safe(name)})

# GOOD: auto-escape (Django does this by default)
return render(request, 'template.html', {'name': name})""",
        "node_express": """// BAD: rendering raw input
// res.send(`<h1>Welcome ${req.query.name}</h1>`);

// GOOD: use template engine with auto-escape
res.render('template', { name: req.query.name });""",
        "java_spring": """// BAD: raw output
// out.println("<h1>Welcome " + request.getParameter("name") + "</h1>");

// GOOD: use template engine with auto-escape
// In Thymeleaf: th:text="${name}" auto-escapes HTML""",
    },
    "command_injection": {
        "python": """import subprocess

# BAD: shell=True with user input
# subprocess.run(f"ping {host}", shell=True)

# GOOD: use list form, avoid shell
subprocess.run(["ping", host], capture_output=True, text=True, timeout=5)""",
        "node_express": """const { execFile } = require('child_process');

// BAD: exec with shell
// exec(`ping ${host}`);

// GOOD: execFile with args array
execFile('ping', [host], { timeout: 5000 });""",
        "java": """// BAD: Runtime.exec with shell
// Runtime.getRuntime().exec("ping " + host);

// GOOD: ProcessBuilder with args list
ProcessBuilder pb = new ProcessBuilder("ping", host);
Process p = pb.start();""",
    },
    "lfi": {
        "python": """import os

# BAD: direct path concatenation
# path = f"/var/www/{filename}"

# GOOD: validate and restrict to safe directory
safe_dir = "/var/www/uploads/"
filename = os.path.basename(filename)  # strip path
path = os.path.join(safe_dir, filename)
if not os.path.realpath(path).startswith(os.path.realpath(safe_dir)):
    raise ValueError("Invalid path")""",
    },
    "ssrf": {
        "python": """import ipaddress

# BAD: fetching user-supplied URL directly
# response = requests.get(user_url)

# GOOD: validate URL first
parsed = urlparse(user_url)
host = parsed.hostname
try:
    ip = ipaddress.ip_address(host)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("Blocked internal IP")
except ValueError:
    # allow hostname resolution (but could still be SSRF)
    pass
response = requests.get(user_url, timeout=5)""",
    },
    "xxe": {
        "python": """from lxml import etree

# BAD: default parser allows XXE
# tree = etree.parse(xml_input)

# GOOD: disable external entities
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(xml_input, parser)""",
    },
    "jwt": {
        "python": """import jwt

# BAD: using user-supplied secret
# decoded = jwt.decode(token, options={"verify_signature": False})

# GOOD: validate with known secret and algorithm whitelist
decoded = jwt.decode(token, SECRET_KEY, algorithms=["RS256", "ES256"])""",
    },
    "cors": {
        "python_flask": """from flask import request

# BAD: reflecting origin without validation
# Access-Control-Allow-Origin: *

# GOOD: whitelist allowed origins
ALLOWED_ORIGINS = {"https://example.com", "https://app.example.com"}
origin = request.headers.get("Origin")
if origin in ALLOWED_ORIGINS:
    response.headers["Access-Control-Allow-Origin"] = origin""",
    },
}

DEFAULT_TEMPLATE = """# Remediation for {scanner_key}

## Issue
{description}

## Recommended Fix
1. **Validate all user input** — never trust client-supplied data
2. **Use parameterized queries / prepared statements** for database operations
3. **Apply output encoding** contextually (HTML, JS, CSS, URL)
4. **Implement strict allowlists** instead of blocklists
5. **Use secure defaults** and disable dangerous features
6. **Add proper authentication and authorization checks**
7. **Run security tests** in CI/CD pipeline

## References
- OWASP: https://owasp.org/www-project-top-ten/
- CWE: https://cwe.mitre.org/
"""


def generate_remediation(vuln: dict) -> str:
    scanner_key = vuln.get("scanner_key", "unknown")
    description = vuln.get("description", "")
    region = TEMPLATES.get(scanner_key)
    if not region:
        return DEFAULT_TEMPLATE.format(scanner_key=scanner_key, description=description)
    best = ""
    pref_order = ["python_flask", "python_django", "python", "node_express", "java_spring", "java"]
    for pref in pref_order:
        if pref in region:
            best = region[pref]
            break
    if not best:
        best = next(iter(region.values()))
    return best

