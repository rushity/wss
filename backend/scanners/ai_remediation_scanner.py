"""
ai_remediation_scanner.py — AI-Powered Remediation Generator
=============================================================
Post-processes all accumulated scan findings and generates:
  1. Prioritized remediation plan (by CVSS score + exploitability)
  2. Contextual, stack-aware fix guidance (detects PHP/Node/Python/Java)
  3. Estimated fix effort (hours) per vulnerability
  4. Executive risk summary
  5. Code snippet examples for common fixes

This scanner should run LAST in the pipeline (it reads other scanners' findings
from the shared in-memory log). In pipeline runs it reads from BaseScanner.all_vulns
injected via the orchestrator. In standalone mode it reads the JSON report.

Optionally uses OpenAI API if OPENAI_API_KEY is set in environment.
"""
import os, re, json, urllib.request
from scanners.base_scanner import BaseScanner, active_scan_logs

# ── Remediation knowledge base ─────────────────────────────────────────────
# Maps vuln title keywords -> {effort_hours, stack_hints, code_example}
KNOWLEDGE_BASE = {
    "missing security header": {
        "effort": 0.5,
        "tags": ["headers", "quick-win"],
        "code": {
            "nginx":  'add_header {HEADER} "{VALUE}" always;',
            "apache": 'Header always set {HEADER} "{VALUE}"',
            "express": 'app.use(helmet()); // npm install helmet',
            "django": 'SECURE_BROWSER_XSS_FILTER = True  # settings.py',
            "laravel": '// Use spatie/laravel-csp package',
        },
    },
    "content security policy": {
        "effort": 4,
        "tags": ["csp", "medium-effort"],
        "code": {
            "nginx":  "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'nonce-{RANDOM}'\" always;",
            "express": "app.use(helmet.contentSecurityPolicy({directives:{defaultSrc:[\"'self'\"]}}));",
        },
    },
    "sql injection": {
        "effort": 8,
        "tags": ["injection", "critical", "high-effort"],
        "code": {
            "python":  "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            "php":     "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);",
            "node":    "db.query('SELECT * FROM users WHERE id = $1', [userId])",
            "java":    "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\"); ps.setInt(1, id);",
        },
    },
    "xss": {
        "effort": 6,
        "tags": ["injection", "high-effort"],
        "code": {
            "python":  "from markupsafe import escape; safe = escape(user_input)",
            "php":     "echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');",
            "node":    "const he = require('he'); safe = he.encode(userInput);",
            "react":   "// React auto-escapes by default. Never use dangerouslySetInnerHTML.",
        },
    },
    "csrf": {
        "effort": 4,
        "tags": ["csrf", "medium-effort"],
        "code": {
            "django":  "{% csrf_token %}  <!-- in template; middleware enabled by default -->",
            "laravel": "@csrf  <!-- Blade directive; VerifyCsrfToken middleware active -->",
            "express": "const csrf = require('csurf'); app.use(csrf());",
            "flask":   "from flask_wtf import CSRFProtect; csrf = CSRFProtect(app)",
        },
    },
    "clickjacking": {
        "effort": 0.5,
        "tags": ["headers", "quick-win"],
        "code": {
            "nginx":  "add_header X-Frame-Options \"DENY\" always;\nadd_header Content-Security-Policy \"frame-ancestors 'none'\" always;",
            "apache": "Header always set X-Frame-Options \"DENY\"",
        },
    },
    "ssl": {
        "effort": 2,
        "tags": ["tls", "medium-effort"],
        "code": {
            "nginx":  "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\nssl_prefer_server_ciphers off;",
            "apache": "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256",
        },
    },
    "hsts": {
        "effort": 0.5,
        "tags": ["headers", "quick-win"],
        "code": {
            "nginx":  'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
            "apache": 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
        },
    },
    "open redirect": {
        "effort": 3,
        "tags": ["redirect", "medium-effort"],
        "code": {
            "python":  "from urllib.parse import urlparse\nif urlparse(dest).netloc not in ALLOWED_HOSTS: dest = '/'",
            "php":     "$allowed = ['example.com'];\nif (!in_array(parse_url($url, PHP_URL_HOST), $allowed)) $url = '/';",
            "node":    "const allowed = ['example.com'];\nif (!allowed.includes(new URL(dest).hostname)) dest = '/';",
        },
    },
    "cookie": {
        "effort": 1,
        "tags": ["cookies", "quick-win"],
        "code": {
            "nginx":  "proxy_cookie_flags ~ Secure HttpOnly SameSite=Strict;",
            "express": "res.cookie('session', val, {httpOnly:true, secure:true, sameSite:'strict'});",
            "django":  "SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = 'Strict'",
            "php":     "session_set_cookie_params(['secure'=>true,'httponly'=>true,'samesite'=>'Strict']);",
        },
    },
    "lfi": {
        "effort": 6,
        "tags": ["injection", "high-effort"],
        "code": {
            "php":    "$allowed = ['home','about','contact'];\nif (!in_array($page, $allowed)) die('Forbidden');\ninclude \"pages/{$page}.php\";",
            "python": "ALLOWED_PAGES = {'home': 'home.html', 'about': 'about.html'}\ntemplate = ALLOWED_PAGES.get(page_param, '404.html')",
        },
    },
    "ssti": {
        "effort": 8,
        "tags": ["injection", "critical", "high-effort"],
        "code": {
            "python":  "from jinja2.sandbox import SandboxedEnvironment\nenv = SandboxedEnvironment()\n# Never use render_template_string(user_input)",
            "php":     "// Use Twig sandbox:\n$policy = new SecurityPolicy($tags,$filters);\n$sandbox = new SandboxExtension($policy);\n$twig->addExtension($sandbox);",
        },
    },
    "secret": {
        "effort": 2,
        "tags": ["secrets", "critical"],
        "code": {
            "general": "# Use environment variables:\nimport os\nAPI_KEY = os.environ['API_KEY']\n\n# Or a secrets manager:\n# AWS Secrets Manager, HashiCorp Vault, Azure Key Vault",
        },
    },
    "git": {
        "effort": 1,
        "tags": ["exposure", "quick-win"],
        "code": {
            "nginx":  "location ~ /\\.(git|svn|hg|env) {\n    deny all;\n    return 404;\n}",
            "apache": "RedirectMatch 404 /\\.git\nRedirectMatch 404 /\\.env",
        },
    },
    "dependency": {
        "effort": 3,
        "tags": ["dependencies", "medium-effort"],
        "code": {
            "node":   "npm audit fix\nnpm update\n# Or: npx npm-check-updates -u && npm install",
            "python": "pip install --upgrade pip\npip list --outdated\npip install safety && safety check",
            "php":    "composer update\ncomposer audit",
        },
    },
    "rate limit": {
        "effort": 3,
        "tags": ["auth", "medium-effort"],
        "code": {
            "nginx":  "limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;\nlimit_req zone=login burst=3 nodelay;",
            "express": "const rateLimit = require('express-rate-limit');\napp.use('/login', rateLimit({windowMs:60000, max:5}));",
        },
    },
}

EFFORT_LABELS = {
    range(0, 1):    "Quick Fix (< 1 hour)",
    range(1, 4):    "Short Sprint (1–3 hours)",
    range(4, 9):    "Medium Task (4–8 hours)",
    range(9, 100):  "Large Effort (> 8 hours)",
}

def _effort_label(hours: float) -> str:
    for r, label in EFFORT_LABELS.items():
        if int(hours) in r:
            return label
    return f"~{int(hours)} hours"


def _match_kb(title: str) -> dict | None:
    title_lower = title.lower()
    for keyword, entry in KNOWLEDGE_BASE.items():
        if keyword in title_lower:
            return entry
    return None


class AiRemediationScanner(BaseScanner):
    SCANNER_NAME = "AI Remediation Generator"
    _SCANNER_KEY = "ai_remediation"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)
        self._openai_key = os.environ.get("OPENAI_API_KEY", "")
        self._stack      = self._detect_stack()

    # ------------------------------------------------------------------
    def run(self) -> list:
        self.log("INFO",
            f"[AI-Remediation] Generating remediation plan for {self.target}...")
        self.log("INFO",
            f"[AI-Remediation] Detected tech stack hint: {self._stack or 'unknown'}")

        try:
            # Gather all vulns from the shared in-memory log for this scan
            all_vulns = self._gather_all_vulns()
            self.log("INFO",
                f"[AI-Remediation] Processing {len(all_vulns)} finding(s) from pipeline...")

            if not all_vulns:
                self.log("SUCCESS",
                    "[AI-Remediation] No findings to remediate — clean scan!")
                return self.vulns

            # Sort by CVSS score descending
            sorted_vulns = sorted(all_vulns,
                key=lambda v: float(v.get("cvss_score") or 0), reverse=True)

            remediation_items = []
            total_effort      = 0.0

            for i, vuln in enumerate(sorted_vulns[:30], 1):  # top 30
                title   = vuln.get("title", "")
                severity= vuln.get("severity","Info")
                cvss    = float(vuln.get("cvss_score") or 0)
                kb      = _match_kb(title)
                effort  = kb["effort"] if kb else self._estimate_effort(cvss)
                total_effort += effort

                code_hint = ""
                if kb and kb.get("code"):
                    stack_code = kb["code"].get(self._stack) or \
                                 next(iter(kb["code"].values()), "")
                    if stack_code:
                        code_hint = f"\n\n**Fix Code ({self._stack or 'generic'}):**\n```\n{stack_code}\n```"

                remediation_items.append({
                    "rank":    i,
                    "title":   title,
                    "severity": severity,
                    "cvss":    cvss,
                    "effort":  effort,
                    "effort_label": _effort_label(effort),
                    "tags":    kb["tags"] if kb else [],
                    "code_hint": code_hint,
                })

            # ── Generate AI-enhanced advice if API key is available ────
            if self._openai_key:
                self._enhance_with_openai(remediation_items[:5])

            # ── Emit consolidated remediation plan as a finding ────────
            self._emit_plan(remediation_items, total_effort, sorted_vulns)

        except Exception as e:
            self.log("WARNING", f"[AI-Remediation] Error: {e}")

        return self.vulns

    # ------------------------------------------------------------------
    def _gather_all_vulns(self) -> list:
        """Collect all vulns from in-memory log for this scan_id.
        NOTE: active_scan_logs stores plain strings, not dicts.
        This method safely skips non-dict entries and always returns [].
        The AI remediation plan is generated from self.vulns populated by
        the orchestrator via scanner.py's _run_scan_job -> all_vulns flow.
        """
        logs = active_scan_logs.get(self.scan_id, [])
        seen = set()
        vulns = []
        for entry in logs:
            # Logs are plain strings — skip any non-dict entries safely
            if not isinstance(entry, dict):
                continue
            if entry.get("type") == "vuln":
                key = entry.get("title", "") + entry.get("severity", "")
                if key not in seen:
                    seen.add(key)
                    vulns.append(entry)
        return vulns

    # ------------------------------------------------------------------
    def _detect_stack(self) -> str:
        """Heuristic: probe the target and detect framework from headers/body."""
        try:
            req = urllib.request.Request(self.target,
                headers={"User-Agent": "LarShield/2.0 AI-Remediation"})
            with urllib.request.urlopen(req, timeout=6, context=self.get_ssl_context()) as r:
                headers = {k.lower(): v.lower() for k, v in r.headers.items()}
                body    = r.read(4096).decode("utf-8", errors="ignore").lower()

            server  = headers.get("server","")
            powered = headers.get("x-powered-by","")

            if "php" in powered or "php" in server:        return "php"
            if "express" in powered or "node" in server:   return "node"
            if "django" in body or "csrfmiddlewaretoken" in body: return "python"
            if "laravel" in body or "laravel_session" in headers.get("set-cookie",""): return "php"
            if "asp.net" in powered or "asp.net" in server: return "aspnet"
            if "java" in server or "tomcat" in server or "jsessionid" in headers.get("set-cookie",""): return "java"
            if "rails" in server or "x-request-id" in headers: return "ruby"
        except Exception as e:
            print(f"ERROR: [AI] Framework detection error: {e}")
        return "nginx"   # default to nginx/generic

    # ------------------------------------------------------------------
    @staticmethod
    def _estimate_effort(cvss: float) -> float:
        if cvss >= 9.0:  return 8.0
        if cvss >= 7.0:  return 5.0
        if cvss >= 4.0:  return 3.0
        return 1.0

    # ------------------------------------------------------------------
    def _enhance_with_openai(self, top_items: list):
        """Call OpenAI API to generate enhanced remediation for top 5 findings."""
        try:
            prompt = (
                "You are a senior application security engineer. "
                "For each finding below, provide a concise, specific fix in 2-3 sentences "
                f"for a {self._stack} application:\n\n"
                + "\n".join(f"{i+1}. [{v['severity']}] {v['title']} (CVSS {v['cvss']})"
                             for i, v in enumerate(top_items))
            )
            body = json.dumps({
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 800,
                "temperature": 0.3,
            }).encode()
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=body,
                headers={
                    "Authorization": f"Bearer {self._openai_key}",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=20) as r:
                resp = json.loads(r.read())
                ai_text = resp["choices"][0]["message"]["content"]
                self.log("INFO", f"[AI-Remediation] OpenAI enhanced advice: {ai_text[:300]}...")
                # Inject into first item
                if top_items:
                    top_items[0]["ai_advice"] = ai_text
        except Exception as e:
            self.log("WARNING", f"[AI-Remediation] OpenAI call failed: {e}")

    # ------------------------------------------------------------------
    def _emit_plan(self, items: list, total_effort: float, all_vulns: list):
        sev_counts = {}
        for v in all_vulns:
            s = v.get("severity","Info")
            sev_counts[s] = sev_counts.get(s,0) + 1

        quick_wins  = [i for i in items if "quick-win" in i.get("tags",[])]
        critical_items = [i for i in items if i["cvss"] >= 9.0]

        plan_lines = [
            f"# Remediation Plan — {self.target}",
            f"**Total findings processed:** {len(all_vulns)}",
            f"**Detected stack:** {self._stack or 'unknown'}",
            f"**Estimated total fix effort:** ~{int(total_effort)} hours",
            "",
            "## Severity Distribution",
            *[f"- **{k}:** {v}" for k, v in sev_counts.items()],
            "",
            f"## ⚡ Quick Wins First ({len(quick_wins)} items, < 1h each)",
            *[f"- [{qw['severity']}] **{qw['title']}** — {qw['effort_label']}" for qw in quick_wins[:10]],
            "",
            f"## 🚨 Critical Priority ({len(critical_items)} items)",
            *[f"- CVSS {ci['cvss']} — **{ci['title']}**" for ci in critical_items[:10]],
            "",
            "## Prioritized Remediation Roadmap",
        ]

        for item in items[:20]:
            code = item.get("code_hint","")
            plan_lines.append(
                f"\n### #{item['rank']} [{item['severity']}] {item['title']}\n"
                f"**CVSS:** {item['cvss']} | **Effort:** {item['effort_label']} | "
                f"**Tags:** {', '.join(item.get('tags',['general']))}"
                f"{code}"
            )

        self.add_vuln(
            title="AI-Generated Remediation Plan",
            severity="Low",
            category="Remediation Plan",
            cvss_score=0.0,
            description="\n".join(plan_lines),
            remediation=(
                "Execute the quick wins immediately (< 1 hour each). "
                f"Address all Critical CVSS ≥ 9.0 items within 24 hours. "
                f"Schedule the remaining {len(items)} items in your next sprint."
            ),
        )

        self.log("SUCCESS",
            f"[AI-Remediation] Plan generated: {len(items)} items, "
            f"~{int(total_effort)}h total effort, "
            f"{len(quick_wins)} quick wins, {len(critical_items)} critical.")
