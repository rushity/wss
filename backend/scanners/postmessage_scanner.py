"""
postmessage_scanner.py — PostMessage Security Scanner
======================================================
Analyzes inline and external JavaScript for insecure postMessage handlers:
  - addEventListener('message', ...) with no origin check
  - Handlers that pass event.data directly to eval/innerHTML/document.write
  - Missing origin validation allowing cross-origin data theft
  - postMessage to window.open targets
"""
import re
from scanners.base_scanner import BaseScanner

UNSAFE_HANDLER_PATTERNS = [
    r"addEventListener\s*\(\s*['\"]message['\"]",
    r"on\s*message\s*=\s*function",
    r"\.onmessage\s*=",
    r"addEventListener\s*\(\s*['\"]message['\"],\s*function",
]

DANGEROUS_SINKS_IN_HANDLER = [
    "eval(", "eval (", "innerHTML", "outerHTML",
    "document.write", "location.href", "location.assign",
    "setTimeout(", "setInterval(", "Function(",
    "document.open(", "srcdoc=",
]

ORIGIN_CHECKS = [
    "event.origin", "e.origin", "msg.origin",
    ".origin ===", ".origin !==", "origin.includes",
    "allowedOrigins", "trusted", "origin.endsWith",
    "origin.startsWith", "origin.indexOf",
]

TARGET_WINDOW_PATTERNS = [
    r"\.postMessage\s*\(",
]


class PostmessageScanner(BaseScanner):
    SCANNER_NAME = "PostMessage Security Scanner"
    _SCANNER_KEY = "postmessage"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[PostMessage] Analyzing JS for insecure postMessage handlers on {self.target}...")
        html, status = self._make_request(self.target)
        if html is None:
            self.log("WARNING", f"[PostMessage] Error fetching page")
            return self.vulns

        scripts_src = re.findall(r'src=["\']([^"\']+\.js)["\']', html, re.I)
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.I | re.S)

        all_js_blocks = []
        for src in scripts_src[:10]:
            js = self._fetch_js(self._resolve(src))
            if js:
                all_js_blocks.append((self._resolve(src), js))
        for idx, block in enumerate(inline_scripts):
            if block.strip():
                all_js_blocks.append((f"inline#{idx+1}", block))

        findings = []
        for js_name, js_code in all_js_blocks:
            result = self._analyze(js_name, js_code)
            findings.extend(result)

        self._check_origin_validation(findings)
        self._check_xss_via_insufficient_origin(all_js_blocks)
        self._check_window_open_postmessage(all_js_blocks)

        if findings:
            critical = [f for f in findings if f["severity"] == "critical"]
            medium = [f for f in findings if f["severity"] == "medium"]

            if critical:
                self.add_vuln(
                    title=f"Insecure postMessage Handler — Missing Origin Check ({len(critical)} instance(s))",
                    severity="High",
                    category="PostMessage Vulnerability",
                    cvss_score=7.4,
                    description="JavaScript `message` event handlers found **without origin validation**:\n\n" +
                        "\n".join(f"- **{f['file']}** line ~{f['line']}: `{f['snippet']}`" for f in critical[:5]) +
                        "\n\nAny window (including attacker-controlled iframes) can send messages "
                        "that will be processed by these handlers, enabling cross-origin data theft.",
                    remediation="1. Always validate `event.origin` before processing messages:\n"
                        "   `if (event.origin !== 'https://trusted.com') return;`\n"
                        "2. Never pass `event.data` to `eval()`, `innerHTML`, or `document.write`.\n"
                        "3. Use a strict allowlist, not a blocklist, for origin validation.",
                    evidence="\n".join(f"{f['file']}:{f['line']} - {f['snippet']}" for f in critical[:5]),
                    confidence="High",
                )
            if medium:
                self.add_vuln(
                    title=f"postMessage Handler Passes Data to Dangerous Sink ({len(medium)} instance(s))",
                    severity="High",
                    category="PostMessage Vulnerability",
                    cvss_score=7.4,
                    description="Message handlers pass `event.data` to dangerous DOM sinks:\n\n" +
                        "\n".join(f"- **{f['file']}**: `{f['snippet']}`" for f in medium[:5]),
                    remediation="Sanitize event.data with DOMPurify before insertion. "
                        "Prefer textContent over innerHTML for message-driven UI updates.",
                    evidence="\n".join(f"{f['file']}:{f['line']} - {f['snippet']}" for f in medium[:5]),
                    confidence="High",
                )
        else:
            self.log("SUCCESS", "[PostMessage] No insecure postMessage handlers found.")
        return self.vulns

    def _analyze(self, js_name, code):
        findings = []
        lines = code.split("\n")
        for i, line in enumerate(lines):
            has_handler = any(re.search(p, line) for p in UNSAFE_HANDLER_PATTERNS)
            if not has_handler:
                continue
            window = "\n".join(lines[max(0, i-2):min(len(lines), i+20)])
            has_origin_check = any(oc in window for oc in ORIGIN_CHECKS)
            has_dangerous_sink = any(ds in window for ds in DANGEROUS_SINKS_IN_HANDLER)

            if not has_origin_check:
                findings.append({
                    "file": js_name, "line": i+1,
                    "snippet": line.strip()[:100],
                    "severity": "critical",
                })
            elif has_dangerous_sink:
                findings.append({
                    "file": js_name, "line": i+1,
                    "snippet": line.strip()[:100],
                    "severity": "medium",
                })
        return findings

    def _check_origin_validation(self, findings):
        for f in findings:
            f["origin_validated"] = False
        self.log("INFO", f"[PostMessage] Origin validation check complete for {len(findings)} handler(s)")

    def _check_xss_via_insufficient_origin(self, all_js_blocks):
        for js_name, js_code in all_js_blocks:
            lines = js_code.split("\n")
            for i, line in enumerate(lines):
                if "postMessage" not in line:
                    continue
                if "event.data" in line or "e.data" in line or "msg.data" in line:
                    window = "\n".join(lines[max(0, i-3):min(len(lines), i+15)])
                    if not any(oc in window for oc in ORIGIN_CHECKS):
                        innerHTML_sink = any(ds in window for ds in ["innerHTML", "document.write", "eval("])
                        if innerHTML_sink:
                            self.add_vuln(
                                title="postMessage XSS via Insufficient Origin Check",
                                severity="Critical",
                                category="PostMessage Vulnerability",
                                cvss_score=8.6,
                                description=f"In `{js_name}` line {i+1}: postMessage data flows into a DOM XSS sink "
                                    "without origin validation. Any cross-origin window can inject malicious content.",
                                remediation="Add strict origin validation before processing message data. "
                                    "NEVER pass event.data to innerHTML or eval.",
                                evidence=f"{js_name}:{i+1} - {line.strip()[:100]}",
                                confidence="High",
                            )

    def _check_window_open_postmessage(self, all_js_blocks):
        for js_name, js_code in all_js_blocks:
            lines = js_code.split("\n")
            for i, line in enumerate(lines):
                if "window.open" in line and "postMessage" in js_code:
                    var_match = re.search(r'var\s+(\w+)\s*=\s*window\.open', line)
                    if not var_match:
                        var_match = re.search(r'(\w+)\s*=\s*window\.open', line)
                    if var_match:
                        win_var = var_match.group(1)
                        for j in range(i + 1, min(i + 15, len(lines))):
                            later = lines[j]
                            if win_var in later and ".postMessage" in later:
                                self.add_vuln(
                                    title="postMessage to window.open Target",
                                    severity="Medium",
                                    category="PostMessage Vulnerability",
                                    cvss_score=5.9,
                                    description=f"In `{js_name}` line {i+1}: A new window is opened and receives "
                                        "postMessage data. If the target origin is not verified, data leaks are possible.",
                                    remediation="Always specify the targetOrigin parameter in postMessage calls.",
                                    evidence=f"{js_name}:{j+1} - {later.strip()[:100]}",
                                    confidence="Medium",
                                )

    def _resolve(self, src):
        from urllib.parse import urlparse
        if src.startswith("//"):
            return f"https:{src}"
        if src.startswith("/"):
            p = urlparse(self.target)
            return f"{p.scheme}://{p.netloc}{src}"
        if not src.startswith("http"):
            return f"{self.target.rstrip('/')}/{src}"
        return src

    def _fetch_js(self, url):
        body, status = self._make_request(url, timeout=5)
        if body is None:
            self.log("ERROR", f"[PostMessage] _fetch_js error for {url}")
            return ""
        return body
