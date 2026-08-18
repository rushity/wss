"""
dom_xss_scanner.py — DOM XSS Static Analysis Scanner
======================================================
Fetches JavaScript files and performs static sink/source analysis to detect
DOM-based XSS patterns that are never visible to the server.
"""
import re
from scanners.base_scanner import BaseScanner

SINKS = [
    "document.write", "document.writeln", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(",
    "location.href", "location.replace", "location.assign",
    "document.location", "window.location", "src=", "href=",
    "importScripts(", "Function(", "Range.createContextualFragment",
    "script.text", "script.textContent", "srcdoc=", "DOMParser",
    "execScript(", "msWriteProfilerMark", "setImmediate(",
    "createHTMLDocument", "location.hash=",
]

SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.URL", "document.referrer", "document.cookie",
    "window.name", "localStorage", "sessionStorage",
    "URLSearchParams", "decodeURIComponent", "unescape(",
    "postMessage(", "MessageChannel", "history.pushState",
    "history.replaceState", "document.documentURI",
    "performance.getEntries", "fetch(", "XMLHttpRequest",
]


class DomXssScanner(BaseScanner):
    SCANNER_NAME = "DOM XSS Static Analysis Scanner"
    _SCANNER_KEY = "dom_xss"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[DomXSS] Performing static JS AST analysis on {self.target}...")
        html, status = self._make_request(self.target)
        if html is None:
            self.log("WARNING", f"[DomXSS] Error fetching page")
            return self.vulns

        scripts = re.findall(r'src=["\']([^"\']+\.js)["\']', html, re.I)
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.I | re.S)

        all_js = []
        for src in scripts[:12]:
            js = self._fetch_js(self._resolve(src))
            if js:
                all_js.append((self._resolve(src), js))

        for idx, block in enumerate(inline_scripts):
            if block.strip():
                all_js.append((f"inline#{idx+1}", block))

        found_flows = []
        for js_name, js_code in all_js:
            flows = self._find_flows(js_name, js_code)
            found_flows.extend(flows)

        taint_flows = self._find_taint_flows(all_js)
        found_flows.extend(taint_flows)

        if found_flows:
            examples = found_flows[:5]
            self.add_vuln(
                title=f"DOM XSS Sink/Source Flows Detected ({len(found_flows)} pattern(s))",
                severity="High",
                category="DOM XSS",
                cvss_score=7.4,
                description="Static analysis identified dangerous source\u2192sink data flows in client-side JavaScript:\n\n" +
                    "\n".join(f"- **{f['file']}**: `{f['source']}` \u2192 `{f['sink']}`\n  `{f['snippet']}`" for f in examples),
                remediation="1. Never pass untrusted sources (location.hash, URL params) directly to sinks.\n"
                    "2. Use textContent instead of innerHTML.\n"
                    "3. Sanitize with DOMPurify before any DOM insertion.\n"
                    "4. Use a strict Content Security Policy to block inline scripts.",
                evidence="\n".join(f"{f['file']}: {f['snippet']}" for f in examples),
                confidence="High",
            )
        else:
            self.log("SUCCESS", "[DomXSS] No obvious DOM XSS flows detected.")
        return self.vulns

    def _find_flows(self, js_name, code):
        flows = []
        lines = code.split("\n")
        for i, line in enumerate(lines):
            has_source = any(src in line for src in SOURCES)
            has_sink = any(sink in line for sink in SINKS)
            if has_source and has_sink:
                src_matches = [s for s in SOURCES if s in line]
                sink_matches = [s for s in SINKS if s in line]
                flows.append({
                    "file": js_name,
                    "source": src_matches[0],
                    "sink": sink_matches[0],
                    "snippet": line.strip()[:120],
                })
            elif has_source and i + 1 < len(lines):
                next_line = lines[i + 1]
                if any(sink in next_line for sink in SINKS):
                    flows.append({
                        "file": js_name,
                        "source": [s for s in SOURCES if s in line][0],
                        "sink": [s for s in SINKS if s in next_line][0],
                        "snippet": (line.strip() + " \u2192 " + next_line.strip())[:120],
                    })
        return flows

    def _find_taint_flows(self, all_js):
        taint_flows = []
        for js_name, js_code in all_js:
            lines = js_code.split("\n")
            for i, line in enumerate(lines):
                for src in SOURCES:
                    if src not in line:
                        continue
                    m = re.search(r'(?:var|let|const)\s+(\w+)\s*=\s*', line)
                    if not m:
                        m = re.search(r'(\w+)\s*=\s*', line)
                    if not m:
                        continue
                    var_name = m.group(1)
                    for j in range(i + 1, min(i + 10, len(lines))):
                        later_line = lines[j]
                        if var_name in later_line:
                            for sink in SINKS:
                                if sink in later_line:
                                    taint_flows.append({
                                        "file": js_name,
                                        "source": src,
                                        "sink": sink,
                                        "snippet": f"{line.strip()} ... {later_line.strip()}"[:120],
                                    })
                                    break
        return taint_flows

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
            self.log("ERROR", f"[DomXSS] _fetch_js error for {url}")
            return ""
        return body
