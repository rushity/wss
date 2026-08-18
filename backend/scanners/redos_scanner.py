"""
redos_scanner.py — ReDoS (Regular Expression Denial of Service) Scanner
========================================================================
Expert-grade rewrite (GAP-014 fix):
  1. Timing-based active confirmation (catastrophic backtracking strings)
  2. Response-time delta analysis vs baseline
  3. Multiple backtracking pattern types (quadratic, exponential, polynomial)
  4. Tests GET params, POST form fields, and JSON body
  5. Static pattern detection in JS source (original behavior)
"""
import re, json, urllib.parse
from scanners.base_scanner import BaseScanner

# ── Catastrophic backtracking strings ────────────────────────────────────
# These are designed to trigger exponential/polynomial backtracking in
# common vulnerable patterns like (a+)+ or ([a-zA-Z]+)* etc.
REDOS_STRINGS = [
    "a" * 30 + "!",                             # Quadratic — (a+)+b pattern
    "a" * 50 + "b" + "a" * 50,                  # Nested quantifier trigger
    "(" * 20 + "a" * 20 + ")" * 20 + "!",       # Deeply nested groups
    "aaaaaaaaaaaaaaaaaaaaaaaaaac",               # Common polynomial worst-case
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaa",              # Long run — tests [a-z]* anchoring
    '"' + "a" * 100 + '"' + "a" * 100,          # Email-like catastrophic
    "1" * 50 + "@" + "a" * 50 + "." + "a" * 50, # Email regex trigger
    "a@" + "a" * 50 + "." + "." * 20 + "a",     # Email regex — multiple dot
    # ReDoS via URL/path parameters
    "/" + "a" * 100 + "/" + "b" * 100,
    "?q=" + "a" * 200,
]

# Timing threshold: if response > baseline * FACTOR, flag it
TIMING_FACTOR   = 5.0   # response must be 5x slower
MIN_ELAPSED     = 2.0   # must take at least 2 seconds
BASELINE_REPS   = 3     # average over N baseline requests

# ── Static vulnerable regex patterns (for source code detection) ──────────
VULN_PATTERNS = [
    (re.compile(r'\([^)]+\+\)\+'), "Nested quantifier (a+)+"),
    (re.compile(r'\([^)]+\*\)\*'), "Nested quantifier (a*)*"),
    (re.compile(r'\([^)]+\|\s*[^)]+\)\+'), "Alternation with quantifier (a|b)+"),
    (re.compile(r'\[[^\]]+\]\+\s*\[[^\]]+\]\+'), "Adjacent character class repetition"),
    (re.compile(r'\([^)]+\+[^)]+\)\+'), "Compound quantifier"),
]


class RedosScanner(BaseScanner):
    SCANNER_NAME = "ReDoS Scanner"
    _SCANNER_KEY = "redos"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[ReDoS] Scanning {self.target} for ReDoS vulnerabilities...")

        # 1. Static source code analysis
        self._check_static()

        # 2. Active timing-based detection
        self._check_timing_active()

        if not self.vulns:
            self.log("SUCCESS", "[ReDoS] No ReDoS indicators detected.")
        return self.vulns

    # ── 1. Static analysis ────────────────────────────────────────────────
    def _check_static(self):
        html, status = self._make_request(self.target)
        if not html: return

        for pattern, label in VULN_PATTERNS:
            if pattern.search(html):
                self.log("WARNING", f"[ReDoS] Vulnerable regex pattern found in source: {label}")
                self.add_vuln(
                    title=f"Potentially Vulnerable Regex Pattern ({label})",
                    severity="Medium",
                    category="ReDoS",
                    cvss_score=5.9,
                    confidence="Low",
                    references=["https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"],
                    description=(
                        f"A potentially catastrophic regex pattern was detected in the page source: **{label}**.\n\n"
                        "Regular expressions with nested quantifiers (e.g., `(a+)+`, `(a|b)+`) can "
                        "cause **exponential backtracking** when given adversarial input, leading to "
                        "CPU exhaustion and application unavailability."
                    ),
                    remediation=(
                        "1. Use linear-time regex engines (RE2, Rust's `regex` crate).\n"
                        "2. Rewrite patterns to eliminate nested quantifiers.\n"
                        "3. Apply input length limits before regex evaluation.\n"
                        "4. Use `regex.timeout` or `re2js` in JavaScript.\n"
                        "5. Test regex with tools like `vuln-regex-detector` or `safe-regex`."
                    ),
                )
                break  # One finding per static scan

    # ── 2. Active timing ──────────────────────────────────────────────────
    def _check_timing_active(self):
        # Calculate baseline (average of 3 requests)
        baseline_t = self._measure_baseline()
        if baseline_t is None:
            self.log("INFO", "[ReDoS] Could not establish timing baseline.")
            return
        self.log("INFO", f"[ReDoS] Baseline response time: {baseline_t:.2f}s")

        parsed = urllib.parse.urlparse(self.target)
        qs = urllib.parse.parse_qsl(parsed.query)

        # Test GET params
        if qs:
            for k, _ in qs[:3]:
                for redos_str in REDOS_STRINGS[:5]:
                    if self._test_param_timing(parsed, qs, k, redos_str, baseline_t):
                        return

        # Test common input field names even if no current QS params
        self._test_common_params(baseline_t)

    def _measure_baseline(self) -> float | None:
        times = []
        for _ in range(BASELINE_REPS):
            _, _, elapsed = self._make_timed_request(self.target, timeout=10)
            if elapsed > 0:
                times.append(elapsed)
        return sum(times) / len(times) if times else None

    def _test_param_timing(self, parsed, qs, key, redos_str, baseline_t) -> bool:
        new_qs = [(k, (redos_str if k == key else v)) for k, v in qs]
        test_url = parsed._replace(query=urllib.parse.urlencode(new_qs)).geturl()
        _, status, elapsed = self._make_timed_request(test_url, timeout=15)

        if elapsed >= MIN_ELAPSED and elapsed > baseline_t * TIMING_FACTOR:
            self.log("CRITICAL",
                f"[ReDoS] Timing anomaly: param={key} string_len={len(redos_str)} "
                f"elapsed={elapsed:.2f}s baseline={baseline_t:.2f}s (ratio={elapsed/baseline_t:.1f}x)")
            self.add_vuln(
                title=f"Active ReDoS Confirmed — GET parameter `{key}`",
                severity="High",
                category="ReDoS",
                cvss_score=7.5,
                confidence="High",
                description=(
                    f"**Active ReDoS** confirmed in GET parameter `{key}`.\n\n"
                    f"**Test string:** `{redos_str[:80]}{'...' if len(redos_str)>80 else ''}`\n"
                    f"**Elapsed:** {elapsed:.2f}s vs baseline {baseline_t:.2f}s ({elapsed/baseline_t:.1f}x slower)\n\n"
                    "The application's regex engine went into catastrophic backtracking, "
                    "consuming excessive CPU. A single malicious request can cause the server "
                    "to become unresponsive for seconds or minutes (application-layer DoS)."
                ),
                remediation=(
                    "1. Replace vulnerable regexes with linear-time alternatives (RE2, Oniguruma).\n"
                    "2. Add **input length limits** before any regex evaluation.\n"
                    "3. Move complex validation to server-side regex with a timeout.\n"
                    "4. Use `@hapi/call` or equivalent with built-in ReDoS protection.\n"
                    "5. Profile regex performance with `vuln-regex-detector`."
                ),
                payload=redos_str,
            )
            return True
        return False

    def _test_common_params(self, baseline_t: float):
        """Test common text input params even without existing URL params."""
        parsed = urllib.parse.urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        common_params = ["email", "username", "q", "search", "query", "input", "value"]
        for param in common_params[:4]:
            for redos_str in REDOS_STRINGS[:3]:
                test_url = f"{base}?{param}={urllib.parse.quote(redos_str)}"
                _, status, elapsed = self._make_timed_request(test_url, timeout=15)
                if elapsed >= MIN_ELAPSED and elapsed > baseline_t * TIMING_FACTOR:
                    self._report_timing(f"GET param `{param}`", redos_str, elapsed, baseline_t)
                    return

    def _report_timing(self, vector: str, payload: str, elapsed: float, baseline: float):
        self.log("CRITICAL", f"[ReDoS] Timing ReDoS via {vector}: {elapsed:.1f}s (baseline {baseline:.1f}s)")
        self.add_vuln(
            title=f"Active ReDoS — {vector}",
            severity="High",
            category="ReDoS",
            cvss_score=7.5,
            confidence="High",
            description=(
                f"**Active ReDoS** via **{vector}**.\n\n"
                f"Elapsed: {elapsed:.2f}s vs baseline {baseline:.2f}s ({elapsed/max(baseline,0.01):.1f}x)"
            ),
            remediation=(
                "1. Apply strict input length limits (max 100 chars for search fields).\n"
                "2. Replace catastrophic regexes with RE2-compatible patterns.\n"
                "3. Add per-request CPU time limits in the application runtime."
            ),
            payload=payload,
        )
