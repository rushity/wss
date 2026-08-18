"""
custom_website_scanner.py — Custom website analysis using Requests + BeautifulSoup.
Performs deep HTML analysis, form detection, link extraction, and content analysis.
"""
import requests
from bs4 import BeautifulSoup
import urllib.request, ssl
from scanners.base_scanner import BaseScanner

class CustomWebsiteScanner(BaseScanner):
    SCANNER_NAME = "Custom Website Analysis"

    def run(self):
        self.log("INFO", f"[Custom Analysis] Starting deep website analysis for {self.target}...")
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        try:
            headers = {"User-Agent": "LarShield/2.0 (Security Audit Bot)"}
            if self.auth_headers:
                headers.update(self.auth_headers)
            
            req = urllib.request.Request(self.target, headers=headers)
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                html = resp.read().decode('utf-8', errors='ignore')
                response_headers = {k.lower(): v for k, v in resp.getheaders()}
                status = resp.status
            
            self.log("SUCCESS", f"[Custom Analysis] Retrieved page: HTTP {status}")
            
            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            
            # Perform various analyses
            self._analyze_forms(soup)
            self._analyze_links(soup)
            self._analyze_scripts(soup)
            self._analyze_meta_tags(soup)
            self._analyze_comments(soup)
            self._analyze_hidden_inputs(soup)
            self._analyze_external_resources(soup)
            
            self.log("SUCCESS", "[Custom Analysis] Website analysis complete.")
            
        except urllib.error.HTTPError as e:
            self.log("WARNING", f"[Custom Analysis] HTTP Error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            self.log("WARNING", f"[Custom Analysis] URL Error: {e.reason}")
        except Exception as e:
            self.log("WARNING", f"[Custom Analysis] Error: {e}")
        
        return self.vulns

    def _analyze_forms(self, soup):
        """Analyze HTML forms for security issues."""
        self.log("INFO", "[Custom Analysis] Analyzing forms...")
        
        forms = soup.find_all('form')
        
        if not forms:
            self.log("INFO", "[Custom Analysis] No forms found.")
            return
        
        self.log("INFO", f"[Custom Analysis] Found {len(forms)} form(s).")
        
        for i, form in enumerate(forms[:10]):  # Limit to first 10 forms
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper()
            
            self.log("INFO", f"[Custom Analysis] Form {i+1}: {form_method} -> {form_action}")
            
            # Check for insecure form method
            if form_method == 'GET' and form_action:
                self.log("WARNING", f"[Custom Analysis] Form {i+1} uses GET method for sensitive data")
                self.add_vuln(
                    title="Form Uses GET Method for Sensitive Data",
                    severity="Medium", category="Form Security", cvss_score=5.3,
                    description=f"Form {i+1} on {self.target} uses GET method. Sensitive data in GET requests appears in browser history and server logs.",
                    remediation="Change form method to POST for sensitive data handling."
                )
            
            # Check for CSRF protection
            has_csrf = False
            for input_field in form.find_all('input'):
                input_name = input_field.get('name', '').lower()
                if 'csrf' in input_name or 'token' in input_name:
                    has_csrf = True
                    break
            
            if not has_csrf and form_method == 'POST':
                self.log("WARNING", f"[Custom Analysis] Form {i+1} may lack CSRF protection")
                self.add_vuln(
                    title="Form May Lack CSRF Protection",
                    severity="Medium", category="Form Security", cvss_score=5.9,
                    description=f"Form {i+1} on {self.target} uses POST method but no CSRF token was detected. This could lead to Cross-Site Request Forgery attacks.",
                    remediation="Implement CSRF tokens in all state-changing forms. Use framework-provided CSRF protection."
                )

    def _analyze_links(self, soup):
        """Analyze links for security issues."""
        self.log("INFO", "[Custom Analysis] Analyzing links...")
        
        links = soup.find_all('a', href=True)
        
        if not links:
            self.log("INFO", "[Custom Analysis] No links found.")
            return
        
        self.log("INFO", f"[Custom Analysis] Found {len(links)} link(s).")
        
        # Check for external links
        external_links = []
        for link in links[:50]:  # Limit to first 50 links
            href = link['href']
            if href.startswith('http'):
                if self.domain not in href:
                    external_links.append(href)
        
        if external_links:
            self.log("INFO", f"[Custom Analysis] Found {len(external_links)} external link(s).")
            
            # Check for suspicious external links
            suspicious_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            for ext_link in external_links:
                for susp in suspicious_domains:
                    if susp in ext_link:
                        self.log("WARNING", f"[Custom Analysis] Suspicious shortener link: {ext_link}")
                        self.add_vuln(
                            title="Suspicious URL Shortener Link",
                            severity="Low", category="Content Security", cvss_score=3.1,
                            description=f"External link uses URL shortener ({susp}): {ext_link}. This could hide malicious destinations.",
                            remediation="Avoid using URL shorteners in production. Use direct links or implement link validation."
                        )

    def _analyze_scripts(self, soup):
        """Analyze JavaScript files for security issues."""
        self.log("INFO", "[Custom Analysis] Analyzing scripts...")
        
        scripts = soup.find_all('script')
        
        if not scripts:
            self.log("INFO", "[Custom Analysis] No scripts found.")
            return
        
        self.log("INFO", f"[Custom Analysis] Found {len(scripts)} script(s).")
        
        # Check for inline scripts
        inline_scripts = [s for s in scripts if s.get('src') is None]
        
        if inline_scripts:
            self.log("WARNING", f"[Custom Analysis] Found {len(inline_scripts)} inline script(s)")
            self.add_vuln(
                title="Inline JavaScript Detected",
                severity="Medium", category="Content Security", cvss_score=5.3,
                description=f"Found {len(inline_scripts)} inline JavaScript script(s). Inline scripts bypass Content Security Policy and increase XSS risk.",
                remediation="Move all JavaScript to external files and implement a strict Content Security Policy."
            )
        
        # Check for external scripts
        external_scripts = [s.get('src') for s in scripts if s.get('src')]
        
        if external_scripts:
            self.log("INFO", f"[Custom Analysis] Found {len(external_scripts)} external script(s).")
            
            # Check for CDNs
            cdn_domains = ['cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'ajax.googleapis.com']
            for script in external_scripts:
                for cdn in cdn_domains:
                    if cdn in script:
                        self.log("INFO", f"[Custom Analysis] CDN script: {script}")

    def _analyze_meta_tags(self, soup):
        """Analyze meta tags for security issues."""
        self.log("INFO", "[Custom Analysis] Analyzing meta tags...")
        
        meta_tags = soup.find_all('meta')
        
        if not meta_tags:
            self.log("INFO", "[Custom Analysis] No meta tags found.")
            return
        
        self.log("INFO", f"[Custom Analysis] Found {len(meta_tags)} meta tag(s).")
        
        # Check for generator meta tag
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator:
            generator_content = generator.get('content', '')
            self.log("WARNING", f"[Custom Analysis] Generator meta tag: {generator_content}")
            self.add_vuln(
                title="Generator Meta Tag Discloses Technology",
                severity="Low", category="Information Disclosure", cvss_score=3.1,
                description=f"Generator meta tag reveals technology: {generator_content}",
                remediation="Remove generator meta tag to reduce information disclosure."
            )
        
        # Check for viewport meta tag
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        if not viewport:
            self.log("INFO", "[Custom Analysis] No viewport meta tag found (accessibility issue).")

    def _analyze_comments(self, soup):
        """Analyze HTML comments for sensitive information."""
        self.log("INFO", "[Custom Analysis] Analyzing HTML comments...")
        
        comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
        
        if not comments:
            self.log("INFO", "[Custom Analysis] No HTML comments found.")
            return
        
        self.log("INFO", f"[Custom Analysis] Found {len(comments)} comment(s).")
        
        # Check for sensitive keywords in comments
        sensitive_keywords = ['password', 'secret', 'api key', 'token', 'debug', 'todo', 'fixme', 'hack']
        
        for comment in comments:
            comment_text = comment.strip()
            for keyword in sensitive_keywords:
                if keyword in comment_text.lower():
                    self.log("WARNING", f"[Custom Analysis] Sensitive comment: {comment_text[:100]}")
                    self.add_vuln(
                        title="Sensitive Information in HTML Comments",
                        severity="Low", category="Information Disclosure", cvss_score=3.1,
                        description=f"HTML comment contains sensitive keyword '{keyword}': {comment_text[:100]}",
                        remediation="Remove sensitive information from HTML comments before deployment."
                    )
                    break

    def _analyze_hidden_inputs(self, soup):
        """Analyze hidden input fields for sensitive data."""
        self.log("INFO", "[Custom Analysis] Analyzing hidden inputs...")
        
        hidden_inputs = soup.find_all('input', type='hidden')
        
        if not hidden_inputs:
            self.log("INFO", "[Custom Analysis] No hidden inputs found.")
            return
        
        self.log("INFO", f"[Custom Analysis] Found {len(hidden_inputs)} hidden input(s).")
        
        for hidden in hidden_inputs[:20]:  # Limit to first 20
            name = hidden.get('name', '')
            value = hidden.get('value', '')
            
            # Check for sensitive data in hidden fields
            if value and len(value) > 20:
                self.log("WARNING", f"[Custom Analysis] Hidden input with long value: {name}")
                self.add_vuln(
                    title="Hidden Input with Long Value",
                    severity="Low", category="Form Security", cvss_score=3.1,
                    description=f"Hidden input field '{name}' contains a long value. This could contain sensitive data.",
                    remediation="Review hidden input fields and ensure they don't contain sensitive information."
                )

    def _analyze_external_resources(self, soup):
        """Analyze external resources for security issues."""
        self.log("INFO", "[Custom Analysis] Analyzing external resources...")
        
        # Check for images
        images = soup.find_all('img', src=True)
        if images:
            self.log("INFO", f"[Custom Analysis] Found {len(images)} image(s).")
            
            # Check for data URIs
            data_uri_images = [img for img in images if img['src'].startswith('data:')]
            if data_uri_images:
                self.log("WARNING", f"[Custom Analysis] Found {len(data_uri_images)} data URI image(s)")
        
        # Check for iframes
        iframes = soup.find_all('iframe', src=True)
        if iframes:
            self.log("WARNING", f"[Custom Analysis] Found {len(iframes)} iframe(s)")
            
            for iframe in iframes[:10]:
                src = iframe.get('src', '')
                self.log("INFO", f"[Custom Analysis] iframe: {src}")
                
                # Check for external iframes
                if src.startswith('http') and self.domain not in src:
                    self.log("WARNING", f"[Custom Analysis] External iframe: {src}")
                    self.add_vuln(
                        title="External iframe Detected",
                        severity="Medium", category="Content Security", cvss_score=5.3,
                        description=f"External iframe detected: {src}. This could lead to clickjacking or content injection attacks.",
                        remediation="Review external iframes and ensure they are trusted. Consider using sandbox attribute or CSP frame-ancestors."
                    )
