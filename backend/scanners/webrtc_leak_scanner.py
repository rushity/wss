"""
webrtc_leak_scanner.py — WebRTC IP Leak Scanner
"""
import re, urllib.request
from scanners.base_scanner import BaseScanner

WEBRTC_INDICATORS = [
    "RTCPeerConnection", "webkitRTCPeerConnection", "mozRTCPeerConnection",
    "new RTCPeerConnection", "RTCIceCandidate", "createOffer", "createAnswer",
    "getUserMedia", "stun:", "turn:",
]
STUN_SERVERS = ["stun.l.google.com", "stun1.l.google.com", "stun.services.mozilla.com"]

class WebrtcLeakScanner(BaseScanner):
    SCANNER_NAME = "WebRTC IP Leak Scanner"
    _SCANNER_KEY = "webrtc_leak"
    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain, **kwargs)

    def run(self) -> list:
        self.log("INFO", f"[WebRTC] Checking for WebRTC IP leak vectors on {self.target}...")
        try:
            req = urllib.request.Request(self.target, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=8, context=self.get_ssl_context()) as r:
                html = r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.log("WARNING", f"[WebRTC] Error: {e}")
            return self.vulns

        # Collect and check inline + external JS
        scripts_src = re.findall(r'src=["\']([^"\']+\.js)["\']', html, re.I)
        inline = re.findall(r'<script[^>]*>(.*?)</script>', html, re.I | re.S)
        all_js = [(s, self._fetch(self._resolve(s))) for s in scripts_src[:10]]
        all_js += [(f"inline#{i}", b) for i, b in enumerate(inline)]

        webrtc_found = []
        for name, code in all_js:
            if not code: continue
            hits = [ind for ind in WEBRTC_INDICATORS if ind in code]
            if hits:
                # Check for STUN server config
                stun_refs = re.findall(r'stun:[^\s"\'>,]+', code)
                webrtc_found.append({"file": name, "indicators": hits[:3], "stun": stun_refs})

        if webrtc_found:
            self.add_vuln(
                title=f"WebRTC Detected — Real IP Leak Risk ({len(webrtc_found)} JS file(s))",
                severity="Medium",
                category="WebRTC IP Leak",
                cvss_score=5.3,
                description="WebRTC API usage detected in client-side JavaScript:\n\n" +
                    "\n".join(f"- **{f['file']}**: `{', '.join(f['indicators'][:2])}`"
                              + (f"\n  STUN: `{', '.join(f['stun'][:2])}`" if f['stun'] else "")
                              for f in webrtc_found[:5]) +
                    "\n\nWebRTC STUN requests bypass proxies/VPNs and expose the real LAN/WAN IP "
                    "address of users. Attackers with iframe injection can use this for deanonymization.",
                remediation="1. Disable WebRTC in browsers via policy if not needed.\n"
                    "2. Restrict ICE candidate types to `relay` only (force TURN):\n"
                    "   `iceTransportPolicy: 'relay'` in RTCPeerConnection config.\n"
                    "3. If WebRTC isn't needed, remove it entirely.",
            )
        else:
            self.log("SUCCESS", "[WebRTC] No WebRTC IP leak vectors found.")
        return self.vulns

    def _resolve(self, src):
        if src.startswith("//"): return f"https:{src}"
        if src.startswith("/"):
            from urllib.parse import urlparse; p = urlparse(self.target)
            return f"{p.scheme}://{p.netloc}{src}"
        if not src.startswith("http"): return f"{self.target.rstrip('/')}/{src}"
        return src

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self._make_headers())
            with urllib.request.urlopen(req, timeout=5, context=self.get_ssl_context()) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.log("ERROR", f"[WebRTC] _fetch error: {e}")
            return ""
