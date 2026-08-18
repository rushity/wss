import urllib.request, urllib.error, ssl, socket
from scanners.base_scanner import BaseScanner

class CloudScanner(BaseScanner):
    SCANNER_NAME = "Cloud Storage Enumerator (S3/Azure/GCP)"

    def __init__(self, scan_id, target, domain, **kwargs):
        super().__init__(scan_id, target, domain)
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        
        # Clean domain for permutation (e.g., test.com -> test)
        parts = self.domain.split('.')
        self.base_name = parts[0] if len(parts) > 1 else self.domain

    def check_bucket(self, url, provider_name):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LarShield/2.0 Cloud-Enum"})
            with urllib.request.urlopen(req, timeout=3, context=self._ctx) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                
                # Check for open bucket listings (XML)
                if "<ListBucketResult" in body or "<Blobs>" in body:
                    self.log("CRITICAL", f"[Cloud] {provider_name} bucket is publicly listable: {url}")
                    self.add_vuln(
                        title=f"Publicly Accessible {provider_name} Bucket",
                        severity="Critical",
                        category="Cloud Security",
                        cvss_score=9.8,
                        description=f"A misconfigured {provider_name} bucket was found at `{url}`. It allows unauthenticated users to list all files, potentially exposing PII, backups, or source code.",
                        remediation=f"Immediately modify the {provider_name} IAM/ACL policies. Remove 'List' and 'Read' permissions for anonymous users or the public 'AllUsers' group."
                    )
                elif resp.status in [200, 403]: # Even 403 means the bucket exists, which is info disclosure
                    pass
        except urllib.error.HTTPError as e:
            if e.code not in [404, 400, 403, 502, 503, 504]:
                self.log("ERROR", f"[Cloud] Bucket check HTTP error: {e}")
        except urllib.error.URLError as e:
            if "getaddrinfo failed" not in str(e) and "Name or service not known" not in str(e):
                self.log("ERROR", f"[Cloud] Bucket check URL error: {e}")
        except Exception as e:
            self.log("ERROR", f"[Cloud] Bucket check error: {e}")

    def run(self):
        self.log("INFO", f"[Cloud] Enumerating misconfigured cloud storage for '{self.base_name}'...")
        
        # Common bucket mutations
        suffixes = ["", "-prod", "-dev", "-staging", "-assets", "-backup", "-static", "-public"]
        
        for suffix in suffixes:
            bucket_name = f"{self.base_name}{suffix}"
            
            # AWS S3
            self.check_bucket(f"https://{bucket_name}.s3.amazonaws.com/", "AWS S3")
            # GCP Storage
            self.check_bucket(f"https://storage.googleapis.com/{bucket_name}/", "GCP Storage")
            # Azure Blob
            self.check_bucket(f"https://{bucket_name}.blob.core.windows.net/?comp=list", "Azure Blob")

        self.log("SUCCESS" if not self.vulns else "WARNING", "[Cloud] Enumeration complete.")
        return self.vulns
