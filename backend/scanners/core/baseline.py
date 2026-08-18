"""
core/baseline.py — Site Baseline Fingerprinter
===============================================
Builds a per-scan fingerprint of the site's generic 404/SPA-fallback response by
requesting 4 random nonexistent paths. Any path probe returning a response that
matches this baseline is suppressed — it is the app's catch-all, not a real resource.

Usage:
    baseline = SiteBaseline()
    baseline.build(target_url, ssl_context=ctx, headers=headers, timeout=6)
    if baseline.is_baseline(status, body):
        # suppress — this is just the SPA shell
"""
import hashlib
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class SiteBaseline:
    """Thread-safe site baseline fingerprint.

    Build once per scanner instantiation, then call is_baseline() before reporting
    any path as "found".  The baseline is never cached globally — it is always
    fresh per scan to handle CDN variance and session-specific behavior.
    """

    # Tolerance in bytes: if a response length is within this many bytes of a
    # baseline sample, it counts as a match (catches gzip/vary minor deltas).
    _LEN_TOLERANCE = 80

    def __init__(self):
        self._samples: list[dict] = []  # [{status, length, body_hash}]
        self._built = False

    # ------------------------------------------------------------------
    def build(
        self,
        target: str,
        ssl_context=None,
        headers: dict | None = None,
        timeout: int = 6,
    ) -> None:
        """
        Request 4 random nonexistent paths and record their response fingerprints.
        Paths cover different depths and extensions to detect sophisticated SPAs that
        return different responses for *.json vs no extension, etc.
        """
        base = target.rstrip("/")
        uid = uuid.uuid4().hex[:8]
        probe_paths = [
            f"/lrs-baseline-{uid}-a",
            f"/lrs-baseline-{uid}-b/sub/path",
            f"/lrs-baseline-{uid}-c.json",
            f"/lrs-baseline-{uid}-d.php",
        ]

        req_headers = {"User-Agent": "LarShield/2.0 BaselineProbe"}
        if headers:
            req_headers.update(headers)

        for path in probe_paths:
            url = f"{base}{path}"
            try:
                req = urllib.request.Request(url, headers=req_headers)
                with urllib.request.urlopen(
                    req, timeout=timeout, context=ssl_context
                ) as r:
                    body = r.read()
                    self._samples.append(
                        {
                            "status": r.status,
                            "length": len(body),
                            "body_hash": hashlib.sha256(body).hexdigest(),
                        }
                    )
            except urllib.error.HTTPError as e:
                # 404/403/etc are also baseline responses
                try:
                    body = e.read()
                except Exception:
                    body = b""
                self._samples.append(
                    {
                        "status": e.code,
                        "length": len(body),
                        "body_hash": hashlib.sha256(body).hexdigest(),
                    }
                )
            except Exception:
                # Network error on probe → skip this sample
                pass

        self._built = True

    # ------------------------------------------------------------------
    def is_baseline(self, status: int, body: str | bytes) -> bool:
        """
        Return True if (status, body) matches the site's baseline catch-all response.

        Matching rules (any one is sufficient):
        1. Body SHA-256 hash matches a baseline sample exactly.
        2. Status AND body length are within tolerance of a baseline sample.

        We require at least 1 baseline sample to agree (not 3/4) to avoid being
        too lenient on sites that return different 404 pages per path.
        """
        if not self._samples:
            # Baseline not built or all probes failed — fail open (don't suppress).
            return False

        if isinstance(body, str):
            body_bytes = body.encode("utf-8", errors="ignore")
        else:
            body_bytes = body

        body_hash = hashlib.sha256(body_bytes).hexdigest()
        body_len = len(body_bytes)

        for sample in self._samples:
            # Exact hash match
            if body_hash == sample["body_hash"]:
                return True
            # Same status + length within tolerance
            if (
                status == sample["status"]
                and abs(body_len - sample["length"]) <= self._LEN_TOLERANCE
            ):
                return True

        return False

    # ------------------------------------------------------------------
    def is_not_found(self, status: int, body: str | bytes = b"") -> bool:
        """
        Convenience: returns True when this response is definitively not-found,
        either by HTTP status >= 400 or by matching the site's catch-all baseline.
        """
        if status >= 400:
            return True
        return self.is_baseline(status, body)

    # ------------------------------------------------------------------
    @property
    def built(self) -> bool:
        return self._built

    @property
    def sample_count(self) -> int:
        return len(self._samples)
