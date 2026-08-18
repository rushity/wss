import uuid
import hashlib
import hmac
import secrets
import base64
import subprocess
from typing import *
import os
import sys
import re
import json
import time
import urllib3
import requests
import socket
import logging
import threading
import concurrent.futures
import ipaddress
import ssl
from urllib.parse import urlparse, urljoin, urlencode, quote
from collections import defaultdict
from bs4 import BeautifulSoup
from datetime import datetime, timezone
import statistics
"""
anomaly.py — Statistical Anomaly Detectors for Timing & Size Analysis
======================================================================
Used by scanners to detect blind injection via timing differentials.

Improvements (June 2026):
  ENH: Minimum 5-sample guard before trusting baseline results.
  ENH: build_baseline() accepts proper callable signature.
  ENH: z_score() is safe against zero stdev and insufficient samples.
  ENH: Added AdaptiveThreshold for dynamic z-score tuning.
"""


class AnomalyDetector:
    """Base statistical detector. Collects numeric samples and detects outliers."""

    MIN_BASELINE_SAMPLES = 5  # Require at least this many samples for reliable stats

    def __init__(self, baseline_samples: list[float] | None = None):
        self._baseline = list(baseline_samples) if baseline_samples else []

    def record(self, value: float) -> None:
        self._baseline.append(value)

    @property
    def mean(self) -> float:
        return statistics.mean(self._baseline) if self._baseline else 0.0

    @property
    def stdev(self) -> float:
        if len(self._baseline) >= 2:
            return statistics.stdev(self._baseline)
        return 0.0

    @property
    def has_baseline(self) -> bool:
        return len(self._baseline) >= self.MIN_BASELINE_SAMPLES

    def z_score(self, value: float) -> float:
        """
        Return z-score of `value` relative to baseline.
        Returns 0.0 if stdev is zero or baseline is insufficient.
        """
        sd = self.stdev
        if sd == 0 or not self._baseline:
            return 0.0
        return (value - self.mean) / sd

    def is_anomalous(self, value: float, threshold: float = 2.5) -> bool:
        """
        Returns True only if we have enough baseline AND the z-score exceeds threshold.
        Guard against false positives from insufficient data.
        """
        if not self.has_baseline:
            return False
        return abs(self.z_score(value)) >= threshold

    def reset(self) -> None:
        """Clear all recorded samples."""
        self._baseline.clear()


class TimingAnomalyDetector(AnomalyDetector):
    """
    Specialized detector for HTTP response timing analysis.
    Used for blind SQLi, CMDi, SSTI, SSRF timing-based detection.
    """

    def __init__(self, baseline_samples: list[float] | None = None):
        super().__init__(baseline_samples)
        self._timing_records: list[tuple[str, float, str]] = []

    def record_timing(self, label: str, elapsed: float, payload: str = "") -> None:
        self.record(elapsed)
        self._timing_records.append((label, elapsed, payload))

    def build_baseline(
        self,
        request_fn,
        url: str,
        n: int = 5,
        headers: dict | None = None,
        method: str = "GET",
    ) -> None:
        """
        Build timing baseline by making `n` requests to `url`.

        FIX: Accepts request_fn with signature (url, method, data, headers, timeout).
             Passes all positional args to avoid keyword-mismatch errors when
             callers pass `self._make_request` directly.
        """
        for _ in range(n):
            t0 = time.monotonic()
            try:
                # Use positional args to match BaseScanner._make_request signature:
                # (url, method="GET", data=None, headers=None, timeout=8)
                request_fn(url, method, None, headers or {}, 8)
            except Exception:
                pass  # Network errors are expected during baseline
            self.record(time.monotonic() - t0)

    def test_payload(
        self,
        label: str,
        elapsed: float,
        payload: str = "",
        z_threshold: float = 3.0,
    ) -> bool:
        """
        Record a timed payload request and test if it's anomalous.
        Returns True if response time is statistically abnormal.
        """
        self.record_timing(label, elapsed, payload)
        return self.is_anomalous(elapsed, z_threshold)


class SizeAnomalyDetector(AnomalyDetector):
    """
    Specialized detector for HTTP response size analysis.
    Used for boolean-based blind injection (different sizes for true/false conditions).
    """

    MIN_BASELINE_SAMPLES = 3  # Size detection can work with fewer samples

    def __init__(self, baseline_sizes: list[int] | None = None):
        sizes = [float(s) for s in (baseline_sizes or [])]
        super().__init__(sizes)

    def record_size(self, size: int) -> None:
        self.record(float(size))

    def test_size(self, size: int, z_threshold: float = 2.5) -> bool:
        return self.is_anomalous(float(size), z_threshold)

    def seed_pair(self, true_len: int, false_len: int) -> None:
        """
        Seed with true/false response sizes to initialize comparison.
        Adds both as baseline samples.
        """
        self.record_size(true_len)
        self.record_size(false_len)

    def pair_differs(self, true_len: int, false_len: int, min_diff: int = 30) -> bool:
        """
        Simple heuristic: return True if the two response sizes differ
        by at least `min_diff` bytes — used before enough baseline exists.
        """
        return abs(true_len - false_len) >= min_diff

