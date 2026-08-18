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


AUTH_STATES = [
    "anonymous",
    "authenticated_user",
    "authenticated_admin",
    "authenticated_other_user",
]


class DifferentialAnalyzer:
    def __init__(self):
        self._responses: dict[str, list[dict]] = {}
        self._entropy: dict[str, float] = {}

    def record(self, label: str, body: str, status: int, elapsed: float, headers: dict | None = None):
        self._responses.setdefault(label, [])
        self._responses[label].append({
            "body": body,
            "status": status,
            "elapsed": elapsed,
            "headers": headers or {},
            "length": len(body),
            "words": len(body.split()),
            "lines": body.count("\n"),
        })

    def get(self, label: str) -> list[dict]:
        return self._responses.get(label, [])

    def compare(self, label_a: str, label_b: str) -> dict:
        ra = self._responses.get(label_a, [])
        rb = self._responses.get(label_b, [])
        if not ra or not rb:
            return {"different": False, "reason": "insufficient data"}
        a = ra[-1]
        b = rb[-1]
        diffs = []
        score = 0.0
        if a["status"] != b["status"]:
            diffs.append(f"Status: {a['status']} vs {b['status']}")
            score += 2.0
        length_ratio = abs(a["length"] - b["length"]) / max(a["length"], b["length"], 1)
        if length_ratio > 0.1:
            diffs.append(f"Length: {a['length']} vs {b['length']} ({length_ratio*100:.0f}% diff)")
            score += length_ratio * 3
        timing_diff = abs(a["elapsed"] - b["elapsed"])
        if timing_diff > 1.0:
            diffs.append(f"Timing: {a['elapsed']:.2f}s vs {b['elapsed']:.2f}s")
            score += min(timing_diff, 5.0)
        word_ratio = abs(a["words"] - b["words"]) / max(a["words"], b["words"], 1)
        if word_ratio > 0.1:
            diffs.append(f"Words: {a['words']} vs {b['words']} ({word_ratio*100:.0f}% diff)")
            score += word_ratio * 2
        html_stripped_a = re.sub(r'<[^>]+>', '', a["body"])
        html_stripped_b = re.sub(r'<[^>]+>', '', b["body"])
        text_ratio = abs(len(html_stripped_a) - len(html_stripped_b)) / max(len(html_stripped_a), len(html_stripped_b), 1)
        if text_ratio > 0.15:
            diffs.append(f"Text content: {len(html_stripped_a)} vs {len(html_stripped_b)} chars")
            score += text_ratio * 2
        return {"different": score > 1.0, "score": round(score, 2), "differences": diffs}

    def compare_all(self, label: str) -> list[dict]:
        results = []
        responses = self._responses.get(label, [])
        if len(responses) < 3:
            return results
        baseline = responses[0]
        for i in range(1, len(responses)):
            diff = self._compare_pair(baseline, responses[i])
            diff["index"] = i
            results.append(diff)
        return results

    def _compare_pair(self, a: dict, b: dict) -> dict:
        diffs = []
        score = 0.0
        if a["status"] != b["status"]:
            diffs.append(f"Status: {a['status']} vs {b['status']}")
            score += 2.0
        length_diff = abs(a["length"] - b["length"])
        if length_diff > 100:
            diffs.append(f"Length diff: {length_diff}")
            score += min(length_diff / 1000, 5.0)
        return {"different": score > 1.0, "score": round(score, 2), "differences": diffs}

    def summary(self) -> dict:
        result = {}
        for label in self._responses:
            result[label] = {
                "count": len(self._responses[label]),
                "avg_length": sum(r["length"] for r in self._responses[label]) / max(len(self._responses[label]), 1),
                "avg_elapsed": sum(r["elapsed"] for r in self._responses[label]) / max(len(self._responses[label]), 1),
            }
        return result


class ParameterMutationTester:
    def __init__(self, request_fn: Callable):
        self._request_fn = request_fn

    def test(self, base_url: str, base_params: dict, mutations: list[dict]) -> list[dict]:
        results = []
        baseline_body, baseline_status = self._request_fn(base_url, base_params)
        baseline_length = len(baseline_body or "")
        for mutation in mutations:
            test_params = dict(base_params)
            test_params.update(mutation.get("params", {}))
            body, status = self._request_fn(base_url, test_params)
            length = len(body or "") if body else 0
            diff = abs(length - baseline_length) / max(baseline_length, 1)
            results.append({
                "mutation": mutation.get("name", "unknown"),
                "status": status,
                "length_diff_pct": round(diff * 100, 1),
                "anomalous": diff > 0.2 or status != baseline_status,
            })
        return results

