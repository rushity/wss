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
import math


class MultiFeatureAnomaly:
    def __init__(self):
        self._baselines: dict[str, list[float]] = {}
        self._feature_names: list[str] = []

    def record_baseline(self, feature: str, value: float):
        self._baselines.setdefault(feature, []).append(value)
        if feature not in self._feature_names:
            self._feature_names.append(feature)

    @property
    def ready(self) -> bool:
        return all(len(v) >= 5 for v in self._baselines.values())

    def mean(self, feature: str) -> float:
        vals = self._baselines.get(feature, [])
        return statistics.mean(vals) if vals else 0.0

    def stdev(self, feature: str) -> float:
        vals = self._baselines.get(feature, [])
        return statistics.stdev(vals) if len(vals) >= 2 else 0.0

    def z_score(self, feature: str, value: float) -> float:
        sd = self.stdev(feature)
        return (value - self.mean(feature)) / sd if sd else 0.0

    def _is_outlier(self, values: list[float]) -> list[bool]:
        q1 = statistics.median(sorted(values)[:len(values)//2])
        q3 = statistics.median(sorted(values)[len(values)//2:])
        iqr = q3 - q1
        lower, upper = q1 - 1.5 * iqr, q3 + 1.5 * iqr
        return [v < lower or v > upper for v in values]

    def cluster_outliers(self, values: list[float]) -> list[int]:
        outliers = self._is_outlier(values)
        return [i for i, o in enumerate(outliers) if o]

    def score(self, timing: float, size: int, status: int, word_count: int, line_count: int) -> float:
        raw = 0.0
        if abs(self.z_score("timing", timing)) > 2:
            raw += abs(self.z_score("timing", timing)) * 0.3
        if abs(self.z_score("size", float(size))) > 2:
            raw += abs(self.z_score("size", float(size))) * 0.25
        if abs(self.z_score("words", float(word_count))) > 2:
            raw += abs(self.z_score("words", float(word_count))) * 0.2
        if abs(self.z_score("lines", float(line_count))) > 2:
            raw += abs(self.z_score("lines", float(line_count))) * 0.15
        if status in (403, 500, 503, 429):
            raw += 2.0
        return round(min(raw, 10.0), 2)


class ResponseCluster:
    def __init__(self, n_init: int = 3):
        self._clusters: dict[int, list[tuple[float, int, int, int]]] = {}
        self._n_init = n_init

    def _distance(self, a: tuple[float, int, int, int], b: tuple[float, int, int, int]) -> float:
        return math.sqrt(
            (a[0] - b[0])**2 * 0.4 +
            (a[1] - b[1])**2 * 0.3 +
            (a[2] - b[2])**2 * 0.2 +
            (a[3] - b[3])**2 * 0.1
        )

    def fit(self, points: list[tuple[float, int, int, int]]):
        if len(points) < self._n_init:
            return
        self._clusters = {}
        centroids = points[:self._n_init]
        for _ in range(10):
            self._clusters = {i: [] for i in range(self._n_init)}
            for p in points:
                dists = [self._distance(p, c) for c in centroids]
                self._clusters[dists.index(min(dists))].append(p)
            for i in range(self._n_init):
                if self._clusters[i]:
                    avg_t = statistics.mean(p[0] for p in self._clusters[i])
                    avg_s = int(statistics.mean(p[1] for p in self._clusters[i]))
                    avg_w = int(statistics.mean(p[2] for p in self._clusters[i]))
                    avg_l = int(statistics.mean(p[3] for p in self._clusters[i]))
                    centroids[i] = (avg_t, avg_s, avg_w, avg_l)

    def predict(self, point: tuple[float, int, int, int]) -> tuple[int, int]:
        if not self._clusters:
            return -1, 0
        centroid_indices = list(self._clusters.keys())
        dists = [self._distance(point, self._cluster_center(i)) for i in centroid_indices]
        closest = centroid_indices[dists.index(min(dists))]
        if self._clusters[closest]:
            center = self._cluster_center(closest)
            d = self._distance(point, center)
            max_d = max(self._distance(p, center) for p in self._clusters[closest]) if self._clusters[closest] else 1
            return (closest, int(min(d / max_d * 10, 10))) if max_d > 0 else (closest, 0)
        return closest, 0

    def _cluster_center(self, idx: int) -> tuple[float, int, int, int]:
        pts = self._clusters.get(idx, [])
        if not pts:
            return (0.0, 0, 0, 0)
        return (
            statistics.mean(p[0] for p in pts),
            int(statistics.mean(p[1] for p in pts)),
            int(statistics.mean(p[2] for p in pts)),
            int(statistics.mean(p[3] for p in pts)),
        )

    def outlier_score(self, point: tuple[float, int, int, int]) -> float:
        cluster_id, distance = self.predict(point)
        if cluster_id < 0:
            return 0.0
        return distance / 10.0

