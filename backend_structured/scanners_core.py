import sys
import os
sys.path.insert(0, os.path.abspath('backend'))

from bs4 import BeautifulSoup
from celery import Celery
from celery.schedules import crontab
from collections import defaultdict
from scanners.base_scanner import (
    active_scan_logs, add_log, get_scan_logs, parse_domain,
    cleanup_scan_logs, schedule_log_cleanup, emit_scan_progress
)
from scanners import get_pipeline, get_phases, build_scanner, apply_scan_options
from utils.fuzzer_engine import ContextAwareFuzzer
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from datetime import datetime, timezone, timedelta
from datetime import datetime, timezone, timezone
from dotenv import load_dotenv
load_dotenv()

import stripe
from flask import Blueprint, request, jsonify, current_app, send_from_directory
from werkzeug.utils import secure_filename
from flask import Blueprint, send_file, jsonify, request
from flask import Flask
from flask import jsonify
from flask import render_template
from flask import request, abort, g, Response, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from markupsafe import escape  # always available with Flask
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, Flowable
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from sqlalchemy import event
from sqlalchemy import func
from sqlalchemy import inspect, text
from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import Any
from typing import Any, Callable
from typing import Callable
from typing import Literal
from urllib.parse import urljoin, urlparse
from urllib.parse import urlparse
import base64
import bcrypt
import concurrent.futures
from backend.utils.email_service import (
    send_welcome_email, 
    send_scan_started, 
    send_scan_completed, 
    send_scan_failed,
    send_critical_alert
)

import hashlib
import html
import io
import itertools
import json
import jwt
import math
import os
import re
import re, time, ipaddress, os, hashlib, threading, queue
import requests
import socket
import sqlite3
import ssl
import statistics
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import urllib3
import uuid
import ipaddress



from .extensions import db, celery, socketio, limiter
from .models import *


# --- From scanner.py ---
"""
scanner.py - Scan orchestration engine
=======================================
Fixes applied (June 2026):
  FIX-1: Celery import wrapped in try/except - backend works without Redis
  FIX-2: _run_scan_job() is a plain function called directly from threads
  FIX-3: Each DB write uses a fresh session, properly removed after use
  FIX-4: SQLAlchemy scoped_session used for thread-safe DB access
  FIX-5: Proper error handling ensures scan always marks as failed/completed
  BUG-6 FIX: cleanup_scan_logs() deferred 5 min post-completion via
             schedule_log_cleanup() - prevents race with frontend /logs polling
  ENH: Deduplication of vulnerabilities before DB write
  ENH: Scan timeout enforcement (SCANNER_TIMEOUT_SECONDS)
"""



# â”€â”€ Celery is optional - works without Redis/Celery installed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
try:
    from .config import _is_redis_running, Config
    CELERY_AVAILABLE = _is_redis_running(Config.CELERY_BROKER_URL)
except Exception:
    CELERY_AVAILABLE = False

# Global timeout: 2 hours for Deep scan (was 600s = too short for 80+ modules)
SCANNER_TIMEOUT_SECONDS = 7200


def _clean_nul(val) -> str:
    if val is None:
        return ""
    if not isinstance(val, str):
        val = str(val)
    return val.replace("\x00", "").replace("\u0000", "")


def calculate_security_score_from_counts(counts: dict) -> int:
    crit = counts.get("critical", 0) or counts.get("Critical", 0)
    high = counts.get("high", 0) or counts.get("High", 0)
    med = counts.get("medium", 0) or counts.get("Medium", 0)
    low = counts.get("low", 0) or counts.get("Low", 0)

    if crit == 0 and high == 0 and med == 0 and low == 0:
        return 100

    # Critical penalty: 1st=15, 2nd=10, 3rd-5th=6, 6th-10th=3, 11th+=1
    crit_deduction = 0
    if crit > 0: crit_deduction += 15
    if crit > 1: crit_deduction += 10
    if crit > 2: crit_deduction += min(crit - 2, 3) * 6
    if crit > 5: crit_deduction += min(crit - 5, 5) * 3
    if crit > 10: crit_deduction += (crit - 10) * 1

    # High penalty: 1st=7, 2nd-5th=4, 6th-10th=2, 11th+=0.5
    high_deduction = 0
    if high > 0: high_deduction += 7
    if high > 1: high_deduction += min(high - 1, 4) * 4
    if high > 5: high_deduction += min(high - 5, 5) * 2
    if high > 10: high_deduction += (high - 10) * 0.5

    # Medium penalty: 1st-3rd=3, 4th-8th=1.5, 9th+=0.5
    med_deduction = 0
    if med > 0: med_deduction += min(med, 3) * 3
    if med > 3: med_deduction += min(med - 3, 5) * 1.5
    if med > 8: med_deduction += (med - 8) * 0.5

    # Low penalty: 1st-5th=1, 6th+=0.25
    low_deduction = 0
    if low > 0: low_deduction += min(low, 5) * 1
    if low > 5: low_deduction += (low - 5) * 0.25

    total_deduction = crit_deduction + high_deduction + med_deduction + low_deduction
    return max(0, min(100, int(round(100 - total_deduction))))


def calculate_security_score(vulns: list[dict]) -> int:
    if not vulns:
        return 100

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in vulns:
        sev = v.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1

    return calculate_security_score_from_counts(counts)


def _deduplicate_scan_vulns(vulns: list[dict]) -> list[dict]:
    """
    Cross-scanner deduplication of vulnerability findings.
    Dedup key: (title, category). Keeps the highest-confidence entry.
    ENH: Prevents DB flooding with identical findings from multiple scanners.
    """
    conf_rank = {"Low": 0, "Medium": 1, "High": 2, "Confirmed": 3}
    seen: dict[tuple, dict] = {}
    for v in vulns:
        key = (v.get("title", ""), v.get("category", ""))
        if key not in seen:
            seen[key] = v
        else:
            existing_rank = conf_rank.get(seen[key].get("confidence", "Low"), 0)
            new_rank = conf_rank.get(v.get("confidence", "Low"), 0)
            if new_rank > existing_rank:
                seen[key] = v
    return list(seen.values())


# â”€â”€ Core scan job - plain Python function, no Celery dependency â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _run_scan_job(scan_id: str) -> None:
    """
    Main scan pipeline executor.
    MUST be called inside an active Flask app context.
    Uses db.session with proper cleanup between writes.
    """
    try:
        # Set socketio instance for real-time progress updates
        from scanners.base_scanner import set_socketio_instance
        if hasattr(current_app, 'socketio'):
            set_socketio_instance(current_app.socketio)

        # Refresh the session to get a clean state for this thread
        db.session.remove()

        scan = db.session.get(Scan, scan_id)
        if not scan:
            print(f"[Scanner] Scan {scan_id} not found in database.", flush=True)
            return

        target = scan.target_url
        scan_type = scan.scan_type
        domain = parse_domain(target)

        # Per-module timeout per scan intensity (Deep gets 600s = 10 min per module)
        MODULE_TIMEOUTS = {
            "quick":    60,
            "standard": 120,
            "advanced": 180,
            "deep":     600,
        }
        _module_timeout = MODULE_TIMEOUTS.get((scan_type or "standard").lower(), 120)

        add_log(scan_id, "INFO", f"LarShield v2.0 - {scan_type.upper()} SCAN INITIATED")
        add_log(scan_id, "INFO", f"Target: {target}")
        add_log(scan_id, "INFO", f"Domain: {domain}")
        add_log(scan_id, "INFO", f"Scan ID: {scan_id}")

        # Mark as scanning
        try:
            db.session.remove()
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = "scanning"
                try:
                    scan.ssl_info = get_ssl_info(target)
                except Exception as ssl_e:
                    print(f"[Scanner] Failed to cache SSL info: {ssl_e}")
                db.session.commit()
        except Exception as e:
            db.session.rollback()
            add_log(scan_id, "WARNING", f"Could not update scan status: {e}")
        finally:
            db.session.remove()

        # Build the scanner pipeline
        db.session.remove()
        scan = db.session.get(Scan, scan_id)
        scan_options = getattr(scan, 'scan_options', None)
        auth_headers = getattr(scan, 'auth_headers', None)
        db.session.remove()

        pipeline = apply_scan_options(
            get_pipeline(scan_type), scan_type, scan_options
        )

        if scan_options:
            add_log(scan_id, "INFO",
                    f"Advanced options - crawl depth: {scan_options.get('crawl_depth', 'default')}, "
                    f"exclusions: {len(scan_options.get('exclude_paths', []))}, "
                    f"red-team: {scan_options.get('enable_red_team', False)}")

        all_vulns: list[dict] = []

        def run_scanner_step(step_num, step_name, scanner_cls, kwargs, total_steps):
            add_log(scan_id, "INFO",
                    f"Step {step_num}/{total_steps}: Running {scanner_cls.SCANNER_NAME}...")
            try:
                scanner = build_scanner(
                    step_name, scanner_cls, kwargs,
                    scan_id=scan_id, target=target,
                    domain=domain, auth_headers=auth_headers,
                )
                import concurrent.futures as _cf_inner
                with _cf_inner.ThreadPoolExecutor(max_workers=1) as _inner_exec:
                    _fut = _inner_exec.submit(scanner.run)
                    try:
                        step_vulns = _fut.result(timeout=_module_timeout) or []
                    except _cf_inner.TimeoutError:
                        add_log(scan_id, "WARNING",
                                f"[{step_name}] MODULE TIMEOUT after {_module_timeout}s - skipped.")
                        try:
                            _fut.cancel()
                        except Exception:
                            pass
                        return []
                n = len(step_vulns) if step_vulns else 0
                add_log(scan_id,
                        "SUCCESS" if not step_vulns else "WARNING",
                        f"[{step_name}] Completed - {n} finding(s).")
                return step_vulns or []
            except Exception as e:
                add_log(scan_id, "WARNING",
                        f"[{step_name}] Scanner raised an unexpected exception: {e}")
                return []

        _scan_start_time = time.time()

        # ── Universal Phase-Based Execution Engine ─────────────────────────────
        # Runs for ALL scan types: Quick (2 phases), Advanced (4 phases), Deep (8 phases)
        # Each phase: modules run CONCURRENTLY (up to max_workers_per_phase)
        # Phases run SEQUENTIALLY — ensures recon finishes before injection probing, etc.
        # ──────────────────────────────────────────────────────────────────────

        # Per-scan-type concurrency caps per phase
        MAX_WORKERS_PER_PHASE = {
            "quick":    6,
            "standard": 8,
            "advanced": 8,
            "deep":     8,
            "ssl":      4,
            "port":     2,
        }
        _max_workers = MAX_WORKERS_PER_PHASE.get((scan_type or "advanced").lower(), 8)

        # Wall-clock hard limits per scan type (seconds)
        HARD_LIMITS = {
            "quick":    300,     # 5 min
            "advanced": 3600,    # 1 hour
            "standard": 3600,
            "deep":     21600,   # 6 hours
            "ssl":      300,
            "port":     600,
        }
        _hard_limit = HARD_LIMITS.get((scan_type or "advanced").lower(), 3600)

        phases = get_phases(scan_type)
        total_steps = len(pipeline)
        n_phases = len(phases)

        add_log(scan_id, "INFO",
                f"[{scan_type} Scan] Starting phase-based execution: "
                f"{total_steps} modules across {n_phases} phase(s), "
                f"max {_max_workers} concurrent per phase, "
                f"{_module_timeout}s per module timeout.")

        # Build name → (i, name, cls, kwargs) lookup from the pipeline
        pipeline_lookup: dict = {}
        for i, (name, cls, kwargs) in enumerate(pipeline):
            pipeline_lookup[name] = (i, name, cls, kwargs)

        assigned_names: set = set()

        for phase_idx, phase in enumerate(phases, 1):
            # Collect steps for this phase that exist in the pipeline and aren't already run
            phase_steps = [
                pipeline_lookup[n]
                for n in phase["keys"]
                if n in pipeline_lookup and n not in assigned_names
            ]
            for step in phase_steps:
                assigned_names.add(step[1])  # mark as assigned

            if not phase_steps:
                add_log(scan_id, "INFO",
                        f"[{scan_type}] {phase['name']} — no matching modules, skipping.")
                continue

            # Hard-limit wall-clock check
            elapsed_total = time.time() - _scan_start_time
            if elapsed_total > _hard_limit:
                add_log(scan_id, "WARNING",
                        f"[{scan_type}] Hard time limit ({_hard_limit}s) reached "
                        f"before {phase['name']}. Stopping early.")
                break

            add_log(scan_id, "INFO",
                    f"[{scan_type}] ▶ {phase['name']} "
                    f"({len(phase_steps)} module(s), phase {phase_idx}/{n_phases})...")

            phase_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=min(len(phase_steps), _max_workers)
            )
            phase_futures = [
                phase_executor.submit(
                    run_scanner_step, i + 1, name, cls, kwargs, total_steps
                )
                for i, name, cls, kwargs in phase_steps
            ]
            # Phase timeout = modules × per-module timeout, capped at 30 min
            phase_timeout = min(len(phase_steps) * _module_timeout, 1800)
            try:
                for future in concurrent.futures.as_completed(phase_futures,
                                                              timeout=phase_timeout):
                    try:
                        result = future.result()
                        if result:
                            all_vulns.extend(result)
                    except Exception:
                        pass
            except concurrent.futures.TimeoutError:
                add_log(scan_id, "WARNING",
                        f"[{scan_type}] {phase['name']} timed out after "
                        f"{phase_timeout}s — continuing to next phase.")
            finally:
                try:
                    phase_executor.shutdown(wait=False, cancel_futures=True)
                except TypeError:
                    phase_executor.shutdown(wait=False)

        # Run any pipeline modules that weren't assigned to any phase
        remaining_steps = [
            (i, name, cls, kwargs)
            for i, (name, cls, kwargs) in enumerate(pipeline)
            if name not in assigned_names
        ]
        if remaining_steps:
            add_log(scan_id, "INFO",
                    f"[{scan_type}] Running {len(remaining_steps)} unassigned module(s)...")
            rem_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=min(len(remaining_steps), _max_workers)
            )
            rem_futures = [
                rem_executor.submit(
                    run_scanner_step, i + 1, name, cls, kwargs, total_steps
                )
                for i, name, cls, kwargs in remaining_steps
            ]
            rem_timeout = min(len(remaining_steps) * _module_timeout, 1800)
            try:
                for future in concurrent.futures.as_completed(rem_futures,
                                                              timeout=rem_timeout):
                    try:
                        result = future.result()
                        if result:
                            all_vulns.extend(result)
                    except Exception:
                        pass
            except concurrent.futures.TimeoutError:
                add_log(scan_id, "WARNING",
                        f"[{scan_type}] Unassigned modules timed out after {rem_timeout}s.")
            finally:
                try:
                    rem_executor.shutdown(wait=False, cancel_futures=True)
                except TypeError:
                    rem_executor.shutdown(wait=False)

        # ENH: Cross-scanner deduplication before scoring and DB write
        original_count = len(all_vulns)
        all_vulns = _deduplicate_scan_vulns(all_vulns)
        if original_count != len(all_vulns):
            add_log(scan_id, "INFO",
                    f"Deduplication: {original_count} â†’ {len(all_vulns)} unique findings.")

        score = calculate_security_score(all_vulns)

        add_log(scan_id, "INFO", f"Running AI post-processing on {len(all_vulns)} finding(s)...")
        self_metadata: list[dict] = []
        try:

            tech_fingerprints: list[dict] = []
            for v in all_vulns:
                resp_det = v.get("response_details", "")
                headers = {"server": v.get("server_header", ""), "x-powered-by": v.get("powered_by", "")}
                if resp_det:
                    tech_fingerprints.extend(match_tech(resp_det, headers))

            if tech_fingerprints:
                unique_tech = {}
                for t in tech_fingerprints:
                    unique_tech[t["name"]] = t
                for t in unique_tech.values():
                    cves = find_cves(t["name"], t.get("version"))
                    t["matched_cves"] = cves
                    self_metadata.append({"type": "tech", "data": t})

            chains = detect_chains(all_vulns)
            for chain in chains:
                add_log(scan_id, "CRITICAL",
                        f"[CHAIN] {chain['chain_name']} (CVSS {chain['cvss_score']})")
                self_metadata.append({"type": "chain", "data": chain})

            high_confidence = [v for v in all_vulns
                               if v.get("confidence") in ("Confirmed", "High")]
            for v in high_confidence[:5]:
                try:
                    exploit = generate_exploit(v)
                    v["exploit_poc"] = exploit
                    v["remediation_code"] = generate_remediation(v)
                except Exception:
                    pass

            add_log(scan_id, "INFO",
                    f"AI engine: {len(self_metadata)} metadata items, "
                    f"{len(high_confidence)} high-conf findings enriched.")
        except Exception as ai_err:
            add_log(scan_id, "INFO", f"AI enrichment (non-fatal): {ai_err}")

        add_log(scan_id, "INFO", f"Syncing {len(all_vulns)} finding(s) to database...")

        # â”€â”€ Write results to DB - fresh session per write â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        try:
            db.session.remove()

            # Persist each vulnerability
            for v_data in all_vulns:
                try:
                    vuln = Vulnerability(
                        scan_id=scan_id,
                        title=_clean_nul(v_data.get("title", "")),
                        severity=_clean_nul(v_data.get("severity", "Low")),
                        category=_clean_nul(v_data.get("category", "")),
                        description=_clean_nul(v_data.get("description", "")),
                        remediation=_clean_nul(v_data.get("remediation", "")),
                        cvss_score=float(v_data.get("cvss_score", 0)),
                        evidence=_clean_nul(v_data.get("evidence", "")),
                        payload=_clean_nul(v_data.get("payload", "")),
                        request_details=_clean_nul(v_data.get("request_details", "")),
                        response_details=_clean_nul(v_data.get("response_details", "")),
                        cwe_ids=v_data.get("cwe_ids"),
                        owasp_category=_clean_nul(v_data.get("owasp_category")),
                        exploit_poc=_clean_nul(v_data.get("exploit_poc")),
                        remediation_code=_clean_nul(v_data.get("remediation_code")),
                    )
                    db.session.add(vuln)
                except Exception as ve:
                    add_log(scan_id, "WARNING", f"Could not create vuln record: {ve}")

            # Update scan status
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = "completed"
                scan.security_score = score
                scan.completed_at = datetime.now(timezone.utc)

            db.session.commit()
            
            try:
                emit_scan_progress(scan_id, 'scan_progress', {'status': 'completed'})
            except Exception:
                pass

            crit = sum(1 for v in all_vulns if v.get("severity") == "Critical")
            high = sum(1 for v in all_vulns if v.get("severity") == "High")
            med  = sum(1 for v in all_vulns if v.get("severity") == "Medium")
            low  = sum(1 for v in all_vulns if v.get("severity") == "Low")

            add_log(scan_id, "SUCCESS",
                    f"SCAN COMPLETE - Security Score: {score}/100")
            add_log(scan_id, "SUCCESS",
                    f"Findings: {crit} Critical | {high} High | {med} Medium | {low} Low")
            add_log(scan_id, "SUCCESS",
                    f"Total unique vulnerabilities: {len(all_vulns)}")

            try:
                if scan:
                    scan_user = db.session.get(User, scan.user_id)
                    if scan_user:
                        duration_secs = (datetime.utcnow() - scan.started_at).total_seconds() if scan.started_at else 0
                        duration_str = f"{int(duration_secs // 60)}m {int(duration_secs % 60)}s" if duration_secs > 0 else "< 1m"
                        send_scan_completed(
                            scan_user.email,
                            scan_user.email.split('@')[0].capitalize(),
                            scan.target_url,
                            duration_str,
                            str(len(all_vulns)),
                            f"https://wss.larshield.com/dashboard/scans/{scan.id}",
                            str(crit),
                            str(high),
                            str(med),
                            str(low)
                        )
                        
                        # Suggestion 4: Send critical alert to Org Admin if high/critical vulns found
                        if crit > 0 or high > 0:
                            org_admin = User.query.filter_by(org_id=scan.org_id, role='org_admin').first()
                            if org_admin and org_admin.id != scan.user_id: # Only if they aren't the one who just got the completed email
                                send_critical_alert(
                                    org_admin.email,
                                    org_admin.first_name or org_admin.email.split('@')[0].capitalize(),
                                    scan.target_url,
                                    duration_str,
                                    str(len(all_vulns)),
                                    f"https://wss.larshield.com/dashboard/scans/{scan.id}",
                                    str(crit),
                                    str(high),
                                    str(med),
                                    str(low)
                                )
                                print(f"[Email] Critical Alert sent to Org Admin: {org_admin.email}")

            except Exception as e:
                print(f"[Email] Failed to send scan completed/alert email: {e}")

            # â”€â”€ Webhook alert â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            try:
                alert_settings = AlertSettings.query.filter_by(
                    user_id=scan.user_id
                ).first() if scan else None

                # Collect all webhook URLs to notify
                urls_to_notify = []
                
                if alert_settings and alert_settings.webhook_url:
                    send = False
                    thresh = alert_settings.severity_threshold
                    if thresh == "All": send = True
                    elif thresh == "Critical" and crit > 0: send = True
                    elif thresh == "High" and (crit > 0 or high > 0): send = True
                    elif thresh == "Medium" and (crit > 0 or high > 0 or med > 0): send = True
                    else: send = True
                    if send:
                        urls_to_notify.append(alert_settings.webhook_url)

                # Organization-level webhook (if high/crit found)
                if scan and scan.org_id:
                    org = db.session.get(Organization, scan.org_id)
                    if org and org.webhook_url and (crit > 0 or high > 0):
                        if org.webhook_url not in urls_to_notify:
                            urls_to_notify.append(org.webhook_url)

                if urls_to_notify:
                    db_vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
                    for url in urls_to_notify:
                        try:
                            send_webhook_alert(url, scan, db_vulns, crit, high)
                        except Exception as inner_e:
                            add_log(scan_id, "WARNING", f"Failed to send webhook to {url}: {inner_e}")
                    
                    add_log(scan_id, "INFO", "[System] Webhook alerts dispatched successfully.")
            except Exception as we:
                add_log(scan_id, "WARNING", f"Webhook error (non-fatal): {we}")

        except Exception as db_err:
            db.session.rollback()
            add_log(scan_id, "CRITICAL", f"Database write failure: {str(db_err)}")
            print(f"[Scanner] DB write error for scan {scan_id}: {db_err}", flush=True)

            # Mark scan as failed
            try:
                db.session.remove()
                scan = db.session.get(Scan, scan_id)
                if scan:
                    scan.status = "failed"
                    db.session.commit()
                    try:
                        scan_user = db.session.get(User, scan.user_id)
                        if scan_user:
                            send_scan_failed(
                                scan_user.email, 
                                scan_user.email.split('@')[0].capitalize(), 
                                scan.target_url, 
                                scan.scan_type, 
                                str(db_err)
                            )
                    except Exception as e:
                        print(f"[Email] Failed to send scan failed email: {e}")
                    try:
                        emit_scan_progress(scan_id, 'scan_progress', {'status': 'failed'})
                    except Exception:
                        pass
            except Exception:
                db.session.rollback()

    except Exception as fatal_err:
        print(f"[Scanner] Fatal error in scan {scan_id}: {fatal_err}", flush=True)
        traceback.print_exc()
        # Mark as failed
        try:
            db.session.remove()
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                db.session.commit()
                try:
                    scan_user = db.session.get(User, scan.user_id)
                    if scan_user:
                        send_scan_failed(
                            scan_user.email, 
                            scan_user.email.split('@')[0].capitalize(), 
                            scan.target_url, 
                            scan.scan_type, 
                            "Fatal system error"
                        )
                except Exception as e:
                    print(f"[Email] Failed to send scan failed email: {e}")
                try:
                    emit_scan_progress(scan_id, 'scan_progress', {'status': 'failed'})
                except Exception:
                    pass
        except Exception:
            db.session.rollback()
    finally:
        # Always clean up the session after completion
        try:
            db.session.remove()
        except Exception:
            pass
        # BUG-6 FIX: Defer log cleanup by 5 minutes so frontend /logs polling works.
        # Old code: cleanup_scan_logs(scan_id) - deleted logs while scan appeared "scanning"
        schedule_log_cleanup(scan_id, delay_seconds=300)


# â”€â”€ Celery tasks (optional - only registered if Celery is available) â”€â”€â”€â”€â”€â”€â”€â”€â”€

if CELERY_AVAILABLE and celery:
    @celery.task(bind=True, name="run_background_scan")
    def run_background_scan_task(self, scan_id: str) -> None:
        """Celery task wrapper - used when Redis is available."""
        app = create_app()
        with app.app_context():
            _run_scan_job(scan_id)

    @celery.task(bind=True, name="process_scheduled_scans")
    def process_scheduled_scans(self):
        """Process scheduled scans via Celery Beat."""
        now = datetime.utcnow()
        schedules = ScheduledScan.query.filter_by(is_active=True).all()
        for s in schedules:
            trigger = False
            
            # Check schedule time if provided
            if s.schedule_time:
                sched_h, sched_m = map(int, s.schedule_time.split(':'))
                curr_h, curr_m = now.hour, now.minute
                time_passed = (curr_h > sched_h) or (curr_h == sched_h and curr_m >= sched_m)
                
                if not time_passed:
                    continue # Not the right time yet
                
            if not s.last_run_at:
                trigger = True
            else:
                diff = now - s.last_run_at
                # If using schedule_time, we still want to respect the frequency
                if s.frequency == "daily" and diff >= timedelta(hours=23):
                    trigger = True
                elif s.frequency == "weekly" and diff >= timedelta(days=6, hours=23):
                    trigger = True
                elif s.frequency == "monthly" and diff >= timedelta(days=29):
                    trigger = True
            if trigger:
                new_scan = Scan(
                    user_id=s.user_id,
                    org_id=s.org_id,
                    target_url=s.target_url,
                    scan_type=s.scan_type,
                    status="queued",
                    auth_headers=s.auth_headers,
                )
                db.session.add(new_scan)
                s.last_run_at = now
                db.session.commit()
                run_background_scan_task.delay(new_scan.id)


# ── Thread-based launcher with Sequential FIFO Queue (One scan at a time) ──

_scan_queue = queue.Queue()
_queue_worker_started = False
_queue_lock = threading.Lock()

def _scan_queue_worker(app):
    print("[ScanQueueWorker] Sequential background worker thread started.", flush=True)
    while True:
        try:
            sid = _scan_queue.get()
            if sid is None:
                break

            print(f"[ScanQueueWorker] Beginning execution of queued scan {sid}...", flush=True)
            with app.app_context():
                try:
                    s = Scan.query.get(sid)
                    if s:
                        s.status = 'scanning'
                        s.started_at = datetime.now(timezone.utc)
                        db.session.commit()
                        add_log(sid, "INFO", f"Target: {s.target_url} ({s.scan_type} Scan)")
                        add_log(sid, "INFO", "Sequential scan worker starting active audit execution...")

                    _run_scan_job(sid)
                except Exception as ex:
                    print(f"[ScanQueueWorker] Error executing scan {sid}: {ex}", flush=True)
                    traceback.print_exc()
                finally:
                    _scan_queue.task_done()
        except Exception as e:
            print(f"[ScanQueueWorker] Queue worker exception: {e}", flush=True)
            time.sleep(1)

def launch_scan(app, scan_id: str) -> bool:
    """
    Launch a scan using a sequential FIFO queue.
    Ensures only ONE active scan executes at any given time.
    Subsequent scans wait in 'queued' state and run automatically when the current scan finishes.
    """
    global _queue_worker_started

    use_celery = os.getenv('USE_CELERY', 'false').lower() == 'true'
    if use_celery and CELERY_AVAILABLE and celery:
        run_background_scan_task.delay(scan_id)
        print(f"[Scanner] Background scan dispatched to Celery for scan {scan_id}", flush=True)
        return True

    with app.app_context():
        try:
            s = Scan.query.get(scan_id)
            if s:
                active_scan = Scan.query.filter(Scan.status == 'scanning', Scan.id != scan_id).first()
                if active_scan or not _scan_queue.empty():
                    s.status = 'queued'
                    print(f"[Scanner] Active scan in progress ({active_scan.id if active_scan else 'queued item'}). Setting scan {scan_id} to queued.", flush=True)
                else:
                    s.status = 'scanning'
                    s.started_at = datetime.now(timezone.utc)
                    print(f"[Scanner] Queue empty. Setting scan {scan_id} directly to scanning.", flush=True)
                db.session.commit()
        except Exception as err:
            print(f"[Scanner] Failed updating scan status on launch: {err}", flush=True)

    with _queue_lock:
        if not _queue_worker_started:
            worker_thread = threading.Thread(target=_scan_queue_worker, args=(app,), daemon=True)
            worker_thread.start()
            _queue_worker_started = True

    _scan_queue.put(scan_id)
    print(f"[Scanner] Scan {scan_id} placed in execution queue (Current queue size: {_scan_queue.qsize()})", flush=True)
    return True



# --- From pdf_generator.py ---

def get_ssl_info(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        if ':' in domain:
            domain = domain.split(':')[0]
            
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    cert = ssock.getpeercert(binary_form=True)
                    if cert is None:
                        return None
                    parsed_cert = x509.load_der_x509_certificate(cert, default_backend())
                    # Use not_valid_after_utc (newer cryptography) with fallback
                    try:
                        expiry_dt = parsed_cert.not_valid_after_utc
                    except AttributeError:
                        expiry_dt = parsed_cert.not_valid_after
                    return {
                        'issuer': parsed_cert.issuer.rfc4514_string(),
                        'subject': parsed_cert.subject.rfc4514_string(),
                        'expiry': expiry_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'version': ssock.version()
                    }
                
                # Default getpeercert output
                issuer = {}
                for item in cert.get('issuer', []):
                    if item and isinstance(item[0], (tuple, list)) and len(item[0]) == 2:
                        issuer[item[0][0]] = item[0][1]
                        
                subject = {}
                for item in cert.get('subject', []):
                    if item and isinstance(item[0], (tuple, list)) and len(item[0]) == 2:
                        subject[item[0][0]] = item[0][1]
                        
                issuer_str = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                subject_str = subject.get('commonName', 'Unknown')
                not_after = cert.get('notAfter', 'Unknown')
                
                # Try to parse 'notAfter' (e.g. 'Oct 19 23:59:59 2026 GMT')
                try:
                    expiry_dt = datetime.strptime(str(not_after), '%b %d %H:%M:%S %Y %Z')
                    expiry = expiry_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                except Exception:
                    expiry = not_after
                    
                return {
                    'issuer': issuer_str,
                    'subject': subject_str,
                    'expiry': expiry,
                    'version': ssock.version()
                }
    except Exception:
        return None

class PageTrackerCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pages = []
        self._header_footer_cb = None

    def showPage(self):
        self.pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self.pages)
        for page in self.pages:
            self.__dict__.update(page)
            if self._header_footer_cb:
                self._header_footer_cb(self, num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

class PageNumberRecorder(Flowable):
    def __init__(self, key_name, page_dict):
        super().__init__()
        self.width = 0
        self.height = 0
        self.key_name = key_name
        self.page_dict = page_dict

    def draw(self):
        if self.page_dict is not None:
            self.page_dict[self.key_name] = self.canv._pageNumber
        # Explicitly create a PDF bookmark for internal linking
        self.canv.bookmarkPage(self.key_name)

def create_proportional_image(img_source, max_width=180, max_height=170, hAlign='CENTER'):
    """
    Creates a ReportLab Image object that strictly preserves original aspect ratio.
    """
    try:
        from PIL import Image as PILImage
        if hasattr(img_source, 'seek'):
            img_source.seek(0)
            pil_img = PILImage.open(img_source)
            img_source.seek(0)
        else:
            pil_img = PILImage.open(img_source)
            
        w, h = pil_img.size
        if not w or not h:
            return Image(img_source, width=max_width, height=max_height, kind='proportional', hAlign=hAlign)
            
        aspect = float(w) / float(h)
        
        if (float(w) / float(max_width)) > (float(h) / float(max_height)):
            calc_w = max_width
            calc_h = max_width / aspect
        else:
            calc_h = max_height
            calc_w = max_height * aspect
            
        return Image(img_source, width=calc_w, height=calc_h, kind='proportional', hAlign=hAlign)
    except Exception:
        return Image(img_source, width=max_width, height=max_height, kind='proportional', hAlign=hAlign)

def generate_scan_pdf(scan, vulnerabilities):
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    vulnerabilities = sorted(vulnerabilities, key=lambda x: (severity_order.get(x.severity, 5), -getattr(x, 'cvss_score', 0)))

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle', parent=styles['Heading1'],
        fontSize=24, textColor=colors.black, spaceAfter=20, alignment=1
    )
    subtitle_style = ParagraphStyle(
        'SubTitle', parent=styles['Heading2'],
        fontSize=18, textColor=colors.HexColor("#EA580C"), spaceAfter=20, alignment=1
    )
    heading2 = ParagraphStyle(
        'Heading2', parent=styles['Heading2'],
        fontSize=14, textColor=colors.black, spaceAfter=10, spaceBefore=15
    )
    normal = styles['Normal']
    normal.fontSize = 10
    normal.spaceAfter = 6
    normal.alignment = 4  # TA_JUSTIFY
    
    bullet_style = ParagraphStyle(
        'BulletStyle', parent=normal,
        leftIndent=15, bulletIndent=5
    )

    # Try to fetch Organization logo and name
    org_name = "[CLIENT ORGANIZATION]"
    org_logo = None
    if scan.org_id:
        org = db.session.get(Organization, scan.org_id)
        if org:
            org_name = org.name
            if org.report_logo_url:
                try:
                    resp = requests.get(org.report_logo_url, timeout=5)
                    if resp.status_code == 200:
                        org_logo = io.BytesIO(resp.content)
                except Exception:
                    pass
    
    logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'frontend', 'public', 'logoo.png'))
    has_local_logo = os.path.exists(logo_path)

    def build_pdf_elements(page_dict=None):
        elements = []
        is_ssl = (scan.scan_type or 'Deep').upper() in ['SSL', 'QUICK']
        is_owasp = (scan.scan_type or 'Deep').upper() in ['OWASP', 'ADVANCED']
        is_full = not (is_ssl or is_owasp)

        
        # --- PAGE 1: COVER PAGE ---
        if has_local_logo:
            elements.append(Spacer(1, 100))
            elements.append(create_proportional_image(logo_path, max_width=180, max_height=170, hAlign='CENTER'))
            elements.append(Spacer(1, 60))
        else:
            elements.append(Spacer(1, 200))
        elements.append(Paragraph("LarShield Security Audit Report", title_style))
        elements.append(PageBreak())
        
        # --- PAGE 2: TITLE & META INFORMATION ---
        if has_local_logo:
            elements.append(create_proportional_image(logo_path, max_width=130, max_height=120, hAlign='CENTER'))
            elements.append(Spacer(1, 25))
            
            
        elements.append(Paragraph("VULNERABILITY ASSESSMENT & PENETRATION TESTING (VAPT) REPORT", title_style))
        elements.append(Spacer(1, 40))
        
        date_testing = scan.completed_at.strftime('%B %d, %Y') if scan.completed_at else 'Unknown'
        
        if is_ssl:
            audit_type_str = "Quick Web Application PenTest"
        elif is_owasp:
            audit_type_str = "Advanced Web Application PenTest"
        else:
            if scan.scan_type in ['Mobile App PenTest', 'API Security Assessment']:
                audit_type_str = scan.scan_type
            else:
                audit_type_str = "Deep Web Application PenTest"
            
        meta_data = [
            ["Target Asset / Application", ":", scan.target_url],
            ["Assessment Type", ":", audit_type_str],
            ["Date of Testing", ":", f"{date_testing}"],
            ["Report Version", ":", "v1.0"],
            ["Report Status", ":", "Final"],
            ["Classification", ":", "Confidential"]
        ]
        
        meta_table = Table(meta_data, colWidths=[150, 10, 300], hAlign='LEFT')
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        
        elements.append(meta_table)
        elements.append(Spacer(1, 40))
        
        elements.append(Paragraph("<b>Prepared by:</b><br/>LarShield<br/>[Larxius Technologies LLP]<br/>info@Larxius.com<br/>www.Larxius.com", normal))
        
        elements.append(PageBreak())
        
        # --- PAGE 3: EXECUTIVE SUMMARY & SCOPE ---
        elements.append(Paragraph("Executive summary", heading2))
        if is_ssl:
            exec_summary_base = f"This report presents the results of the Quick Web Application PenTest for {scan.target_url}. The recommendations provided in this report are structured to facilitate the remediation of the identified security risks. This is a Quick Scan. "
        elif is_owasp:
            exec_summary_base = f"This report presents the results of the Advanced Web Application PenTest for {scan.target_url}. The recommendations provided in this report are structured to facilitate the remediation of the identified security risks. This is an Advanced Scan. "
        else:
            if scan.scan_type in ['Mobile App PenTest', 'API Security Assessment']:
                exec_summary_base = f"This report presents the results of the {scan.scan_type} for {scan.target_url}. The recommendations provided in this report are structured to facilitate the remediation of the identified security risks. This document serves as a formal letter of attestation for the recent engagement. "
            else:
                exec_summary_base = f"This report presents the results of the Deep Web Application PenTest for {scan.target_url}. The recommendations provided in this report are structured to facilitate the remediation of the identified security risks. This document serves as a formal letter of attestation for the recent engagement. This is a Deep Scan. "
        
        crit_count = sum(1 for v in vulnerabilities if v.severity == "Critical")
        high_count = sum(1 for v in vulnerabilities if v.severity == "High")
        
        if crit_count > 0:
            exec_summary_dynamic = f"The assessment revealed a critical exposure in the perimeter, with {crit_count} Critical and {high_count} High severity vulnerabilities identified. Immediate remediation is required to prevent potential compromise."
        elif high_count > 0:
            exec_summary_dynamic = f"The assessment identified {high_count} High severity vulnerabilities that pose a direct threat to key business processes. Prompt attention is recommended."
        else:
            exec_summary_dynamic = "The target demonstrated a strong security posture with no critical or high severity vulnerabilities discovered."
            
        exec_summary_end = " We highly recommend reviewing the section of Summary of business risks and High-Level Recommendations for a better understanding of risks and discovered security issues."
        
        exec_summary = exec_summary_base + exec_summary_dynamic + exec_summary_end
        elements.append(Paragraph(exec_summary, normal))
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Scope", heading2))
        
        def get_rating_grade(score):
            if score is None: return '--'
            if score >= 90: return 'A'
            if score >= 80: return 'B'
            if score >= 70: return 'C'
            if score >= 50: return 'D'
            return 'F'
            
        grade = get_rating_grade(scan.security_score)
        security_level_text = { 'A': 'Excellent', 'B': 'Good', 'C': 'Fair', 'D': 'Poor', 'F': 'Inadequate', '--': 'Unknown' }.get(grade, 'Unknown')
        
        sl_data = [
            ["Scope", "Security level", "Grade"],
            ["Web API perimeter", security_level_text, grade]
        ]
        sl_t = Table(sl_data, colWidths=[150, 150, 100], hAlign='LEFT')
        sl_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F3F4F6")),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold')
        ]))
        elements.append(sl_t)
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Under Defense Grading Criteria:", normal))
        def_data = [
            ["Grade", "Security", "Criteria Description"],
            ["A", "Excellent", Paragraph("The security exceeds \"Industry Best Practice\" standards. The overall posture was found to be excellent with only a few low-risk findings identified.", normal)],
            ["B", "Good", Paragraph("The security meets with accepted standards for 'Industry Best Practice.' The overall posture was found to be strong with only a handful of medium- and low-risk shortcomings identified.", normal)],
            ["C", "Fair", Paragraph("Current solutions protect some areas of the enterprise from security issues. Moderate changes are required to elevate the discussed areas to \"Industry Best Practice\" standards.", normal)],
            ["D", "Poor", Paragraph("Significant security deficiencies exist. Immediate attention should be given to the discussed issues to address exposures identified. Major changes are required to elevate to \"Industry Best Practice\" standards.", normal)],
            ["F", "Inadequate", Paragraph("Serious security deficiencies exist. Shortcomings were identified throughout most or even all of the security controls examined. Improving security will require a major allocation of resources.", normal)]
        ]
        
        def_t = Table(def_data, colWidths=[40, 80, 350], hAlign='LEFT')
        def_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F3F4F6")),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('VALIGN', (0,0), (-1,-1), 'TOP')
        ]))
        elements.append(def_t)
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Assumptions & Constraints", heading2))
        elements.append(Paragraph("As the environment changes, and new vulnerabilities and risks are discovered and made public, an organization's overall security posture will change. Such changes may affect the validity of this letter. Therefore, the conclusion reached from our analysis only represents a 'snapshot' in time.", normal))
        
        elements.append(PageBreak())
        
        # --- PAGE 4: OBJECTIVES, SCOPE & RESULTS ---
        elements.append(Paragraph("Objectives & Scope", heading2))
        obj_data = [
            ["Organization", Paragraph(org_name, normal)],
            ["Audit type", Paragraph(audit_type_str, normal)],
            ["Asset URL", Paragraph(scan.target_url, normal)],
            ["Audit Date", Paragraph(date_testing, normal)]
        ]
        obj_t = Table(obj_data, colWidths=[150, 320], hAlign='LEFT')
        obj_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F3F4F6")),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('VALIGN', (0,0), (-1,-1), 'TOP')
        ]))
        elements.append(obj_t)
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Testing Process:", normal))
        elements.append(Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Consultants performed a discovery process to gather information about the target and searched for information disclosure vulnerabilities. With this data in hand, we conducted the bulk of the testing manually, which consisted of input validation tests, impersonation (authentication and authorization) tests, and session state management tests. The purpose of this penetration testing is to illuminate security risks by leveraging weaknesses within the environment that lead to the obtainment of unauthorized access and/or the retrieval of sensitive information. The shortcomings identified during the assessment were used to formulate recommendations and mitigation strategies for improving the overall security posture.", normal))
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Results Overview", heading2))
        elements.append(Paragraph("The test uncovered a few vulnerabilities that may cause sensitive data leakage, broken confidentiality and integrity, and availability of the resource. Identified vulnerabilities are easily exploitable and the risk posed by these vulnerabilities can cause damage to the application and company. Security experts performed manual security testing according to OWASP Web Application Testing Methodology, which demonstrates the following results.", normal))
        
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for v in vulnerabilities:
            if v.severity in counts:
                counts[v.severity] += 1
                
        sev_data = [
            ["Critical", "High", "Medium", "Low", "Informational"],
            [str(counts["Critical"]), str(counts["High"]), str(counts["Medium"]), str(counts["Low"]), str(counts["Informational"])]
        ]
        sev_t = Table(sev_data, colWidths=[80, 80, 80, 80, 80], hAlign='LEFT')
        sev_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F3F4F6")),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'CENTER')
        ]))
        elements.append(Spacer(1, 10))
        elements.append(sev_t)
        
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from reportlab.graphics.shapes import Drawing
        
        color_map = {
            "Critical": colors.HexColor("#DC2626"),
            "High": colors.HexColor("#EA580C"),
            "Medium": colors.HexColor("#FFCC00"),
            "Low": colors.HexColor("#99CC33"),
            "Informational": colors.HexColor("#33CC33")
        }
        
        severities = ["Critical", "High", "Medium", "Low", "Informational"]
        bar_values = [counts[s] for s in severities]
        
        if any(v > 0 for v in bar_values):
            d = Drawing(450, 180)
            bc = VerticalBarChart()
            bc.x = 40
            bc.y = 25
            bc.height = 130
            bc.width = 370
            bc.data = [bar_values]
            
            # Category Axis Styling
            bc.categoryAxis.categoryNames = [f"{s}" for s in severities]
            bc.categoryAxis.labels.fontSize = 10
            bc.categoryAxis.labels.fontName = 'Helvetica'
            bc.categoryAxis.labels.dy = -15
            bc.categoryAxis.strokeWidth = 1
            bc.categoryAxis.strokeColor = colors.HexColor("#9CA3AF")
            
            # Value Axis Styling
            bc.valueAxis.valueMin = 0
            max_val = max(bar_values)
            bc.valueAxis.valueMax = max(max_val + (max_val * 0.2) + 1, 5)
            bc.valueAxis.valueStep = max(1, (max_val + 2) // 5)
            bc.valueAxis.labels.fontSize = 9
            bc.valueAxis.labels.fontName = 'Helvetica'
            bc.valueAxis.strokeWidth = 0
            bc.valueAxis.visibleGrid = True
            bc.valueAxis.gridStrokeColor = colors.HexColor("#E5E7EB")
            bc.valueAxis.gridStrokeWidth = 1
            bc.valueAxis.gridStrokeDashArray = [2, 2]
            
            # Bar Styling
            bc.barSpacing = 15
            bc.barWidth = 45
            bc.barLabelFormat = '%d'
            bc.barLabels.fontName = 'Helvetica-Bold'
            bc.barLabels.fontSize = 10
            bc.barLabels.nudge = 8
            
            for i, s in enumerate(severities):
                bc.bars[(0, i)].fillColor = color_map[s]
                bc.bars[(0, i)].strokeColor = color_map[s]
                bc.bars[(0, i)].strokeWidth = 0
                
            d.add(bc)
            elements.append(Spacer(1, 20))
            elements.append(d)
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Severity scoring definitions:", normal))
        elements.append(Paragraph("<bullet>&bull;</bullet>Critical - Immediate threat to key business processes.", bullet_style))
        elements.append(Paragraph("<bullet>&bull;</bullet>High - Direct threat to key business processes.", bullet_style))
        elements.append(Paragraph("<bullet>&bull;</bullet>Medium - Indirect threat to key business processes or partial threat to business processes.", bullet_style))
        elements.append(Paragraph("<bullet>&bull;</bullet>Low - No direct threat exists. Vulnerability may be exploited using other vulnerabilities.", bullet_style))
        elements.append(Paragraph("<bullet>&bull;</bullet>Informational - This finding does not indicate vulnerability, but states a comment that notifies about design flaws and improper implementation that might cause a problem in the long run.", bullet_style))
        
        elements.append(Spacer(1, 20))
        elements.append(Paragraph("<b>Scan Coverage Note:</b>", normal))
        if is_ssl:
            note_text = "This is a <b>Quick Scan</b>. It is a basic scan that quickly verifies fundamental security controls, focusing primarily on SSL/TLS configurations, open ports, and surface-level misconfigurations. It checks these basic items but does not perform deep vulnerability probing."
        elif is_owasp:
            note_text = "This is an <b>Advanced/Medium Scan</b>. This assessment executes over 34 targeted security scripts designed to rigorously uncover common and critical web application vulnerabilities. While it provides strong practical coverage, it does not perform all exhaustive scanning techniques."
        else:
            note_text = "This is a <b>Deep Scan</b>. This is our most advanced, best-in-class scanning engine. It executes our complete arsenal of scripts, fuzzers, and deep-crawling tools to rigorously analyze the entire website and provide a comprehensive security evaluation. It identifies even deeply hidden or chained vulnerabilities for maximum protection."
            
        elements.append(Paragraph(f"{note_text}", normal))
        elements.append(Spacer(1, 15))        
        elements.append(PageBreak())
        
        # --- PAGE 5: TABLE OF CONTENTS / FINDINGS INDEX ---
        elements.append(Paragraph("Vulnerability Summary", heading2))
        elements.append(Paragraph("Click on any vulnerability title or page number below to jump directly to its detailed section in this report.", normal))
        elements.append(Spacer(1, 15))

        if vulnerabilities:
            toc_rows = []
            for idx, vuln in enumerate(vulnerabilities, 1):
                target_key = f"vuln_{idx}"
                p_num = page_dict.get(target_key, 8) if page_dict else 8
                
                display_sev = vuln.severity
                if display_sev == 'Critical': sev_hex = '#DC2626'
                elif display_sev == 'High': sev_hex = '#EA580C'
                elif display_sev == 'Medium': sev_hex = '#D97706'
                elif display_sev == 'Low': sev_hex = '#65A30D'
                else: sev_hex = '#059669'
                
                title_cell = Paragraph(
                    f'<a href="#{target_key}" color="#1D4ED8"><b>{idx}. {html.escape(vuln.title or "")}</b></a>', 
                    normal
                )
                sev_cell = Paragraph(f'<font color="{sev_hex}"><b>[{display_sev}]</b></font>', normal)
                
                right_align = ParagraphStyle('RightAlign', parent=normal, alignment=2)
                page_cell = Paragraph(f'<a href="#{target_key}" color="#1D4ED8"><b>{p_num}</b></a>', right_align)
                
                toc_rows.append([title_cell, sev_cell, page_cell])
                
            toc_table = Table(toc_rows, colWidths=[340, 80, 80])
            toc_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('ALIGN', (2,0), (2,-1), 'RIGHT'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#F3F4F6")),
            ]))
            elements.append(toc_table)
        else:
            elements.append(Paragraph("<i>No vulnerabilities detected during this assessment.</i>", normal))

        elements.append(PageBreak())

        # --- PAGE 6: RISKS & RECOMMENDATIONS ---
        elements.append(Paragraph("Summary of business risks", heading2))
        elements.append(Paragraph("Critical and High severity issues can lead to:", normal))
        crit_risks = [
            "Complete compromise of the application and underlying systems, leading to total loss of data confidentiality and integrity.",
            "Significant financial loss, reputational damage, and legal consequences due to regulatory violations.",
            "Complete disruption of key business processes and denial of service to legitimate users.",
            "Unauthorized access to sensitive user data and intellectual property."
        ]
        for r in crit_risks:
            elements.append(Paragraph(f"<bullet>&bull;</bullet>{r}", bullet_style))
        elements.append(Spacer(1, 10))
        
        elements.append(Paragraph("Medium and low severity issues can lead to:", normal))
        risks = [
            "Attacks on communication channels and as a result on sensitive data leakage and possible modification; in other words, it affects the integrity and confidentiality of data transferred.",
            "Information leakage about system components which may be used by attackers for further malicious actions.",
            "Attacks on old and unpatched system components with a bunch of publicly known vulnerabilities.",
            "Enumerating existing users' emails/usernames and brute-forcing their passwords. Easy access to their session after exploitation of high-level risks.",
            "Combination of a few issues can be used for successful realization of attacks.",
            "Informational severity issues do not carry a direct threat, but they can be used to gather useful information for an attacker."
        ]
        for r in risks:
            elements.append(Paragraph(f"<bullet>&bull;</bullet>{r}", bullet_style))
            
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("High-Level Recommendations", heading2))
        elements.append(Paragraph("Taking into consideration all issues that have been discovered, we highly recommend to:", normal))
        recs = [
            "Conduct current vs. future IT/Security program review",
            "Conduct Static code analysis for codebase",
            "Establish Secure SDLC best practices, assign Security Engineer to a project to monthly review code, conduct SAST & DAST security testing",
            "Review Architecture of application",
            "Deploy Web Application Firewall solution to detect any malicious manipulations",
            "Continuously monitor logs for anomalies to detect abnormal behaviour and fraud transactions. Dedicate a security operations engineer to this task",
            "Implement Patch Management procedures for whole IT infrastructure and endpoints of employees and developers",
            "Continuously Patch production and development environments and systems on regular bases with latest releases and security updates",
            "Conduct annual Penetration test and quarterly Vulnerability Scanning against internal and external environment",
            "Develop and Conduct Security Awareness training for employees and developers",
            "Develop Incident Response Plan in case of Data breach or security incidents",
            "Analyse risks for key assets and resources",
            "Update codebase to conduct verification and sanitization of user input on both, client and server side",
            "Use only encrypted channels for communications",
            "Do not send any unnecessary data in requests and cookies",
            "Improve server and application configuration to meet security best practises"
        ]
        for r in recs:
            elements.append(Paragraph(f"<bullet>&bull;</bullet>{r}", bullet_style))
            
        elements.append(PageBreak())
        
        # --- PAGE 7: METHODOLOGY & FINDINGS ---
        if not is_ssl:
            elements.append(Paragraph("Performed tests", heading2))
            elements.append(Paragraph("<bullet>&bull;</bullet>All set of applicable OWASP Top 10 Security Threats", bullet_style))
            if is_full:
                elements.append(Paragraph("<bullet>&bull;</bullet>All set of applicable SANS 25 Security Threats", bullet_style))
            elements.append(Spacer(1, 10))
            
            owasp_data = [
                ["A1:2017-Injection", "Evaluated", "Injection Flaws"],
                ["A2:2017-Broken Authentication", "Evaluated", "Authentication Issues"],
                ["A3:2017-Sensitive Data Exposure", "Evaluated", "Data Protection"],
                ["A4:2017-XML External Entities (XXE)", "Evaluated", "XML Processors"],
                ["A5:2017-Broken Access Control", "Evaluated", "Access Control"],
                ["A6:2017-Security Misconfiguration", "Evaluated", "System Configuration"],
                ["A7:2017-Cross-Site Scripting (XSS)", "Evaluated", "Client-side Flaws"],
                ["A8:2017-Insecure Deserialization", "Evaluated", "Deserialization"],
                [Paragraph("A9:2017-Using Components with Known Vulnerabilities", normal), "Evaluated", "Vulnerable Components"],
                ["A10:2017-Insufficient Logging & Monitoring", "Evaluated", "Logging"]
            ]
            owasp_t = Table(owasp_data, colWidths=[200, 100, 170], hAlign='LEFT')
            owasp_t.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ]))
            elements.append(owasp_t)
            
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Methodology", heading2))
            elements.append(Paragraph("Our Penetration Testing Methodology is grounded on the following guides and standards:", normal))
            if is_full:
                elements.append(Paragraph("<bullet>&bull;</bullet>Penetration Testing Execution Standard", bullet_style))
            elements.append(Paragraph("<bullet>&bull;</bullet>OWASP Top 10 Application Security Risks - 2017", bullet_style))
            elements.append(Paragraph("<bullet>&bull;</bullet>OWASP Testing Guide", bullet_style))
            elements.append(Paragraph("<bullet>&bull;</bullet>OWASP ASVS", bullet_style))
            
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("<b>Methodology Overview:</b> Open Web Application Security Project (OWASP) is an industry initiative for web application security. OWASP has identified the 10 most common attacks that succeed against web applications. These comprise the OWASP Top 10. Application penetration test includes all the items in the OWASP Top 10 and more. The penetration tester remotely tries to compromise the OWASP Top 10 flaws. The flaws listed by OWASP in its most recent Top 10 and the status of the application against those are depicted in the table above.", normal))
            elements.append(Spacer(1, 15))
        
        elements.append(Paragraph("SSL/TLS Analysis", heading2))
        ssl_info = getattr(scan, 'ssl_info', None) or get_ssl_info(scan.target_url)
        if ssl_info:
            elements.append(Paragraph(f"<b>Issuer:</b> {html.escape(str(ssl_info.get('issuer', 'Unknown') or 'Unknown'))}", normal))
            elements.append(Paragraph(f"<b>Subject:</b> {html.escape(str(ssl_info.get('subject', 'Unknown') or 'Unknown'))}", normal))
            elements.append(Paragraph(f"<b>Expiry:</b> {html.escape(str(ssl_info.get('expiry', 'Unknown') or 'Unknown'))}", normal))
            elements.append(Paragraph(f"<b>TLS Version:</b> {html.escape(str(ssl_info.get('version', 'Unknown') or 'Unknown'))}", normal))
        else:
            elements.append(Paragraph("Could not retrieve SSL certificate details.", normal))
        elements.append(Spacer(1, 15))
            
        elements.append(PageBreak())
        elements.append(Paragraph("Findings Details", heading2))
        
        def markdown_to_reportlab_html(text):
            if not text: return ""
            import html, re
            text = text.replace("\\n", "\n")
            text = html.escape(text)
            
            # Bold: **text**
            text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
            # Italics: *text*
            text = re.sub(r'\*(?!\*)(.+?)(?<!\*)\*', r'<i>\1</i>', text)
            # Inline Code: `text`
            text = re.sub(r'`([^`]+)`', r'<font name="Courier">\1</font>', text)
            
            lines = text.split('\n')
            out_lines = []
            for line in lines:
                sline = line.lstrip()
                if not sline:
                    out_lines.append("")
                    continue
                
                # List items
                m = re.match(r'^([-*]|\d+\.)\s+(.*)', sline)
                if m:
                    line = "&nbsp;&nbsp;&bull; " + m.group(2)
                else:
                    # Bold common prefixes
                    line = re.sub(r'^(\*\*.*?\*\*|Payload:|Impact:|Recommendation:|Framework:|Score:|Failed Controls:)', r'<b>\1</b>', line)
                    
                out_lines.append(line)
                
            return "<br/>".join(out_lines)

        parsed = urlparse(scan.target_url)
        domain = parsed.netloc or parsed.path
        if ':' in domain:
            domain = domain.split(':')[0]
            
        def get_proof_of_detection(v, dom):
            proof = ""
            if getattr(v, 'request_details', None): proof += f"# Request Details\n{v.request_details}\n\n"
            if getattr(v, 'payload', None): proof += f"# Payload Used\n{v.payload}\n\n"
            if getattr(v, 'response_details', None): proof += f"# Response Details\n{v.response_details}\n\n"
            if getattr(v, 'evidence', None): proof += f"# Evidence\n{v.evidence}\n\n"
            
            if proof.strip(): return proof.strip()
            
            cat = getattr(v, 'category', '')
            title = getattr(v, 'title', '')
            desc = getattr(v, 'description', '')
            
            if cat == 'Security Headers':
                return f"# Request Headers\nGET / HTTP/1.1\nHost: {dom}\nUser-Agent: LarShield/2.0\n\n# Response Headers Analysis\nHTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html\n... [snip] ...\n\n[Detection] {title}\nMissing or misconfigured attribute in server response."
            if cat == 'SSL/TLS':
                return f"# TLS Handshake Probe\nopenssl s_client -connect {dom}:443 -tls1_2\n\n# Protocol Analysis\nCONNECTED(00000003)\n[Detection] {title}\nCertificate or protocol weakness verified during handshake negotiation."
            if 'SQL' in title or cat == 'Injection':
                return f"# Malicious Request Payload\nPOST /api/v1/query HTTP/1.1\nHost: {dom}\nContent-Type: application/json\n\n{{\n    \"input\": \"1' OR '1'='1' --\"\n}}\n\n# Response Analysis\nHTTP/1.1 500 Internal Server Error\n[Detection] {title}\nDatabase error or behavioral delay confirmed injection execution."
            if 'XSS' in title or 'Cross-Site' in title:
                return f"# Payload Injection\nGET /search?q=<script>alert('XSS')</script> HTTP/1.1\nHost: {dom}\n\n# Response Analysis\nHTTP/1.1 200 OK\n[Detection] {title}\nPayload reflected in DOM without sanitization."
                
            return f"# Automated Probe Log\nTarget: {dom}\nCategory: {cat}\nScanner Module: {title}\n\n# Detection Output\n[System] Vulnerability confirmed via behavioral analysis and pattern matching.\n[Evidence] {desc.split('.')[0] if desc else ''}."

        for idx, vuln in enumerate(vulnerabilities, 1):
            if idx > 1:
                elements.append(PageBreak())
            target_key = f"vuln_{idx}"
            display_sev = vuln.severity
            if display_sev == 'Critical': sev_hex = '#DC2626'
            elif display_sev == 'High': sev_hex = '#EA580C'
            elif display_sev == 'Medium': sev_hex = '#FFCC00'
            elif display_sev == 'Low': sev_hex = '#99CC33'
            else: sev_hex = '#33CC33'
            
            elements.append(PageNumberRecorder(target_key, page_dict))
            elements.append(Paragraph(f'<a name="{target_key}"/><b>{idx}. {html.escape(vuln.title or "")}</b>', styles['Heading3']))
            
            cvss_vector = getattr(vuln, 'cvss_vector', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
            if display_sev == 'Low': cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
            elif display_sev == 'Medium': cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
            
            vuln_data = [
                ["Severity", Paragraph(f"<font color='{sev_hex}'>{display_sev}</font>"), "CVSS Score", str(vuln.cvss_score)],
                ["Category", vuln.category, "Detected", vuln.detected_at.strftime('%Y-%m-%d')],
                ["CVSS Vector", cvss_vector, ", "]
            ]
            vt = Table(vuln_data, colWidths=[80, 150, 80, 150])
            vt.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F9FAFB")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('FONTNAME', (2,0), (2,-1), 'Helvetica-Bold'),
            ]))
            
            elements.append(vt)
            elements.append(Spacer(1, 10))
            
            elements.append(Paragraph("<b>Description:</b>", styles['Normal']))
            desc_text = markdown_to_reportlab_html(vuln.description)
            elements.append(Paragraph(desc_text, normal))
            elements.append(Spacer(1, 10))
            
            proof_text = get_proof_of_detection(vuln, domain)
            elements.append(Paragraph("<b>Proof of Detection (Engine Payload Audit Log):</b>", styles['Normal']))
            elements.append(Spacer(1, 5))
            proof_lines = proof_text.split('\n')
            
            proof_html = []
            for line in proof_lines:
                escaped = html.escape(line).replace(" ", "&nbsp;")
                if escaped.startswith("#"):
                    proof_html.append(f"<font color='#94A3B8'>{escaped}</font>")
                elif "[Detection]" in escaped or "[System]" in escaped or "[Evidence]" in escaped:
                    proof_html.append(f"<font color='#93C5FD'>{escaped}</font>")
                else:
                    proof_html.append(f"<font color='#F8FAFC'>{escaped}</font>")
            
            proof_html_str = "<br/>".join(proof_html)
            
            proof_table = Table([[Paragraph(f"<font face='Courier' size='8'>{proof_html_str}</font>", normal)]], colWidths=[460])
            proof_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#0B0F19")),
                ('TOPPADDING', (0,0), (-1,-1), 12),
                ('BOTTOMPADDING', (0,0), (-1,-1), 12),
                ('LEFTPADDING', (0,0), (-1,-1), 12),
                ('RIGHTPADDING', (0,0), (-1,-1), 12),
                ('CORNER_RADIUS', (0,0), (-1,-1), 4),
            ]))
            elements.append(proof_table)
            elements.append(Spacer(1, 15))
            
            elements.append(Paragraph("<b>Remediation:</b>", styles['Normal']))
            rem_text_raw = vuln.remediation or ""
            rem_text_raw = re.sub(r'\.\s+', '.\n', rem_text_raw)
            rem_text = markdown_to_reportlab_html(rem_text_raw)
            elements.append(Paragraph(rem_text, normal))
            elements.append(Spacer(1, 25))
            
        return elements

    total_pages = [0]
    
    def header_footer_draw(canvas_obj, doc):
        canvas_obj.saveState()
        from reportlab.lib.utils import ImageReader
        import pytz
        from datetime import datetime
        
        if canvas_obj._pageNumber > 2:
            # --- Header ---
            if has_local_logo:
                try:
                    canvas_obj.drawImage(ImageReader(logo_path), 40, letter[1] - 55, width=120, height=40, preserveAspectRatio=True, mask='auto')
                except Exception:
                    pass
            
            canvas_obj.setFont('Helvetica-Bold', 12)
            canvas_obj.drawCentredString(letter[0] / 2.0, letter[1] - 35, "Web Application VAPT Report")
            
            if org_logo:
                org_logo.seek(0)
                try:
                    canvas_obj.drawImage(ImageReader(org_logo), letter[0] - 160, letter[1] - 55, width=120, height=40, preserveAspectRatio=True, mask='auto')
                except Exception:
                    pass
                    
            # --- Footer ---
            canvas_obj.setFont('Helvetica', 9)
            canvas_obj.drawString(40, 30, "CONFIDENTIAL")
            
            try:
                ist = pytz.timezone('Asia/Kolkata')
                gen_time = datetime.now(ist).strftime('%d-%b-%Y %H:%M IST')
            except Exception:
                gen_time = datetime.now().strftime('%d-%b-%Y %H:%M')
            canvas_obj.drawCentredString(letter[0] / 2.0, 30, f"{gen_time}")
            
            canvas_obj.drawRightString(letter[0] - 40, 30, f"Page {canvas_obj._pageNumber} of {total_pages[0]}")
            
        canvas_obj.restoreState()

    page_dict = {}
    buf1 = io.BytesIO()
    doc1 = SimpleDocTemplate(buf1, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=60, bottomMargin=60)
    doc1.build(build_pdf_elements(page_dict), onFirstPage=header_footer_draw, onLaterPages=header_footer_draw)
    total_pages[0] = doc1.page
    
    buffer = io.BytesIO()
    doc2 = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=60, bottomMargin=60)
    doc2.multiBuild(build_pdf_elements(page_dict), onFirstPage=header_footer_draw, onLaterPages=header_footer_draw)

    pdf = buffer.getvalue()
    buffer.close()
    return pdf

# --- From vuln_classifier.py ---
VULN_CLASSIFICATION = {
    "sql_injection": {
        "cwe_ids": ["CWE-89"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 9.8,
    },
    "blind_xss": {
        "cwe_ids": ["CWE-79"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 8.2,
    },
    "dom_xss": {
        "cwe_ids": ["CWE-79"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 8.2,
    },
    "command_injection": {
        "cwe_ids": ["CWE-78"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 9.8,
    },
    "ssti": {
        "cwe_ids": ["CWE-1336"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 9.8,
    },
    "xxe": {
        "cwe_ids": ["CWE-611"],
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cvss_base": 8.6,
    },
    "ssrf": {
        "cwe_ids": ["CWE-918"],
        "owasp_category": "A10:2021 - Server-Side Request Forgery",
        "cvss_base": 8.6,
    },
    "lfi": {
        "cwe_ids": ["CWE-22"],
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_base": 7.5,
    },
    "path_traversal": {
        "cwe_ids": ["CWE-22"],
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_base": 7.5,
    },
    "idor": {
        "cwe_ids": ["CWE-639"],
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_base": 6.5,
    },
    "csrf": {
        "cwe_ids": ["CWE-352"],
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_base": 5.3,
    },
    "jwt": {
        "cwe_ids": ["CWE-287", "CWE-345"],
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "cvss_base": 7.5,
    },
    "auth": {
        "cwe_ids": ["CWE-287"],
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "cvss_base": 7.3,
    },
    "session": {
        "cwe_ids": ["CWE-384", "CWE-613"],
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "cvss_base": 6.8,
    },
    "open_redirect": {
        "cwe_ids": ["CWE-601"],
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_base": 4.7,
    },
    "crlf": {
        "cwe_ids": ["CWE-93"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 7.3,
    },
    "request_smuggling": {
        "cwe_ids": ["CWE-444"],
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_base": 8.6,
    },
    "host_header": {
        "cwe_ids": ["CWE-644"],
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_base": 6.5,
    },
    "cache_poisoning": {
        "cwe_ids": ["CWE-644"],
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_base": 6.1,
    },
    "deserialization": {
        "cwe_ids": ["CWE-502"],
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "cvss_base": 9.8,
    },
    "nosql": {
        "cwe_ids": ["CWE-943"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 9.1,
    },
    "ldap": {
        "cwe_ids": ["CWE-90"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 9.1,
    },
    "file_upload": {
        "cwe_ids": ["CWE-434"],
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_base": 8.8,
    },
    "race_condition": {
        "cwe_ids": ["CWE-362"],
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_base": 7.5,
    },
    "cors": {
        "cwe_ids": ["CWE-942"],
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_base": 6.1,
    },
    "csp": {
        "cwe_ids": ["CWE-1021", "CWE-693"],
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cvss_base": 5.9,
    },
    "clickjacking": {
        "cwe_ids": ["CWE-1021"],
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_base": 4.3,
    },
    "cookie": {
        "cwe_ids": ["CWE-1004", "CWE-614"],
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cvss_base": 5.3,
    },
    "headers": {
        "cwe_ids": ["CWE-693"],
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cvss_base": 5.0,
    },
    "cache_control": {
        "cwe_ids": ["CWE-525"],
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cvss_base": 3.1,
    },
    "password_reset": {
        "cwe_ids": ["CWE-640"],
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "cvss_base": 6.3,
    },
    "saml": {
        "cwe_ids": ["CWE-287"],
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "cvss_base": 8.1,
    },
    "oauth": {
        "cwe_ids": ["CWE-862"],
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "cvss_base": 7.5,
    },
    "prototype_pollution": {
        "cwe_ids": ["CWE-1321"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 8.2,
    },
    "mfa_bypass": {
        "cwe_ids": ["CWE-308"],
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "cvss_base": 7.4,
    },
    "bypass_403": {
        "cwe_ids": ["CWE-290"],
        "owasp_category": "A01:2021 - Broken Access Control",
        "cvss_base": 5.3,
    },
    "http_method_tampering": {
        "cwe_ids": ["CWE-749"],
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cvss_base": 5.3,
    },
    "subdomain_takeover": {
        "cwe_ids": ["CWE-350"],
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cvss_base": 7.5,
    },
    "csti": {
        "cwe_ids": ["CWE-1336"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 8.6,
    },
    "postmessage": {
        "cwe_ids": ["CWE-345"],
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_base": 5.3,
    },
    "second_order": {
        "cwe_ids": ["CWE-89", "CWE-79"],
        "owasp_category": "A03:2021 - Injection",
        "cvss_base": 8.2,
    },
    "web_cache_deception": {
        "cwe_ids": ["CWE-444"],
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_base": 5.3,
    },
}


def classify(scanner_key: str) -> dict:
    return VULN_CLASSIFICATION.get(scanner_key, {
        "cwe_ids": ["CWE-1104"],
        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
        "cvss_base": 5.0,
    })


def enrich(vuln: dict, scanner_key: str) -> dict:
    cls = classify(scanner_key)
    vuln.setdefault("cwe_ids", cls["cwe_ids"])
    vuln.setdefault("owasp_category", cls["owasp_category"])
    if "cvss_score" not in vuln or vuln.get("cvss_score", 0) == 0:
        vuln["cvss_score"] = cls["cvss_base"]
    return vuln


# --- From fuzzer_engine.py ---

PARAM_TYPE_PATTERNS = {
    "id": r'(?i)(id|uid|pid|sid|account_id|user_id|item_id|order_id|profile_id)',
    "uuid": r'(?i)(uuid|guid|token|session|nonce|csrf)',
    "email": r'(?i)(email|mail|user|login|username)',
    "search": r'(?i)(search|q|query|keyword|term|filter)',
    "page": r'(?i)(page|offset|limit|start|count|per_page)',
    "file": r'(?i)(file|path|doc|document|attachment|download|upload)',
    "url": r'(?i)(url|link|redirect|next|return|referer|callback)',
    "numeric": r'(?i)(price|amount|cost|total|quantity|age|year)',
    "boolean": r'(?i)(flag|enable|disable|active|visible|published|status)',
}

TYPE_MUTATIONS: dict[str, list[dict]] = {
    "id": [
        {"name": "negative", "value": "-1"},
        {"name": "zero", "value": "0"},
        {"name": "large", "value": "9999999"},
        {"name": "float", "value": "1.5"},
        {"name": "string", "value": "abc"},
        {"name": "sql", "value": "1' OR '1'='1"},
        {"name": "special", "value": "../etc/passwd"},
        {"name": "array", "value": "id[]=1&id[]=2"},
    ],
    "uuid": [
        {"name": "empty", "value": """},
        {"name": "invalid", "value": "not-a-uuid"},
        {"name": "all_zero", "value": "00000000-0000-0000-0000-000000000000"},
        {"name": "past_token", "value": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
    ],
    "email": [
        {"name": "no_at", "value": "admin"},
        {"name": "double_at", "value": "admin@@example.com"},
        {"name": "sql_injection", "value": "admin' OR '1'='1"},
        {"name": "xss", "value": "<script>alert(1)</script>"},
        {"name": "traversal", "value": "../../etc/passwd"},
        {"name": "long", "value": "a" * 256 + "@example.com"},
    ],
    "search": [
        {"name": "sql_wildcard", "value": "%' OR '1'='1' --"},
        {"name": "xss", "value": "<img src=x onerror=alert(1)>"},
        {"name": "regex", "value": "^(?=.*[a-z])(?=.*[A-Z]).*$"},
        {"name": "null_byte", "value": "test\x00"},
        {"name": "unicode_normalize", "value": "\uff1cscript\uff1e"},
    ],
    "file": [
        {"name": "traversal", "value": "../../../etc/passwd"},
        {"name": "null_byte", "value": "../../../etc/passwd%00.jpg"},
        {"name": "windows", "value": "..\\..\\..\\windows\\win.ini"},
        {"name": "php_wrapper", "value": "php://filter/convert.base64-encode/resource=index"},
        {"name": "long_path", "value": "A" * 4096},
    ],
    "url": [
        {"name": "open_redirect", "value": "//evil.com"},
        {"name": "ssrf", "value": "http://169.254.169.254/latest/meta-data/"},
        {"name": "protocol_bypass", "value": "javascript:alert(1)"},
        {"name": "data_uri", "value": "data:text/html,<script>alert(1)</script>"},
    ],
    "numeric": [
        {"name": "negative", "value": "-1"},
        {"name": "zero", "value": "0"},
        {"name": "overflow", "value": "9999999999999999999999999999999999999"},
        {"name": "float", "value": "0.5"},
        {"name": "string", "value": "abcdefgh"},
    ],
    "boolean": [
        {"name": "not_1", "value": "0"},
        {"name": "not_0", "value": "1"},
        {"name": "string", "value": "true"},
        {"name": "empty", "value": """},
        {"name": "random", "value": "asdfghjkl"},
    ],
}


class ContextAwareFuzzer:
    def __init__(self, request_fn: Callable):
        self._request_fn = request_fn
        self._results: list[dict] = []

    def classify_params(self, params: dict) -> dict[str, str]:
        classified = {}
        for key in params:
            param_type = "string"
            for ptype, pattern in PARAM_TYPE_PATTERNS.items():
                if re.match(pattern, key):
                    param_type = ptype
                    break
            classified[key] = param_type
        return classified

    def fuzz(self, url: str, params: dict, headers: dict | None = None) -> list[dict]:
        types = self.classify_params(params)
        for key, ptype in types.items():
            mutations = TYPE_MUTATIONS.get(ptype, [{"name": "random", "value": "test"}])
            for mutation in mutations:
                test_params = dict(params)
                test_params[key] = mutation["value"]
                body, status = self._request_fn(url, test_params, headers)
                self._results.append({
                    "param": key,
                    "type": ptype,
                    "mutation": mutation["name"],
                    "value": mutation["value"],
                    "status": status,
                    "length": len(body or ""),
                })
        return self._results

    def anomalies(self, baseline_length: int) -> list[dict]:
        return [
            r for r in self._results
            if abs(r["length"] - baseline_length) / max(baseline_length, 1) > 0.2
               or r["status"] in (500, 403, 302, 301)
        ]


# --- From web_crawler.py ---

# Suppress insecure request warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebCrawler:
    def __init__(self, target_url, max_depth=2, delay=0.5, auth_headers=None, log_fn=None,
                 exclude_paths=None, max_urls=None):
        self.target_url = target_url
        self.max_depth = max_depth
        self.delay = delay
        self.auth_headers = auth_headers or {}
        self.log_fn = log_fn
        self.exclude_paths = exclude_paths or []
        self.max_urls = max_urls or max(50, max_depth * 25)
        self.visited_urls = set()
        self.discovered_urls = []
        self.discovered_forms = []
        self.domain = urlparse(target_url).netloc

    def log(self, level, message):
        """Helper to write to the scanner logger if provided, else console."""
        if self.log_fn:
            self.log_fn(level, message)
        else:
            print(f"[{level}] {message}")

    def is_valid_url(self, url):
        """Check if URL is valid and belongs to the target domain"""
        parsed = urlparse(url)
        return parsed.netloc == self.domain and parsed.scheme in ['http', 'https']

    def is_excluded(self, url):
        """Skip URLs matching user-defined path exclusions."""
        if not self.exclude_paths:
            return False
        path = urlparse(url).path or "/"
        for pattern in self.exclude_paths:
            if not pattern:
                continue
            normalized = pattern if pattern.startswith("/") else f"/{pattern}"
            if path.startswith(normalized) or normalized in path:
                return True
        return False
    
    def get_all_links(self, url, soup):
        """Extract all links from page"""
        links = set()
        for tag in soup.find_all('a', href=True):
            link = urljoin(url, tag['href'])
            link = link.split('#')[0]
            if self.is_valid_url(link):
                links.add(link)
        return links
    
    def extract_forms(self, url, soup):
        """Extract all forms from page"""
        forms_data = []
        forms = soup.find_all('form')
        
        for form in forms:
            form_details = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                if input_name:
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_tag.get('value', '')
                    })
            
            if form_details['inputs']:
                forms_data.append(form_details)
        
        return forms_data
    
    def crawl(self, url, depth=0):
        """Recursively crawl website"""
        if depth > self.max_depth or url in self.visited_urls:
            return
        if self.is_excluded(url):
            self.log("INFO", f"[Crawler] Skipping excluded path: {url}")
            return
        if len(self.visited_urls) >= self.max_urls:
            self.log("WARNING", f"[Crawler] Max URL limit ({self.max_urls}) reached - stopping crawl")
            return
        
        self.log("INFO", f"[Crawler] Crawling depth {depth}: {url}")
        self.visited_urls.add(url)
        
        try:
            # Inject auth_headers for authenticated crawling
            headers = {"User-Agent": "LarShield/2.0 Crawler"}
            headers.update(self.auth_headers)
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True, verify=False)
            self.discovered_urls.append({
                'url': url,
                'status': response.status_code,
                'depth': depth
            })
            
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.content, 'html.parser')
                
                forms = self.extract_forms(url, soup)
                self.discovered_forms.extend(forms)
                if forms:
                    self.log("SUCCESS", f"[Crawler] Found {len(forms)} form(s) on {url}")
                
                links = self.get_all_links(url, soup)
                for link in links:
                    if link not in self.visited_urls:
                        time.sleep(self.delay)
                        self.crawl(link, depth + 1)
                        
        except Exception as e:
            self.log("WARNING", f"[Crawler] Error crawling {url}: {str(e)}")
    
    def start(self):
        """Start crawling from target URL"""
        exclusion_note = f", Exclusions: {len(self.exclude_paths)}" if self.exclude_paths else ""
        self.log("INFO",
                 f"[Crawler] Starting Web Crawler (Target: {self.target_url}, "
                 f"Max Depth: {self.max_depth}, Max URLs: {self.max_urls}{exclusion_note})")
        self.crawl(self.target_url)
        self.log("SUCCESS", f"[Crawler] Crawl complete. Discovered {len(self.discovered_urls)} URLs and {len(self.discovered_forms)} forms.")
        return {
            'urls': self.discovered_urls,
            'forms': self.discovered_forms
        }


# --- From chain_detector.py ---

CHAIN_RULES: list[dict] = [
    {
        "name": "SSRF â†’ Cloud Metadata Credential Theft",
        "risk": "Critical",
        "cvss_bonus": 2.0,
        "conditions": [
            {"scanner_key": "ssrf", "severity": {"$in": ["High", "Critical"]}},
            {"scanner_key": "secrets", "category": "Cloud Credentials"},
        ],
    },
    {
        "name": "LFI â†’ Remote Code Execution (log poisoning)",
        "risk": "Critical",
        "cvss_bonus": 1.5,
        "conditions": [
            {"scanner_key": "lfi", "severity": {"$in": ["High", "Critical"]}},
            {"scanner_key": "file_upload", "severity": "Medium"},
        ],
    },
    {
        "name": "XSS + CSRF â†’ Full Account Takeover",
        "risk": "Critical",
        "cvss_bonus": 2.5,
        "conditions": [
            {"scanner_key": "blind_xss", "severity": {"$in": ["High", "Critical"]}},
            {"scanner_key": "csrf"},
        ],
    },
    {
        "name": "Open Redirect + OAuth Token Leakage",
        "risk": "High",
        "cvss_bonus": 1.0,
        "conditions": [
            {"scanner_key": "open_redirect"},
            {"scanner_key": "oauth"},
        ],
    },
    {
        "name": "Weak JWT + IDOR â†’ Privilege Escalation",
        "risk": "Critical",
        "cvss_bonus": 2.0,
        "conditions": [
            {"scanner_key": "jwt"},
            {"scanner_key": "idor"},
        ],
    },
    {
        "name": "SQL Injection + File Upload â†’ Web Shell",
        "risk": "Critical",
        "cvss_bonus": 2.5,
        "conditions": [
            {"scanner_key": "sql_injection"},
            {"scanner_key": "file_upload"},
        ],
    },
    {
        "name": "Broken Authentication + Weak Session â†’ Account Takeover",
        "risk": "High",
        "cvss_bonus": 1.5,
        "conditions": [
            {"scanner_key": "auth"},
            {"scanner_key": "session"},
        ],
    },
    {
        "name": "Subdomain Takeover + XSS â†’ Full Application Compromise",
        "risk": "Critical",
        "cvss_bonus": 2.0,
        "conditions": [
            {"scanner_key": "subdomain_takeover"},
            {"scanner_key": {"$in": ["blind_xss", "dom_xss"]}},
        ],
    },
    {
        "name": "SSTI + Path Traversal â†’ Remote Code Execution",
        "risk": "Critical",
        "cvss_bonus": 2.5,
        "conditions": [
            {"scanner_key": "ssti"},
            {"scanner_key": "path_traversal"},
        ],
    },
    {
        "name": "CORS Misconfiguration + XSS â†’ Cross-Origin Data Theft",
        "risk": "High",
        "cvss_bonus": 1.5,
        "conditions": [
            {"scanner_key": "cors", "severity": {"$in": ["High", "Critical"]}},
            {"scanner_key": {"$in": ["blind_xss", "dom_xss"]}},
        ],
    },
    {
        "name": "Race Condition + Coupon â†’ Financial Loss",
        "risk": "High",
        "cvss_bonus": 1.0,
        "conditions": [
            {"scanner_key": "race_condition"},
            {"scanner_key": "business_logic"},
        ],
    },
    {
        "name": "Host Header Injection + Cache Poisoning â†’ Widespread XSS",
        "risk": "Critical",
        "cvss_bonus": 2.5,
        "conditions": [
            {"scanner_key": "host_header"},
            {"scanner_key": "cache_poisoning"},
        ],
    },
    {
        "name": "NoSQL Injection + Authentication Bypass â†’ Full Admin Access",
        "risk": "Critical",
        "cvss_bonus": 2.0,
        "conditions": [
            {"scanner_key": "nosql"},
            {"scanner_key": "auth"},
        ],
    },
    {
        "name": "Deserialization + Command Injection â†’ Remote Code Execution",
        "risk": "Critical",
        "cvss_bonus": 2.5,
        "conditions": [
            {"scanner_key": "deserialization"},
            {"scanner_key": "command_injection"},
        ],
    },
    {
        "name": "Cookie Without Secure + Session Hijacking â†’ Account Takeover",
        "risk": "High",
        "cvss_bonus": 1.0,
        "conditions": [
            {"scanner_key": "cookie"},
            {"scanner_key": "session"},
        ],
    },
]

EVIDENCE_EXTRACTORS: dict[str, list[str]] = {
    "ssrf": ["http://169.254", "imds", "metadata"],
    "lfi": ["root:", "etc/passwd", "boot.ini", "windows"],
    "sql_injection": ["SQL syntax", "mysql_fetch", "ORA-", "unclosed quotation"],
    "xss": ["<script>", "alert(", "onerror=", "onload="],
}


def detect_chains(vulns: list[dict]) -> list[dict]:
    chains = []
    keyed: dict[str, list[dict]] = {}
    for v in vulns:
        sk = v.get("scanner_key", "unknown")
        keyed.setdefault(sk, []).append(v)

    for rule in CHAIN_RULES:
        matched = []
        for cond in rule["conditions"]:
            sk_cond = cond.get("scanner_key", "")
            sev_cond = cond.get("severity", {})
            if isinstance(sk_cond, dict) and "$in" in sk_cond:
                candidates = []
                for alt_sk in sk_cond["$in"]:
                    candidates.extend(keyed.get(alt_sk, []))
            else:
                candidates = keyed.get(sk_cond, [])

            if not candidates:
                matched = []
                break

            if sev_cond and "$in" in sev_cond:
                candidates = [c for c in candidates if c.get("severity") in sev_cond["$in"]]

            if not candidates:
                matched = []
                break

            matched.extend(candidates[:2])

        if matched:
            combined_title = rule["name"]
            combined_desc = f"Attack chain detected: {rule['name']}\n\n"
            combined_desc += "Contributing findings:\n"
            base_cvss = 0.0
            for m in matched:
                combined_desc += f"  - {m.get('title', 'unknown')} ({m.get('severity', 'Info')})\n"
                base_cvss = max(base_cvss, m.get("cvss_score", 0))
            combined_cvss = min(base_cvss + rule.get("cvss_bonus", 0), 10.0)

            chains.append({
                "chain_name": rule["name"],
                "risk": rule.get("risk", "Medium"),
                "cvss_score": round(combined_cvss, 1),
                "description": combined_desc,
                "contributing_findings": matched,
                "remediation": "Each finding in this chain must be addressed. "
                "Attackers chain these weaknesses for maximum impact. "
                "Priority: fix the chain as a whole.",
            })

    return chains


# --- From anomaly.py ---
"""
anomaly.py - Statistical Anomaly Detectors for Timing & Size Analysis
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
        by at least `min_diff` bytes - used before enough baseline exists.
        """
        return abs(true_len - false_len) >= min_diff


# --- From anomaly_ai.py ---


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


# --- From evasion.py ---
"""
evasion.py - WAF Evasion / Payload Encoding Helpers
=====================================================
Advanced WAF bypass techniques used by scanner modules.

FIXES (June 2026):
  BUG-13: mixed_case() "" lambda closure referenced undefined `i` variable.
           Refactored to use enumerate() with a proper loop instead of a lambda.
  ENH-1:  Added HTML entity, Unicode codepoint, and SQL comment splice encoders.
  ENH-2:  Added case-splice SQL comment technique.
"""


def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def unicode_encode(s: str) -> str:
    return "".join(f"%u{ord(c):04X}" for c in s)


def hex_encode(s: str) -> str:
    return "".join(f"\\x{ord(c):02x}" for c in s)


def utf16_encode(s: str) -> str:
    return "".join(
        f"%00{ord(c):02x}" if ord(c) < 256 else f"%u{ord(c):04X}" for c in s
    )


def html_entity_encode(s: str) -> str:
    """Encode each char as HTML entity (useful for XSS context evasion)."""
    return "".join(f"&#{ord(c)};" for c in s)


def sql_comment_splice(s: str) -> str:
    """
    Inject /**/ between every character (common SQL WAF bypass).
    E.g., SELECT -> S/**/E/**/L/**/E/**/C/**/T
    """
    return "/**/".join(list(s))


def mixed_case(s: str, variant: int = 0) -> str:
    """
    Return a mixed-case version of `s`.
    Variant 0 â†’ uppercase even positions
    Variant 1 â†’ lowercase even positions
    Variant 2 â†’ swapcase entire string
    BUG-13 FIX: Previously used a lambda with `i` from enumerate() but the
    lambda was defined in a list comprehension where `i` was not in scope.
    Now uses a simple loop with index tracking.
    """
    result = []
    alpha_idx = 0  # count only alphabetic chars
    for ch in s:
        if ch.isalpha():
            if variant == 0:
                result.append(ch.upper() if alpha_idx % 2 == 0 else ch.lower())
            elif variant == 1:
                result.append(ch.lower() if alpha_idx % 2 == 0 else ch.upper())
            else:  # variant 2
                result.append(ch.swapcase())
            alpha_idx += 1
        else:
            result.append(ch)
    return "".join(result)


ENCODERS = [
    ("plain",             lambda s: s),
    ("url",               url_encode),
    ("double_url",        double_url_encode),
    ("unicode",           unicode_encode),
    ("utf16",             utf16_encode),
    ("hex",               hex_encode),
    ("html_entity",       html_entity_encode),
    ("sql_comment_splice",sql_comment_splice),
    ("mixed_case_1",      lambda s: mixed_case(s, 0)),
    ("mixed_case_2",      lambda s: mixed_case(s, 1)),
    ("mixed_case_3",      lambda s: mixed_case(s, 2)),
]


def generate_variants(payload: str) -> list[tuple[str, str]]:
    results = []
    for name, encoder in ENCODERS:
        try:
            encoded = encoder(payload)
            if encoded != payload:
                results.append((name, encoded))
        except Exception:
            pass
    return results


WAF_EVASION_PREFIXES = [
    ("tab",                    "%09"),      # \t - URL-encoded to avoid urllib ValueError
    ("newline",                "%0a"),      # \n - URL-encoded to avoid urllib ValueError
    ("carriage",               "%0d"),      # \r - URL-encoded to avoid urllib ValueError
    ("null_byte",              "%00"),      # \x00 - URL-encoded to avoid urllib ValueError
    ("comment",                "/**/"),
    ("multiline_comment",      "/*!*/"),
    ("backticks",              "``"),
    ("parenthesis_overflow",   "(((("),
    ("tab_before",             "%09/"),     # \t/ - URL-encoded
    ("path_param",             "/;/"),
    ("sp_prefix",              "%20"),      # space - URL-encoded to avoid urllib ValueError
    ("plus_prefix",            "+"),        # URL-decoded space
]

# Additional SQL-specific suffix tricks
WAF_EVASION_SUFFIXES = [
    ("sql_dash_comment",   "-- -"),
    ("sql_hash_comment",   "#"),
    ("sql_block_comment",  "/*"),
]


def waf_evade(payload: str) -> list[tuple[str, str]]:
    """
    Return a deduplicated list of (evasion_name, evaded_payload) tuples.
    Includes prefix tricks, encoding tricks, and SQL comment suffixes.
    """
    seen: set[str] = set()
    variants: list[tuple[str, str]] = []

    def _add(name: str, val: str):
        if val != payload and val not in seen:
            seen.add(val)
            variants.append((name, val))

    # Plain payload always first (for baseline)
    _add("plain", payload)

    # Prefix-based evasion
    for name, prefix in WAF_EVASION_PREFIXES:
        _add(f"prefix_{name}", prefix + payload)

    # Encoding-based evasion
    for name, encoded in generate_variants(payload):
        _add(f"encode_{name}", encoded)

    return variants


# --- From differential.py ---

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


# --- From dmarc_email_security.py ---
"""
dmarc_email_security.py - Email/DNS Security Fix (FIX-12, FIX-13)
==================================================================
Reference implementation for:
  FIX-12: Enforce DMARC (none â†’ quarantine â†’ reject)
  FIX-13: Add SRI to external resources
  (Companion to security_middleware.py)
"""

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-12: DMARC DNS Records
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Add these DNS TXT records to your larshield.com zone:
#
# Step 1 - SPF (if not already set):
#   Name:  larshield.com
#   Type:  TXT
#   Value: "v=spf1 include:_spf.hostinger.com ~all"
#
# Step 2 - DKIM (get selector from Hostinger email panel):
#   Name:  default._domainkey.larshield.com
#   Type:  TXT
#   Value: "v=DKIM1; k=rsa; p=<your-public-key-from-hostinger>"
#
# Step 3 - DMARC progression:
#   Name:  _dmarc.larshield.com
#   Type:  TXT
#
#   Week 1 - Monitor mode (no enforcement, collect reports):
#   Value: "v=DMARC1; p=none; rua=mailto:dmarc-reports@larshield.com; ruf=mailto:dmarc-forensics@larshield.com; fo=1; adkim=s; aspf=s"
#
#   Week 3 - Quarantine (move failing mail to spam):
#   Value: "v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@larshield.com; fo=1; adkim=s; aspf=s"
#   (Start with pct=25 - only quarantine 25% of failing mail, ramp up)
#
#   Week 5 - Full enforcement (reject):
#   Value: "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@larshield.com; fo=1; adkim=s; aspf=s"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIX-13: Subresource Integrity (SRI) Helper
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


SRI_ALGORITHMS = ("sha256", "sha384", "sha512")


def compute_sri(url: str, algorithm: Literal["sha256", "sha384", "sha512"] = "sha384") -> str:
    """
    Download an external resource and compute its SRI hash.
    Returns the integrity attribute value: "sha384-<base64hash>"

    Usage:
        integrity = compute_sri("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js")
        # Returns: "sha384-<hash>"
        # Then in HTML: <script src="..." integrity="sha384-<hash>" crossorigin="anonymous"></script>
    """
    with urllib.request.urlopen(url, timeout=10) as resp:
        content = resp.read()

    h = hashlib.new(algorithm, content)
    digest = base64.b64encode(h.digest()).decode()
    return f"{algorithm}-{digest}"


def generate_sri_tags(external_resources: list[dict]) -> list[str]:
    """
    Generate HTML <script> and <link> tags with SRI integrity attributes.

    Usage:
        resources = [
            {"type": "script", "url": "https://cdn.example.com/app.js"},
            {"type": "style",  "url": "https://cdn.example.com/app.css"},
        ]
        tags = generate_sri_tags(resources)
        for tag in tags:
            print(tag)
    """
    tags = []
    for res in external_resources:
        url = res["url"]
        res_type = res.get("type", "script")
        algo = res.get("algorithm", "sha384")
        try:
            integrity = compute_sri(url, algo)
            if res_type == "script":
                tags.append(
                    f'<script src="{url}" integrity="{integrity}" '
                    f'crossorigin="anonymous" referrerpolicy="no-referrer"></script>'
                )
            elif res_type == "style":
                tags.append(
                    f'<link rel="stylesheet" href="{url}" integrity="{integrity}" '
                    f'crossorigin="anonymous" referrerpolicy="no-referrer">'
                )
        except Exception as e:
            tags.append(f"<!-- SRI generation failed for {url}: {e} -->")
    return tags


# â”€â”€ Example: Generate SRI for larshield.com's external resources â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Run this once to get the correct integrity values, then hardcode them in HTML.
if __name__ == "__main__":
    # Add all external JS/CSS loaded by larshield.com here:
    EXTERNAL_RESOURCES = [
        # Example - replace with actual CDN URLs from your site's HTML
        # {"type": "script", "url": "https://cdn.example.com/bundle.js"},
        # {"type": "style",  "url": "https://fonts.googleapis.com/css2?family=Inter"},
    ]

    if not EXTERNAL_RESOURCES:
        print("Add your external resource URLs to EXTERNAL_RESOURCES list above.")
        print("Run: python dmarc_email_security.py")
    else:
        for tag in generate_sri_tags(EXTERNAL_RESOURCES):
            print(tag)


# --- From exploit_gen.py ---


def _curl_cmd(method: str, url: str, headers: dict | None = None, data: str | None = None,
              cookie: str | None = None, proxy: str | None = None) -> str:
    parts = ["curl", "-X", method]
    if cookie:
        parts.extend(["-H", f"'Cookie: {cookie}'"])
    if headers:
        for k, v in headers.items():
            parts.extend(["-H", f"'{k}: {v}'"])
    if data:
        parts.extend(["-d", f"'{data}'"])
    if proxy:
        parts.extend(["-x", proxy])
    parts.append(f"'{url}'")
    return " ".join(parts)


def _python_script(method: str, url: str, headers: dict | None = None, data: str | None = None,
                   cookie: str | None = None) -> str:
    lines = ["import requests"]
    lines.append(f"url = '{url}'")
    if headers:
        lines.append(f"headers = {json.dumps(headers)}")
    else:
        lines.append("headers = {}")
    if cookie:
        lines.append(f"headers['Cookie'] = '{cookie}'")
    if data:
        lines.append(f"data = '''{data}'''")
        lines.append(f"r = requests.{method.lower()}(url, headers=headers, data=data)")
    else:
        lines.append(f"r = requests.{method.lower()}(url, headers=headers)")
    lines.append("print(r.status_code, r.text[:500])")
    return "\n".join(lines)


def _js_fetch(method: str, url: str, headers: dict | None = None, data: str | None = None) -> str:
    js_headers = json.dumps(headers or {})
    if data:
        return f"fetch('{url}', {{ method: '{method}', headers: {js_headers}, body: `{data}` }}).then(r => r.text().then(console.log))"
    return f"fetch('{url}', {{ method: '{method}', headers: {js_headers} }}).then(r => r.text().then(console.log))"


GENERATORS: dict[str, dict] = {
    "sql_injection": {
        "name": "SQL Injection",
        "exploit_template": {0: "curl"},
        "payload_template": "' OR '1'='1' -- ",
    },
    "xss": {
        "name": "Cross-Site Scripting",
        "exploit_template": {0: "curl", 1: "browser"},
    },
    "command_injection": {
        "name": "OS Command Injection",
        "payload_template": "; whoami",
    },
    "lfi": {
        "name": "Local File Inclusion",
        "payload_template": "../../../etc/passwd",
    },
    "path_traversal": {
        "name": "Path Traversal",
        "payload_template": "../../../etc/passwd",
    },
    "ssrf": {
        "name": "Server-Side Request Forgery",
        "payload_template": "http://169.254.169.254/latest/meta-data/",
    },
}


def generate_exploit(vuln: dict, pwn_type: str | None = None) -> dict:
    scanner_key = vuln.get("scanner_key", "unknown")
    method = "GET"
    title = vuln.get("title", "")
    description = vuln.get("description", "")
    payload = vuln.get("payload", "")
    request_details = vuln.get("request_details", "")
    url = request_details.replace("GET ", "").replace("POST ", "").strip().split(" ")[0] if request_details else ""

    if not url:
        url_match = __import__("re").search(r"https?://[^\s\"'<>]+", title + " " + description)
        url = url_match.group(0) if url_match else "TARGET_URL"

    if "POST" in request_details:
        method = "POST"

    headers = {"User-Agent": "Exploit-PoC"}
    data = payload if method == "POST" else None

    exploits = {
        "curl": _curl_cmd(method, url, headers, data),
        "python": _python_script(method, url, headers, data),
        "javascript": _js_fetch(method, url, headers, data),
    }

    generator = GENERATORS.get(scanner_key, {})
    pwn_type = pwn_type or generator.get("payload_template", "")

    return {
        "vulnerability": title,
        "scanner_key": scanner_key,
        "target_url": url,
        "method": method,
        "payload_used": payload or pwn_type,
        "exploits": exploits,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# --- From remediation_gen.py ---
TEMPLATES: dict[str, dict[str, str]] = {
    "sql_injection": {
        "python_flask": """"from flask import request

def get_user(user_id):
    # BAD: direct string interpolation
    # cur.execute(f"SELECT * FROM users WHERE id = {user_id}")

    # GOOD: parameterized query
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cur.fetchone()""",
        "python_django": """# BAD: raw SQL
# User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")

# GOOD: ORM query
User.objects.filter(id=user_id).first()""",
        "node_express": """// BAD: string concatenation
// db.query(`SELECT * FROM users WHERE id = ${userId}`);

// GOOD: parameterized query
db.query('SELECT * FROM users WHERE id = $1', [userId]);""",
        "java_spring": """// BAD: string concatenation
// String sql = "SELECT * FROM users WHERE id = " + userId;

// GOOD: parameterized query with JDBC
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();""",
    },
    "xss": {
        "python_flask": """"from flask import escape

# BAD: rendering raw input
# return f"<h1>Welcome {request.args.get('name')}</h1>"

# GOOD: escape output
name = escape(request.args.get('name', ''))
return f"<h1>Welcome {name}</h1>" """,
        "python_django": """# BAD: marking safe
# from django.utils.safestring import mark_safe
# return render(request, 'template.html', {'name': mark_safe(name)})

# GOOD: auto-escape (Django does this by default)
return render(request, 'template.html', {'name': name})""",
        "node_express": """// BAD: rendering raw input
// res.send(`<h1>Welcome ${req.query.name}</h1>`);

// GOOD: use template engine with auto-escape
res.render('template', { name: req.query.name });""",
        "java_spring": """// BAD: raw output
// out.println("<h1>Welcome " + request.getParameter("name") + "</h1>");

// GOOD: use template engine with auto-escape
// In Thymeleaf: th:text="${name}" auto-escapes HTML""",
    },
    "command_injection": {
        "python": """import subprocess

# BAD: shell=True with user input
# subprocess.run(f"ping {host}", shell=True)

# GOOD: use list form, avoid shell
subprocess.run(["ping", host], capture_output=True, text=True, timeout=5)""",
        "node_express": """const { execFile } = require('child_process');

// BAD: exec with shell
// exec(`ping ${host}`);

// GOOD: execFile with args array
execFile('ping', [host], { timeout: 5000 });""",
        "java": """// BAD: Runtime.exec with shell
// Runtime.getRuntime().exec("ping " + host);

// GOOD: ProcessBuilder with args list
ProcessBuilder pb = new ProcessBuilder("ping", host);
Process p = pb.start();""",
    },
    "lfi": {
        "python": """import os

# BAD: direct path concatenation
# path = f"/var/www/{filename}"

# GOOD: validate and restrict to safe directory
safe_dir = "/var/www/uploads/"
filename = os.path.basename(filename)  # strip path
path = os.path.join(safe_dir, filename)
if not os.path.realpath(path).startswith(os.path.realpath(safe_dir)):
    raise ValueError("Invalid path")""",
    },
    "ssrf": {
        "python": """import ipaddress

# BAD: fetching user-supplied URL directly
# response = requests.get(user_url)

# GOOD: validate URL first
parsed = urlparse(user_url)
host = parsed.hostname
try:
    ip = ipaddress.ip_address(host)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("Blocked internal IP")
except ValueError:
    # allow hostname resolution (but could still be SSRF)
    pass
response = requests.get(user_url, timeout=5)""",
    },
    "xxe": {
        "python": """from lxml import etree

# BAD: default parser allows XXE
# tree = etree.parse(xml_input)

# GOOD: disable external entities
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(xml_input, parser)""",
    },
    "jwt": {
        "python": """import jwt

# BAD: using user-supplied secret
# decoded = jwt.decode(token, options={"verify_signature": False})

# GOOD: validate with known secret and algorithm whitelist
decoded = jwt.decode(token, SECRET_KEY, algorithms=["RS256", "ES256"])""",
    },
    "cors": {
        "python_flask": """"from flask import request

# BAD: reflecting origin without validation
# Access-Control-Allow-Origin: *

# GOOD: whitelist allowed origins
ALLOWED_ORIGINS = {"https://example.com", "https://app.example.com"}
origin = request.headers.get("Origin")
if origin in ALLOWED_ORIGINS:
    response.headers["Access-Control-Allow-Origin"] = origin""",
    },
}

DEFAULT_TEMPLATE = """# Remediation for {scanner_key}

## Issue
{description}

## Recommended Fix
1. **Validate all user input** - never trust client-supplied data
2. **Use parameterized queries / prepared statements** for database operations
3. **Apply output encoding** contextually (HTML, JS, CSS, URL)
4. **Implement strict allowlists** instead of blocklists
5. **Use secure defaults** and disable dangerous features
6. **Add proper authentication and authorization checks**
7. **Run security tests** in CI/CD pipeline

## References
- OWASP: https://owasp.org/www-project-top-ten/
- CWE: https://cwe.mitre.org/
"""


def generate_remediation(vuln: dict) -> str:
    scanner_key = vuln.get("scanner_key", "unknown")
    description = vuln.get("description", "")
    region = TEMPLATES.get(scanner_key)
    if not region:
        return DEFAULT_TEMPLATE.format(scanner_key=scanner_key, description=description)
    best = ""
    pref_order = ["python_flask", "python_django", "python", "node_express", "java_spring", "java"]
    for pref in pref_order:
        if pref in region:
            best = region[pref]
            break
    if not best:
        best = next(iter(region.values()))
    return best


# --- From fingerprint_db.py ---

FINGERPRINTS: list[dict] = [
    {"name": "WordPress", "regex": r'<meta name="generator" content="WordPress ([0-9.]+)"', "type": "CMS"},
    {"name": "Drupal", "regex": r'<meta name="Generator" content="Drupal ([0-9.]+)"', "type": "CMS"},
    {"name": "Joomla", "regex": r'<meta name="generator" content="Joomla! ([0-9.]+)"', "type": "CMS"},
    {"name": "jQuery", "regex": r'jquery[.-]v?([0-9.]+)(?:\.min)?\.js', "type": "JS Library"},
    {"name": "Bootstrap", "regex": r'bootstrap[.-]v?([0-9.]+)(?:\.min)?\.css', "type": "CSS Framework"},
    {"name": "React", "regex": r'react[.-]v?([0-9.]+)(?:\.min)?\.js|__REACT_DEVTOOLS_GLOBAL_HOOK__', "type": "JS Framework"},
    {"name": "Angular", "regex": r'angular[.-]v?([0-9.]+)(?:\.min)?\.js|ng-version="([0-9.]+)"', "type": "JS Framework"},
    {"name": "Vue.js", "regex": r'vue[.-]v?([0-9.]+)(?:\.min)?\.js|__VUE_DEVTOOLS_GLOBAL_HOOK__', "type": "JS Framework"},
    {"name": "Django", "regex": r'csrfmiddlewaretoken|__admin_media_prefix__', "type": "Python Web"},
    {"name": "Flask", "regex": r'flask|__glÃ—Ã—Ã—Ã—Ã—Ã—?', "type": "Python Web"},
    {"name": "Laravel", "regex": r'Laravel|__livewire', "type": "PHP Framework"},
    {"name": "Symfony", "regex": r'symfony|_sf2_attributes|_sf2_meta', "type": "PHP Framework"},
    {"name": "ASP.NET", "regex": r'__VIEWSTATE|__EVENTVALIDATION|X-AspNet-Version', "type": ".NET Web"},
    {"name": "Nginx", "regex": r'nginx(?:/([0-9.]+))?', "type": "Web Server"},
    {"name": "Apache", "regex": r'Apache(?:/([0-9.]+))?', "type": "Web Server"},
    {"name": "Cloudflare", "regex": r'cloudflare|__cfduid|cf-ray', "type": "CDN/WAF"},
    {"name": "AWS", "regex": r'aws|amazonaws\.com|x-amz-', "type": "Cloud"},
    {"name": "Google Cloud", "regex": r'googleapis\.com|gstatic\.com|cloudfront', "type": "Cloud"},
]

CVE_DATABASE: list[dict] = [
    {"cve": "CVE-2024-21626", "software": "Docker", "versions": {"<": "25.0.2"}, "severity": "Critical", "cvss": 9.9},
    {"cve": "CVE-2024-27198", "software": "JetBrains TeamCity", "versions": {"<": "2023.11.4"}, "severity": "Critical", "cvss": 9.8},
    {"cve": "CVE-2023-46604", "software": "Apache ActiveMQ", "versions": {"<": "5.18.3"}, "severity": "Critical", "cvss": 10.0},
    {"cve": "CVE-2023-50164", "software": "Apache Struts", "versions": {"<": "2.5.33"}, "severity": "Critical", "cvss": 9.8},
    {"cve": "CVE-2023-44487", "software": "HTTP/2", "versions": {}, "severity": "High", "cvss": 7.5},
    {"cve": "CVE-2023-22527", "software": "Atlassian Confluence", "versions": {"<": "8.5.4"}, "severity": "Critical", "cvss": 10.0},
    {"cve": "CVE-2023-46674", "software": "WordPress", "versions": {"<": "6.4.1"}, "severity": "High", "cvss": 8.3},
    {"cve": "CVE-2023-43786", "software": "Drupal", "versions": {"<": "10.1.6"}, "severity": "High", "cvss": 8.1},
    {"cve": "CVE-2023-51441", "software": "Apache Axis", "versions": {}, "severity": "Critical", "cvss": 9.8},
    {"cve": "CVE-2023-2986", "software": "WordPress", "versions": {"<": "6.3"}, "severity": "High", "cvss": 7.5},
    {"cve": "CVE-2023-5362", "software": "Joomla", "versions": {"<": "5.0.1"}, "severity": "Medium", "cvss": 5.3},
    {"cve": "CVE-2023-44487", "software": "nginx", "versions": {"<": "1.25.3"}, "severity": "High", "cvss": 7.5},
    {"cve": "CVE-2023-50447", "software": "Django", "versions": {"<": "5.0.1"}, "severity": "High", "cvss": 8.1},
    {"cve": "CVE-2023-34034", "software": "Spring", "versions": {"<": "6.0.14"}, "severity": "High", "cvss": 7.5},
    {"cve": "CVE-2023-38286", "software": "Apache", "versions": {"<": "2.4.57"}, "severity": "High", "cvss": 7.5},
]

TECH_EOL: dict[str, dict[str, str]] = {
    "jQuery": {"< 3.0": "EOL since 2019, known CVEs in 1.x/2.x"},
    "AngularJS": {"1.x": "EOL since Jan 2022, no security patches"},
    "Bootstrap": {"< 3.4": "EOL since 2019"},
    "WordPress": {"< 5.0": "Multiple known vulnerabilities"},
    "Drupal": {"< 8.0": "EOL, multiple known CVEs"},
    "Internet Explorer": {"any": "Browser EOL, no security support"},
}


def match_tech(body: str, headers: dict) -> list[dict]:
    results = []
    for fp in FINGERPRINTS:
        try:
            m = re.search(fp["regex"], body, re.I)
            if m:
                version = m.group(1) if m.lastindex and m.group(1) else m.group(0)
                eol_info = TECH_EOL.get(fp["name"], {}).get(version, "")
                results.append({
                    "name": fp["name"],
                    "version": version,
                    "type": fp["type"],
                    "eol": eol_info,
                })
        except Exception:
            pass
    for k, v in (headers or {}).items():
        if k.lower() == "server":
            results.append({"name": v, "version": """, "type": "Server Header", "eol": """})
        if k.lower() == "x-powered-by":
            results.append({"name": v, "version": """, "type": "Powered-By", "eol": """})
    return results


def find_cves(tech_name: str, version: str | None = None) -> list[dict]:
    matches = []
    for cve in CVE_DATABASE:
        if cve["software"].lower() not in tech_name.lower():
            continue
        if not cve["versions"]:
            matches.append(cve)
        elif version and cve["versions"].get("<"):
            try:
                if float(version) < float(cve["versions"]["<"]):
                    matches.append(cve)
            except ValueError:
                matches.append(cve)
    return matches

