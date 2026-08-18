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
import re, time, ipaddress, os, hashlib, threading
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


# --- From models.py ---

class Organization(db.Model):
    __tablename__ = 'organizations'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    subscription_tier = db.Column(db.String(50), nullable=False, default='free')
    status = db.Column(db.String(50), default='active')
    api_key = db.Column(db.String(100), unique=True, nullable=True)
    webhook_url = db.Column(db.String(500), nullable=True)
    report_logo_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    users = db.relationship('User', backref='organization', lazy=True)
    scans = db.relationship('Scan', backref='organization', lazy=True, cascade="all, delete-orphan")


class Role(db.Model):
    __tablename__ = 'roles'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(50), unique=True, nullable=False)

class User(db.Model):
    __tablename__ = 'users'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(50), nullable=False, default='org_admin') # super_admin, support_engineer, org_admin, soc_analyst, executive, read_only
    org_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=True)
    
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    scans = db.relationship('Scan', backref='user', lazy=True, cascade="all, delete-orphan")
    alert_settings = db.relationship('AlertSettings', backref='user', uselist=False, lazy=True, cascade="all, delete-orphan")
    
    @property
    def subscription_tier(self):
        if self.organization:
            return self.organization.subscription_tier
        return 'free'

    @subscription_tier.setter
    def subscription_tier(self, value):
        if self.organization:
            self.organization.subscription_tier = value
    
    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        
    def check_password(self, password):
        if not self.password_hash or not password:
            return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except (ValueError, TypeError, AttributeError):
            return False

class SubscriptionTier(db.Model):
    __tablename__ = 'subscription_tiers'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    id = db.Column(db.String(50), primary_key=True) 
    name = db.Column(db.String(100), nullable=False)
    monthly_price = db.Column(db.Integer, nullable=False, default=0) 
    yearly_price = db.Column(db.Integer, nullable=False, default=0)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    admin_id = db.Column(db.String(36), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    target_id = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    __tablename__ = 'payments'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = db.Column(db.String(36), db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    razorpay_payment_id = db.Column(db.String(100), unique=True, nullable=True)
    razorpay_order_id = db.Column(db.String(100), nullable=True)
    stripe_session_id = db.Column(db.String(100), unique=True, nullable=True)
    stripe_payment_id = db.Column(db.String(100), unique=True, nullable=True)
    tier_id = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(10), default='USD')
    status = db.Column(db.String(50), default='successful')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Scan(db.Model):
    __tablename__ = 'scans'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False, default='Full') # Full, Port, SSL, OWASP
    status = db.Column(db.String(50), nullable=False, default='queued') # queued, scanning, completed, failed
    security_score = db.Column(db.Integer, nullable=True) # 0 to 100
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    auth_headers = db.Column(db.JSON, nullable=True) # For authenticated scanning
    scan_options = db.Column(db.JSON, nullable=True) # crawl_depth, exclude_paths, enable_red_team
    ssl_info = db.Column(db.JSON, nullable=True) # Cached SSL certificate info
    
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade="all, delete-orphan")

    def __init__(self, org_id, user_id, target_url, scan_type='Full', status='queued', security_score=None, started_at=None, completed_at=None, auth_headers=None, scan_options=None, id=None):
        if id: self.id = id
        self.org_id = org_id
        self.user_id = user_id
        self.target_url = target_url
        self.scan_type = scan_type
        self.status = status
        self.security_score = security_score
        self.auth_headers = auth_headers
        self.scan_options = scan_options
        if started_at: self.started_at = started_at
        if completed_at: self.completed_at = completed_at

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.String(36), db.ForeignKey('scans.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(50), nullable=False) # Critical, High, Medium, Low
    category = db.Column(db.String(100), nullable=False) # SSL/TLS, Port, Security Headers, Injection
    description = db.Column(db.Text, nullable=False)
    remediation = db.Column(db.Text, nullable=False)
    cvss_score = db.Column(db.Float, nullable=False)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    evidence = db.Column(db.Text, default="")
    payload = db.Column(db.Text, default="")
    request_details = db.Column(db.Text, default="")
    response_details = db.Column(db.Text, default="")
    is_false_positive = db.Column(db.Boolean, default=False)
    cwe_ids = db.Column(db.JSON, nullable=True)
    owasp_category = db.Column(db.String(100), nullable=True)
    exploit_poc = db.Column(db.JSON, nullable=True)
    remediation_code = db.Column(db.Text, nullable=True)

    def __init__(self, scan_id, title, severity, category, description, remediation, cvss_score, detected_at=None, id=None, evidence="", payload="", request_details="", response_details="", cwe_ids=None, owasp_category=None, exploit_poc=None, remediation_code=None):
        if id: self.id = id
        self.scan_id = scan_id
        self.title = title
        self.severity = severity
        self.category = category
        self.description = description
        self.remediation = remediation
        self.cvss_score = cvss_score
        if detected_at: self.detected_at = detected_at
        self.evidence = evidence
        self.payload = payload
        self.request_details = request_details
        self.response_details = response_details
        self.cwe_ids = cwe_ids
        self.owasp_category = owasp_category
        self.exploit_poc = exploit_poc
        self.remediation_code = remediation_code

class DemoBooking(db.Model):
    __tablename__ = 'demo_bookings'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), nullable=False)
    company_size = db.Column(db.String(100), nullable=False)
    meeting_date = db.Column(db.String(100), nullable=False)
    meeting_time = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, email, company_size, meeting_date, meeting_time, status='pending', id=None):
        if id: self.id = id
        self.email = email
        self.company_size = company_size
        self.meeting_date = meeting_date
        self.meeting_time = meeting_time
        self.status = status

class EmailLog(db.Model):
    __tablename__ = 'email_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    recipient = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='sent')
    error_message = db.Column(db.Text, nullable=True)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, recipient, subject, status='sent', error_message=None, id=None):
        if id: self.id = id
        self.recipient = recipient
        self.subject = subject
        self.status = status
        self.error_message = error_message

class ScheduledScan(db.Model):
    __tablename__ = 'scheduled_scans'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False, default='Full')
    frequency = db.Column(db.String(50), nullable=False, default='daily') # daily, weekly, monthly, once
    schedule_time = db.Column(db.String(5), nullable=True) # HH:MM format like "20:00"
    day_of_week = db.Column(db.String(20), nullable=True) # monday, tuesday, etc.
    day_of_month = db.Column(db.Integer, nullable=True) # 1..31
    specific_date = db.Column(db.String(20), nullable=True) # YYYY-MM-DD
    is_active = db.Column(db.Boolean, default=True)
    auth_headers = db.Column(db.JSON, nullable=True) # For authenticated scanning
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_run_at = db.Column(db.DateTime, nullable=True)

    def __init__(self, org_id, user_id, target_url, scan_type='Full', frequency='daily', schedule_time=None, day_of_week=None, day_of_month=None, specific_date=None, is_active=True, last_run_at=None, auth_headers=None, id=None):
        if id: self.id = id
        self.org_id = org_id
        self.user_id = user_id
        self.target_url = target_url
        self.scan_type = scan_type
        self.frequency = frequency
        self.schedule_time = schedule_time
        self.day_of_week = day_of_week
        self.day_of_month = day_of_month
        self.specific_date = specific_date
        self.is_active = is_active
        self.auth_headers = auth_headers
        if last_run_at: self.last_run_at = last_run_at

class AlertSettings(db.Model):
    __tablename__ = 'alert_settings'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    email_notifications = db.Column(db.Boolean, default=True)
    webhook_url = db.Column(db.String(500), nullable=True)
    severity_threshold = db.Column(db.String(50), default='Medium') # Low, Medium, High, Critical


class OrganizationScanQuota(db.Model):
    __tablename__ = 'organization_scan_quotas'
    def __init__(self, **kwargs): super().__init__(**kwargs)
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    allocated_count = db.Column(db.Integer, nullable=False, default=0)
    used_count = db.Column(db.Integer, nullable=False, default=0)
    
    __table_args__ = (db.UniqueConstraint('org_id', 'scan_type', name='uix_org_scan_type'),)



