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
try:
    from backend.utils.fuzzer_engine import ContextAwareFuzzer
except ImportError:
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





# --- From config.py ---

def _is_redis_running(url_or_host):
    # Parse hostname and port
    host = "localhost"
    port = 6379
    if "://" in url_or_host:
        parts = url_or_host.split("://")[1].split("/")[0].split(":")
        host = parts[0]
        if len(parts) > 1:
            port = int(parts[1])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL') or 'sqlite:///wss.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Connection pooling for high concurrency
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'max_overflow': 10,
        'pool_recycle': 1800,
        'pool_pre_ping': True
    } if not SQLALCHEMY_DATABASE_URI.startswith('sqlite') else {
        'connect_args': {'check_same_thread': False}
    }

    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    
    # Local fallback for uploads. In production, files are stored in Firebase
    # Storage (see backend/utils/firebase_storage.py).
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', os.path.join(os.getcwd(), 'uploads', 'logos'))
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB max upload

    # Firebase Cloud Storage (for logos, PDFs, and general file uploads)
    FIREBASE_CREDENTIALS = os.getenv('FIREBASE_CREDENTIALS', '')
    FIREBASE_STORAGE_BUCKET = os.getenv('FIREBASE_STORAGE_BUCKET', '')
    
    # Fallback to local memory limiter if Redis is offline
    if _is_redis_running(CELERY_BROKER_URL):
        RATELIMIT_STORAGE_URI = CELERY_BROKER_URL
    else:
        RATELIMIT_STORAGE_URI = 'memory://'


