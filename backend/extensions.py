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
from flask_caching import Cache
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





# --- From database.py ---

db = SQLAlchemy()


# â”€â”€ SQLite thread safety + WAL mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Allows SQLAlchemy sessions to be used across scanner threads safely.
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        # WAL mode: concurrent reads don't block writes and vice-versa
        cursor.execute("PRAGMA journal_mode=WAL")
        # Relax fsync for scanner workloads (safe for dev/prod on local disk)
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


# --- From celery_app.py ---

celery = Celery(
    "sentinel_tasks",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)
_celery = celery

celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
)

# Enterprise Feature: Celery Beat Schedule

celery.conf.beat_schedule = {
    'process-scheduled-scans-every-hour': {
        'task': 'process_scheduled_scans',
        'schedule': crontab(minute=0), # Run top of every hour
    },
}



# --- From extensions.py ---

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10000 per day", "2000 per hour", "100 per minute"]
)

socketio = SocketIO()
cache = Cache()
from flask_migrate import Migrate
migrate = Migrate()

