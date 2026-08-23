from flask import (
    Flask, Blueprint, request, jsonify, current_app, send_from_directory,
    send_file, render_template, abort, g, Response, make_response
)
api_bp = Blueprint("api", __name__)

import sys
import os
import re
import time
import json
import math
import uuid
import html
import io
import hashlib
import sqlite3
import socket
import ssl
import base64
import bcrypt
import jwt
import requests
import urllib3
import ipaddress
import queue
import threading
import statistics
import itertools
import traceback
import concurrent.futures
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Literal
from collections import defaultdict
from functools import wraps
from urllib.parse import urljoin, urlparse
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BACKEND_DIR = os.path.join(BASE_DIR, 'backend')
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from bs4 import BeautifulSoup
from celery import Celery
from celery.schedules import crontab
from scanners.base_scanner import (
    active_scan_logs, add_log, get_scan_logs, parse_domain,
    cleanup_scan_logs, schedule_log_cleanup, emit_scan_progress
)
from scanners import get_pipeline, get_phases, build_scanner, apply_scan_options
from utils.fuzzer_engine import ContextAwareFuzzer
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import stripe
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from markupsafe import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, Flowable
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart

from sqlalchemy import event, func, inspect, text
from sqlalchemy.engine import Engine

try:
    from backend.utils.email_service import (
        send_welcome_email, 
        send_scan_started, 
        send_scan_completed, 
        send_scan_failed,
        send_critical_alert
    )
except ImportError:
    from utils.email_service import (
        send_welcome_email, 
        send_scan_started, 
        send_scan_completed, 
        send_scan_failed,
        send_critical_alert
    )



from .extensions import db, celery, socketio, limiter, cache
from .models import *
from .middleware import *
from .scanners_core import *


# --- From auth.py ---

auth_bp = Blueprint('auth', __name__)
JWT_SECRET = os.getenv('JWT_SECRET', 'fallback_secret')
JWT_EXPIRY_MINUTES = int(os.getenv('JWT_EXPIRY_MINUTES', '1440'))
JWT_REFRESH_EXPIRY_DAYS = int(os.getenv('JWT_REFRESH_EXPIRY_DAYS', '7'))

# Account lockout config
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def format_iso_timestamp(dt):
    if not dt:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is not None:
        return dt.isoformat()
    return dt.isoformat() + 'Z'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'X-API-Key' in request.headers:
            api_key = request.headers['X-API-Key']
            org = Organization.query.filter_by(api_key=api_key).first()
            if org:
                org_admin = User.query.filter_by(org_id=org.id, role='org_admin').first()
                if org_admin:
                    return f(org_admin, *args, **kwargs)
                else:
                    return jsonify({'message': 'No organization admin found for this API key!'}), 401
            else:
                return jsonify({'message': 'Invalid API Key!'}), 401

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'message': 'Authentication token is missing!'}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            # Reject refresh tokens used as access tokens
            if data.get('type') != 'access':
                return jsonify({'message': 'Invalid token type - use access token!'}), 401
            current_user = db.session.get(User, data['user_id'])
            if not current_user:
                return jsonify({'message': 'Invalid authentication session!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'message': 'Authentication token is missing!'}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            if data.get('type') != 'access':
                return jsonify({'message': 'Invalid token type - use access token!'}), 401
            current_user = db.session.get(User, data['user_id'])
            if not current_user:
                return jsonify({'message': 'Invalid authentication session!'}), 401
            if current_user.role != 'super_admin':
                return jsonify({'message': 'Admin privileges required!'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


def _generate_tokens(user_id: str) -> dict:
    now = datetime.now(timezone.utc)
    access_token = jwt.encode({
        'user_id': user_id,
        'type': 'access',
        'iat': now,
        'exp': now + timedelta(minutes=JWT_EXPIRY_MINUTES),
    }, JWT_SECRET, algorithm='HS256')

    refresh_token = jwt.encode({
        'user_id': user_id,
        'type': 'refresh',
        'iat': now,
        'exp': now + timedelta(days=JWT_REFRESH_EXPIRY_DAYS),
    }, JWT_SECRET, algorithm='HS256')

    return {'access_token': access_token, 'refresh_token': refresh_token}


def _is_account_locked(user) -> tuple[bool, int]:
    # Disabled account lockout mechanism per user request
    return False, 0


def _record_failed_attempt(user):
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
    db.session.commit()


def _reset_lockout(user):
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()

# --- RBAC Decorators ---
def require_role(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'user', None)
            if not user and args:
                user = args[0]
            if not user:
                return jsonify({'message': 'Authentication required'}), 401
            if user.role not in roles:
                return jsonify({'message': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters!'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User with this email already exists!'}), 400

    try:
        org_name = email.split('@')[0].capitalize() + " Organization"
        new_org = Organization(name=org_name)
        db.session.add(new_org)
        db.session.flush()

        new_user = User(email=email, org_id=new_org.id)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.flush()

        alert_settings = AlertSettings(user_id=new_user.id)
        db.session.add(alert_settings)

        db.session.commit()

        try:
            send_welcome_email(email, org_name)
        except Exception as e:
            print(f"[Email] Failed to send welcome email: {e}")

        tokens = _generate_tokens(new_user.id)

        return jsonify({
            'message': 'Registration successful!',
            **tokens,
            'user': {
                'id': new_user.id,
                'email': new_user.email,
                'role': new_user.role,
                'org_id': new_user.org_id
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Server error: {str(e)}'}), 500


@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()

    # BUG-5 / SEC-1 FIX: Check lockout BEFORE verifying password.
    # Previously the order was reversed - a locked account would still call
    # check_password() and _record_failed_attempt(), incrementing the counter
    # and creating a timing side-channel revealing account existence.
    if user:
        locked, remaining = _is_account_locked(user)
        if locked:
            return jsonify({
                'message': f'Account locked due to too many failed attempts. Try again in {remaining} seconds.',
                'retry_after': remaining,
            }), 429

    if not user or not user.check_password(password):
        if user:
            _record_failed_attempt(user)
        # Return identical message for both "user not found" and "wrong password"
        # to prevent user enumeration via error messages
        return jsonify({'message': 'Invalid email or password!'}), 401

    _reset_lockout(user)
    
    log = AuditLog(admin_id=user.id, action=f"User {user.email} logged in", target_id=user.id)
    db.session.add(log)
    db.session.commit()

    org_name = None
    if user.org_id:
        org = db.session.get(Organization, user.org_id)
        if org:
            org_name = org.name

    tokens = _generate_tokens(user.id)

    resp = make_response(jsonify({
        'message': 'Login successful!',
        **tokens,
        'user': {
            'id': user.id,
            'email': user.email,
            'role': user.role,
            'subscription_tier': user.subscription_tier,
            'org_id': user.org_id,
            'org_name': org_name
        }
    }), 200)
    # Set refresh token as HttpOnly cookie (30 days) so it survives localStorage
    # clears and tab closures without being accessible to JS (XSS protection)
    resp.set_cookie(
        'wss_refresh',
        tokens['refresh_token'],
        httponly=True,
        secure=False,          # set True in production with HTTPS
        samesite='Lax',
        max_age=60 * 60 * 24 * JWT_REFRESH_EXPIRY_DAYS,
        path='/api/auth/refresh'
    )
    return resp


@auth_bp.route('/refresh', methods=['POST'])
def refresh():
    data = request.get_json() or {}
    # Accept refresh token from JSON body OR HttpOnly cookie (fallback)
    refresh_token = data.get('refresh_token') or request.cookies.get('wss_refresh')

    if not refresh_token:
        return jsonify({'message': 'Refresh token is required!'}), 400

    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=['HS256'])
        if payload.get('type') != 'refresh':
            return jsonify({'message': 'Invalid token type!'}), 401

        user = db.session.get(User, payload['user_id'])
        if not user:
            return jsonify({'message': 'User not found!'}), 401

        tokens = _generate_tokens(user.id)
        resp = make_response(jsonify({'message': 'Tokens refreshed!', **tokens}), 200)
        # Rotate the cookie too
        resp.set_cookie(
            'wss_refresh',
            tokens['refresh_token'],
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=60 * 60 * 24 * JWT_REFRESH_EXPIRY_DAYS,
            path='/api/auth/refresh'
        )
        return resp

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token has expired! Please login again.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token!'}), 401


@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    org_name = None
    if current_user.org_id:
        org = db.session.get(Organization, current_user.org_id)
        if org:
            org_name = org.name

    return jsonify({
        'user': {
            'id': current_user.id,
            'email': current_user.email,
            'first_name': getattr(current_user, 'first_name', ''),
            'last_name': getattr(current_user, 'last_name', ''),
            'role': current_user.role,
            'org_name': org_name,
            'subscription_tier': current_user.subscription_tier,
            'subscription_status': getattr(current_user, 'subscription_status', 'active'),
            'created_at': current_user.created_at.isoformat() + 'Z' if current_user.created_at else None,
            'org_id': current_user.org_id,
            'org_name': org_name
        }
    }), 200

@auth_bp.route('/password', methods=['PUT'])
@token_required
@limiter.limit("50 per hour")
def update_password(current_user):
    if current_user.role in ('soc_analyst', 'executive_user'):
        return jsonify({'message': 'Permission denied. Please contact your organization administrator to change your password.'}), 403
        
    data = request.get_json() or {}
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    
    if not current_password or not new_password:
        return jsonify({'message': 'Missing required fields'}), 400
        
    print(f"DEBUG: Password change for {current_user.email}, provided current password: '{current_password}'")
    is_valid = current_user.check_password(current_password)
    print(f"DEBUG: check_password returned {is_valid}")
    
    if not is_valid:
        # We can also rate limit or add lockout here if desired, 
        # but the route limiter handles basic brute force prevention.
        return jsonify({'message': 'Incorrect current password'}), 401
        
    if len(new_password) < 6:
        return jsonify({'message': 'New password must be at least 6 characters'}), 400
        
    current_user.set_password(new_password)
    db.session.commit()
    
    # Log the action
    log = AuditLog(admin_id=current_user.id, action="Changed password", target_id=current_user.org_id)
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'Password updated successfully'}), 200


@auth_bp.route('/organizations/<org_id>/users', methods=['GET'])
@token_required
def get_org_users(current_user, org_id):
    if current_user.role != 'super_admin' and current_user.org_id != org_id:
        return jsonify({'message': 'Unauthorized access to organization users.'}), 403
        
    org_users = User.query.filter_by(org_id=org_id).all()
    
    return jsonify({
        'users': [{
            'id': u.id,
            'email': u.email,
            'role': u.role,
            'first_name': u.first_name,
            'last_name': u.last_name,
            'created_at': u.created_at.isoformat() + 'Z' if u.created_at else None,
            'status': 'Active' if getattr(u, 'is_active', True) else 'Suspended'
        } for u in org_users]
    }), 200

@auth_bp.route('/users/invite', methods=['POST'])
@token_required
def invite_user(current_user):
    if current_user.role not in ('org_admin', 'super_admin'):
        return jsonify({'message': 'Permission denied'}), 403
        
    data = request.get_json()
    email = data.get('email')
    role = data.get('role', 'soc_analyst')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    
    if not email:
        return jsonify({'message': 'Email is required'}), 400
        
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400
        
        
    import string, random
    # Use provided password or generate a temporary password
    provided_password = data.get('password')
    temp_password = provided_password if provided_password else ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    
    try:
        new_user = User(
            id=str(uuid.uuid4()),
            email=email,
            role=role,
            org_id=current_user.org_id,
            first_name=first_name,
            last_name=last_name
        )
        new_user.set_password(temp_password)
        db.session.add(new_user)
        
        log = AuditLog(admin_id=current_user.id, action=f"Invited user {email} with role {role}", target_id=current_user.org_id)
        db.session.add(log)
        
        db.session.commit()
        
        return jsonify({
            'message': 'User invited successfully', 
            'temp_password': temp_password,
            'user': {
                'id': new_user.id,
                'email': new_user.email,
                'role': new_user.role,
                'status': 'Active'
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        import traceback
        error_info = traceback.format_exc()
        return jsonify({'message': f'Server error: {str(e)}\n\nTraceback:\n{error_info}'}), 500

@auth_bp.route('/users/<user_id>/role', methods=['PUT'])
@token_required
def update_user_role(current_user, user_id):
    if current_user.role not in ('org_admin', 'super_admin'):
        return jsonify({'message': 'Permission denied'}), 403
        
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
        
    if current_user.role == 'org_admin' and user.org_id != current_user.org_id:
        return jsonify({'message': 'Permission denied. Cannot modify users outside your organization.'}), 403
        
    data = request.get_json()
    new_role = data.get('role')
    new_org_id = data.get('org_id')
    if not new_role:
        return jsonify({'message': 'Role is required'}), 400
        
    user.role = new_role
    if new_org_id is not None:
        user.org_id = new_org_id if new_org_id != '' else None
    
    log = AuditLog(admin_id=current_user.id, action=f"Updated role to {new_role}", target_id=user.id)
    db.session.add(log)
    
    db.session.commit()
    return jsonify({'message': 'User details updated successfully'}), 200

@auth_bp.route('/users/<user_id>/credentials', methods=['PUT'])
@token_required
def update_user_credentials(current_user, user_id):
    if current_user.role not in ('org_admin', 'super_admin'):
        return jsonify({'message': 'Permission denied'}), 403
        
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
        
    if current_user.role == 'org_admin' and user.org_id != current_user.org_id:
        return jsonify({'message': 'Permission denied. Cannot modify users outside your organization.'}), 403
        
    data = request.get_json()
    new_email = data.get('email')
    new_password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    
    updates = []
    
    if new_email and new_email != user.email:
        # Check if new email is already taken
        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user:
            return jsonify({'message': 'Email already in use'}), 400
        user.email = new_email
        updates.append('email')
        
    if new_password:
        user.set_password(new_password)
        updates.append('password')
        
    if first_name is not None and first_name != user.first_name:
        user.first_name = first_name
        updates.append('first_name')
        
    if last_name is not None and last_name != user.last_name:
        user.last_name = last_name
        updates.append('last_name')
        
    if updates:
        log = AuditLog(admin_id=current_user.id, action=f"Updated user {user.id} credentials ({', '.join(updates)})", target_id=user.id)
        db.session.add(log)
        db.session.commit()
        
    return jsonify({'message': 'User credentials updated successfully'}), 200


@auth_bp.route('/organizations/<org_id>/quotas', methods=['GET', 'POST'])
@token_required
def manage_org_quotas(current_user, org_id):
    if request.method == 'POST' and current_user.role not in ['super_admin', 'admin']:
        return jsonify({'message': 'Permission denied'}), 403

    if request.method == 'GET':
        quotas = OrganizationScanQuota.query.filter_by(org_id=org_id).all()
        quota_dict = {q.scan_type: q for q in quotas}
        
        default_types = ['Quick', 'Advanced', 'Deep']
        result = []
        for stype in default_types:
            if stype in quota_dict:
                q = quota_dict[stype]
                result.append({
                    'scan_type': q.scan_type,
                    'allocated_count': q.allocated_count,
                    'used_count': q.used_count
                })
            else:
                result.append({
                    'scan_type': stype,
                    'allocated_count': 0,
                    'used_count': 0
                })
                
        # Also include any other quotas that might exist
        for q in quotas:
            if q.scan_type not in default_types:
                result.append({
                    'scan_type': q.scan_type,
                    'allocated_count': q.allocated_count,
                    'used_count': q.used_count
                })
                
        return jsonify({'quotas': result}), 200

    if request.method == 'POST':
        data = request.get_json()
        scan_type = data.get('scan_type')
        count = data.get('count')
        
        if not scan_type or count is None:
            return jsonify({'message': 'scan_type and count are required'}), 400
            
        try:
            count = int(count)
        except ValueError:
            return jsonify({'message': 'count must be an integer'}), 400

        quota = OrganizationScanQuota.query.filter_by(org_id=org_id, scan_type=scan_type).first()
        if not quota:
            quota = OrganizationScanQuota(org_id=org_id, scan_type=scan_type, allocated_count=count)
            db.session.add(quota)
        else:
            quota.allocated_count += count
            
        db.session.commit()
        return jsonify({'message': 'Scan quota updated successfully'}), 200


@auth_bp.route('/organizations', methods=['GET', 'POST'])
@token_required
def manage_organizations(current_user):
    if current_user.role not in ['super_admin', 'admin']:
        return jsonify({'message': 'Permission denied'}), 403
        
    if request.method == 'GET':
        orgs = Organization.query.all()
        # Fetch all quotas in one go for efficiency
        quotas = OrganizationScanQuota.query.all()
        quota_map = {}
        for q in quotas:
            if q.org_id not in quota_map:
                quota_map[q.org_id] = {}
            quota_map[q.org_id][q.scan_type] = q

        default_types = ['Quick', 'Advanced', 'Deep']

        org_list = []
        for o in orgs:
            org_quotas = []
            q_dict = quota_map.get(o.id, {})
            
            for stype in default_types:
                if stype in q_dict:
                    org_quotas.append({
                        'scan_type': stype,
                        'allocated_count': q_dict[stype].allocated_count,
                        'used_count': q_dict[stype].used_count
                    })
                else:
                    org_quotas.append({
                        'scan_type': stype,
                        'allocated_count': 0,
                        'used_count': 0
                    })
            
            # also include any non-default ones
            for stype, q in q_dict.items():
                if stype not in default_types:
                    org_quotas.append({
                        'scan_type': stype,
                        'allocated_count': q.allocated_count,
                        'used_count': q.used_count
                    })

            org_list.append({
                'id': o.id,
                'name': o.name,
                'subscription_tier': o.subscription_tier,
                'is_active': o.status == 'active' if hasattr(o, 'status') else True,
                'created_at': o.created_at.isoformat() + 'Z' if o.created_at else None,
                'quotas': org_quotas
            })
            
        return jsonify({'organizations': org_list}), 200

    if current_user.role != 'super_admin':
        return jsonify({'message': 'Permission denied'}), 403
        
    data = request.get_json()
    org_name = data.get('name')
    tier = data.get('tier', 'free')
    
    if not org_name:
        return jsonify({'message': 'Organization name is required'}), 400
        
    org = Organization(name=org_name, subscription_tier=tier)
    db.session.add(org)
    db.session.commit()
    
    # Needs to be after commit to get org.id
    log = AuditLog(admin_id=current_user.id, action="Provisioned new tenant", target_id=org.id)
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'Tenant provisioned successfully', 'org_id': org.id}), 201

@auth_bp.route('/organizations/<org_id>', methods=['PUT', 'DELETE'])
@token_required
def manage_single_organization(current_user, org_id):
    if current_user.role not in ('super_admin', 'org_admin'):
        return jsonify({'message': 'Permission denied'}), 403
        
    if current_user.role == 'org_admin' and str(current_user.org_id) != str(org_id):
        return jsonify({'message': 'Permission denied: Cannot modify other organizations'}), 403
        
    org = db.session.get(Organization, org_id)
    if not org:
        return jsonify({'message': 'Organization not found'}), 404

    if request.method == 'DELETE':
        if current_user.role != 'super_admin':
            return jsonify({'message': 'Permission denied: Only Super Admin can delete organizations'}), 403
            
        db.session.delete(org)
        log = AuditLog(admin_id=current_user.id, action="Deleted tenant", target_id=org.id)
        db.session.add(log)
        db.session.commit()
        return jsonify({'message': 'Tenant deleted successfully'}), 200
        
    # PUT method
    data = request.get_json()
    if 'name' in data:
        org.name = data['name']
        
    if 'tier' in data:
        if current_user.role != 'super_admin':
            return jsonify({'message': 'Permission denied: Only Super Admin can change tier'}), 403
        org.subscription_tier = data['tier']
        
    log = AuditLog(admin_id=current_user.id, action="Updated tenant configuration", target_id=org.id)
    db.session.add(log)
    db.session.commit()
    return jsonify({'message': 'Tenant updated successfully'}), 200

@auth_bp.route('/organizations/logo', methods=['POST'])
@token_required
def upload_organization_logo(current_user):
    if current_user.role not in ('org_admin', 'super_admin'):
        return jsonify({'message': 'Permission denied'}), 403
        
    org = db.session.get(Organization, current_user.org_id)
    if not org:
        return jsonify({'message': 'Organization not found'}), 404
        
    if 'logo' not in request.files:
        return jsonify({'message': 'No file part'}), 400
        
    file = request.files['logo']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
        
    if file:
        from utils.firebase_storage import is_available, upload_bytes
        
        filename = secure_filename(f"org_{org.id}_{file.filename}")
        file_bytes = file.read()
        content_type = file.content_type or 'image/png'
        
        if is_available():
            # Upload to Firebase Cloud Storage
            blob_path = f"logos/{org.id}/{filename}"
            logo_url = upload_bytes(file_bytes, content_type, blob_path)
            if not logo_url:
                return jsonify({'message': 'Firebase upload failed'}), 500
        else:
            # Fallback: save to local disk
            upload_folder = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            with open(file_path, 'wb') as f:
                f.write(file_bytes)
            logo_url = f"/uploads/logos/{filename}"
        
        org.report_logo_url = logo_url
        db.session.commit()
        
        return jsonify({'message': 'Logo uploaded successfully', 'report_logo_url': logo_url}), 200

@auth_bp.route('/organizations/webhook', methods=['GET', 'PUT'])
@token_required
def manage_webhook(current_user):
    if current_user.role not in ('org_admin', 'super_admin'):
        return jsonify({'message': 'Permission denied'}), 403
        
    org = db.session.get(Organization, current_user.org_id)
    if not org:
        return jsonify({'message': 'Organization not found'}), 404

    if request.method == 'GET':
        return jsonify({
            'webhook_url': org.webhook_url,
            'report_logo_url': org.report_logo_url,
            'name': org.name
        }), 200
        
    data = request.get_json()
    if 'webhook_url' in data:
        org.webhook_url = data['webhook_url']
    if 'report_logo_url' in data:
        org.report_logo_url = data['report_logo_url']
    db.session.commit()
    return jsonify({'message': 'Organization settings updated successfully', 'webhook_url': org.webhook_url, 'report_logo_url': org.report_logo_url}), 200

@auth_bp.route('/organizations/<org_id>/suspend', methods=['POST'])
@token_required
def suspend_organization(current_user, org_id):
    if current_user.role != 'super_admin':
        return jsonify({'message': 'Permission denied'}), 403
        
    org = db.session.get(Organization, org_id)
    if not org:
        return jsonify({'message': 'Organization not found'}), 404
    
    if getattr(org, 'status', 'active') == 'suspended':
        org.status = 'active'
    else:
        org.status = 'suspended'
        
    log = AuditLog(admin_id=current_user.id, action=f"{org.status.capitalize()} organization", target_id=org_id)
    db.session.add(log)
    db.session.commit()
    return jsonify({'message': f'Organization status changed to {org.status}', 'status': org.status}), 200

@auth_bp.route('/impersonate/<org_id>', methods=['POST'])
@token_required
def impersonate_org(current_user, org_id):
    if current_user.role != 'super_admin':
        return jsonify({'message': 'Permission denied'}), 403
        
    target_user = User.query.filter_by(org_id=org_id, role='org_admin').first()
    if not target_user:
        target_user = User.query.filter_by(org_id=org_id).filter(User.role != 'super_admin').first()
        
    if not target_user:
        # Create a dummy user so super admins can view empty organizations
        import uuid
        target_user = User(
            id=str(uuid.uuid4()),
            email=f'impersonated_{org_id[:8]}@larxius.internal',
            password_hash='',
            role='org_admin',
            org_id=org_id
        )
        db.session.add(target_user)
        db.session.commit()
        
    log = AuditLog(admin_id=current_user.id, action=f"Impersonated org {org_id}", target_id=target_user.id)
    db.session.add(log)
    db.session.commit()
        
    tokens = _generate_tokens(target_user.id)
    return jsonify({
        'message': f'Impersonating {target_user.email}',
        'access_token': tokens['access_token'],
        'user': {
            'id': target_user.id,
            'email': target_user.email,
            'role': target_user.role,
            'org_id': target_user.org_id
        }
    }), 200

@auth_bp.route('/users', methods=['GET'])
@admin_required
def list_users(current_user):
    users = User.query.all()
    return jsonify({
        'users': [{
            'id': u.id,
            'email': u.email,
            'role': u.role,
            'first_name': u.first_name,
            'last_name': u.last_name,
            'created_at': u.created_at.isoformat() + 'Z' if u.created_at else None,
            'failed_login_attempts': u.failed_login_attempts or 0,
            'locked_until': u.locked_until.isoformat() + 'Z' if u.locked_until else None,
            'status': 'Active' if getattr(u, 'is_active', True) else 'Suspended'
        } for u in users]
    }), 200


@auth_bp.route('/email-logs', methods=['GET'])
@token_required
@require_role(['super_admin', 'admin', 'support_engineer'])
def get_email_logs(current_user):
    try:
        logs = EmailLog.query.order_by(EmailLog.sent_at.desc()).all()
        result = []
        for log in logs:
            result.append({
                "id": log.id,
                "recipient": log.recipient,
                "subject": log.subject,
                "status": log.status,
                "error_message": log.error_message,
                "sent_at": log.sent_at.isoformat() + "Z" if log.sent_at else None
            })
        return jsonify({"status": "success", "logs": result}), 200
    except Exception as e:
        current_app.logger.error(f"Failed to fetch email logs: {e}")
        return jsonify({"error": "Failed to fetch email logs"}), 500

@auth_bp.route('/global-stats', methods=['GET'])
@token_required
@require_role(['super_admin', 'admin', 'support_engineer'])
@cache.cached(timeout=300, query_string=True)
def get_global_stats(current_user):
    # Calculate stats
    total_orgs = Organization.query.count()
    total_users = User.query.count()
    active_licenses = Organization.query.filter(Organization.subscription_tier != 'free').count()
    
    # Real ARR Calculation
    arr = 0
    paid_orgs = Organization.query.filter(Organization.subscription_tier != 'free').all()
    for o in paid_orgs:
        tier = (o.subscription_tier or "").lower()
        if tier == 'enterprise':
            arr += 999 * 12
        elif tier == 'advanced':
            arr += 299 * 12
        else:
            arr += 99 * 12

    # Scans metrics
    active_scans = Scan.query.filter_by(status='scanning').count()
    queued_scans = Scan.query.filter_by(status='queued').count()
    total_scans_today = Scan.query.filter(Scan.started_at >= datetime.now(timezone.utc) - timedelta(days=1)).count()
    
    # Fetch all quotas in one go for efficiency
    quotas = OrganizationScanQuota.query.all()
    quota_map = {}
    for q in quotas:
        if q.org_id not in quota_map:
            quota_map[q.org_id] = {}
        quota_map[q.org_id][q.scan_type] = q

    default_types = ['Quick', 'Advanced', 'Deep']

    # Fetch organizations with user counts and quotas
    orgs_data = []
    orgs = Organization.query.all()
    for org in orgs:
        org_users = User.query.filter_by(org_id=org.id).count()
        
        org_quotas = []
        q_dict = quota_map.get(org.id, {})
        for stype in default_types:
            if stype in q_dict:
                org_quotas.append({
                    'scan_type': stype,
                    'allocated_count': q_dict[stype].allocated_count,
                    'used_count': q_dict[stype].used_count
                })
            else:
                org_quotas.append({
                    'scan_type': stype,
                    'allocated_count': 0,
                    'used_count': 0
                })
        for stype, q in q_dict.items():
            if stype not in default_types:
                org_quotas.append({
                    'scan_type': stype,
                    'allocated_count': q.allocated_count,
                    'used_count': q.used_count
                })

        orgs_data.append({
            'id': org.id,
            'name': org.name,
            'tier': org.subscription_tier.capitalize() if org.subscription_tier else 'Free',
            'users': org_users,
            'status': getattr(org, 'status', 'active'),
            'created': org.created_at.strftime('%Y-%m-%d') if org.created_at else 'Unknown',
            'quotas': org_quotas
        })
    # Fetch recent payments
    payments_data = []
    recent_payments = Payment.query.order_by(Payment.created_at.desc()).limit(20).all()
    for p in recent_payments:
        # Get org name if available
        org = db.session.get(Organization, p.org_id)
        org_name = org.name if org else "Unknown"
        user = db.session.get(User, p.user_id)
        user_email = user.email if user else "Unknown"
        
        payments_data.append({
            'id': p.id,
            'org_name': org_name,
            'user_email': user_email,
            'amount': p.amount / 100 if p.amount else 0, # Assuming amount is in cents/paise
            'currency': p.currency,
            'tier_id': p.tier_id,
            'status': p.status,
            'created_at': p.created_at.isoformat() + 'Z' if p.created_at else None
        })
        
    # Get global vulnerability trends
    trends_query = db.session.query(
        Vulnerability.title,
        db.func.count(Vulnerability.id).label('count')
    ).group_by(Vulnerability.title).order_by(db.func.count(Vulnerability.id).desc()).limit(5).all()
    
    trends_data = [{'title': t[0], 'count': t[1]} for t in trends_query]
    
    # Get recent audit logs enriched with user emails and target names (limit 10 for dashboard preview)
    audit_logs_query = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()
    user_ids = {a.admin_id for a in audit_logs_query if a.admin_id and a.admin_id != 'System'}
    target_ids = {a.target_id for a in audit_logs_query if a.target_id}
    all_uids = list(user_ids | target_ids)

    users_dict = {u.id: u.email for u in User.query.filter(User.id.in_(all_uids)).all()} if all_uids else {}
    orgs_dict = {o.id: o.name for o in Organization.query.all()}

    audit_data = []
    for a in audit_logs_query:
        resolved_email = users_dict.get(a.admin_id) or users_dict.get(a.target_id)
        if not resolved_email and a.action:
            import re
            m = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', a.action)
            if m:
                resolved_email = m.group(0)

        user_email = resolved_email if resolved_email else (a.admin_id if a.admin_id and a.admin_id != 'System' else 'System')
        target_name = users_dict.get(a.target_id) or orgs_dict.get(a.target_id) or a.target_id

        action_text = a.action
        if action_text == "User logged in" and resolved_email:
            action_text = f"User {resolved_email} logged in"
        elif "logged in" in action_text and resolved_email and resolved_email not in action_text:
            action_text = f"User {resolved_email} logged in"

        audit_data.append({
            'id': a.id,
            'action': action_text,
            'admin_id': a.admin_id,
            'user_email': user_email,
            'target_id': a.target_id,
            'target_name': target_name,
            'timestamp': format_iso_timestamp(a.created_at)
        })
        
    # Get all users for Members tab
    users_data = []
    if current_user.role == 'admin':
        all_users = User.query.filter(User.role != 'super_admin').all()
    else:
        all_users = User.query.all()
    for u in all_users:
        org = db.session.get(Organization, u.org_id) if u.org_id else None
        users_data.append({
            'id': u.id,
            'email': u.email,
            'role': u.role,
            'org_name': org.name if org else 'No Org (Super Admin)',
            'created_at': u.created_at.isoformat() + 'Z' if u.created_at else None
        })

    return jsonify({
        'metrics': {
            'total_tenants': total_orgs,
            'active_licenses': active_licenses,
            'global_users': total_users,
            'active_scanners': active_scans,
            'total_scanners': 50, # Max capacity
            'arr': arr,
            'db_connections': 14 + active_scans * 2, # Simulated DB connection load based on active scans
            'db_query_time': 0.02,
            'queue_size': queued_scans,
            'active_threads': active_scans * 4 # Simulating thread usage
        },
        'organizations': orgs_data,
        'recent_payments': payments_data,
        'trends': trends_data,
        'audit_logs': audit_data,
        'users': users_data
    }), 200


@auth_bp.route('/audit-logs', methods=['GET'])
@token_required
def get_all_audit_logs(current_user):
    """Retrieve all system audit logs with optional search filtering."""
    try:
        limit = request.args.get('limit', default=500, type=int)
        search_query = request.args.get('q', default='', type=str).strip().lower()

        logs_query = AuditLog.query.order_by(AuditLog.created_at.desc())
        if limit and limit > 0:
            logs_query = logs_query.limit(min(limit, 1000))

        audit_logs = logs_query.all()
        user_ids = {a.admin_id for a in audit_logs if a.admin_id and a.admin_id != 'System'}
        target_ids = {a.target_id for a in audit_logs if a.target_id}
        all_uids = list(user_ids | target_ids)

        users_dict = {u.id: u.email for u in User.query.filter(User.id.in_(all_uids)).all()} if all_uids else {}
        orgs_dict = {o.id: o.name for o in Organization.query.all()}

        audit_data = []
        for a in audit_logs:
            resolved_email = users_dict.get(a.admin_id) or users_dict.get(a.target_id)
            if not resolved_email and a.action:
                import re
                m = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', a.action)
                if m:
                    resolved_email = m.group(0)

            user_email = resolved_email if resolved_email else (a.admin_id if a.admin_id and a.admin_id != 'System' else 'System')
            target_name = users_dict.get(a.target_id) or orgs_dict.get(a.target_id) or a.target_id

            action_text = a.action
            if action_text == "User logged in" and resolved_email:
                action_text = f"User {resolved_email} logged in"
            elif "logged in" in action_text and resolved_email and resolved_email not in action_text:
                action_text = f"User {resolved_email} logged in"

            item = {
                'id': a.id,
                'action': action_text,
                'admin_id': a.admin_id,
                'user_email': user_email,
                'target_id': a.target_id,
                'target_name': target_name,
                'timestamp': format_iso_timestamp(a.created_at)
            }

            if search_query:
                if (search_query in action_text.lower() or 
                    search_query in user_email.lower() or 
                    search_query in (target_name or '').lower() or 
                    search_query in (a.target_id or '').lower()):
                    audit_data.append(item)
            else:
                audit_data.append(item)

        return jsonify({'audit_logs': audit_data, 'total': len(audit_data)}), 200
    except Exception as e:
        return jsonify({'message': f'Failed to fetch audit logs: {str(e)}'}), 500


@auth_bp.route('/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    notifications = []
    
    # 1. Recent Scans
    scans = Scan.query.filter_by(org_id=current_user.org_id).order_by(Scan.started_at.desc()).limit(10).all()
    for s in scans:
        if s.status == 'completed':
            notifications.append({
                'id': f"scan_{s.id}",
                'title': 'Scan Completed',
                'message': f"Scan for {s.target_url} finished. Score: {s.security_score or 'N/A'}",
                'timestamp': s.completed_at.isoformat() + 'Z' if s.completed_at else s.started_at.isoformat() + 'Z',
                'icon': 'verified_user',
                'color': 'text-green-500',
                'bg': 'bg-green-500/10'
            })
        elif s.status == 'failed':
            notifications.append({
                'id': f"scan_{s.id}",
                'title': 'Scan Failed',
                'message': f"Scan for {s.target_url} encountered an error.",
                'timestamp': s.completed_at.isoformat() + 'Z' if s.completed_at else s.started_at.isoformat() + 'Z',
                'icon': 'error',
                'color': 'text-error',
                'bg': 'bg-error/10'
            })
            
    # 2. Recent Audit Logs
    logs = AuditLog.query.filter_by(target_id=current_user.org_id).order_by(AuditLog.created_at.desc()).limit(5).all()
    for l in logs:
        if "logged in" not in l.action and "Changed password" not in l.action:
            notifications.append({
                'id': f"audit_{l.id}",
                'title': 'System Notification',
                'message': l.action,
                'timestamp': l.created_at.isoformat() + 'Z',
                'icon': 'info',
                'color': 'text-primary',
                'bg': 'bg-primary/10'
            })
            
    notifications.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify({'notifications': notifications[:15]}), 200

@auth_bp.route('/users/<user_id>/unlock', methods=['POST'])
@admin_required
def unlock_user(current_user, user_id):
    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'message': 'User not found!'}), 404

    _reset_lockout(target)
    return jsonify({'message': 'User unlocked!'}), 200

@auth_bp.route('/users/<user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'message': 'User not found!'}), 404
        
    if current_user.role not in ('org_admin', 'super_admin'):
        return jsonify({'message': 'Permission denied'}), 403
        
    if current_user.role == 'org_admin' and target.org_id != current_user.org_id:
        return jsonify({'message': 'Unauthorized to modify this user!'}), 403
        
    data = request.get_json()
    if 'first_name' in data:
        target.first_name = data['first_name']
    if 'last_name' in data:
        target.last_name = data['last_name']
    if 'email' in data:
        new_email = data['email']
        if new_email and new_email != target.email:
            if User.query.filter_by(email=new_email).first():
                return jsonify({'message': 'Email already in use'}), 400
            target.email = new_email
    if 'password' in data and data['password']:
        target.set_password(data['password'])
    if 'role' in data:
        new_role = data['role']
        if new_role != target.role:
            target.role = new_role
            
    log = AuditLog(admin_id=current_user.id, action=f"Updated user {target.email}", target_id=target.org_id)
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'User updated successfully!'}), 200

@auth_bp.route('/users/<user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    target = db.session.get(User, user_id)
    if not target:
        return jsonify({'message': 'User not found!'}), 404
    if current_user.role != 'super_admin' and target.org_id != current_user.org_id:
        return jsonify({'message': 'Unauthorized to delete this user!'}), 403
    
    log = AuditLog(admin_id=current_user.id, action=f"Deleted user {target.email}", target_id=target.org_id)
    db.session.delete(target)
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'User deleted successfully!'}), 200

import secrets

@auth_bp.route('/organizations/<org_id>/api-key', methods=['GET', 'POST'])
@admin_required
def manage_api_key(current_user, org_id):
    if current_user.role != 'super_admin' and current_user.org_id != org_id:
        return jsonify({'message': 'Unauthorized!'}), 403
        
    org = db.session.get(Organization, org_id)
    if not org:
        return jsonify({'message': 'Organization not found!'}), 404
        
    if request.method == 'GET':
        return jsonify({'api_key': org.api_key}), 200
        
    new_key = f"lx_{secrets.token_hex(24)}"
    org.api_key = new_key
    db.session.commit()
    
    log = AuditLog(admin_id=current_user.id, action=f"Generated new API Key", target_id=org_id)
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'API Key generated successfully!', 'api_key': new_key}), 200


# --- From scans.py ---

scans_bp = Blueprint("scans", __name__)

@scans_bp.route("/active", methods=["GET"])
@token_required
def get_active_scans(current_user):
    # If not admin/super admin, only show their own org's scans
    query = Scan.query.filter(Scan.status.in_(['queued', 'scanning']))
    if current_user.role not in ('super_admin', 'support_engineer'):
        query = query.filter_by(org_id=current_user.org_id)
        
    scans = query.order_by(Scan.started_at.desc()).all()
    
    return jsonify({
        'scans': [{
            'id': s.id,
            'target_url': s.target_url,
            'status': s.status,
            'started_at': s.started_at.isoformat() + 'Z' if s.started_at else None,
            'org_id': s.org_id
        } for s in scans]
    }), 200

@scans_bp.route("/<scan_id>/terminate", methods=["POST"])
@token_required
def terminate_scan(current_user, scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'message': 'Scan not found'}), 404
        
    if current_user.role not in ('super_admin', 'support_engineer') and scan.org_id != current_user.org_id:
        return jsonify({'message': 'Permission denied'}), 403
        
    scan.status = 'terminated'
    db.session.commit()
    
    # Log the action
    if current_user.role in ('super_admin', 'support_engineer'):
        log = AuditLog(admin_id=current_user.id, action=f"Terminated scan {scan_id}", target_id=scan.org_id)
        db.session.add(log)
        db.session.commit()
        
    return jsonify({'message': 'Scan terminated successfully', 'status': scan.status}), 200

def is_valid_target_url(url: str) -> bool:
    try:
        # Require http or https
        if not (url.startswith("http://") or url.startswith("https://")):
            return False
            
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
            
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # Reject localhost
        if hostname.lower() == "localhost":
            return False
            
        # Check if it's an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            # Must be a public, globally routable IP
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False
        except ValueError:
            # Not an IP address, which is fine (it's a domain name)
            # Ensure the domain has at least one dot (basic validity)
            if "." not in hostname:
                return False
                
        return True
    except Exception:
        return False



@scans_bp.route("/new", methods=["POST"])
@token_required
@limiter.limit("5 per minute")
def create_scan(current_user):
    data = request.get_json() or {}
    target_url = data.get("target_url")
    scan_type = data.get("scan_type", "Advanced")
    auth_headers = data.get("auth_headers", {})

    exclude_raw = data.get("exclude_paths", "")
    if isinstance(exclude_raw, str):
        exclude_paths = [p.strip() for p in exclude_raw.split(",") if p.strip()]
    else:
        exclude_paths = exclude_raw or []

    try:
        crawl_depth = int(data.get("crawl_depth", 10))
        crawl_depth = max(1, min(crawl_depth, 20))
    except (TypeError, ValueError):
        crawl_depth = 10

    scan_options = {
        "crawl_depth": crawl_depth,
        "exclude_paths": exclude_paths,
        "enable_red_team": bool(data.get("enable_red_team", False)),
    }

    if not target_url:
        return jsonify({"message": "Target website URL is required!"}), 400

    scan_tier_levels = {"quick": 1, "standard": 2, "advanced": 2, "deep": 3, "full": 2}
    user_tier_levels = {"free": 0, "quick": 1, "standard": 2, "pro": 2, "advanced": 2, "enterprise": 3}
    
    requested_level = scan_tier_levels.get(scan_type.lower(), 1)
    user_level = user_tier_levels.get((current_user.subscription_tier or "free").lower(), 0)
    
    quota = None
    has_quota = False
    is_unlimited = False
    
    if current_user.role in ['admin', 'super_admin']:
        has_quota = True
        is_unlimited = True
    elif current_user.org_id:
        # Match case-insensitively just in case
        quota = OrganizationScanQuota.query.filter(
            OrganizationScanQuota.org_id == current_user.org_id,
            func.lower(OrganizationScanQuota.scan_type) == scan_type.lower()
        ).first()
        
        if quota:
            if quota.allocated_count == -1:
                has_quota = True
                is_unlimited = True
            elif quota.used_count < quota.allocated_count:
                has_quota = True

    if not has_quota:
        return jsonify({"message": f"Quota exceeded: You do not have enough quota for a {scan_type} Scan. Please upgrade your plan."}), 403

    if not target_url:
        return jsonify({"message": "Target website URL is required!"}), 400

    if not (
        target_url.startswith("http://") or target_url.startswith("https://")
    ):
        target_url = "https://" + target_url
        
    if not is_valid_target_url(target_url):
        return jsonify({"message": "Invalid target URL. Please enter a valid public domain or IP address."}), 400

    effective_org_id = current_user.org_id
    if not effective_org_id:
        first_org = Organization.query.first()
        if not first_org:
            first_org = Organization(name="Default System Tenant", subscription_tier="enterprise")
            db.session.add(first_org)
            db.session.commit()
        effective_org_id = first_org.id
        current_user.org_id = effective_org_id
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    try:
        new_scan = Scan(
            user_id=current_user.id,
            org_id=effective_org_id,
            target_url=target_url,
            scan_type=scan_type,
            status="queued",
            auth_headers=auth_headers,
            scan_options=scan_options,
            started_at=datetime.now(timezone.utc),
        )
        db.session.add(new_scan)
        
        if quota and not is_unlimited:
            quota.used_count += 1

        log = AuditLog(admin_id=current_user.id, action=f"Initiated manual {scan_type} scan for {target_url}", target_id=effective_org_id)
        db.session.add(log)
        
        db.session.commit()

        flask_app = current_app._get_current_object()  # type: ignore
        launch_scan(flask_app, new_scan.id)
        
        try:
            send_scan_started(
                current_user.email, 
                current_user.email.split('@')[0].capitalize(), 
                target_url, 
                scan_type
            )
        except Exception as e:
            print(f"[Email] Failed to send scan started email: {e}")

        return (
            jsonify(
                {
                    "message": "Scan queued successfully!",
                    "scan": {
                        "id": new_scan.id,
                        "target_url": new_scan.target_url,
                        "scan_type": new_scan.scan_type,
                        "status": new_scan.status,
                        "started_at": format_iso_timestamp(new_scan.started_at),
                    },
                }
            ),
            201,
        )
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@scans_bp.route("/<scan_id>/logs", methods=["GET"])
@token_required
def fetch_scan_logs(current_user, scan_id):
    try:
        scan = get_scan_for_user(scan_id, current_user)
        if not scan:
            return jsonify({"status": "error", "message": "Scan not found or access denied"}), 404

        logs = get_scan_logs(scan_id)
        if not logs:
            if scan.status == 'queued':
                logs = [f"[INFO] Target: {scan.target_url} — Scan queued. Waiting for active scan to finish..."]
            elif scan.status == 'scanning':
                logs = [f"[INFO] Target: {scan.target_url} — Audit thread active. Spawning vulnerability scanners..."]

        return jsonify({
            "status": scan.status,
            "logs": logs
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@scans_bp.route("/history", methods=["GET"])
@token_required
def get_scans_history(current_user):
    try:

        limit_val = request.args.get('limit', 50, type=int)
        if current_user.role in ['super_admin', 'support_engineer'] or request.args.get('global') == 'true':
            scans_query = Scan.query
        elif current_user.org_id:
            scans_query = Scan.query.filter_by(org_id=current_user.org_id)
        else:
            scans_query = Scan.query.filter_by(user_id=current_user.id)

        scans = scans_query.order_by(Scan.started_at.desc()).limit(limit_val).all()
        scan_ids = [s.id for s in scans]

        counts_map = {
            s.id: {"critical": 0, "high": 0, "medium": 0, "low": 0} for s in scans
        }

        if scan_ids:
            vuln_counts = (
                db.session.query(
                    Vulnerability.scan_id,
                    Vulnerability.severity,
                    func.count(Vulnerability.id),
                )
                .filter(
                    Vulnerability.scan_id.in_(scan_ids),
                    Vulnerability.is_false_positive.isnot(True),
                )
                .group_by(Vulnerability.scan_id, Vulnerability.severity)
                .all()
            )

            for scan_id, severity, count in vuln_counts:
                counts_map[scan_id][severity.lower()] = count

        orgs = Organization.query.all()
        org_map = {org.id: org.name for org in orgs}

        scans_list = []
        for s in scans:
            counts = counts_map[s.id]
            effective_score = s.security_score
            if s.status == "completed":
                effective_score = calculate_security_score_from_counts(counts)

            scans_list.append(
                {
                    "id": s.id,
                    "target_url": s.target_url,
                    "scan_type": s.scan_type,
                    "status": s.status,
                    "org_id": s.org_id,
                    "org_name": org_map.get(s.org_id, "Unknown"),
                    "security_score": effective_score,
                    "started_at": format_iso_timestamp(s.started_at),
                    "completed_at": format_iso_timestamp(s.completed_at),
                    "vulnerabilities_count": {
                        "critical": counts["critical"],
                        "high": counts["high"],
                        "medium": counts["medium"],
                        "low": counts["low"],
                        "total": sum(counts.values()),
                    },
                }
            )
        return jsonify({"scans": scans_list}), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@scans_bp.route("/<scan_id>", methods=["GET"])
@token_required
def get_scan_details(current_user, scan_id):
    try:
        scan = get_scan_for_user(scan_id, current_user)
        if not scan:
            return jsonify({"message": "Scan session not found!"}), 404

        crit = Vulnerability.query.filter_by(
            scan_id=scan.id, severity="Critical"
        ).filter(Vulnerability.is_false_positive.isnot(True)).count()
        high = Vulnerability.query.filter_by(
            scan_id=scan.id, severity="High"
        ).filter(Vulnerability.is_false_positive.isnot(True)).count()
        med = Vulnerability.query.filter_by(
            scan_id=scan.id, severity="Medium"
        ).filter(Vulnerability.is_false_positive.isnot(True)).count()
        low = Vulnerability.query.filter_by(
            scan_id=scan.id, severity="Low"
        ).filter(Vulnerability.is_false_positive.isnot(True)).count()

        counts = {"critical": crit, "high": high, "medium": med, "low": low}
        effective_score = scan.security_score
        if scan.status == "completed":
            effective_score = calculate_security_score_from_counts(counts)

        return (
            jsonify(
                {
                    "scan": {
                        "id": scan.id,
                        "target_url": scan.target_url,
                        "scan_type": scan.scan_type,
                        "status": scan.status,
                        "security_score": effective_score,
                        "started_at": scan.started_at.isoformat() + "Z",
                        "completed_at": (
                            scan.completed_at.isoformat() + "Z"
                        ) if scan.completed_at else None,
                        "vulnerabilities_count": {
                            "critical": crit,
                            "high": high,
                            "medium": med,
                            "low": low,
                            "total": crit + high + med + low,
                        },
                    }
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@scans_bp.route("/<scan_id>/logs", methods=["GET"])
@token_required
@limiter.exempt   # Polled frequently during active scans - exempt from rate limits
def get_scan_live_logs(current_user, scan_id):
    scan = get_scan_for_user(scan_id, current_user)
    if not scan:
        return jsonify({"message": "Scan session not found!"}), 404

    logs = get_scan_logs(scan_id)
    return jsonify({"scan_id": scan_id, "status": scan.status, "logs": logs}), 200


@scans_bp.route("/<scan_id>/vulnerabilities", methods=["GET"])
@token_required
def get_scan_vulnerabilities(current_user, scan_id):
    scan = get_scan_for_user(scan_id, current_user)
    if not scan:
        return jsonify({"message": "Scan session not found!"}), 404

    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 50, type=int)

        pagination = (
            Vulnerability.query.filter_by(scan_id=scan_id)
            .order_by(Vulnerability.cvss_score.desc())
            .paginate(page=page, per_page=limit, error_out=False)
        )
        
        vulns_list = []
        for v in pagination.items:
            vulns_list.append(
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity,
                    "category": v.category,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "remediation": v.remediation,
                    "detected_at": v.detected_at.isoformat() + "Z",
                    "evidence": v.evidence or "",
                    "payload": v.payload or "",
                    "request_details": v.request_details or "",
                    "response_details": v.response_details or "",
                    "is_false_positive": v.is_false_positive or False,
                    "cwe_ids": v.cwe_ids or [],
                    "owasp_category": v.owasp_category or "",
                    "exploit_poc": v.exploit_poc or None,
                    "remediation_code": v.remediation_code or "",
                }
            )
            
        return jsonify({
            "vulnerabilities": vulns_list,
            "total_items": pagination.total,
            "total_pages": pagination.pages,
            "current_page": page,
            "has_next": pagination.has_next,
            "has_prev": pagination.has_prev
        }), 200
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500


@scans_bp.route("/schedule", methods=["GET", "POST"])
@token_required
def handle_scheduled_scans(current_user):
    if current_user.subscription_tier == "Free":
        return jsonify({'message': 'Scheduled scans require a premium subscription.'}), 403

    if request.method == "GET":
        if current_user.role in ['super_admin', 'support_engineer'] and not current_user.org_id:
            schedules = ScheduledScan.query.all()
        elif current_user.org_id:
            schedules = ScheduledScan.query.filter_by(org_id=current_user.org_id).all()
        else:
            schedules = ScheduledScan.query.filter_by(user_id=current_user.id).all()
        return jsonify({
            'schedules': [{
                'id': s.id,
                'target_url': s.target_url,
                'scan_type': s.scan_type,
                'frequency': s.frequency,
                'schedule_time': s.schedule_time,
                'day_of_week': s.day_of_week,
                'day_of_month': s.day_of_month,
                'specific_date': s.specific_date,
                'is_active': s.is_active,
                'last_run_at': s.last_run_at.isoformat() + 'Z' if s.last_run_at else None,
                'created_at': s.created_at.isoformat() + 'Z'
            } for s in schedules]
        }), 200

    if request.method == "POST":
        data = request.get_json() or {}
        target_url = data.get('target_url')
        schedule_time = data.get('schedule_time') # e.g. "20:00"
        
        if not target_url or not schedule_time:
            return jsonify({'message': 'Target URL and schedule time are required.'}), 400
            
        if not (target_url.startswith("http://") or target_url.startswith("https://")):
            target_url = "https://" + target_url
            
        if not is_valid_target_url(target_url):
            return jsonify({"message": "Invalid target URL. Please enter a valid public domain or IP address."}), 400
            
        new_schedule = ScheduledScan(
            user_id=current_user.id,
            org_id=current_user.org_id,
            target_url=target_url,
            scan_type=data.get('scan_type', 'Advanced'),
            frequency=data.get('frequency', 'daily'),
            schedule_time=schedule_time,
            day_of_week=data.get('day_of_week'),
            day_of_month=data.get('day_of_month'),
            specific_date=data.get('specific_date')
        )
        db.session.add(new_schedule)
        
        log = AuditLog(admin_id=current_user.id, action=f"Scheduled {new_schedule.frequency} scan for {target_url}", target_id=current_user.org_id)
        db.session.add(log)
        
        db.session.commit()
        return jsonify({'message': 'Scan scheduled successfully.', 'id': new_schedule.id}), 201

@scans_bp.route("/schedule/<schedule_id>", methods=["DELETE"])
@token_required
def delete_scheduled_scan(current_user, schedule_id):
    if current_user.role in ['super_admin', 'support_engineer']:
        schedule = ScheduledScan.query.filter_by(id=schedule_id).first()
    elif current_user.org_id:
        schedule = ScheduledScan.query.filter_by(id=schedule_id, org_id=current_user.org_id).first()
    else:
        schedule = ScheduledScan.query.filter_by(id=schedule_id, user_id=current_user.id).first()
    if not schedule:
        return jsonify({'message': 'Scheduled scan not found.'}), 404
        
    db.session.delete(schedule)
    
    log = AuditLog(admin_id=current_user.id, action=f"Deleted scheduled scan for {schedule.target_url}", target_id=current_user.org_id)
    db.session.add(log)
    
    db.session.commit()
    return jsonify({'message': 'Scheduled scan deleted.'}), 200

@scans_bp.route("/schedule/<schedule_id>", methods=["PUT"])
@token_required
def edit_scheduled_scan(current_user, schedule_id):
    if current_user.role in ['super_admin', 'support_engineer']:
        schedule = ScheduledScan.query.filter_by(id=schedule_id).first()
    elif current_user.org_id:
        schedule = ScheduledScan.query.filter_by(id=schedule_id, org_id=current_user.org_id).first()
    else:
        schedule = ScheduledScan.query.filter_by(id=schedule_id, user_id=current_user.id).first()
    if not schedule:
        return jsonify({'message': 'Scheduled scan not found.'}), 404
        
    data = request.get_json() or {}
    target_url = data.get('target_url')
    schedule_time = data.get('schedule_time')
    
    if 'target_url' in data:
        target_url = data['target_url']
        if not (target_url.startswith("http://") or target_url.startswith("https://")):
            target_url = "https://" + target_url
        if not is_valid_target_url(target_url):
            return jsonify({"message": "Invalid target URL. Please enter a valid public domain or IP address."}), 400
        schedule.target_url = target_url
    if schedule_time:
        schedule.schedule_time = schedule_time
    if 'scan_type' in data:
        schedule.scan_type = data['scan_type']
    if 'frequency' in data:
        schedule.frequency = data['frequency']
    if 'day_of_week' in data:
        schedule.day_of_week = data['day_of_week']
    if 'day_of_month' in data:
        schedule.day_of_month = data['day_of_month']
    if 'specific_date' in data:
        schedule.specific_date = data['specific_date']
        
    log = AuditLog(admin_id=current_user.id, action=f"Edited scheduled scan for {schedule.target_url}", target_id=current_user.org_id)
    db.session.add(log)
    
    db.session.commit()
    return jsonify({'message': 'Scheduled scan updated.'}), 200

@scans_bp.route("/vulnerability/<vuln_id>/false-positive", methods=["PUT"])
@token_required
def toggle_false_positive(current_user, vuln_id):
    vuln = db.session.get(Vulnerability, vuln_id)
    if not vuln:
        return jsonify({"message": "Vulnerability not found!"}), 404
    scan = get_scan_for_user(vuln.scan_id, current_user)
    if not scan:
        return jsonify({"message": "Unauthorized!"}), 403

    data = request.get_json() or {}
    vuln.is_false_positive = data.get("is_false_positive", True)
    db.session.commit()
    return jsonify({"message": "Updated", "is_false_positive": vuln.is_false_positive}), 200


# --- From vulnerabilities.py ---

vuln_bp = Blueprint('vulnerabilities', __name__)

@vuln_bp.route('/summary', methods=['GET'])
@token_required
@cache.cached(timeout=30, query_string=True)
def get_vulnerabilities_summary(current_user):
    try:
        if current_user.role in ['super_admin', 'support_engineer'] or request.args.get('global') == 'true':
            scan_filter = (Scan.id.isnot(None),)
        elif current_user.org_id:
            scan_filter = (Scan.org_id == current_user.org_id,)
        else:
            scan_filter = (Scan.user_id == current_user.id,)

        scans_count = db.session.query(func.count(Scan.id)).filter(*scan_filter).scalar() or 0
        
        if scans_count == 0:
            return jsonify({
                'summary': {
                    'vulnerabilities_count': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0},
                    'scans_count': 0,
                    'average_security_score': 100,
                    'by_category': {},
                    'score_history': []
                }
            }), 200

        # Global counts using join
        vuln_counts = db.session.query(
            Vulnerability.severity,
            func.count(Vulnerability.id)
        ).join(Scan, Vulnerability.scan_id == Scan.id)\
         .filter(*scan_filter, Vulnerability.is_false_positive.isnot(True))\
         .group_by(Vulnerability.severity).all()
        
        crit = high = med = low = 0
        for severity, count in vuln_counts:
            if severity == 'Critical': crit = count
            elif severity == 'High': high = count
            elif severity == 'Medium': med = count
            elif severity == 'Low': low = count
        
        # Avg score
        avg_score_raw = db.session.query(func.avg(Scan.security_score)).filter(*scan_filter, Scan.security_score.isnot(None)).scalar()
        avg_score = int(avg_score_raw) if avg_score_raw else 100
        
        # Categories breakdown
        cat_counts = db.session.query(
            Vulnerability.category,
            func.count(Vulnerability.id)
        ).join(Scan, Vulnerability.scan_id == Scan.id)\
         .filter(*scan_filter, Vulnerability.is_false_positive.isnot(True))\
         .group_by(Vulnerability.category).all()
        
        by_category = {cat: count for cat, count in cat_counts if cat}
            
        # Score history (last 20 scans)
        recent_scans = Scan.query.filter(*scan_filter, Scan.security_score.isnot(None))\
            .order_by(Scan.started_at.desc()).limit(20).all()
        
        recent_scans.reverse()
        score_history = []
        for s in recent_scans:
            score_history.append({
                'scan_id': s.id,
                'target_url': s.target_url,
                'security_score': s.security_score,
                'completed_at': (s.completed_at.isoformat() + 'Z') if s.completed_at else (s.started_at.isoformat() + 'Z')
            })
            
        return jsonify({
            'summary': {
                'vulnerabilities_count': {
                    'critical': crit,
                    'high': high,
                    'medium': med,
                    'low': low,
                    'total': crit + high + med + low
                },
                'scans_count': scans_count,
                'average_security_score': avg_score,
                'by_category': by_category,
                'score_history': score_history
            }
        }), 200
    except Exception as e:
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@vuln_bp.route('/settings', methods=['GET', 'POST'])
@token_required
def manage_alert_settings(current_user):
    settings = AlertSettings.query.filter_by(user_id=current_user.id).first()
    if not settings:
        # Create default if missing
        settings = AlertSettings(user_id=current_user.id)
        db.session.add(settings)
        db.session.commit()
        
    if request.method == 'GET':
        return jsonify({
            'settings': {
                'email_notifications': settings.email_notifications,
                'webhook_url': settings.webhook_url,
                'severity_threshold': settings.severity_threshold
            }
        }), 200
        
    if request.method == 'POST':
        data = request.get_json() or {}
        settings.email_notifications = data.get('email_notifications', settings.email_notifications)
        settings.webhook_url = data.get('webhook_url', settings.webhook_url)
        settings.severity_threshold = data.get('severity_threshold', settings.severity_threshold)
        
        try:
            db.session.commit()
            return jsonify({
                'message': 'Alert preferences updated successfully!',
                'settings': {
                    'email_notifications': settings.email_notifications,
                    'webhook_url': settings.webhook_url,
                    'severity_threshold': settings.severity_threshold
                }
            }), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': f'Server error: {str(e)}'}), 500


# --- From reports.py ---

def get_scan_for_user(scan_id, current_user):
    """
    Retrieve scan object with role-based access permissions:
    - Super Admins & Support Engineers: full system-wide access to all scans.
    - Org Admins & Org Members: full access to all scans created in their organization.
    - Standard Users: access to scans they created.
    """
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return None
    if current_user.role in ('super_admin', 'support_engineer'):
        return scan
    if current_user.org_id and scan.org_id == current_user.org_id:
        return scan
    if scan.user_id == current_user.id:
        return scan
    return None

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/<scan_id>/pdf', methods=['GET'])
@token_required
def generate_pdf_report(current_user, scan_id):
    scan = get_scan_for_user(scan_id, current_user)
    if not scan:
        return jsonify({'message': 'Scan session not found!'}), 404
        
    try:
        vulns = Vulnerability.query.filter_by(scan_id=scan_id).order_by(Vulnerability.cvss_score.desc()).all()
        
        # Generate PDF using reportlab enterprise utility
        try:
            pdf_bytes_data = generate_scan_pdf(scan, vulns)
        except Exception as e:
            import traceback
            with open('pdf_error.log', 'w') as f:
                traceback.print_exc(file=f)
            return jsonify({'message': f'PDF Generation failed: {str(e)}'}), 500
            
        pdf_bytes = io.BytesIO(pdf_bytes_data)
        pdf_bytes.seek(0)
        
        parsed = urlparse(scan.target_url)
        domain = parsed.netloc or parsed.path
        if ':' in domain:
            domain = domain.split(':')[0]
            
        date_str = scan.completed_at.strftime('%Y%m%d_%H%M') if scan.completed_at else 'Unknown'
        filename = f"{domain}_Scan_Report_{date_str}.pdf"
        
        # Store a copy in Firebase Cloud Storage for history
        from utils.firebase_storage import is_available, upload_bytes
        if is_available():
            try:
                blob_path = f"reports/{scan_id}/{filename}"
                upload_bytes(pdf_bytes_data, 'application/pdf', blob_path)
            except Exception as e:
                print(f"[Firebase] PDF backup failed for {scan_id}: {e}")
            pdf_bytes.seek(0)
        
        return send_file(
            pdf_bytes,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'message': f'Server error: {str(e)}'}), 500


@reports_bp.route('/<scan_id>/public-pdf', methods=['GET'])
def generate_public_pdf_report(scan_id):
    """Direct unauthenticated access to stream/render PDF report natively in browser."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'message': 'Scan session not found!'}), 404
        
    try:
        vulns = Vulnerability.query.filter_by(scan_id=scan_id).order_by(Vulnerability.cvss_score.desc()).all()
        
        try:
            pdf_bytes_data = generate_scan_pdf(scan, vulns)
        except Exception as e:
            import traceback
            with open('pdf_error.log', 'w') as f:
                traceback.print_exc(file=f)
            return jsonify({'message': f'PDF Generation failed: {str(e)}'}), 500
            
        pdf_bytes = io.BytesIO(pdf_bytes_data)
        pdf_bytes.seek(0)
        
        parsed = urlparse(scan.target_url)
        domain = parsed.netloc or parsed.path
        if ':' in domain:
            domain = domain.split(':')[0]
            
        date_str = scan.completed_at.strftime('%Y%m%d_%H%M') if scan.completed_at else 'Unknown'
        filename = f"{domain}_Scan_Report_{date_str}.pdf"
        
        return send_file(
            pdf_bytes,
            mimetype='application/pdf',
            as_attachment=False,
            download_name=filename
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'message': f'Server error: {str(e)}'}), 500



# --- From webhook.py ---

def send_webhook_alert(webhook_url, scan, vulnerabilities, crit_count, high_count):
    """
    Sends a formatted Discord/Slack compatible webhook payload summarizing the scan.
    """
    if not webhook_url:
        return

    score = scan.security_score
    status_color = 0x00FF00 # Green
    if crit_count > 0:
        status_color = 0xFF0000 # Red
    elif high_count > 0:
        status_color = 0xFFA500 # Orange

    embed = {
        "title": f"ðŸš¨ Security Scan Completed: {scan.target_url}",
        "description": f"Scan type **{scan.scan_type}** finished with a security score of **{score}/100**.",
        "color": status_color,
        "fields": [
            {"name": "Target", "value": scan.target_url, "inline": True},
            {"name": "Scan ID", "value": scan.id[:8], "inline": True},
            {"name": "Score", "value": str(score), "inline": True},
            {"name": "Critical", "value": str(crit_count), "inline": True},
            {"name": "High", "value": str(high_count), "inline": True},
            {"name": "Total Vulns", "value": str(len(vulnerabilities)), "inline": True},
        ],
        "footer": {"text": f"LarShield Web Security \u2022 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"}
    }

    # If criticals exist, add a snippet of the top finding
    if crit_count > 0:
        top_vuln = next((v for v in vulnerabilities if v.severity == "Critical"), None)
        if top_vuln:
            embed["fields"].append({
                "name": f"Top Finding: {top_vuln.title}",
                "value": top_vuln.description[:250] + "...",
                "inline": False
            })

    payload = {
        "username": "LarShield Alert System",
        "avatar_url": "https://i.imgur.com/4M34hi2.png", # Placeholder shield icon
        "embeds": [embed]
    }

    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        print(f"DEBUG: Webhook failed: {e}")

from flask_socketio import join_room, leave_room

@socketio.on('join_scan')
def handle_join_scan(data):
    scan_id = data.get('scan_id')
    if scan_id:
        join_room(f'scan_{scan_id}')

@socketio.on('leave_scan')
def handle_leave_scan(data):
    scan_id = data.get('scan_id')
    if scan_id:
        leave_room(f'scan_{scan_id}')


# --- Demo Booking API Endpoints ---

@api_bp.route('/api/demo/book', methods=['POST'])
def book_demo():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    company_size = data.get('company_size', '').strip()
    meeting_date = data.get('meeting_date', '').strip()
    meeting_time = data.get('meeting_time', '').strip()

    if not email:
        return jsonify({'message': 'Work email is required.'}), 400
    if '@' not in email or len(email) < 5:
        return jsonify({'message': 'Invalid work email format.'}), 400
    if not company_size:
        return jsonify({'message': 'Company size is required.'}), 400
    if not meeting_date or not meeting_time:
        return jsonify({'message': 'Meeting date and time are required.'}), 400

    try:
        booking = DemoBooking(
            email=email,
            company_size=company_size,
            meeting_date=meeting_date,
            meeting_time=meeting_time,
            status='pending'
        )
        db.session.add(booking)
        db.session.commit()
        return jsonify({
            'message': 'Demo booked successfully!',
            'booking': booking.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Server error booking demo: {str(e)}'}), 500


@api_bp.route('/api/demo/bookings', methods=['GET'])
def get_demo_bookings():
    try:
        bookings = DemoBooking.query.order_by(DemoBooking.created_at.desc()).all()
        return jsonify({'bookings': [b.to_dict() for b in bookings]}), 200
    except Exception as e:
        return jsonify({'message': f'Error fetching demo bookings: {str(e)}', 'bookings': []}), 500


@api_bp.route('/api/demo/bookings/<booking_id>', methods=['PUT'])
def update_demo_booking_status(booking_id):
    data = request.get_json() or {}
    try:
        booking = db.session.get(DemoBooking, booking_id)
        if not booking:
            return jsonify({'message': 'Booking not found.'}), 404
        if 'status' in data:
            booking.status = data['status']
        if 'meeting_date' in data and data['meeting_date']:
            booking.meeting_date = data['meeting_date']
        if 'meeting_time' in data and data['meeting_time']:
            booking.meeting_time = data['meeting_time']
        db.session.commit()
        return jsonify({'message': 'Booking status updated successfully!', 'booking': booking.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error updating booking status: {str(e)}'}), 500


@api_bp.route('/api/demo/bookings/<booking_id>', methods=['DELETE'])
def delete_demo_booking(booking_id):
    try:
        booking = db.session.get(DemoBooking, booking_id)
        if not booking:
            return jsonify({'message': 'Booking not found.'}), 404
        db.session.delete(booking)
        db.session.commit()
        return jsonify({'message': 'Booking deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error deleting booking: {str(e)}'}), 500

