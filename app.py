#!/usr/bin/env python3
"""
VCC - Vibe-Code Checker
Ultra-Secure Code Analysis Platform
Author: Aziza Ocosso
Company: VCCC (Vibe-Code Checking Corporation)
Copyright (c) 2024-2025 VCCC. All rights reserved.
"""

__author__ = "Aziza Ocosso"
__company__ = "VCCC"
__version__ = "2.0.0"
__license__ = "Proprietary"

import os
import json
import secrets
import hashlib
import hmac
import time
import base64
import tempfile
import shutil
import subprocess
import logging
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Optional, Any, Union
from collections import defaultdict

from flask import Flask, render_template, redirect, url_for, session, jsonify, request, abort, Response
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash
import redis
from celery import Celery
from cryptography.fernet import Fernet
from pythonjsonlogger import jsonlogger
from opentelemetry import trace
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from pyrasp.pyrasp import FlaskRASP
import jwt

# Import our analyzer
from vcc import VibeCodeAnalyzer

# ============================================================================
# VCC CONFIGURATION
# ============================================================================

class VCCConfig:
    """VCC Security Configuration - VCCC Standards"""
    
    # Application Branding
    APP_NAME = "VCC - Vibe-Code Checker"
    APP_AUTHOR = "Aziza Ocosso"
    APP_COMPANY = "VCCC"
    APP_VERSION = __version__
    APP_DESCRIPTION = "Vibe-code detection and remediation"
    
    # Core Security
    SECRET_KEY = os.environ.get('VCC_SECRET_KEY') or secrets.token_urlsafe(32)
    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    SESSION_COOKIE_NAME = 'vcc_session'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # VCC Zero-Trust Configuration
    VCC_ENABLE_ZERO_TRUST = True
    VCC_MAX_RISK_SCORE = 50
    VCC_DEVICE_TRUST_REQUIRED = True
    VCC_CONTINUOUS_AUTH_INTERVAL = 300
    
    # GitHub OAuth for VCC
    GITHUB_CLIENT_ID = os.environ.get('VCC_GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.environ.get('VCC_GITHUB_CLIENT_SECRET')
    
    # WebAuthn Configuration
    RP_ID = os.environ.get('VCC_RP_ID', 'vcc.vccc.io')
    RP_NAME = 'VCC by VCCC'
    
    # Redis Configuration
    REDIS_URL = os.environ.get('VCC_REDIS_URL', 'redis://localhost:6379/0')
    
    # VCC Analysis Limits
    VCC_MAX_REPO_SIZE_MB = 50
    VCC_ANALYSIS_TIMEOUT = 180
    VCC_MAX_ANALYSES_PER_DAY = 20
    
    # VCCC Support
    SUPPORT_EMAIL = 'support@vccc.io'
    SECURITY_EMAIL = 'security@vccc.io'
    DOCUMENTATION_URL = 'https://docs.vccc.io'

# ============================================================================
# VCC APPLICATION INITIALIZATION
# ============================================================================

app = Flask(__name__, 
    static_folder='static',
    template_folder='templates'
)
app.config.from_object(VCCConfig)

# Set VCC metadata
app.config['APP_METADATA'] = {
    'name': VCCConfig.APP_NAME,
    'author': VCCConfig.APP_AUTHOR,
    'company': VCCConfig.APP_COMPANY,
    'version': VCCConfig.APP_VERSION,
    'description': VCCConfig.APP_DESCRIPTION,
    'copyright': f"© 2024-2025 {VCCConfig.APP_COMPANY}. All rights reserved.",
    'support': VCCConfig.SUPPORT_EMAIL
}

# Initialize Flask instrumentation
FlaskInstrumentor().instrument_app(app)

# ============================================================================
# VCC SECURITY MIDDLEWARE
# ============================================================================

# Enhanced CSP for VCC
csp = {
    'default-src': "'none'",
    'script-src': "'self'",
    'style-src': "'self' 'unsafe-inline'",  # Needed for inline styles
    'img-src': "'self' data: avatars.githubusercontent.com",
    'font-src': "'self' data:",
    'connect-src': "'self' wss://vcc.vccc.io",
    'frame-ancestors': "'none'",
    'form-action': "'self'",
    'base-uri': "'none'",
    'object-src': "'none'"
}

talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=63072000,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    session_cookie_secure=True,
    session_cookie_http_only=True,
    session_cookie_samesite='Strict'
)

# RASP for VCC
rasp_config = {
    "protection": {
        "xss": {"enabled": True, "confidence": 0.9},
        "sqli": {"enabled": True, "confidence": 0.95},
        "command_injection": {"enabled": True, "confidence": 0.9}
    },
    "telemetry": {
        "enabled": True,
        "endpoint": "https://telemetry.vccc.io"
    }
}
rasp = FlaskRASP(app, config=rasp_config)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "20 per minute"],
    storage_uri=app.config['REDIS_URL']
)

# CORS
CORS(app, origins=['https://vcc.vccc.io', 'http://localhost:5000'])

# SocketIO
socketio = SocketIO(app, cors_allowed_origins=['https://vcc.vccc.io'])

# OAuth
oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id=app.config['GITHUB_CLIENT_ID'],
    client_secret=app.config['GITHUB_CLIENT_SECRET'],
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email repo'},
)

# Initialize Redis
try:
    redis_client = redis.from_url(app.config['REDIS_URL'])
    redis_client.ping()
except:
    redis_client = None
    print("Warning: Redis not available, using in-memory storage")

# ============================================================================
# VCC SECURITY LOGGING
# ============================================================================

def setup_vcc_logging():
    """Setup VCC security logging"""
    formatter = jsonlogger.JsonFormatter()
    
    vcc_logger = logging.getLogger('vcc_security')
    vcc_logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    vcc_logger.addHandler(handler)
    
    return vcc_logger

vcc_logger = setup_vcc_logging()

def log_vcc_event(event_type: str, details: Dict[str, Any], severity: str = 'info'):
    """Log VCC security event"""
    vcc_logger.info({
        'app': 'VCC',
        'company': 'VCCC',
        'event_type': event_type,
        'timestamp': time.time(),
        'details': details,
        'severity': severity,
        'version': VCCConfig.APP_VERSION
    })

# ============================================================================
# VCC ROUTES
# ============================================================================

@app.route('/')
def index():
    """VCC Home Page"""
    return render_template('index.html', 
        app_info=app.config['APP_METADATA'],
        user=session.get('user'))

@app.route('/research')
def research():
    """VCC Security Research Page"""
    return render_template('research.html',
        app_info=app.config['APP_METADATA'])

@app.route('/about')
def about():
    """About VCC and VCCC"""
    return render_template('about.html',
        app_info=app.config['APP_METADATA'])

@app.route('/login')
@limiter.limit("5 per hour")
def login():
    """Initiate VCC GitHub OAuth"""
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    redirect_uri = url_for('authorize', _external=True)
    log_vcc_event('login_initiated', {'method': 'github_oauth'})
    return github.authorize_redirect(redirect_uri, state=state)

@app.route('/authorize')
def authorize():
    """VCC OAuth callback"""
    try:
        state = request.args.get('state')
        if not state or state != session.pop('oauth_state', None):
            log_vcc_event('oauth_state_mismatch', {'state': state}, 'high')
            abort(400)
        
        token = github.authorize_access_token()
        
        resp = github.get('user', token=token)
        user_info = resp.json()
        
        repos_resp = github.get('user/repos?per_page=100', token=token)
        user_repos = repos_resp.json()
        
        session['user'] = {
            'id': user_info['id'],
            'login': user_info['login'],
            'name': user_info.get('name'),
            'avatar_url': user_info.get('avatar_url'),
            'repos': user_repos
        }
        
        session['github_token'] = token['access_token']
        
        log_vcc_event('successful_login', {
            'user_id': user_info['id'],
            'username': user_info['login']
        })
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        log_vcc_event('oauth_error', {'error': str(e)}, 'high')
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """VCC User Dashboard"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html',
        app_info=app.config['APP_METADATA'],
        user=session['user'])

@app.route('/logout')
def logout():
    """VCC Logout"""
    user_id = session.get('user', {}).get('id')
    session.clear()
    log_vcc_event('logout', {'user_id': user_id})
    return redirect(url_for('index'))

@app.route('/api/vcc/info')
def vcc_info():
    """Get VCC application information"""
    return jsonify({
        'application': VCCConfig.APP_NAME,
        'version': VCCConfig.APP_VERSION,
        'author': VCCConfig.APP_AUTHOR,
        'company': VCCConfig.APP_COMPANY,
        'description': VCCConfig.APP_DESCRIPTION,
        'support': VCCConfig.SUPPORT_EMAIL,
        'documentation': VCCConfig.DOCUMENTATION_URL
    })

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("5 per hour")
def analyze():
    """VCC Repository Analysis"""
    if 'user' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.json
    repo_url = data.get('repo_url')
    
    # Validate repository
    if not repo_url:
        return jsonify({'error': 'Repository URL required'}), 400
    
    # Check daily limit
    user_id = session['user']['id']
    daily_key = f"vcc_daily_analyses:{user_id}:{datetime.now().date()}"
    
    if redis_client:
        analyses_today = redis_client.incr(daily_key)
        redis_client.expire(daily_key, 86400)
        
        if analyses_today > VCCConfig.VCC_MAX_ANALYSES_PER_DAY:
            return jsonify({
                'error': f'Daily limit reached ({VCCConfig.VCC_MAX_ANALYSES_PER_DAY} analyses)',
                'upgrade_url': 'https://vccc.io/pricing'
            }), 429
    
    # Mock analysis for demo
    result = {
        'vibe_coding_score': 72,
        'critical_vulnerabilities': 3,
        'high_issues': 7,
        'medium_issues': 15,
        'low_issues': 23,
        'technical_debt_hours': 145,
        'analyzed_by': 'VCC v' + VCCConfig.APP_VERSION,
        'timestamp': datetime.now().isoformat()
    }
    
    log_vcc_event('analysis_complete', {
        'user_id': user_id,
        'repo_url': repo_url,
        'score': result['vibe_coding_score']
    })
    
    return jsonify(result)

@app.route('/health')
def health():
    """VCC Health Check"""
    return jsonify({
        'status': 'healthy',
        'application': 'VCC',
        'version': VCCConfig.APP_VERSION,
        'company': 'VCCC'
    })

# ============================================================================
# VCC ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    """VCC 404 Handler"""
    return render_template('error.html',
        app_info=app.config['APP_METADATA'],
        error_code=404,
        error_message='Page not found'), 404

@app.errorhandler(500)
def server_error(e):
    """VCC 500 Handler"""
    log_vcc_event('server_error', {'error': str(e)}, 'critical')
    return render_template('error.html',
        app_info=app.config['APP_METADATA'],
        error_code=500,
        error_message='Internal server error'), 500

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    print(f"""
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║     VCC - Vibe-Code Checker v{__version__}                ║
    ║     Author: {__author__}                          ║
    ║     Company: {__company__}                                    ║
    ║     © 2024-2025 VCCC. All rights reserved.          ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
    """)
    
    if not app.config['GITHUB_CLIENT_ID'] or not app.config['GITHUB_CLIENT_SECRET']:
        print("ERROR: VCC_GITHUB_CLIENT_ID and VCC_GITHUB_CLIENT_SECRET must be set")
        print("Contact support@vccc.io for assistance")
        exit(1)
    
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)