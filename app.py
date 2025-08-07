#!/usr/bin/env python3
"""
Vibe-Code Detector Web Frontend
Secure Flask application with GitHub OAuth and real-time analysis
"""

import os
import json
import secrets
import tempfile
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Optional, Any

from flask import Flask, render_template, redirect, url_for, session, jsonify, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from authlib.integrations.flask_client import OAuth
from werkzeug.exceptions import HTTPException
import redis
import git
from celery import Celery
from cryptography.fernet import Fernet

# Import our analyzer (from previous artifact)
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vibe_code_detector import VibeCodeAnalyzer, ReportFormatter, AnalysisReport

# Configuration
class Config:
    """Secure configuration with environment variables"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    
    # GitHub OAuth (MUST be set in environment)
    GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
    
    # Redis for session storage and rate limiting
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Celery for background tasks
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')
    
    # Security
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY') or Fernet.generate_key()
    MAX_REPO_SIZE_MB = 100  # Maximum repo size to analyze
    ANALYSIS_TIMEOUT = 300  # 5 minutes timeout
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/3')

# Initialize Flask app with security
app = Flask(__name__)
app.config.from_object(Config)

# Security headers with Talisman
talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' cdn.socket.io",
        'style-src': "'self' 'unsafe-inline' cdn.jsdelivr.net",
        'font-src': "'self' data:",
        'img-src': "'self' data: avatars.githubusercontent.com",
        'connect-src': "'self' wss: ws:"
    }
)

# CORS with strict origin control
CORS(app, origins=[os.environ.get('FRONTEND_URL', 'http://localhost:5000')])

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri=app.config['RATELIMIT_STORAGE_URL']
)

# Initialize SocketIO with security
socketio = SocketIO(
    app,
    cors_allowed_origins=[os.environ.get('FRONTEND_URL', 'http://localhost:5000')],
    async_mode='threading',
    logger=True,
    engineio_logger=False
)

# Initialize OAuth
oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id=app.config['GITHUB_CLIENT_ID'],
    client_secret=app.config['GITHUB_CLIENT_SECRET'],
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email repo'},
)

# Initialize Celery
celery = Celery(app.name)
celery.conf.update(
    broker_url=app.config['CELERY_BROKER_URL'],
    result_backend=app.config['CELERY_RESULT_BACKEND'],
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_time_limit=app.config['ANALYSIS_TIMEOUT'],
    task_soft_time_limit=app.config['ANALYSIS_TIMEOUT'] - 10
)

# Redis client for caching
redis_client = redis.from_url(app.config['REDIS_URL'])

# Encryption for sensitive data
fernet = Fernet(app.config['ENCRYPTION_KEY'] if isinstance(app.config['ENCRYPTION_KEY'], bytes) 
                else app.config['ENCRYPTION_KEY'].encode())

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Security helper functions
def validate_repo_url(repo_url: str, user_repos: list) -> bool:
    """Validate that the user owns the repository"""
    # Extract repo path from URL
    if 'github.com/' not in repo_url:
        return False
    
    repo_path = repo_url.split('github.com/')[-1].rstrip('.git').rstrip('/')
    
    # Check if repo is in user's repo list
    return any(repo['full_name'] == repo_path for repo in user_repos)

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal"""
    return "".join(c for c in filename if c.isalnum() or c in ('_', '-', '.'))

def get_repo_size(repo_url: str, token: str) -> int:
    """Get repository size in MB from GitHub API"""
    # Extract owner/repo from URL
    parts = repo_url.split('github.com/')[-1].rstrip('.git').rstrip('/').split('/')
    if len(parts) != 2:
        return 0
    
    owner, repo = parts
    
    # Make API request
    import requests
    headers = {'Authorization': f'token {token}'}
    response = requests.get(f'https://api.github.com/repos/{owner}/{repo}', headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return data.get('size', 0) / 1024  # Convert KB to MB
    
    return 0

# Celery task for background analysis
@celery.task(bind=True)
def analyze_repository_task(self, repo_url: str, user_id: str, room_id: str):
    """Background task to analyze repository"""
    temp_dir = None
    
    try:
        # Update progress
        socketio.emit('analysis_progress', {
            'status': 'cloning',
            'message': 'Cloning repository...',
            'progress': 10
        }, room=room_id)
        
        # Create secure temporary directory
        temp_dir = tempfile.mkdtemp(prefix='vibe_analysis_')
        repo_path = Path(temp_dir) / 'repo'
        
        # Clone repository (with timeout)
        process = subprocess.Popen(
            ['git', 'clone', '--depth', '1', repo_url, str(repo_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        try:
            stdout, stderr = process.communicate(timeout=60)  # 1 minute timeout for cloning
        except subprocess.TimeoutExpired:
            process.kill()
            raise Exception("Repository clone timeout")
        
        if process.returncode != 0:
            raise Exception(f"Git clone failed: {stderr}")
        
        # Update progress
        socketio.emit('analysis_progress', {
            'status': 'analyzing',
            'message': 'Analyzing codebase...',
            'progress': 30
        }, room=room_id)
        
        # Run analysis
        analyzer = VibeCodeAnalyzer(str(repo_path))
        report = analyzer.analyze()
        
        # Convert report to JSON-serializable format
        report_data = {
            'vibe_coding_score': report.vibe_coding_score,
            'critical_vulnerabilities': report.critical_vulnerabilities,
            'high_issues': report.high_issues,
            'medium_issues': report.medium_issues,
            'low_issues': report.low_issues,
            'technical_debt_hours': report.technical_debt_hours,
            'summary': report.summary,
            'findings': [
                {
                    'severity': f.severity,
                    'category': f.category,
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'description': f.description,
                    'fix_suggestion': f.fix_suggestion,
                    'confidence': f.confidence,
                    'impact_score': f.impact_score,
                    'auto_fixable': f.auto_fixable
                }
                for f in report.findings[:100]  # Limit to 100 findings for performance
            ],
            'timestamp': datetime.now().isoformat(),
            'repository': repo_url
        }
        
        # Store encrypted results in Redis
        result_key = f'analysis_{user_id}_{datetime.now().timestamp()}'
        encrypted_data = fernet.encrypt(json.dumps(report_data).encode())
        redis_client.setex(result_key, 3600, encrypted_data)  # Expire after 1 hour
        
        # Send completion
        socketio.emit('analysis_complete', {
            'status': 'complete',
            'message': 'Analysis complete!',
            'progress': 100,
            'result_key': result_key,
            'report': report_data
        }, room=room_id)
        
    except Exception as e:
        # Send error
        socketio.emit('analysis_error', {
            'status': 'error',
            'message': str(e),
            'progress': 0
        }, room=room_id)
        
    finally:
        # Cleanup
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html', user=session.get('user'))

@app.route('/login')
def login():
    """Initiate GitHub OAuth login"""
    redirect_uri = url_for('authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    """GitHub OAuth callback"""
    try:
        token = github.authorize_access_token()
        
        # Get user info
        resp = github.get('user', token=token)
        user_info = resp.json()
        
        # Get user's repositories
        repos_resp = github.get('user/repos?per_page=100', token=token)
        user_repos = repos_resp.json()
        
        # Store in session (encrypted)
        session['user'] = {
            'id': user_info['id'],
            'login': user_info['login'],
            'name': user_info.get('name'),
            'avatar_url': user_info.get('avatar_url'),
            'repos': user_repos
        }
        
        # Store encrypted token
        session['github_token'] = fernet.encrypt(token['access_token'].encode()).decode()
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        app.logger.error(f"OAuth error: {e}")
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with repository list"""
    return render_template('dashboard.html', user=session.get('user'))

@app.route('/api/analyze', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def start_analysis():
    """Start repository analysis"""
    try:
        data = request.json
        repo_url = data.get('repo_url')
        
        if not repo_url:
            return jsonify({'error': 'Repository URL required'}), 400
        
        # Validate user owns the repository
        if not validate_repo_url(repo_url, session['user']['repos']):
            return jsonify({'error': 'Unauthorized: You can only analyze your own repositories'}), 403
        
        # Check repository size
        token = fernet.decrypt(session['github_token'].encode()).decode()
        repo_size = get_repo_size(repo_url, token)
        
        if repo_size > app.config['MAX_REPO_SIZE_MB']:
            return jsonify({'error': f'Repository too large ({repo_size:.1f}MB). Maximum: {app.config["MAX_REPO_SIZE_MB"]}MB'}), 413
        
        # Generate room ID for WebSocket communication
        room_id = f"analysis_{session['user']['id']}_{secrets.token_urlsafe(8)}"
        
        # Start background task
        task = analyze_repository_task.delay(repo_url, str(session['user']['id']), room_id)
        
        return jsonify({
            'task_id': task.id,
            'room_id': room_id,
            'status': 'started'
        }), 202
        
    except Exception as e:
        app.logger.error(f"Analysis error: {e}")
        return jsonify({'error': 'Analysis failed'}), 500

@app.route('/api/results/<result_key>')
@login_required
def get_results(result_key):
    """Get analysis results"""
    try:
        # Validate result key format
        if not result_key.startswith(f"analysis_{session['user']['id']}_"):
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get encrypted data from Redis
        encrypted_data = redis_client.get(result_key)
        if not encrypted_data:
            return jsonify({'error': 'Results not found or expired'}), 404
        
        # Decrypt and return
        decrypted_data = fernet.decrypt(encrypted_data)
        report_data = json.loads(decrypted_data)
        
        return jsonify(report_data), 200
        
    except Exception as e:
        app.logger.error(f"Results error: {e}")
        return jsonify({'error': 'Failed to retrieve results'}), 500

@app.route('/api/export/<result_key>')
@login_required
def export_results(result_key):
    """Export analysis results as JSON or Markdown"""
    try:
        format_type = request.args.get('format', 'json')
        
        # Get results
        encrypted_data = redis_client.get(result_key)
        if not encrypted_data:
            return jsonify({'error': 'Results not found'}), 404
        
        decrypted_data = fernet.decrypt(encrypted_data)
        report_data = json.loads(decrypted_data)
        
        if format_type == 'markdown':
            # Convert to markdown
            markdown = generate_markdown_report(report_data)
            return markdown, 200, {
                'Content-Type': 'text/markdown',
                'Content-Disposition': f'attachment; filename="vibe_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md"'
            }
        else:
            # Return JSON
            return jsonify(report_data), 200, {
                'Content-Type': 'application/json',
                'Content-Disposition': f'attachment; filename="vibe_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
            }
            
    except Exception as e:
        app.logger.error(f"Export error: {e}")
        return jsonify({'error': 'Export failed'}), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    if 'user' not in session:
        return False  # Reject connection
    emit('connected', {'message': 'Connected to analysis server'})

@socketio.on('join_analysis')
def handle_join_analysis(data):
    """Join analysis room for updates"""
    if 'user' not in session:
        return
    
    room_id = data.get('room_id')
    if room_id and room_id.startswith(f"analysis_{session['user']['id']}_"):
        join_room(room_id)
        emit('joined', {'message': f'Joined analysis room: {room_id}'})

@socketio.on('leave_analysis')
def handle_leave_analysis(data):
    """Leave analysis room"""
    room_id = data.get('room_id')
    if room_id:
        leave_room(room_id)

# Helper functions
def generate_markdown_report(report_data: Dict[str, Any]) -> str:
    """Generate markdown report from data"""
    lines = []
    lines.append("# Vibe-Code Analysis Report\n")
    lines.append(f"Generated: {report_data.get('timestamp', datetime.now().isoformat())}\n")
    lines.append(f"Repository: {report_data.get('repository', 'Unknown')}\n")
    
    lines.append("## Executive Summary\n")
    lines.append(f"- **Vibe-Coding Score**: {report_data['vibe_coding_score']}/100")
    lines.append(f"- **Technical Debt**: {report_data['technical_debt_hours']} hours")
    lines.append(f"- **Critical Issues**: {report_data['critical_vulnerabilities']}")
    lines.append(f"- **High Issues**: {report_data['high_issues']}")
    lines.append(f"- **Medium Issues**: {report_data['medium_issues']}")
    lines.append(f"- **Low Issues**: {report_data['low_issues']}\n")
    
    # Group findings by severity
    findings_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
    for finding in report_data.get('findings', []):
        findings_by_severity[finding['severity']].append(finding)
    
    for severity, findings in findings_by_severity.items():
        if findings:
            lines.append(f"## {severity} Issues\n")
            for finding in findings[:10]:  # Limit to 10 per category
                lines.append(f"### {finding['description']}\n")
                lines.append(f"- **File**: `{finding['file_path']}:{finding['line_number']}`")
                lines.append(f"- **Category**: {finding['category']}")
                lines.append(f"- **Fix**: {finding['fix_suggestion']}")
                lines.append(f"- **Confidence**: {finding['confidence']*100:.0f}%")
                lines.append("")
    
    return '\n'.join(lines)

# Error handlers
@app.errorhandler(HTTPException)
def handle_exception(e):
    """Handle HTTP exceptions"""
    return jsonify({
        'error': e.name,
        'message': e.description
    }), e.code

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    """Handle unexpected errors"""
    app.logger.error(f"Unexpected error: {e}")
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred'
    }), 500

if __name__ == '__main__':
    # Check required environment variables
    if not app.config['GITHUB_CLIENT_ID'] or not app.config['GITHUB_CLIENT_SECRET']:
        print("ERROR: GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set")
        sys.exit(1)
    
    # Run with SocketIO
    socketio.run(app, debug=False, host='0.0.0.0', port=6432)