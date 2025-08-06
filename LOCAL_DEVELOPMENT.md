# VCC Local Development Guide

## How to Run VCC Locally

### Prerequisites

1. **Python 3.9+** installed on your system
2. **Git** installed
3. **Redis** (optional - will work without it but with limited functionality)
4. **GitHub OAuth App** (for authentication features)

### Quick Start (5 Minutes)

#### 1. Install Dependencies

```powershell
# Create virtual environment (recommended)
python -m venv vcc-env
.\vcc-env\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

#### 2. Basic Configuration

```powershell
# Copy environment template
copy env.example .env
```

Edit `.env` file with a text editor:
```bash
# Minimal configuration for local development
VCC_SECRET_KEY=your-secret-key-here-make-it-long-and-random
VCC_GITHUB_CLIENT_ID=your-github-client-id
VCC_GITHUB_CLIENT_SECRET=your-github-client-secret
VCC_REDIS_URL=redis://localhost:6379/0
VCC_RP_ID=localhost
```

#### 3. Run the Application

```powershell
python app.py
```

**Open browser to: http://localhost:5000**

---

## Detailed Setup Instructions

### Step 1: Environment Setup

**Option A: Virtual Environment (Recommended)**
```powershell
# Create virtual environment
python -m venv vcc-env
.\vcc-env\Scripts\Activate.ps1

# Verify Python version
python --version  # Should be 3.9+
```

**Option B: Global Installation**
```powershell
# Install directly (not recommended for production)
pip install -r requirements.txt
```

### Step 2: GitHub OAuth Setup (Optional but Recommended)

1. **Go to GitHub Settings:**
   - Visit: https://github.com/settings/developers
   - Click "New OAuth App"

2. **Configure OAuth App:**
   ```
   Application name: VCC Local Dev
   Homepage URL: http://localhost:5000
   Authorization callback URL: http://localhost:5000/authorize
   ```

3. **Get Credentials:**
   - Copy the Client ID and Client Secret
   - Add them to your `.env` file

### Step 3: Redis Setup (Optional)

**Option A: Install Redis Locally**
```powershell
# Windows - using Chocolatey
choco install redis-64

# Or download from: https://github.com/microsoftarchive/redis/releases
```

**Option B: Use Docker**
```powershell
docker run -d -p 6379:6379 --name redis redis:alpine
```

**Option C: Skip Redis (Limited Functionality)**
- The app will work without Redis but with in-memory storage
- You'll see a warning message but it will still run

### Step 4: Configuration

Create `.env` file from template:
```powershell
copy env.example .env
notepad .env
```

**Minimal Configuration:**
```bash
VCC_SECRET_KEY=your-very-long-secret-key-here-make-it-random-and-secure
VCC_GITHUB_CLIENT_ID=your_github_client_id_here
VCC_GITHUB_CLIENT_SECRET=your_github_client_secret_here
VCC_REDIS_URL=redis://localhost:6379/0
VCC_RP_ID=localhost
```

**Generate Secret Key:**
```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Step 5: Run the Application

```powershell
# Make sure you're in the vcc directory
cd c:\Users\cathe\OneDrive\Desktop\github\vcc

# Activate virtual environment (if using one)
.\vcc-env\Scripts\Activate.ps1

# Run the application
python app.py
```

**Expected Output:**
```
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║     VCC - Vibe-Code Checker v2.0.0                  ║
    ║     Author: Aziza Ocosso                             ║
    ║     Company: VCCC                                    ║
    ║     © 2024-2025 VCCC. All rights reserved.          ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝

 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://localhost:5000
```

---

## Accessing the Application

### Main Pages

- **Home:** http://localhost:5000
- **About:** http://localhost:5000/about
- **Research:** http://localhost:5000/research
- **Login:** http://localhost:5000/login (requires GitHub OAuth)
- **Dashboard:** http://localhost:5000/dashboard (after login)

### API Endpoints

- **App Info:** http://localhost:5000/api/vcc/info
- **Health Check:** http://localhost:5000/health

---

## Troubleshooting

### Common Issues

#### "Module not found" errors
```powershell
# Make sure virtual environment is activated
.\vcc-env\Scripts\Activate.ps1
pip install -r requirements.txt
```

#### Redis connection errors
```bash
# Option 1: Install Redis
# Option 2: Comment out Redis parts in app.py
# Option 3: The app will run with warnings but still work
```

#### GitHub OAuth errors
```bash
# Make sure OAuth callback URL is exactly: http://localhost:5000/authorize
# Check Client ID and Secret in .env file
# You can skip OAuth and still see the home page
```

#### Port 5000 already in use
```powershell
# Kill process using port 5000
netstat -ano | findstr :5000
taskkill /PID <process_id> /F

# Or change port in app.py:
# socketio.run(app, debug=False, host='0.0.0.0', port=5001)
```

### Development Tips

#### Enable Debug Mode
```python
# In app.py, change the last line to:
socketio.run(app, debug=True, host='127.0.0.1', port=5000)
```

#### Hot Reload
```python
# Debug mode enables automatic reloading when files change
app.run(debug=True, host='127.0.0.1', port=5000)
```

#### View Logs
```powershell
# Application logs appear in the terminal
# Security events are logged in JSON format
```

---

## What You Can Do

### Without Authentication
- View home page with VCC branding
- Read about page and research information
- Test basic functionality

### With GitHub OAuth
- Login with GitHub account
- Access dashboard
- Analyze your repositories
- View analysis history
- Real-time analysis progress

### Features Available
- Professional UI with VCC branding
- Responsive design
- Repository analysis (mock data)
- Security scoring
- WebSocket real-time updates
- Rate limiting
- Security headers

---

## Quick Commands Reference

```powershell
# Setup (one time)
python -m venv vcc-env
.\vcc-env\Scripts\Activate.ps1
pip install -r requirements.txt
copy env.example .env

# Daily development
.\vcc-env\Scripts\Activate.ps1
python app.py

# Open in browser
start http://localhost:5000
```

**You're ready to develop with VCC locally!**
