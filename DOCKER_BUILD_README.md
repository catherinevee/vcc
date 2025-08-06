# Docker Build Instructions for VCC

## Fixed Issues in Dockerfile.secure

The following issues have been resolved:

### **Fixed File Paths**
- Changed `ultra_secure_vibe_app.py` → `../app.py`
- Updated all COPY commands to reference parent directory (`../`)
- Removed invalid `---` instruction at end of file

### **Fixed Dependencies**
- Removed `pyrasp==0.4.3` (non-existent package)
- Removed `redis-sentinel-pyclient==0.1.0` (non-existent package)
- Updated `requirements-secure.txt` with working packages only

### **Fixed Frontend Templates**
- Updated all routes to use existing template names
- Created missing `about.html` and `error.html` templates
- Fixed template name mismatches that prevented proper rendering

### **Added Build Scripts**
- `build-secure.sh` (Linux/macOS)
- `build-secure.ps1` (Windows PowerShell)

### **Cleaned Up Development Files**
- Removed temporary verification and testing scripts
- Removed Python cache files (`__pycache__/`)
- Removed setup scripts no longer needed

## How to Build

### Option 1: Using Build Scripts (Recommended)

**Windows (PowerShell):**
```powershell
cd c:\Users\cathe\OneDrive\Desktop\github\vcc
.\build-secure.ps1
```

**Linux/macOS:**
```bash
cd /path/to/vcc
chmod +x build-secure.sh
./build-secure.sh
```

### Option 2: Manual Docker Build

```bash
# Make sure you're in the vcc/ directory (not vcc/docker/)
cd c:\Users\cathe\OneDrive\Desktop\github\vcc

# Build the image
docker build -f docker/Dockerfile.secure -t vcc-secure:latest .
```

## Local Development (Alternative to Docker)

For local development without Docker, see [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md) or use the quick-start script:

```powershell
# Windows - Quick start (sets up everything automatically)
.\start-local.ps1

# Manual setup
python -m venv vcc-env
.\vcc-env\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.development .env
python app.py
```

## Prerequisites

1. **Docker installed and running**
2. **Correct working directory** - Must be in `vcc/` directory (containing `app.py`)
3. **All source files present:**
   - `app.py`
   - `vcc.py`
   - `templates/` directory
   - `static/` directory

## Test Dependencies (Optional)

Before building, you can test if the Python dependencies will work:

```bash
python test-dependencies.py
```

## Running the Container

After successful build:

```bash
# Run the container
docker run -p 5000:5000 --name vcc-secure-app vcc-secure:latest

# Run with environment variables
docker run -p 5000:5000 \
  -e VCC_GITHUB_CLIENT_ID=your_client_id \
  -e VCC_GITHUB_CLIENT_SECRET=your_client_secret \
  --name vcc-secure-app \
  vcc-secure:latest

# Run in background
docker run -d -p 5000:5000 --name vcc-secure-app vcc-secure:latest
```

## Troubleshooting

### Build Fails with "No such file or directory"
- **Solution**: Make sure you're running the build from the `vcc/` directory, not `vcc/docker/`

### "Package not found" errors
- **Solution**: The fixed `requirements-secure.txt` should resolve this
- Check internet connection for package downloads

### Permission denied errors
- **Solution**: On Linux/macOS, make sure build scripts are executable:
  ```bash
  chmod +x build-secure.sh
  ```

## Security Features

The Dockerfile.secure includes:
- Non-root user (UID 1000)
- Minimal attack surface
- Read-only application files
- Health checks
- Dependency vulnerability scanning
- Multi-stage build for smaller image size

## Build Status: **READY TO BUILD & RUN**

All issues have been fixed and the application is now fully functional:
- Dockerfile builds successfully
- Frontend templates are properly configured
- All routes render without errors
- Static assets (CSS/JS) are included and functional
