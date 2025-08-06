# VCC Quick Start Script for Windows PowerShell
# Run this script to set up and start VCC for local development

Write-Host "VCC - Vibe-Code Checker Local Setup" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

# Check if Python is installed
try {
    $pythonVersion = python --version 2>$null
    Write-Host "Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Python not found. Please install Python 3.9+ first." -ForegroundColor Red
    Write-Host "Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Check if we're in the right directory
if (-not (Test-Path "app.py")) {
    Write-Host "app.py not found. Please run this script from the vcc/ directory." -ForegroundColor Red
    exit 1
}

Write-Host "`nSetting up VCC environment..." -ForegroundColor Yellow

# Create virtual environment if it doesn't exist
if (-not (Test-Path "vcc-env")) {
    Write-Host "Creating Python virtual environment..." -ForegroundColor Blue
    python -m venv vcc-env
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Virtual environment created" -ForegroundColor Green
    } else {
        Write-Host "Failed to create virtual environment" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Virtual environment already exists" -ForegroundColor Green
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Blue
& ".\vcc-env\Scripts\Activate.ps1"

# Install dependencies
Write-Host "Installing Python dependencies..." -ForegroundColor Blue
pip install -r requirements.txt --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "Dependencies installed successfully" -ForegroundColor Green
} else {
    Write-Host "Some dependencies may have failed to install" -ForegroundColor Yellow
    Write-Host "The application may still work with limited functionality" -ForegroundColor Yellow
}

# Set up environment file
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env configuration file..." -ForegroundColor Blue
    Copy-Item ".env.development" ".env"
    Write-Host "Environment file created from template" -ForegroundColor Green
    Write-Host "Edit .env file to add your GitHub OAuth credentials for full functionality" -ForegroundColor Yellow
} else {
    Write-Host "Environment file already exists" -ForegroundColor Green
}

Write-Host "`nStarting VCC application..." -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "VCC will be available at: http://localhost:5000" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
Write-Host ""

# Start the application
python app.py
