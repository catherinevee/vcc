# Build script for Dockerfile.secure (PowerShell version)
# This script ensures the Docker build is run from the correct context

Write-Host "Building VCC Secure Docker Image..." -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Check if we're in the correct directory
if (-not (Test-Path "app.py") -or -not (Test-Path "vcc.py")) {
    Write-Host "ERROR: Please run this script from the vcc\ directory" -ForegroundColor Red
    Write-Host "Current directory should contain app.py and vcc.py" -ForegroundColor Red
    exit 1
}

# Check if Docker is running
try {
    docker info 2>$null | Out-Null
} catch {
    Write-Host "ERROR: Docker is not running" -ForegroundColor Red
    exit 1
}

# Build the image
Write-Host "Building Docker image with secure configuration..." -ForegroundColor Yellow
docker build `
    -f docker/Dockerfile.secure `
    -t vcc-secure:latest `
    --no-cache `
    .

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ Build successful!" -ForegroundColor Green
    Write-Host "Image: vcc-secure:latest" -ForegroundColor Green
    Write-Host ""
    Write-Host "To run the container:" -ForegroundColor Cyan
    Write-Host "docker run -p 5000:5000 --name vcc-secure-app vcc-secure:latest" -ForegroundColor White
} else {
    Write-Host ""
    Write-Host "❌ Build failed!" -ForegroundColor Red
    exit 1
}
