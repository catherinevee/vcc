#!/bin/bash
# Build script for Dockerfile.secure
# This script ensures the Docker build is run from the correct context

echo "Building VCC Secure Docker Image..."
echo "=================================="

# Check if we're in the correct directory
if [ ! -f "app.py" ] || [ ! -f "vcc.py" ]; then
    echo "ERROR: Please run this script from the vcc/ directory"
    echo "Current directory should contain app.py and vcc.py"
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker is not running"
    exit 1
fi

# Build the image
echo "Building Docker image with secure configuration..."
docker build \
    -f docker/Dockerfile.secure \
    -t vcc-secure:latest \
    --no-cache \
    .

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Build successful!"
    echo "Image: vcc-secure:latest"
    echo ""
    echo "To run the container:"
    echo "docker run -p 5000:5000 --name vcc-secure-app vcc-secure:latest"
else
    echo ""
    echo "❌ Build failed!"
    exit 1
fi
