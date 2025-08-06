---
# security-scanning.sh - Automated security scanning script
#!/bin/bash
set -euo pipefail

echo "🔍 Starting comprehensive security scan..."

# 1. Container vulnerability scanning with Trivy
echo "📦 Scanning container images..."
trivy image --severity HIGH,CRITICAL your-registry/vibe-detector:latest

# 2. Dependency vulnerability scanning
echo "📚 Scanning Python dependencies..."
safety check -r requirements-secure.txt
pip-audit --desc

# 3. SAST - Static Application Security Testing
echo "🔬 Running static analysis..."
bandit -r . -f json -o bandit-report.json
semgrep --config=auto --json -o semgrep-report.json .

# 4. Secret scanning
echo "🔑 Scanning for secrets..."
trufflehog filesystem . --json > trufflehog-report.json
gitleaks detect --source . -f json -r gitleaks-report.json

# 5. DAST - Dynamic Application Security Testing (if app is running)
if curl -f http://localhost:5000/health > /dev/null 2>&1; then
    echo "🌐 Running DAST scan..."
    docker run -t owasp/zap2docker-stable zap-baseline.py \
        -t http://localhost:5000 \
        -J zap-report.json
fi

# 6. Infrastructure as Code scanning
echo "🏗️ Scanning IaC configurations..."
checkov -d . --framework dockerfile --output json > checkov-docker.json
checkov -d . --framework kubernetes --output json > checkov-k8s.json
tfsec . --format json > tfsec-report.json

# 7. License compliance checking
echo "📜 Checking license compliance..."
pip-licenses --format=json > licenses.json

# 8. SBOM generation
echo "📋 Generating Software Bill of Materials..."
syft packages dir:. -o json > sbom.json
grype sbom.json --output json > grype-vulns.json

echo "✅ Security scan complete! Check reports for details."

---