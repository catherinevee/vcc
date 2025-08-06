# VCC - Vibe-Code Checker

Detection and remediation of AI-generated code vulnerabilities.

**Author:** Aziza Ocosso  
**Company:** VCCC (Vibe-Code Checking Corporation)

## Features

- Detects hardcoded secrets, SQL injection, Firebase misconfigurations
- Identifies performance anti-patterns (N+1 queries, memory leaks)
- Analyzes architectural incoherence
- Zero-trust security architecture
- Enterprise-ready with GDPR compliance

## Quick Start

### Prerequisites
- Python 3.9+
- Redis
- GitHub OAuth App

### Installation

1. Clone the repository:
\`\`\`bash
git clone https://github.com/yourusername/vcc-vibe-code-checker.git
cd vcc-vibe-code-checker
\`\`\`

2. Install dependencies:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

3. Configure environment:
\`\`\`bash
cp .env.example .env
# Edit .env with your configuration
\`\`\`

4. Run the application:
\`\`\`bash
python app.py
\`\`\`

Visit http://localhost:5000

## Security

VCC implements 15 advanced security measures based on 2024-2025 research:
- WebAuthn/Passkeys authentication
- RASP (Runtime Application Self-Protection)
- Zero-trust architecture
- Quantum-resistant cryptography ready

## License

© 2024-2025 VCCC. All rights reserved.