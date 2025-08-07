# Vibe-Code Detector

A secure Flask web application that analyzes GitHub repositories for vibe-coding patterns, technical debt, and code quality issues. The application provides real-time analysis with detailed reports and actionable recommendations.

## What is Vibe-Code Detector?

Vibe-Code Detector is a static code analysis tool designed to identify "vibe-coding" patterns - coding practices that prioritize quick development over code quality, often leading to technical debt. The application scans your codebase to find problematic patterns that could impact security, maintainability, and code quality.

### What is "Vibe-Coding"?

Vibe-coding refers to coding practices that focus on rapid development and "getting things working" rather than following best practices. While this approach can be useful for prototyping, it often leads to:

- **Security vulnerabilities** (hardcoded credentials, insecure patterns)
- **Code quality issues** (debug statements in production, magic numbers)
- **Technical debt** (TODO comments, broad exception handling)
- **Maintainability problems** (poor error handling, inconsistent patterns)

### How It Works

The application follows a comprehensive analysis workflow:

1. **Authentication**: Users authenticate via GitHub OAuth to access their repositories
2. **Repository Selection**: Users select a repository from their GitHub account for analysis
3. **Repository Cloning**: The application securely clones the repository to a temporary location
4. **Static Analysis**: The core analyzer scans the codebase for various patterns across multiple programming languages
5. **Pattern Detection**: Identifies issues like hardcoded credentials, debug statements, security vulnerabilities, and code quality problems
6. **Report Generation**: Creates a comprehensive report with severity classifications and actionable recommendations
7. **Real-time Updates**: Provides live progress updates via WebSocket during the analysis process

### Analysis Process

```
Repository URL → Validation → Clone → Static Analysis → Pattern Detection → Report Generation → Results
```

**Step-by-step breakdown:**

1. **Repository Submission**: User provides a GitHub repository URL
2. **Ownership Validation**: App verifies the user owns the repository and checks size limits (100MB max)
3. **Secure Cloning**: Repository is cloned to a temporary, isolated directory
4. **Multi-language Scanning**: Analyzer scans files across supported programming languages
5. **Pattern Recognition**: Identifies specific patterns based on language-specific rules
6. **Severity Assessment**: Classifies findings as Critical, High, Medium, or Low
7. **Report Compilation**: Generates comprehensive report with scores and recommendations
8. **Secure Storage**: Results are encrypted and stored temporarily in Redis
9. **Real-time Delivery**: Results are delivered via WebSocket with live progress updates

## Features

- **Secure GitHub OAuth Integration** - Secure authentication with GitHub
- **Multi-Language Analysis** - Supports Python, JavaScript, TypeScript, Java, C++, C#, PHP, Ruby, Go, Rust, Swift, and Kotlin
- **Real-time Analysis** - Live progress updates via WebSocket
- **Security Scanning** - Detects hardcoded credentials, insecure patterns, and vulnerabilities
- **Code Quality Metrics** - Comprehensive analysis of technical debt and code quality
- **Detailed Reports** - Exportable reports in JSON and Markdown formats
- **Background Processing** - Celery-based task queue for scalable analysis
- **Modern UI** - Responsive Bootstrap-based interface

## Architecture

The application is built with a modern microservices architecture:

- **Flask Web Server** - Main application server with SocketIO for real-time updates
- **Celery Workers** - Background task processing for repository analysis
- **Redis** - Session storage, caching, and message broker
- **GitHub API** - Repository access and authentication

## Quick Start

### Prerequisites

- Python 3.11+
- Redis server
- GitHub OAuth application

### 1. Clone the Repository

```bash
git clone <repository-url>
cd vcc
```

### 2. Set Up Environment

```bash
# Copy environment template
cp env.example .env

# Edit .env with your configuration
# You MUST set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Start Redis

```bash
# On macOS with Homebrew
brew install redis
brew services start redis

# On Ubuntu/Debian
sudo apt-get install redis-server
sudo systemctl start redis

# On Windows
# Download and install Redis from https://redis.io/download
```

### 5. Run the Application

```bash
# Start Celery worker (in a separate terminal)
celery -A app.celery worker --loglevel=info

# Start the Flask application
python app.py
```

The application will be available at `http://localhost:6432`

## Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Build and start all services
docker-compose up --build

# Run in background
docker-compose up -d
```

### Manual Docker Build

```bash
# Build the image
docker build -t vibe-code-detector .

# Run with Redis
docker run -p 6432:6432 --env-file .env vibe-code-detector
```

## GitHub OAuth Setup

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the details:
   - **Application name**: Vibe-Code Detector
   - **Homepage URL**: `http://localhost:6432`
   - **Authorization callback URL**: `http://localhost:6432/authorize`
4. Copy the Client ID and Client Secret to your `.env` file

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_CLIENT_ID` | GitHub OAuth Client ID | Required |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth Client Secret | Required |
| `SECRET_KEY` | Flask secret key | Auto-generated |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379/0` |
| `CELERY_BROKER_URL` | Celery broker URL | `redis://localhost:6379/1` |
| `CELERY_RESULT_BACKEND` | Celery result backend | `redis://localhost:6379/2` |
| `ENCRYPTION_KEY` | Encryption key for sensitive data | Auto-generated |
| `MAX_REPO_SIZE_MB` | Maximum repository size to analyze | `100` |
| `ANALYSIS_TIMEOUT` | Analysis timeout in seconds | `300` |

### Security Features

- **HTTPS Enforcement** - All connections use HTTPS in production
- **Rate Limiting** - API endpoints are rate-limited to prevent abuse
- **Session Security** - Secure, signed sessions with Redis storage
- **CORS Protection** - Strict CORS policies
- **Input Validation** - All inputs are validated and sanitized
- **Encryption** - Sensitive data is encrypted at rest

## API Endpoints

### Authentication
- `GET /login` - Initiate GitHub OAuth login
- `GET /authorize` - OAuth callback handler
- `GET /logout` - Logout user

### Analysis
- `POST /api/analyze` - Start repository analysis
- `GET /api/results/<key>` - Get analysis results
- `GET /api/export/<key>` - Export results as JSON/Markdown

### WebSocket Events
- `connect` - Client connects to WebSocket
- `join_analysis` - Join analysis room for updates
- `leave_analysis` - Leave analysis room
- `analysis_progress` - Real-time progress updates
- `analysis_complete` - Analysis completion notification

## What Does It Detect?

The application identifies various patterns that indicate potential issues in your codebase:

### Security Analysis
- **Hardcoded Credentials**: API keys, passwords, tokens embedded in code
- **Insecure Patterns**: Weak authentication, unsafe data handling
- **Potential Vulnerabilities**: SQL injection patterns, XSS indicators
- **Dangerous Functions**: eval() usage, unsafe deserialization

### Code Quality Analysis
- **Debug Statements**: print() in Python, console.log() in JavaScript
- **Exception Handling**: Overly broad try-catch blocks
- **Code Comments**: TODO/FIXME comments indicating incomplete work
- **Magic Numbers**: Hardcoded values without explanation
- **Code Smells**: Long functions, complex conditionals, code duplication

### Technical Debt Metrics
- **Vibe-Coding Score**: Overall code quality rating (0-100)
- **Technical Debt Hours**: Estimated time to fix identified issues
- **Severity Classification**: Critical, High, Medium, Low priority issues
- **Actionable Recommendations**: Specific suggestions for improvement

## What You Get

### Comprehensive Reports
- **Executive Summary**: High-level overview of findings
- **Detailed Findings**: File locations, line numbers, and specific issues
- **Severity Breakdown**: Count of issues by priority level
- **Fix Suggestions**: Actionable recommendations for each finding
- **Confidence Scores**: How certain the analyzer is about each detection

### Export Options
- **JSON Format**: Machine-readable data for integration with other tools
- **Markdown Reports**: Human-readable reports for documentation
- **Real-time Updates**: Live progress during analysis
- **Secure Storage**: Encrypted results with automatic expiration

### Use Cases
- **Code Reviews**: Identify issues before merging pull requests
- **Technical Debt Assessment**: Quantify code quality problems
- **Security Audits**: Find potential vulnerabilities
- **Team Onboarding**: Help new developers understand codebase quality
- **CI/CD Integration**: Automated quality checks in development pipelines

## Development

### Project Structure

```
vcc/
├── app.py                 # Main Flask application
├── vibe_code_detector.py  # Core analysis engine
├── templates/             # HTML templates
│   ├── base.html         # Base template
│   ├── index.html        # Home page
│   └── dashboard.html    # Dashboard page
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose setup
├── env.example          # Environment template
└── README.md           # This file
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-flask

# Run tests
pytest
```

### Code Style

The project follows PEP 8 style guidelines. Use a linter like `flake8` or `black`:

```bash
pip install flake8 black
flake8 .
black .
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the code examples

## Roadmap

- [ ] Support for more programming languages
- [ ] Advanced static analysis integration
- [ ] Team collaboration features
- [ ] CI/CD integration
- [ ] Advanced reporting and analytics
- [ ] API rate limiting improvements
- [ ] Mobile application 