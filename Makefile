.PHONY: help install test run clean docker-build docker-run docker-stop setup

# Default target
help:
	@echo "Available commands:"
	@echo "  install      - Install Python dependencies"
	@echo "  test         - Run tests"
	@echo "  run          - Run the Flask application"
	@echo "  run-worker   - Run Celery worker"
	@echo "  clean        - Clean up temporary files"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker Compose"
	@echo "  docker-stop  - Stop Docker Compose services"
	@echo "  setup        - Initial setup (install + env setup)"

# Install dependencies
install:
	pip install -r requirements.txt

# Run tests
test:
	python -m pytest test_app.py -v

# Run the Flask application
run:
	python app.py

# Run Celery worker
run-worker:
	celery -A app.celery worker --loglevel=info

# Clean up temporary files
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.log" -delete
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -f .coverage

# Build Docker image
docker-build:
	docker build -t vibe-code-detector .

# Run with Docker Compose
docker-run:
	docker-compose up --build

# Run with Docker Compose in background
docker-run-bg:
	docker-compose up -d --build

# Stop Docker Compose services
docker-stop:
	docker-compose down

# Initial setup
setup: install
	@echo "Setting up Vibe-Code Detector..."
	@if [ ! -f .env ]; then \
		echo "Creating .env file from template..."; \
		cp env.example .env; \
		echo "Please edit .env file with your GitHub OAuth credentials"; \
	else \
		echo ".env file already exists"; \
	fi
	@echo "Setup complete! Don't forget to:"
	@echo "1. Edit .env file with your GitHub OAuth credentials"
	@echo "2. Start Redis server"
	@echo "3. Run 'make run' to start the application"

# Development setup with virtual environment
dev-setup:
	python -m venv venv
	@echo "Virtual environment created. Activate it with:"
	@echo "  source venv/bin/activate  # On Unix/macOS"
	@echo "  venv\\Scripts\\activate     # On Windows"
	@echo "Then run 'make install' to install dependencies"

# Format code
format:
	black .
	flake8 .

# Security check
security:
	bandit -r . -f json -o security-report.json
	@echo "Security report generated: security-report.json"

# Performance check
performance:
	python -m cProfile -o profile.stats app.py
	@echo "Performance profile generated: profile.stats"

# Database setup (if needed in future)
db-setup:
	@echo "Database setup not implemented yet"

# Backup
backup:
	@echo "Creating backup..."
	tar -czf backup-$(shell date +%Y%m%d-%H%M%S).tar.gz \
		--exclude=venv \
		--exclude=__pycache__ \
		--exclude=*.pyc \
		--exclude=.env \
		.

# Production deployment
deploy:
	@echo "Production deployment not implemented yet"
	@echo "Consider using Docker Compose or a cloud platform" 