# Test script to verify Docker build will work
# Run this before building the full secure image

import sys
import importlib

print("Testing VCC Dependencies...")
print("=" * 40)

# Core dependencies that should be available
required_packages = [
    'flask',
    'flask_socketio', 
    'flask_cors',
    'flask_limiter',
    'flask_talisman',
    'flask_login',
    'authlib',
    'redis',
    'celery',
    'git',  # GitPython
    'cryptography',
    'socketio',
    'eventlet',
    'gunicorn',
    'requests',
    'hvac',
    'pythonjsonlogger',
    'opentelemetry',
    'webauthn',
    'jwt',
    'pyotp'
]

failed_imports = []
successful_imports = []

for package in required_packages:
    try:
        importlib.import_module(package)
        successful_imports.append(package)
        print(f"✅ {package}")
    except ImportError as e:
        failed_imports.append((package, str(e)))
        print(f"❌ {package} - {e}")

print("\n" + "=" * 40)
print(f"Summary: {len(successful_imports)} successful, {len(failed_imports)} failed")

if failed_imports:
    print("\nFailed imports:")
    for pkg, error in failed_imports:
        print(f"  - {pkg}: {error}")
    print("\nNote: Some failures are expected if packages aren't installed yet.")
    print("The Docker build will install these dependencies.")
else:
    print("\n🎉 All dependencies are available!")

print(f"\nPython version: {sys.version}")
