#!/usr/bin/env python3
"""
Verification script to check that the vcc.py rename was successful
"""

import os
import sys

def check_file_rename():
    """Check if the file rename was successful"""
    print("VCC File Rename Verification")
    print("=" * 40)
    
    # Check if old file is gone
    old_file = "vibe_code_detector.py"
    new_file = "vcc.py"
    
    if os.path.exists(old_file):
        print(f"❌ {old_file} still exists - rename incomplete")
        return False
    else:
        print(f"✅ {old_file} successfully removed")
    
    if os.path.exists(new_file):
        print(f"✅ {new_file} exists")
    else:
        print(f"❌ {new_file} not found")
        return False
    
    # Test that the file is valid Python syntax
    try:
        with open(new_file, 'r') as f:
            content = f.read()
        
        # Check if it contains the expected class
        if "class VibeCodeAnalyzer" in content:
            print("✅ vcc.py contains VibeCodeAnalyzer class")
        elif "VibeCodeAnalyzer" in content:
            print("✅ vcc.py contains VibeCodeAnalyzer")
        else:
            print("⚠️  VibeCodeAnalyzer class not found in vcc.py")
        
        # Try to compile the file (syntax check)
        compile(content, new_file, 'exec')
        print("✅ vcc.py syntax is valid")
        return True
        
    except Exception as e:
        print(f"❌ Error reading/compiling vcc.py: {e}")
        return False

def check_dockerfile():
    """Check if Dockerfile was updated"""
    dockerfile_path = "docker/Dockerfile.secure"
    
    if not os.path.exists(dockerfile_path):
        print(f"❌ {dockerfile_path} not found")
        return False
    
    with open(dockerfile_path, 'r') as f:
        content = f.read()
    
    if "vibe_code_detector.py" in content:
        print("❌ Dockerfile still references old filename")
        return False
    elif "../vcc.py" in content:
        print("✅ Dockerfile updated with new filename")
        return True
    else:
        print("⚠️  Dockerfile may need manual review")
        return False

if __name__ == "__main__":
    print("Running verification checks...\n")
    
    file_check = check_file_rename()
    dockerfile_check = check_dockerfile()
    
    print("\n" + "=" * 40)
    if file_check and dockerfile_check:
        print("🎉 All checks passed! Rename successful.")
        print("\nYou can now build the Docker image with:")
        print("  ./build-secure.ps1  (Windows)")
        print("  ./build-secure.sh   (Linux/macOS)")
    else:
        print("❌ Some checks failed. Please review the issues above.")
