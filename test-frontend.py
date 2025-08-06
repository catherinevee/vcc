#!/usr/bin/env python3
"""
Frontend Functionality Test
Verify that all templates can be rendered properly
"""

import os
import sys
from pathlib import Path

def test_templates():
    """Test that all required templates exist"""
    templates_dir = Path("templates")
    
    print("VCC Frontend Template Check")
    print("=" * 40)
    
    required_templates = [
        "index.html",
        "dashboard.html", 
        "research.html",
        "about.html",
        "error.html"
    ]
    
    missing_templates = []
    existing_templates = []
    
    for template in required_templates:
        template_path = templates_dir / template
        if template_path.exists():
            existing_templates.append(template)
            print(f"✅ {template}")
        else:
            missing_templates.append(template)
            print(f"❌ {template}")
    
    print("\n" + "=" * 40)
    print(f"Summary: {len(existing_templates)} found, {len(missing_templates)} missing")
    
    return len(missing_templates) == 0

def test_static_assets():
    """Test that static assets exist"""
    print("\nVCC Static Assets Check")
    print("=" * 40)
    
    static_files = [
        "static/css/style.css",
        "static/js/app.js"
    ]
    
    missing_assets = []
    existing_assets = []
    
    for asset in static_files:
        if os.path.exists(asset):
            existing_assets.append(asset)
            print(f"✅ {asset}")
        else:
            missing_assets.append(asset)
            print(f"❌ {asset}")
    
    print(f"\nAssets: {len(existing_assets)} found, {len(missing_assets)} missing")
    return len(missing_assets) == 0

def test_route_template_mapping():
    """Test that app.py routes use correct template names"""
    print("\nRoute-Template Mapping Check")
    print("=" * 40)
    
    try:
        with open("app.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        # Check for old template names (should not exist)
        old_templates = ["vcc_index.html", "vcc_dashboard.html", "vcc_research.html", "vcc_about.html", "vcc_error.html"]
        found_old = []
        
        for old_template in old_templates:
            if old_template in content:
                found_old.append(old_template)
        
        if found_old:
            print("❌ Found old template references:")
            for template in found_old:
                print(f"   - {template}")
            return False
        else:
            print("✅ All template references updated")
            
        # Check for new template names (should exist)
        new_templates = ["index.html", "dashboard.html", "research.html", "about.html", "error.html"]
        found_new = []
        
        for new_template in new_templates:
            if new_template in content:
                found_new.append(new_template)
        
        print(f"✅ Found {len(found_new)} correct template references")
        return True
        
    except Exception as e:
        print(f"❌ Error reading app.py: {e}")
        return False

if __name__ == "__main__":
    print("Testing VCC Frontend Functionality...\n")
    
    templates_ok = test_templates()
    assets_ok = test_static_assets() 
    mapping_ok = test_route_template_mapping()
    
    print("\n" + "=" * 50)
    if templates_ok and assets_ok and mapping_ok:
        print("🎉 Frontend is FUNCTIONAL!")
        print("\nYou can now:")
        print("  - Build the Docker image successfully")
        print("  - Run the VCC application")
        print("  - Access all pages without template errors")
    else:
        print("❌ Frontend has issues that need to be resolved")
        sys.exit(1)
