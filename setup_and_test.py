#!/usr/bin/env python3
"""
Setup and test script for Multi-Platform System Hardening Tool.

This script demonstrates the complete setup and basic testing of the hardening tool.
"""

import subprocess
import sys
from pathlib import Path


def run_command(command: str, description: str) -> bool:
    """Run a command and return success status."""
    print(f"🔧 {description}")
    print(f"   Running: {command}")
    
    try:
        result = subprocess.run(command, shell=True, check=True, 
                              capture_output=True, text=True)
        print(f"   ✅ Success")
        return True
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Failed: {e}")
        if e.stdout:
            print(f"   stdout: {e.stdout}")
        if e.stderr:
            print(f"   stderr: {e.stderr}")
        return False


def main():
    """Main setup and test procedure."""
    print("🚀 Multi-Platform System Hardening Tool - Setup & Test")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 11):
        print("❌ Python 3.11+ is required")
        sys.exit(1)
    
    print(f"✅ Python {sys.version}")
    
    # Install the package in development mode
    if not run_command("pip install -e .", "Installing hardening tool in development mode"):
        print("❌ Installation failed")
        sys.exit(1)
    
    # Test basic imports
    try:
        print("🧪 Testing basic imports...")
        from hardening_tool import HardeningTool
        from hardening_tool.utils.os_detection import detect_os, validate_supported_os
        from hardening_tool.core.models import OSType
        print("   ✅ All imports successful")
    except ImportError as e:
        print(f"   ❌ Import failed: {e}")
        sys.exit(1)
    
    # Test OS detection
    try:
        print("🔍 Testing OS detection...")
        system_info = detect_os()
        print(f"   Detected OS: {system_info.os_type.value}")
        print(f"   OS Version: {system_info.os_version}")
        print(f"   Architecture: {system_info.architecture}")
        print(f"   Hostname: {system_info.hostname}")
        
        supported = validate_supported_os(system_info)
        print(f"   Supported: {'✅ Yes' if supported else '❌ No'}")
        
    except Exception as e:
        print(f"   ❌ OS detection failed: {e}")
        sys.exit(1)
    
    # Test rule loading
    try:
        print("📋 Testing rule loading...")
        from hardening_tool.rules.loader import RuleLoader
        loader = RuleLoader()
        rules = loader.get_rules()
        print(f"   ✅ Loaded {len(rules)} rules")
        
        # Show sample rules
        for rule in rules[:3]:  # Show first 3 rules
            print(f"   - {rule.id}: {rule.title}")
            
    except Exception as e:
        print(f"   ❌ Rule loading failed: {e}")
        sys.exit(1)
    
    # Test CLI help
    if not run_command("hardening-tool --help", "Testing CLI interface"):
        print("❌ CLI test failed")
        sys.exit(1)
    
    # Test audit command (dry run)
    print("🔍 Testing audit functionality...")
    try:
        tool = HardeningTool()
        result = tool.audit()
        print(f"   ✅ Audit completed - Score: {result.overall_score:.1f}%")
        print(f"   Rules: {result.run.total_rules} total, {result.run.passed_rules} passed, {result.run.failed_rules} failed")
    except Exception as e:
        print(f"   ❌ Audit test failed: {e}")
        # Don't exit here as this might fail on unsupported systems
    
    # Summary
    print("\n" + "=" * 60)
    print("🎉 Setup and basic testing completed!")
    print("\n📖 Next steps:")
    print("   1. Run: hardening-tool audit")
    print("   2. Review results and understand current compliance")
    print("   3. Test with: hardening-tool apply --dry-run")
    print("   4. Create rollback point: hardening-tool apply --interactive")
    print("\n⚠️  Important:")
    print("   - Always test in a non-production environment first")
    print("   - Ensure you have proper backups")
    print("   - Run with administrative privileges when applying changes")
    print("   - Review the documentation in README.md")
    
    print(f"\n📁 Project structure created in: {Path.cwd()}")


if __name__ == "__main__":
    main()