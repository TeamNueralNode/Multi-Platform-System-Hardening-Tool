"""
Resource finder for PyInstaller bundled applications.
Locates YAML rules, scripts, and other bundled resources at runtime.
"""

import os
import sys
from pathlib import Path
from typing import Optional, List


def get_bundle_dir() -> Path:
    """Get the directory containing bundled resources."""
    if hasattr(sys, '_MEIPASS'):
        # Running as PyInstaller bundle
        return Path(sys._MEIPASS)
    else:
        # Running as normal Python script
        return Path(__file__).parent.parent


def find_rules_directory() -> Optional[Path]:
    """Find the rules definitions directory."""
    bundle_dir = get_bundle_dir()
    
    # Try bundled rules first
    rules_dir = bundle_dir / 'rules' / 'definitions'
    if rules_dir.exists():
        return rules_dir
    
    # Try relative to script location
    script_dir = Path(__file__).parent.parent
    rules_dir = script_dir / 'hardening_tool' / 'rules' / 'definitions'
    if rules_dir.exists():
        return rules_dir
    
    # Try current working directory
    rules_dir = Path.cwd() / 'rules' / 'definitions'
    if rules_dir.exists():
        return rules_dir
    
    return None


def find_script_file(script_name: str) -> Optional[Path]:
    """Find a bundled script file."""
    bundle_dir = get_bundle_dir()
    
    # Try bundled scripts
    script_path = bundle_dir / 'scripts' / script_name
    if script_path.exists():
        return script_path
    
    # Try bundle root
    script_path = bundle_dir / script_name
    if script_path.exists():
        return script_path
    
    # Try relative to current location
    script_dir = Path(__file__).parent.parent
    script_path = script_dir / script_name
    if script_path.exists():
        return script_path
    
    return None


def find_template_file(template_name: str) -> Optional[Path]:
    """Find a bundled template file."""
    bundle_dir = get_bundle_dir()
    
    # Try bundle root
    template_path = bundle_dir / template_name
    if template_path.exists():
        return template_path
    
    # Try relative to script location
    script_dir = Path(__file__).parent.parent
    template_path = script_dir / template_name
    if template_path.exists():
        return template_path
    
    return None


def list_bundled_resources() -> dict:
    """List all bundled resources for debugging."""
    bundle_dir = get_bundle_dir()
    
    resources = {
        'bundle_dir': str(bundle_dir),
        'rules': [],
        'scripts': [],
        'templates': [],
        'docs': []
    }
    
    # Find rules
    rules_dir = find_rules_directory()
    if rules_dir:
        resources['rules'] = [str(f) for f in rules_dir.glob('*.yaml')]
    
    # Find scripts
    scripts_dir = bundle_dir / 'scripts'
    if scripts_dir.exists():
        resources['scripts'] = [str(f) for f in scripts_dir.iterdir() if f.is_file()]
    
    # Find templates
    for template in ['report_template.html']:
        template_path = find_template_file(template)
        if template_path:
            resources['templates'].append(str(template_path))
    
    # Find docs
    for doc in ['README.md', 'TESTING.md', 'LICENSE']:
        doc_path = bundle_dir / doc
        if doc_path.exists():
            resources['docs'].append(str(doc_path))
    
    return resources
