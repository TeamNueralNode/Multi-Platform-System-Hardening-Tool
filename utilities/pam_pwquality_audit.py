#!/usr/bin/env python3
"""
PAM pwquality Audit Script
Audits PAM password quality settings per Annexure requirements
"""

import os
import re
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any


class PAMPwqualityAuditor:
    """Audits PAM password quality configuration."""
    
    def __init__(self):
        # Common PAM configuration files by distribution
        self.pam_password_files = [
            "/etc/pam.d/common-password",  # Debian/Ubuntu
            "/etc/pam.d/system-auth",      # RHEL/CentOS/Fedora
            "/etc/pam.d/password-auth",    # RHEL/CentOS/Fedora
            "/etc/pam.d/passwd"            # Some distributions
        ]
        
        self.pwquality_conf = "/etc/security/pwquality.conf"
        
        # Required settings per Annexure
        self.required_settings = {
            'minlen': 14,          # Minimum password length
            'dcredit': -1,         # At least 1 digit
            'ucredit': -1,         # At least 1 uppercase
            'lcredit': -1,         # At least 1 lowercase  
            'ocredit': -1,         # At least 1 special character
            'retry': 3,            # Maximum retry attempts
            'dictcheck': 1,        # Enable dictionary check
            'maxrepeat': 3,        # Maximum consecutive identical characters
            'maxclasschg': 4,      # Maximum consecutive characters from same class
            'minclass': 4,         # Minimum character classes required
            'difok': 5,            # Minimum different characters from old password
            'gecoscheck': 1,       # Check against GECOS field
            'badwords': '',        # Custom bad words (empty by default)
            'enforce_for_root': 1  # Enforce for root user
        }
    
    def find_active_pam_file(self) -> Optional[str]:
        """Find the active PAM password configuration file."""
        for pam_file in self.pam_password_files:
            if Path(pam_file).exists():
                return pam_file
        return None
    
    def parse_pam_password_file(self, pam_file: str) -> Dict[str, Any]:
        """Parse PAM password configuration file."""
        result = {
            'file_path': pam_file,
            'exists': False,
            'pam_pwquality_enabled': False,
            'pam_pwhistory_enabled': False,
            'pam_faillock_enabled': False,
            'pwquality_settings': {},
            'raw_lines': []
        }
        
        if not Path(pam_file).exists():
            return result
        
        result['exists'] = True
        
        try:
            with open(pam_file, 'r') as f:
                lines = f.readlines()
                result['raw_lines'] = [line.strip() for line in lines]
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Check for pam_pwquality
                    if 'pam_pwquality' in line and not line.startswith('#'):
                        result['pam_pwquality_enabled'] = True
                        
                        # Extract pwquality settings from PAM line
                        settings = self._extract_pam_settings(line)
                        result['pwquality_settings'].update(settings)
                    
                    # Check for pam_pwhistory
                    if 'pam_pwhistory' in line and not line.startswith('#'):
                        result['pam_pwhistory_enabled'] = True
                    
                    # Check for pam_faillock
                    if 'pam_faillock' in line and not line.startswith('#'):
                        result['pam_faillock_enabled'] = True
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _extract_pam_settings(self, line: str) -> Dict[str, str]:
        """Extract settings from PAM configuration line."""
        settings = {}
        
        # Match patterns like minlen=14, dcredit=-1, etc.
        pattern = r'(\w+)=([^\s]+)'
        matches = re.findall(pattern, line)
        
        for key, value in matches:
            settings[key] = value
        
        return settings
    
    def parse_pwquality_conf(self) -> Dict[str, Any]:
        """Parse /etc/security/pwquality.conf file."""
        result = {
            'file_path': self.pwquality_conf,
            'exists': False,
            'settings': {},
            'raw_lines': []
        }
        
        if not Path(self.pwquality_conf).exists():
            return result
        
        result['exists'] = True
        
        try:
            with open(self.pwquality_conf, 'r') as f:
                lines = f.readlines()
                result['raw_lines'] = [line.strip() for line in lines]
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse key = value pairs
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        result['settings'][key] = value
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def get_effective_settings(self) -> Dict[str, str]:
        """Get effective pwquality settings (PAM settings override conf file)."""
        # Start with pwquality.conf settings
        conf_data = self.parse_pwquality_conf()
        effective_settings = conf_data.get('settings', {}).copy()
        
        # Override with PAM file settings
        pam_file = self.find_active_pam_file()
        if pam_file:
            pam_data = self.parse_pam_password_file(pam_file)
            effective_settings.update(pam_data.get('pwquality_settings', {}))
        
        return effective_settings
    
    def audit_setting(self, setting_name: str, current_value: str, required_value: Any) -> Dict[str, Any]:
        """Audit individual setting compliance."""
        result = {
            'setting': setting_name,
            'current': current_value,
            'required': str(required_value),
            'compliant': False,
            'action': 'not_set'
        }
        
        if not current_value:
            result['action'] = f'set_to_{required_value}'
            return result
        
        try:
            # Convert values for comparison
            if isinstance(required_value, int):
                current_int = int(current_value)
                required_int = int(required_value)
                
                if current_int == required_int:
                    result['compliant'] = True
                    result['action'] = 'compliant'
                else:
                    result['action'] = f'change_from_{current_value}_to_{required_value}'
            else:
                if str(current_value) == str(required_value):
                    result['compliant'] = True
                    result['action'] = 'compliant'
                else:
                    result['action'] = f'change_from_{current_value}_to_{required_value}'
        
        except ValueError:
            result['action'] = f'invalid_value_change_to_{required_value}'
        
        return result
    
    def audit_pam_modules(self) -> Dict[str, Any]:
        """Audit required PAM modules configuration."""
        pam_file = self.find_active_pam_file()
        
        result = {
            'pam_file': pam_file,
            'modules': {
                'pam_pwquality': {'enabled': False, 'compliant': False},
                'pam_pwhistory': {'enabled': False, 'compliant': False},
                'pam_faillock': {'enabled': False, 'compliant': False}
            }
        }
        
        if not pam_file:
            result['error'] = 'No PAM password configuration file found'
            return result
        
        pam_data = self.parse_pam_password_file(pam_file)
        
        # Check pam_pwquality
        result['modules']['pam_pwquality']['enabled'] = pam_data['pam_pwquality_enabled']
        result['modules']['pam_pwquality']['compliant'] = pam_data['pam_pwquality_enabled']
        
        # Check pam_pwhistory
        result['modules']['pam_pwhistory']['enabled'] = pam_data['pam_pwhistory_enabled']
        result['modules']['pam_pwhistory']['compliant'] = pam_data['pam_pwhistory_enabled']
        
        # Check pam_faillock
        result['modules']['pam_faillock']['enabled'] = pam_data['pam_faillock_enabled']
        result['modules']['pam_faillock']['compliant'] = pam_data['pam_faillock_enabled']
        
        return result
    
    def audit_all_settings(self) -> Dict[str, Any]:
        """Perform comprehensive audit of all PAM pwquality settings."""
        results = {
            'timestamp': datetime.now().isoformat(),
            'operation': 'audit',
            'pam_file_analysis': None,
            'pwquality_conf_analysis': None,
            'pam_modules_check': None,
            'settings_audit': [],
            'compliance': {
                'pam_modules_compliant': False,
                'settings_compliant': False,
                'overall_compliant': False
            },
            'recommendations': []
        }
        
        # Analyze configuration files
        pam_file = self.find_active_pam_file()
        if pam_file:
            results['pam_file_analysis'] = self.parse_pam_password_file(pam_file)
        
        results['pwquality_conf_analysis'] = self.parse_pwquality_conf()
        
        # Audit PAM modules
        results['pam_modules_check'] = self.audit_pam_modules()
        
        # Check if all required modules are enabled
        modules_check = results['pam_modules_check']['modules']
        all_modules_compliant = all(
            module['compliant'] for module in modules_check.values()
        )
        results['compliance']['pam_modules_compliant'] = all_modules_compliant
        
        if not all_modules_compliant:
            for module_name, module_info in modules_check.items():
                if not module_info['compliant']:
                    results['recommendations'].append(f"Enable {module_name} in PAM configuration")
        
        # Audit individual settings
        effective_settings = self.get_effective_settings()
        settings_compliant_count = 0
        
        for setting_name, required_value in self.required_settings.items():
            current_value = effective_settings.get(setting_name, '')
            audit_result = self.audit_setting(setting_name, current_value, required_value)
            results['settings_audit'].append(audit_result)
            
            if audit_result['compliant']:
                settings_compliant_count += 1
            else:
                results['recommendations'].append(
                    f"Set {setting_name} to {required_value} (currently: {current_value or 'not set'})"
                )
        
        # Calculate settings compliance
        total_settings = len(self.required_settings)
        results['compliance']['settings_compliant'] = (settings_compliant_count == total_settings)
        
        # Overall compliance
        results['compliance']['overall_compliant'] = (
            results['compliance']['pam_modules_compliant'] and 
            results['compliance']['settings_compliant']
        )
        
        return results


def main():
    """Main function for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Audit PAM password quality configuration')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    parser.add_argument('--check-setting', type=str, help='Check specific setting only')
    
    args = parser.parse_args()
    
    auditor = PAMPwqualityAuditor()
    
    if args.check_setting:
        # Check single setting
        effective_settings = auditor.get_effective_settings()
        current_value = effective_settings.get(args.check_setting, '')
        required_value = auditor.required_settings.get(args.check_setting)
        
        if required_value is None:
            print(f"Error: Unknown setting '{args.check_setting}'")
            return 1
        
        result = auditor.audit_setting(args.check_setting, current_value, required_value)
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Setting: {result['setting']}")
            print(f"Current: {result['current'] or 'not set'}")
            print(f"Required: {result['required']}")
            print(f"Compliant: {'✓' if result['compliant'] else '✗'}")
            print(f"Action: {result['action']}")
    
    else:
        # Full audit
        results = auditor.audit_all_settings()
        
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print("PAM Password Quality Configuration Audit")
            print("=" * 50)
            print(f"Timestamp: {results['timestamp']}\n")
            
            # PAM Modules Status
            if results['pam_modules_check']:
                modules = results['pam_modules_check']['modules']
                print("PAM Modules Status:")
                for module_name, module_info in modules.items():
                    status = "✓" if module_info['compliant'] else "✗"
                    print(f"  {module_name}: {status} {'Enabled' if module_info['enabled'] else 'Disabled'}")
                print()
            
            # Settings Audit
            print("Password Quality Settings:")
            compliant_count = 0
            for setting in results['settings_audit']:
                status = "✓" if setting['compliant'] else "✗"
                print(f"  {setting['setting']}: {status} {setting['current'] or 'not set'} (required: {setting['required']})")
                if setting['compliant']:
                    compliant_count += 1
            
            print(f"\nSettings Compliance: {compliant_count}/{len(results['settings_audit'])}")
            
            # Overall Compliance
            compliance = results['compliance']
            print(f"Overall Compliance: {'✓ COMPLIANT' if compliance['overall_compliant'] else '✗ NON-COMPLIANT'}")
            
            # Recommendations
            if results['recommendations']:
                print("\nRecommendations:")
                for rec in results['recommendations']:
                    print(f"  • {rec}")
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())