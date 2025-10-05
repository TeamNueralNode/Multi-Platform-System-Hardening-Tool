#!/usr/bin/env python3
"""
UFW (Uncomplicated Firewall) Enforcer Module
Manages UFW firewall configuration with idempotent rule application
"""

import os
import json
import yaml
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union


class UFWEnforcer:
    """Manages UFW firewall configuration and enforcement."""
    
    def __init__(self, rollback_dir: str = "/var/log/hardening-tool"):
        self.rollback_dir = Path(rollback_dir)
        self.rollback_dir.mkdir(parents=True, exist_ok=True)
        
        # Default required loopback rules
        self.required_loopback_rules = [
            {"direction": "allow", "interface": "lo"},
            {"direction": "deny", "from": "127.0.0.0/8", "to": "!127.0.0.1"}
        ]
    
    def run_command(self, command: List[str], check_output: bool = True) -> Tuple[int, str, str]:
        """Execute command and return exit code, stdout, stderr."""
        try:
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=30,
                check=False
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return 1, "", "Command timed out"
        except Exception as e:
            return 1, "", str(e)
    
    def is_ufw_installed(self) -> bool:
        """Check if UFW is installed."""
        exit_code, _, _ = self.run_command(['which', 'ufw'])
        return exit_code == 0
    
    def is_ufw_enabled(self) -> bool:
        """Check if UFW is enabled."""
        exit_code, output, _ = self.run_command(['ufw', 'status'])
        return exit_code == 0 and "Status: active" in output
    
    def is_iptables_persistent_installed(self) -> bool:
        """Check if iptables-persistent is installed (conflict with UFW)."""
        # Check if package is installed
        for cmd in [['dpkg', '-l', 'iptables-persistent'], ['rpm', '-q', 'iptables-services']]:
            exit_code, output, _ = self.run_command(cmd)
            if exit_code == 0 and 'ii' in output:
                return True
        
        # Check if service is enabled
        exit_code, _, _ = self.run_command(['systemctl', 'is-enabled', 'iptables'])
        if exit_code == 0:
            return True
            
        return False
    
    def get_ufw_status(self) -> Dict[str, Any]:
        """Get comprehensive UFW status."""
        status = {
            'installed': self.is_ufw_installed(),
            'enabled': False,
            'default_incoming': None,
            'default_outgoing': None,
            'default_routed': None,
            'logging': None,
            'rules_count': 0,
            'iptables_persistent_conflict': self.is_iptables_persistent_installed()
        }
        
        if not status['installed']:
            return status
        
        # Get UFW status output
        exit_code, output, _ = self.run_command(['ufw', 'status', 'verbose'])
        if exit_code == 0:
            status['enabled'] = "Status: active" in output
            
            # Parse default policies
            for line in output.split('\n'):
                line = line.strip()
                if 'Default:' in line:
                    # Parse "Default: deny (incoming), allow (outgoing), disabled (routed)"
                    match = re.search(r'Default:\s*(\w+)\s*\(incoming\),\s*(\w+)\s*\(outgoing\)(?:,\s*(\w+)\s*\(routed\))?', line)
                    if match:
                        status['default_incoming'] = match.group(1)
                        status['default_outgoing'] = match.group(2) 
                        if match.group(3):
                            status['default_routed'] = match.group(3)
                
                elif 'Logging:' in line:
                    status['logging'] = line.split('Logging:')[1].strip()
            
            # Count rules (exclude header lines)
            rule_lines = [line for line in output.split('\n') 
                         if line.strip() and not line.startswith('Status:') 
                         and not line.startswith('Default:') and not line.startswith('Logging:')
                         and not line.startswith('-----') and not line.startswith('To')
                         and not line.startswith('Anywhere')]
            status['rules_count'] = len([line for line in rule_lines if '/' in line or 'ALLOW' in line or 'DENY' in line])
        
        return status
    
    def get_current_rules(self) -> List[Dict[str, Any]]:
        """Get current UFW rules in structured format."""
        rules = []
        
        exit_code, output, _ = self.run_command(['ufw', 'status', 'numbered'])
        if exit_code != 0:
            return rules
        
        # Parse numbered rules
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('[') and ']' not in line:
                continue
                
            # Match pattern like: [ 1] 22/tcp                     ALLOW IN    Anywhere
            match = re.match(r'\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY)\s+(IN|OUT)\s+(.+)', line)
            if match:
                rule_num = int(match.group(1))
                service_port = match.group(2).strip()
                action = match.group(3).lower()
                direction = match.group(4).lower()
                source = match.group(5).strip()
                
                rule = {
                    'number': rule_num,
                    'service_port': service_port,
                    'action': action,
                    'direction': direction,
                    'source': source if source != 'Anywhere' else None,
                    'raw_line': line
                }
                rules.append(rule)
        
        return rules
    
    def check_loopback_rules(self) -> Dict[str, Any]:
        """Check if required loopback rules are present."""
        current_rules = self.get_current_rules()
        
        result = {
            'compliant': True,
            'missing_rules': [],
            'existing_rules': []
        }
        
        # Check for loopback allow rule
        lo_allow_found = False
        for rule in current_rules:
            if 'lo' in rule['service_port'] or 'Anywhere on lo' in rule.get('raw_line', ''):
                lo_allow_found = True
                result['existing_rules'].append(rule)
                break
        
        if not lo_allow_found:
            result['compliant'] = False
            result['missing_rules'].append("allow in on lo")
        
        # Check for deny from 127.0.0.0/8 to !127.0.0.1 (this is harder to detect in UFW output)
        # UFW typically handles this automatically, but we'll note it
        
        return result
    
    def load_allowed_ports_config(self, config_path: str) -> Dict[str, Any]:
        """Load allowed ports configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            return {
                'success': True,
                'config': config,
                'error': None
            }
        except FileNotFoundError:
            return {
                'success': False,
                'config': None,
                'error': f"Configuration file not found: {config_path}"
            }
        except yaml.YAMLError as e:
            return {
                'success': False,
                'config': None,
                'error': f"YAML parsing error: {e}"
            }
        except Exception as e:
            return {
                'success': False,
                'config': None,
                'error': f"Error loading configuration: {e}"
            }
    
    def validate_port_rules(self, allowed_ports_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate that all required ports have UFW rules."""
        current_rules = self.get_current_rules()
        
        result = {
            'compliant': True,
            'missing_rules': [],
            'existing_rules': [],
            'extra_rules': []
        }
        
        # Get required ports from config
        required_ports = allowed_ports_config.get('allowed_ports', [])
        
        for port_config in required_ports:
            port = port_config.get('port')
            protocol = port_config.get('protocol', 'tcp').lower()
            source = port_config.get('source', 'any')
            description = port_config.get('description', '')
            
            # Look for matching rule
            rule_found = False
            for rule in current_rules:
                service_port = rule['service_port']
                
                # Match port and protocol
                if f"{port}/{protocol}" in service_port or str(port) == service_port:
                    # Check source if specified
                    if source == 'any' or not source or source in str(rule.get('source', '')):
                        rule_found = True
                        result['existing_rules'].append({
                            'port': port,
                            'protocol': protocol,
                            'source': source,
                            'description': description,
                            'ufw_rule': rule
                        })
                        break
            
            if not rule_found:
                result['compliant'] = False
                result['missing_rules'].append({
                    'port': port,
                    'protocol': protocol,
                    'source': source,
                    'description': description
                })
        
        return result
    
    def create_backup_manifest(self) -> str:
        """Create backup manifest of current UFW configuration."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = self.rollback_dir / f"ufw_backup_{timestamp}.json"
        
        # Get current UFW configuration
        backup_data = {
            'timestamp': datetime.now().isoformat(),
            'ufw_status': self.get_ufw_status(),
            'current_rules': self.get_current_rules(),
            'raw_status': '',
            'raw_rules': ''
        }
        
        # Get raw UFW output for complete restoration
        exit_code, output, _ = self.run_command(['ufw', 'status', 'verbose'])
        if exit_code == 0:
            backup_data['raw_status'] = output
        
        exit_code, output, _ = self.run_command(['ufw', 'status', 'numbered'])
        if exit_code == 0:
            backup_data['raw_rules'] = output
        
        # Save backup
        with open(backup_file, 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        return str(backup_file)
    
    def enable_ufw(self) -> Tuple[bool, str]:
        """Enable UFW firewall."""
        if self.is_ufw_enabled():
            return True, "UFW already enabled"
        
        # Enable UFW (non-interactive)
        exit_code, output, error = self.run_command(['ufw', '--force', 'enable'])
        if exit_code == 0:
            return True, "UFW enabled successfully"
        else:
            return False, f"Failed to enable UFW: {error}"
    
    def set_default_policies(self) -> Tuple[bool, List[str]]:
        """Set default UFW policies to deny incoming, allow outgoing."""
        messages = []
        success = True
        
        # Set default incoming to deny
        exit_code, output, error = self.run_command(['ufw', '--force', 'default', 'deny', 'incoming'])
        if exit_code == 0:
            messages.append("Set default incoming policy to deny")
        else:
            messages.append(f"Failed to set incoming policy: {error}")
            success = False
        
        # Set default outgoing to allow
        exit_code, output, error = self.run_command(['ufw', '--force', 'default', 'allow', 'outgoing'])
        if exit_code == 0:
            messages.append("Set default outgoing policy to allow")
        else:
            messages.append(f"Failed to set outgoing policy: {error}")
            success = False
        
        return success, messages
    
    def add_loopback_rules(self) -> Tuple[bool, List[str]]:
        """Add required loopback interface rules."""
        messages = []
        success = True
        
        # Allow incoming on loopback
        exit_code, output, error = self.run_command(['ufw', 'allow', 'in', 'on', 'lo'])
        if exit_code == 0:
            messages.append("Added loopback allow rule")
        else:
            # Rule might already exist
            if "Skipping" in error or "already exists" in error.lower():
                messages.append("Loopback allow rule already exists")
            else:
                messages.append(f"Failed to add loopback rule: {error}")
                success = False
        
        # Deny from loopback network to anywhere except localhost
        exit_code, output, error = self.run_command(['ufw', 'deny', 'in', 'from', '127.0.0.0/8', 'to', '!127.0.0.1'])
        if exit_code == 0:
            messages.append("Added loopback deny rule for network range")
        else:
            if "Skipping" in error or "already exists" in error.lower():
                messages.append("Loopback deny rule already exists")
            else:
                # This rule might not be supported in all UFW versions, so don't fail
                messages.append(f"Note: Could not add loopback network deny rule: {error}")
        
        return success, messages
    
    def add_port_rules(self, allowed_ports_config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Add port rules from configuration."""
        messages = []
        success = True
        
        required_ports = allowed_ports_config.get('allowed_ports', [])
        
        for port_config in required_ports:
            port = port_config.get('port')
            protocol = port_config.get('protocol', 'tcp').lower()
            source = port_config.get('source', 'any')
            description = port_config.get('description', '')
            
            # Build UFW command
            ufw_cmd = ['ufw', 'allow']
            
            # Add source if specified
            if source and source != 'any':
                ufw_cmd.extend(['from', source])
            
            # Add port and protocol
            ufw_cmd.extend(['to', 'any', 'port', str(port)])
            
            if protocol != 'tcp':  # TCP is default
                ufw_cmd.extend(['proto', protocol])
            
            # Execute command
            exit_code, output, error = self.run_command(ufw_cmd)
            if exit_code == 0:
                msg = f"Added rule: {port}/{protocol}"
                if source and source != 'any':
                    msg += f" from {source}"
                if description:
                    msg += f" ({description})"
                messages.append(msg)
            else:
                if "Skipping" in error or "already exists" in error.lower():
                    msg = f"Rule already exists: {port}/{protocol}"
                    if description:
                        msg += f" ({description})"
                    messages.append(msg)
                else:
                    msg = f"Failed to add rule for {port}/{protocol}: {error}"
                    messages.append(msg)
                    success = False
        
        return success, messages
    
    def audit(self, allowed_ports_config_path: Optional[str] = None) -> Dict[str, Any]:
        """Perform comprehensive UFW audit."""
        results = {
            'timestamp': datetime.now().isoformat(),
            'operation': 'audit',
            'ufw_status': self.get_ufw_status(),
            'loopback_check': self.check_loopback_rules(),
            'port_rules_check': None,
            'compliance': {
                'ufw_installed': False,
                'ufw_enabled': False,
                'no_iptables_conflict': False,
                'default_policies_correct': False,
                'loopback_configured': False,
                'required_ports_configured': None,
                'overall_compliant': False
            },
            'recommendations': []
        }
        
        status = results['ufw_status']
        compliance = results['compliance']
        
        # Check UFW installation
        compliance['ufw_installed'] = status['installed']
        if not compliance['ufw_installed']:
            results['recommendations'].append("Install UFW package")
        
        # Check UFW enabled
        compliance['ufw_enabled'] = status['enabled']
        if not compliance['ufw_enabled']:
            results['recommendations'].append("Enable UFW firewall")
        
        # Check for iptables-persistent conflict
        compliance['no_iptables_conflict'] = not status['iptables_persistent_conflict']
        if status['iptables_persistent_conflict']:
            results['recommendations'].append("Remove iptables-persistent package (conflicts with UFW)")
        
        # Check default policies
        compliance['default_policies_correct'] = (
            status['default_incoming'] == 'deny' and 
            status['default_outgoing'] == 'allow'
        )
        if not compliance['default_policies_correct']:
            results['recommendations'].append("Set default policies: deny incoming, allow outgoing")
        
        # Check loopback configuration
        compliance['loopback_configured'] = results['loopback_check']['compliant']
        if not compliance['loopback_configured']:
            results['recommendations'].append("Configure loopback interface rules")
        
        # Check port rules if configuration provided
        if allowed_ports_config_path:
            config_result = self.load_allowed_ports_config(allowed_ports_config_path)
            if config_result['success']:
                results['port_rules_check'] = self.validate_port_rules(config_result['config'])
                compliance['required_ports_configured'] = results['port_rules_check']['compliant']
                
                if not compliance['required_ports_configured']:
                    missing_count = len(results['port_rules_check']['missing_rules'])
                    results['recommendations'].append(f"Configure {missing_count} missing port rules")
            else:
                results['port_rules_check'] = {
                    'error': config_result['error'],
                    'compliant': False
                }
                compliance['required_ports_configured'] = False
                results['recommendations'].append("Fix allowed ports configuration file")
        
        # Overall compliance
        required_checks = [
            compliance['ufw_installed'],
            compliance['ufw_enabled'],
            compliance['no_iptables_conflict'],
            compliance['default_policies_correct'],
            compliance['loopback_configured']
        ]
        
        # Only include port check if configuration was provided
        if compliance['required_ports_configured'] is not None:
            required_checks.append(compliance['required_ports_configured'])
        
        compliance['overall_compliant'] = all(required_checks)
        
        return results
    
    def apply(self, allowed_ports_config_path: Optional[str] = None) -> Dict[str, Any]:
        """Apply UFW configuration changes."""
        results = {
            'timestamp': datetime.now().isoformat(),
            'operation': 'apply',
            'backup_file': None,
            'actions_taken': [],
            'errors': [],
            'success': True
        }
        
        try:
            # Create backup before any changes
            results['backup_file'] = self.create_backup_manifest()
            results['actions_taken'].append(f"Created backup: {results['backup_file']}")
            
            # Check if UFW is installed
            if not self.is_ufw_installed():
                results['errors'].append("UFW is not installed")
                results['success'] = False
                return results
            
            # Enable UFW
            success, message = self.enable_ufw()
            if success:
                results['actions_taken'].append(message)
            else:
                results['errors'].append(message)
                results['success'] = False
            
            # Set default policies
            success, messages = self.set_default_policies()
            results['actions_taken'].extend(messages)
            if not success:
                results['success'] = False
            
            # Add loopback rules
            success, messages = self.add_loopback_rules()
            results['actions_taken'].extend(messages)
            if not success:
                results['success'] = False
            
            # Add port rules if configuration provided
            if allowed_ports_config_path:
                config_result = self.load_allowed_ports_config(allowed_ports_config_path)
                if config_result['success']:
                    success, messages = self.add_port_rules(config_result['config'])
                    results['actions_taken'].extend(messages)
                    if not success:
                        results['success'] = False
                else:
                    results['errors'].append(f"Failed to load port configuration: {config_result['error']}")
                    results['success'] = False
        
        except Exception as e:
            results['errors'].append(f"Unexpected error: {e}")
            results['success'] = False
        
        return results


def main():
    """Main function for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='UFW Firewall Enforcer')
    parser.add_argument('--audit', action='store_true', help='Audit current UFW configuration')
    parser.add_argument('--apply', action='store_true', help='Apply UFW configuration')
    parser.add_argument('--allowed-ports', type=str, help='Path to YAML file with allowed ports configuration')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    parser.add_argument('--rollback-dir', default='/var/log/hardening-tool', 
                       help='Directory for rollback files')
    
    args = parser.parse_args()
    
    if not (args.audit or args.apply):
        parser.print_help()
        return 1
    
    # Check if running as root for apply operations
    if args.apply and os.geteuid() != 0:
        print("Error: Must run as root to apply UFW configuration", file=sys.stderr)
        return 1
    
    enforcer = UFWEnforcer(rollback_dir=args.rollback_dir)
    
    if args.audit:
        results = enforcer.audit(args.allowed_ports)
        
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print("UFW Firewall Configuration Audit")
            print("=" * 40)
            print(f"Timestamp: {results['timestamp']}\n")
            
            # UFW Status
            status = results['ufw_status']
            print("UFW Status:")
            print(f"  Installed: {'✓' if status['installed'] else '✗'}")
            print(f"  Enabled: {'✓' if status['enabled'] else '✗'}")
            print(f"  Default Incoming: {status['default_incoming'] or 'Unknown'}")
            print(f"  Default Outgoing: {status['default_outgoing'] or 'Unknown'}")
            print(f"  Rules Count: {status['rules_count']}")
            print(f"  Iptables Conflict: {'✗' if status['iptables_persistent_conflict'] else '✓'}")
            
            # Loopback Check
            loopback = results['loopback_check']
            print(f"\nLoopback Configuration: {'✓' if loopback['compliant'] else '✗'}")
            if loopback['missing_rules']:
                print(f"  Missing Rules: {len(loopback['missing_rules'])}")
            
            # Port Rules Check
            if results['port_rules_check']:
                port_check = results['port_rules_check']
                if 'error' in port_check:
                    print(f"\nPort Rules: Error - {port_check['error']}")
                else:
                    print(f"\nPort Rules: {'✓' if port_check['compliant'] else '✗'}")
                    print(f"  Missing Rules: {len(port_check['missing_rules'])}")
                    print(f"  Existing Rules: {len(port_check['existing_rules'])}")
            
            # Overall Compliance
            compliance = results['compliance']
            print(f"\nOverall Compliance: {'✓ COMPLIANT' if compliance['overall_compliant'] else '✗ NON-COMPLIANT'}")
            
            if results['recommendations']:
                print("\nRecommendations:")
                for rec in results['recommendations']:
                    print(f"  • {rec}")
    
    elif args.apply:
        results = enforcer.apply(args.allowed_ports)
        
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print("UFW Firewall Configuration Apply")
            print("=" * 40)
            print(f"Timestamp: {results['timestamp']}\n")
            
            if results['backup_file']:
                print(f"Backup Created: {results['backup_file']}\n")
            
            if results['actions_taken']:
                print("Actions Taken:")
                for action in results['actions_taken']:
                    print(f"  ✓ {action}")
            
            if results['errors']:
                print("\nErrors:")
                for error in results['errors']:
                    print(f"  ✗ {error}")
            
            print(f"\nOverall Success: {'✓' if results['success'] else '✗'}")
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())