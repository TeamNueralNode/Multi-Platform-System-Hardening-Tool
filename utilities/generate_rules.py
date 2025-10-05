#!/usr/bin/env python3
"""
Annexure A & B Rules Generator
Generates machine-friendly YAML rule files from Annexure content
"""

import os
import json
import yaml
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class AnnexureRulesGenerator:
    """Generates YAML rule files from Annexure A (Windows) and B (Linux) content."""
    
    def __init__(self, output_dir: str = "rules/definitions"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Annexure A - Windows Rules
        self.annexure_a_rules = {
            # Password Policy Rules
            "password_policy_minimum_length": {
                "title": "Minimum Password Length",
                "description": "Password must be at least 14 characters long",
                "category": "password_policy",
                "desired_value": "14",
                "severity": "high",
                "check_command": "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' -Name MinimumPasswordLength -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MinimumPasswordLength",
                "remediate_command": "secedit /export /cfg C:\\temp\\secpol.cfg; (Get-Content C:\\temp\\secpol.cfg) -replace 'MinimumPasswordLength = .*', 'MinimumPasswordLength = 14' | Set-Content C:\\temp\\secpol.cfg; secedit /configure /db C:\\Windows\\security\\local.sdb /cfg C:\\temp\\secpol.cfg",
                "rollback_instructions": "Restore original password policy using secedit with backup configuration",
                "manual_flag": False
            },
            "password_policy_complexity": {
                "title": "Password Complexity Requirements",
                "description": "Passwords must meet complexity requirements (uppercase, lowercase, numbers, symbols)",
                "category": "password_policy",
                "desired_value": "Enabled",
                "severity": "high",
                "check_command": "secedit /export /cfg C:\\temp\\secpol.cfg; Select-String -Path C:\\temp\\secpol.cfg -Pattern 'PasswordComplexity'",
                "remediate_command": "secedit /export /cfg C:\\temp\\secpol.cfg; (Get-Content C:\\temp\\secpol.cfg) -replace 'PasswordComplexity = .*', 'PasswordComplexity = 1' | Set-Content C:\\temp\\secpol.cfg; secedit /configure /db C:\\Windows\\security\\local.sdb /cfg C:\\temp\\secpol.cfg",
                "rollback_instructions": "Restore original complexity policy using secedit backup",
                "manual_flag": False
            },
            "password_policy_history": {
                "title": "Password History",
                "description": "Remember last 24 passwords to prevent reuse",
                "category": "password_policy",
                "desired_value": "24",
                "severity": "medium",
                "check_command": "secedit /export /cfg C:\\temp\\secpol.cfg; Select-String -Path C:\\temp\\secpol.cfg -Pattern 'PasswordHistorySize'",
                "remediate_command": "secedit /export /cfg C:\\temp\\secpol.cfg; (Get-Content C:\\temp\\secpol.cfg) -replace 'PasswordHistorySize = .*', 'PasswordHistorySize = 24' | Set-Content C:\\temp\\secpol.cfg; secedit /configure /db C:\\Windows\\security\\local.sdb /cfg C:\\temp\\secpol.cfg",
                "rollback_instructions": "Restore original password history setting using secedit backup",
                "manual_flag": False
            },
            
            # Account Lockout Policy Rules
            "account_lockout_threshold": {
                "title": "Account Lockout Threshold",
                "description": "Lock account after 5 invalid logon attempts",
                "category": "account_lockout",
                "desired_value": "5",
                "severity": "high",
                "check_command": "net accounts | Select-String 'Lockout threshold'",
                "remediate_command": "net accounts /lockoutthreshold:5",
                "rollback_instructions": "Reset lockout threshold using 'net accounts /lockoutthreshold:0' to disable or restore original value",
                "manual_flag": False
            },
            "account_lockout_duration": {
                "title": "Account Lockout Duration",
                "description": "Keep account locked for 30 minutes after lockout",
                "category": "account_lockout",
                "desired_value": "30",
                "severity": "medium",
                "check_command": "net accounts | Select-String 'Lockout duration'",
                "remediate_command": "net accounts /lockoutduration:30",
                "rollback_instructions": "Reset lockout duration using 'net accounts /lockoutduration:0' or restore original value",
                "manual_flag": False
            },
            
            # Windows Firewall Rules
            "firewall_private_profile": {
                "title": "Windows Firewall Private Profile",
                "description": "Enable Windows Firewall for Private profile",
                "category": "firewall",
                "desired_value": "Enabled",
                "severity": "critical",
                "check_command": "Get-NetFirewallProfile -Profile Private | Select-Object -ExpandProperty Enabled",
                "remediate_command": "Set-NetFirewallProfile -Profile Private -Enabled True",
                "rollback_instructions": "Use Set-NetFirewallProfile -Profile Private -Enabled False to disable",
                "manual_flag": False
            },
            "firewall_public_profile": {
                "title": "Windows Firewall Public Profile",
                "description": "Enable Windows Firewall for Public profile",
                "category": "firewall",
                "desired_value": "Enabled",
                "severity": "critical",
                "check_command": "Get-NetFirewallProfile -Profile Public | Select-Object -ExpandProperty Enabled",
                "remediate_command": "Set-NetFirewallProfile -Profile Public -Enabled True",
                "rollback_instructions": "Use Set-NetFirewallProfile -Profile Public -Enabled False to disable",
                "manual_flag": False
            },
            
            # User Rights Assignment
            "user_right_logon_as_service": {
                "title": "Log on as a Service",
                "description": "Restrict 'Log on as a service' user right to authorized accounts only",
                "category": "user_rights",
                "desired_value": "Specific authorized accounts only",
                "severity": "medium",
                "check_command": "secedit /export /cfg C:\\temp\\secpol.cfg; Select-String -Path C:\\temp\\secpol.cfg -Pattern 'SeServiceLogonRight'",
                "remediate_command": "Configure via Group Policy or secedit to restrict service logon rights",
                "rollback_instructions": "Restore original user rights assignment using secedit backup",
                "manual_flag": True
            },
            
            # Services Hardening
            "service_telnet": {
                "title": "Telnet Service",
                "description": "Disable Telnet service for security",
                "category": "services",
                "desired_value": "Disabled",
                "severity": "high",
                "check_command": "Get-Service -Name TlntSvr -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status",
                "remediate_command": "Stop-Service -Name TlntSvr -Force; Set-Service -Name TlntSvr -StartupType Disabled",
                "rollback_instructions": "Use Set-Service -Name TlntSvr -StartupType Manual/Automatic to restore",
                "manual_flag": False
            },
            "service_ftp": {
                "title": "FTP Service",
                "description": "Disable FTP service unless required",
                "category": "services",
                "desired_value": "Disabled",
                "severity": "medium",
                "check_command": "Get-Service -Name FTPSVC -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status",
                "remediate_command": "Stop-Service -Name FTPSVC -Force; Set-Service -Name FTPSVC -StartupType Disabled",
                "rollback_instructions": "Use Set-Service -Name FTPSVC -StartupType Manual/Automatic to restore",
                "manual_flag": False
            },
            
            # Advanced Audit Policy
            "audit_credential_validation": {
                "title": "Audit Credential Validation",
                "description": "Enable auditing for credential validation events",
                "category": "audit_policy",
                "desired_value": "Success and Failure",
                "severity": "medium",
                "check_command": "auditpol /get /subcategory:'Credential Validation'",
                "remediate_command": "auditpol /set /subcategory:'Credential Validation' /success:enable /failure:enable",
                "rollback_instructions": "Use auditpol to disable or restore original audit settings",
                "manual_flag": False
            },
            "audit_process_creation": {
                "title": "Audit Process Creation",
                "description": "Enable auditing for process creation events",
                "category": "audit_policy",
                "desired_value": "Success",
                "severity": "low",
                "check_command": "auditpol /get /subcategory:'Process Creation'",
                "remediate_command": "auditpol /set /subcategory:'Process Creation' /success:enable /failure:disable",
                "rollback_instructions": "Use auditpol to disable process creation auditing",
                "manual_flag": False
            }
        }
        
        # Annexure B - Linux Rules
        self.annexure_b_rules = {
            # SSH Hardening Rules
            "ssh_permit_root_login": {
                "title": "SSH Permit Root Login",
                "description": "Disable direct root login via SSH",
                "category": "ssh",
                "desired_value": "no",
                "severity": "critical",
                "check_command": "grep '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin not set'",
                "remediate_command": "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config; systemctl restart sshd",
                "rollback_instructions": "Edit /etc/ssh/sshd_config to restore original PermitRootLogin setting and restart sshd",
                "manual_flag": False
            },
            "ssh_protocol_version": {
                "title": "SSH Protocol Version",
                "description": "Use SSH Protocol version 2 only",
                "category": "ssh",
                "desired_value": "2",
                "severity": "high",
                "check_command": "grep '^Protocol' /etc/ssh/sshd_config || echo 'Protocol not explicitly set'",
                "remediate_command": "echo 'Protocol 2' >> /etc/ssh/sshd_config; systemctl restart sshd",
                "rollback_instructions": "Remove 'Protocol 2' line from /etc/ssh/sshd_config and restart sshd",
                "manual_flag": False
            },
            "ssh_empty_passwords": {
                "title": "SSH Permit Empty Passwords",
                "description": "Disable empty password authentication in SSH",
                "category": "ssh",
                "desired_value": "no",
                "severity": "critical",
                "check_command": "grep '^PermitEmptyPasswords' /etc/ssh/sshd_config || echo 'PermitEmptyPasswords not set'",
                "remediate_command": "sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config; systemctl restart sshd",
                "rollback_instructions": "Edit /etc/ssh/sshd_config to restore original PermitEmptyPasswords setting and restart sshd",
                "manual_flag": False
            },
            
            # Password Policy Rules (PAM)
            "pam_password_minlen": {
                "title": "Minimum Password Length",
                "description": "Set minimum password length to 14 characters",
                "category": "password_policy",
                "desired_value": "14",
                "severity": "high",
                "check_command": "grep 'minlen' /etc/security/pwquality.conf || grep 'minlen' /etc/pam.d/common-password",
                "remediate_command": "echo 'minlen = 14' >> /etc/security/pwquality.conf",
                "rollback_instructions": "Edit /etc/security/pwquality.conf to remove or modify minlen setting",
                "manual_flag": False
            },
            "pam_password_complexity": {
                "title": "Password Complexity Requirements",
                "description": "Require uppercase, lowercase, digits, and special characters",
                "category": "password_policy",
                "desired_value": "dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1",
                "severity": "high",
                "check_command": "grep -E '(dcredit|ucredit|lcredit|ocredit)' /etc/security/pwquality.conf",
                "remediate_command": "echo -e 'dcredit = -1\\nucredit = -1\\nlcredit = -1\\nocredit = -1' >> /etc/security/pwquality.conf",
                "rollback_instructions": "Edit /etc/security/pwquality.conf to remove or modify credit settings",
                "manual_flag": False
            },
            
            # File System Security
            "filesystem_tmp_noexec": {
                "title": "/tmp Filesystem noexec",
                "description": "Mount /tmp with noexec option to prevent execution",
                "category": "filesystem",
                "desired_value": "noexec",
                "severity": "medium",
                "check_command": "mount | grep '/tmp' | grep noexec || echo '/tmp not mounted with noexec'",
                "remediate_command": "mount -o remount,noexec /tmp",
                "rollback_instructions": "Use 'mount -o remount,exec /tmp' to restore execution permissions",
                "manual_flag": False
            },
            "filesystem_var_log_nodev": {
                "title": "/var/log Filesystem nodev",
                "description": "Mount /var/log with nodev option to prevent device files",
                "category": "filesystem",
                "desired_value": "nodev",
                "severity": "low",
                "check_command": "mount | grep '/var/log' | grep nodev || echo '/var/log not mounted with nodev'",
                "remediate_command": "mount -o remount,nodev /var/log",
                "rollback_instructions": "Use 'mount -o remount,dev /var/log' to restore device access",
                "manual_flag": False
            },
            
            # Network Security
            "network_ip_forwarding": {
                "title": "IP Forwarding",
                "description": "Disable IP forwarding unless router functionality needed",
                "category": "network",
                "desired_value": "0",
                "severity": "medium",
                "check_command": "sysctl net.ipv4.ip_forward",
                "remediate_command": "sysctl -w net.ipv4.ip_forward=0; echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf",
                "rollback_instructions": "Set net.ipv4.ip_forward=1 in /etc/sysctl.conf and run sysctl -p",
                "manual_flag": False
            },
            "network_icmp_redirects": {
                "title": "ICMP Redirects",
                "description": "Disable acceptance of ICMP redirect messages",
                "category": "network",
                "desired_value": "0",
                "severity": "low",
                "check_command": "sysctl net.ipv4.conf.all.accept_redirects",
                "remediate_command": "sysctl -w net.ipv4.conf.all.accept_redirects=0; echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf",
                "rollback_instructions": "Set net.ipv4.conf.all.accept_redirects=1 in /etc/sysctl.conf and run sysctl -p",
                "manual_flag": False
            },
            
            # Audit Configuration
            "audit_sudoers_changes": {
                "title": "Audit Sudoers Changes",
                "description": "Monitor changes to sudoers file",
                "category": "audit",
                "desired_value": "Monitored",
                "severity": "medium",
                "check_command": "auditctl -l | grep '/etc/sudoers'",
                "remediate_command": "echo '-w /etc/sudoers -p wa -k sudoers_changes' >> /etc/audit/rules.d/hardening.rules; auditctl -R /etc/audit/rules.d/hardening.rules",
                "rollback_instructions": "Remove sudoers audit rule from /etc/audit/rules.d/hardening.rules and reload auditctl",
                "manual_flag": False
            },
            "audit_passwd_changes": {
                "title": "Audit Password File Changes",
                "description": "Monitor changes to password-related files",
                "category": "audit",
                "desired_value": "Monitored",
                "severity": "medium",
                "check_command": "auditctl -l | grep '/etc/passwd'",
                "remediate_command": "echo '-w /etc/passwd -p wa -k passwd_changes' >> /etc/audit/rules.d/hardening.rules; auditctl -R /etc/audit/rules.d/hardening.rules",
                "rollback_instructions": "Remove passwd audit rule from /etc/audit/rules.d/hardening.rules and reload auditctl",
                "manual_flag": False
            },
            
            # Service Hardening
            "service_telnet_disabled": {
                "title": "Telnet Service Disabled",
                "description": "Disable telnet service for security",
                "category": "services",
                "desired_value": "disabled",
                "severity": "high",
                "check_command": "systemctl is-enabled telnet 2>/dev/null || echo 'telnet service not found'",
                "remediate_command": "systemctl stop telnet; systemctl disable telnet",
                "rollback_instructions": "Use 'systemctl enable telnet && systemctl start telnet' to restore",
                "manual_flag": False
            },
            "service_ftp_disabled": {
                "title": "FTP Service Disabled", 
                "description": "Disable FTP service unless required",
                "category": "services",
                "desired_value": "disabled",
                "severity": "medium",
                "check_command": "systemctl is-enabled vsftpd 2>/dev/null || echo 'vsftpd service not found'",
                "remediate_command": "systemctl stop vsftpd; systemctl disable vsftpd",
                "rollback_instructions": "Use 'systemctl enable vsftpd && systemctl start vsftpd' to restore",
                "manual_flag": False
            },
            
            # Kernel Hardening
            "kernel_module_cramfs": {
                "title": "Disable cramfs Kernel Module",
                "description": "Blacklist cramfs filesystem module",
                "category": "kernel",
                "desired_value": "blacklisted",
                "severity": "low",
                "check_command": "lsmod | grep cramfs || echo 'cramfs module not loaded'",
                "remediate_command": "echo 'blacklist cramfs' >> /etc/modprobe.d/hardening.conf; depmod -a",
                "rollback_instructions": "Remove 'blacklist cramfs' from /etc/modprobe.d/hardening.conf and run depmod -a",
                "manual_flag": False
            },
            "kernel_module_usb_storage": {
                "title": "Disable USB Storage Module",
                "description": "Blacklist USB storage module to prevent unauthorized USB devices",
                "category": "kernel",
                "desired_value": "blacklisted",
                "severity": "medium",
                "check_command": "lsmod | grep usb_storage || echo 'usb-storage module not loaded'",
                "remediate_command": "echo 'blacklist usb-storage' >> /etc/modprobe.d/hardening.conf; depmod -a",
                "rollback_instructions": "Remove 'blacklist usb-storage' from /etc/modprobe.d/hardening.conf and run depmod -a",
                "manual_flag": False
            }
        }
    
    def generate_rule_id(self, base_name: str, category: str) -> str:
        """Generate consistent rule ID from base name and category."""
        # Clean the base name
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', base_name.lower())
        clean_category = re.sub(r'[^a-zA-Z0-9_]', '_', category.lower())
        
        return f"{clean_category}_{clean_name}"
    
    def create_rule_entry(self, rule_id: str, rule_data: Dict[str, Any], platform: str) -> Dict[str, Any]:
        """Create a standardized rule entry."""
        return {
            'id': rule_id,
            'title': rule_data['title'],
            'description': rule_data['description'],
            'category': rule_data['category'],
            'platform': platform,
            'severity': rule_data['severity'],
            'desired_value': rule_data['desired_value'],
            'check_command': rule_data['check_command'],
            'remediate_command': rule_data['remediate_command'],
            'rollback_instructions': rule_data['rollback_instructions'],
            'manual_flag': rule_data['manual_flag'],
            'created_date': datetime.now().isoformat(),
            'version': '1.0'
        }
    
    def generate_windows_rules(self) -> Dict[str, Any]:
        """Generate Windows rules YAML structure."""
        rules_data = {
            'metadata': {
                'name': 'Annexure-A Windows Security Rules',
                'description': 'Windows security hardening rules based on Annexure-A requirements',
                'platform': 'windows',
                'version': '1.0',
                'generated_date': datetime.now().isoformat(),
                'total_rules': len(self.annexure_a_rules)
            },
            'categories': list(set(rule['category'] for rule in self.annexure_a_rules.values())),
            'rules': []
        }
        
        for rule_name, rule_data in self.annexure_a_rules.items():
            rule_id = self.generate_rule_id(rule_name, rule_data['category'])
            rule_entry = self.create_rule_entry(rule_id, rule_data, 'windows')
            rules_data['rules'].append(rule_entry)
        
        return rules_data
    
    def generate_linux_rules(self) -> Dict[str, Any]:
        """Generate Linux rules YAML structure."""
        rules_data = {
            'metadata': {
                'name': 'Annexure-B Linux Security Rules',
                'description': 'Linux security hardening rules based on Annexure-B requirements',
                'platform': 'linux',
                'version': '1.0', 
                'generated_date': datetime.now().isoformat(),
                'total_rules': len(self.annexure_b_rules)
            },
            'categories': list(set(rule['category'] for rule in self.annexure_b_rules.values())),
            'rules': []
        }
        
        for rule_name, rule_data in self.annexure_b_rules.items():
            rule_id = self.generate_rule_id(rule_name, rule_data['category'])
            rule_entry = self.create_rule_entry(rule_id, rule_data, 'linux')
            rules_data['rules'].append(rule_entry)
        
        return rules_data
    
    def save_yaml_file(self, data: Dict[str, Any], filename: str) -> str:
        """Save data to YAML file with proper formatting."""
        file_path = self.output_dir / filename
        
        yaml_content = yaml.dump(
            data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
            indent=2
        )
        
        # Add header comment
        header = f"""# Generated by Hardening Tool Rules Generator
# Generated on: {datetime.now().isoformat()}
# Platform: {data['metadata']['platform'].title()}
# Total Rules: {data['metadata']['total_rules']}
#
# This file contains security hardening rules based on Annexure requirements.
# Each rule includes check commands, remediation steps, and rollback instructions.

"""
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(yaml_content)
        
        return str(file_path)
    
    def process_custom_annexure_content(self, content: str, platform: str) -> Dict[str, Any]:
        """Process custom annexure content from text or JSON."""
        rules = {}
        
        try:
            # Try to parse as JSON first
            json_data = json.loads(content)
            
            if isinstance(json_data, dict) and 'rules' in json_data:
                # JSON format with rules array
                for rule in json_data['rules']:
                    rule_id = rule.get('id', f"custom_{len(rules)}")
                    rules[rule_id] = {
                        'title': rule.get('title', 'Custom Rule'),
                        'description': rule.get('description', ''),
                        'category': rule.get('category', 'custom'),
                        'desired_value': rule.get('desired_value', ''),
                        'severity': rule.get('severity', 'medium'),
                        'check_command': rule.get('check_command', ''),
                        'remediate_command': rule.get('remediate_command', ''),
                        'rollback_instructions': rule.get('rollback_instructions', ''),
                        'manual_flag': rule.get('manual_flag', True)
                    }
            
        except json.JSONDecodeError:
            # Parse as structured text
            lines = content.split('\n')
            current_rule = {}
            rule_counter = 0
            
            for line in lines:
                line = line.strip()
                if not line:
                    if current_rule:
                        # Save current rule
                        rule_id = f"custom_rule_{rule_counter}"
                        rules[rule_id] = current_rule.copy()
                        current_rule = {}
                        rule_counter += 1
                    continue
                
                # Parse key-value pairs
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_')
                    value = value.strip()
                    
                    mapping = {
                        'title': 'title',
                        'description': 'description', 
                        'category': 'category',
                        'desired_value': 'desired_value',
                        'severity': 'severity',
                        'check_command': 'check_command',
                        'remediate_command': 'remediate_command',
                        'rollback_instructions': 'rollback_instructions'
                    }
                    
                    if key in mapping:
                        current_rule[mapping[key]] = value
                    
                    # Set defaults
                    if 'manual_flag' not in current_rule:
                        current_rule['manual_flag'] = True
            
            # Save last rule if exists
            if current_rule:
                rule_id = f"custom_rule_{rule_counter}"
                rules[rule_id] = current_rule
        
        return rules
    
    def generate_all_rules(self, custom_windows_content: Optional[str] = None, 
                          custom_linux_content: Optional[str] = None) -> Dict[str, str]:
        """Generate all rule files and return file paths."""
        generated_files = {}
        
        # Generate Windows rules
        if custom_windows_content:
            custom_rules = self.process_custom_annexure_content(custom_windows_content, 'windows')
            self.annexure_a_rules.update(custom_rules)
        
        windows_rules = self.generate_windows_rules()
        windows_file = self.save_yaml_file(windows_rules, 'windows_security_rules.yaml')
        generated_files['windows'] = windows_file
        
        # Generate Linux rules
        if custom_linux_content:
            custom_rules = self.process_custom_annexure_content(custom_linux_content, 'linux')
            self.annexure_b_rules.update(custom_rules)
        
        linux_rules = self.generate_linux_rules()
        linux_file = self.save_yaml_file(linux_rules, 'linux_security_rules.yaml')
        generated_files['linux'] = linux_file
        
        return generated_files
    
    def generate_summary_report(self, generated_files: Dict[str, str]) -> str:
        """Generate summary report of generated rules."""
        report = [
            "Annexure Rules Generation Summary",
            "=" * 40,
            f"Generated on: {datetime.now().isoformat()}",
            ""
        ]
        
        for platform, file_path in generated_files.items():
            if platform == 'windows':
                rule_count = len(self.annexure_a_rules)
                categories = list(set(rule['category'] for rule in self.annexure_a_rules.values()))
            else:
                rule_count = len(self.annexure_b_rules)
                categories = list(set(rule['category'] for rule in self.annexure_b_rules.values()))
            
            report.extend([
                f"{platform.title()} Rules:",
                f"  File: {file_path}",
                f"  Total Rules: {rule_count}",
                f"  Categories: {', '.join(sorted(categories))}",
                ""
            ])
        
        return '\n'.join(report)


def main():
    """Main function for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate YAML rules from Annexure A & B content')
    parser.add_argument('--output-dir', default='rules/definitions',
                       help='Output directory for generated YAML files')
    parser.add_argument('--windows-content', type=str,
                       help='Custom Windows (Annexure-A) content as JSON or structured text')
    parser.add_argument('--linux-content', type=str,
                       help='Custom Linux (Annexure-B) content as JSON or structured text')
    parser.add_argument('--windows-file', type=str,
                       help='File containing custom Windows content')
    parser.add_argument('--linux-file', type=str,
                       help='File containing custom Linux content')
    parser.add_argument('--json-output', action='store_true',
                       help='Output summary as JSON')
    
    args = parser.parse_args()
    
    generator = AnnexureRulesGenerator(output_dir=args.output_dir)
    
    # Load custom content from files if provided
    windows_content = args.windows_content
    if args.windows_file and Path(args.windows_file).exists():
        with open(args.windows_file, 'r', encoding='utf-8') as f:
            windows_content = f.read()
    
    linux_content = args.linux_content
    if args.linux_file and Path(args.linux_file).exists():
        with open(args.linux_file, 'r', encoding='utf-8') as f:
            linux_content = f.read()
    
    # Generate rules
    try:
        generated_files = generator.generate_all_rules(
            custom_windows_content=windows_content,
            custom_linux_content=linux_content
        )
        
        if args.json_output:
            summary = {
                'success': True,
                'generated_files': generated_files,
                'timestamp': datetime.now().isoformat(),
                'windows_rules_count': len(generator.annexure_a_rules),
                'linux_rules_count': len(generator.annexure_b_rules)
            }
            print(json.dumps(summary, indent=2))
        else:
            print(generator.generate_summary_report(generated_files))
            print("\nRule files generated successfully!")
            for platform, file_path in generated_files.items():
                print(f"  {platform.title()}: {file_path}")
    
    except Exception as e:
        if args.json_output:
            error_summary = {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            print(json.dumps(error_summary, indent=2))
        else:
            print(f"Error generating rules: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())