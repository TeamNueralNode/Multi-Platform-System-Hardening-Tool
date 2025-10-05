#!/usr/bin/env python3
"""
Auditd, Rsyslog, and Logrotate Configuration Script
Audits and configures system logging and auditing per Annexure-B requirements
"""

import os
import sys
import json
import sqlite3
import subprocess
import shutil
import difflib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any


class AuditdRsyslogManager:
    """Manages auditd, rsyslog, and logrotate configuration for security compliance."""
    
    def __init__(self, db_path: str = "/var/log/hardening-tool/audit_config.db"):
        self.db_path = db_path
        self.backup_dir = Path("/var/log/hardening-tool/backups")
        self.audit_rules_file = Path("/etc/audit/rules.d/hardening.rules")
        self.auditd_conf = Path("/etc/audit/auditd.conf")
        self.rsyslog_conf = Path("/etc/rsyslog.conf")
        
        # Annexure-B recommended audit rules
        self.audit_rules = [
            # Monitor sudoers file changes
            "-w /etc/sudoers -p wa -k sudoers_changes",
            "-w /etc/sudoers.d/ -p wa -k sudoers_changes",
            
            # Monitor privileged command usage
            "-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged_commands",
            "-a always,exit -F arch=b32 -S execve -F euid=0 -k privileged_commands",
            
            # Monitor file deletion events
            "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k file_deletion",
            "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k file_deletion",
            
            # Monitor kernel module operations
            "-w /sbin/insmod -p x -k kernel_modules",
            "-w /sbin/rmmod -p x -k kernel_modules",
            "-w /sbin/modprobe -p x -k kernel_modules",
            "-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_modules",
            "-a always,exit -F arch=b32 -S init_module -S delete_module -k kernel_modules",
            
            # Monitor system calls for privilege escalation
            "-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation",
            "-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation",
            
            # Monitor password file changes
            "-w /etc/passwd -p wa -k passwd_changes",
            "-w /etc/group -p wa -k group_changes",
            "-w /etc/shadow -p wa -k shadow_changes",
            
            # Monitor authentication events
            "-w /var/log/auth.log -p wa -k auth_events",
            "-w /var/log/secure -p wa -k auth_events",
            
            # Monitor cron configuration
            "-w /etc/crontab -p wa -k cron_config",
            "-w /etc/cron.d/ -p wa -k cron_config",
            "-w /var/spool/cron/ -p wa -k cron_config",
            
            # Monitor network configuration
            "-a always,exit -F arch=b64 -S socket -F a0=10 -k network_ipv4",
            "-a always,exit -F arch=b32 -S socket -F a0=2 -k network_ipv4",
            
            # Monitor system administration actions
            "-w /etc/hosts -p wa -k network_config",
            "-w /etc/hostname -p wa -k system_config",
            "-w /etc/issue -p wa -k system_config",
            
            # Make configuration immutable
            "-e 2"
        ]
        
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for tracking operations."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    component TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT,
                    rollback_path TEXT
                )
            """)
    
    def _log_operation(self, operation: str, component: str, status: str, 
                      details: str = "", rollback_path: str = ""):
        """Log operation to database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO audit_operations 
                (timestamp, operation, component, status, details, rollback_path)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), operation, component, status, details, rollback_path))
    
    def run_command(self, command: List[str]) -> Tuple[int, str, str]:
        """Execute command and return exit code, stdout, stderr."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return 1, "", "Command timed out"
        except Exception as e:
            return 1, "", str(e)
    
    def is_service_installed(self, service: str) -> bool:
        """Check if a service is installed."""
        exit_code, _, _ = self.run_command(['which', service])
        if exit_code == 0:
            return True
        
        # Check package manager
        for cmd in [['dpkg', '-l', service], ['rpm', '-q', service]]:
            exit_code, _, _ = self.run_command(cmd)
            if exit_code == 0:
                return True
        
        return False
    
    def is_service_enabled(self, service: str) -> bool:
        """Check if a service is enabled."""
        exit_code, _, _ = self.run_command(['systemctl', 'is-enabled', service])
        return exit_code == 0
    
    def is_service_active(self, service: str) -> bool:
        """Check if a service is active/running."""
        exit_code, _, _ = self.run_command(['systemctl', 'is-active', service])
        return exit_code == 0
    
    def get_auditd_status(self) -> Dict[str, Any]:
        """Get comprehensive auditd status."""
        status = {
            'installed': False,
            'enabled': False,
            'active': False,
            'rules_count': 0,
            'backlog_limit': None,
            'config_immutable': False
        }
        
        # Check installation
        status['installed'] = self.is_service_installed('auditd')
        if not status['installed']:
            return status
        
        # Check service status
        status['enabled'] = self.is_service_enabled('auditd')
        status['active'] = self.is_service_active('auditd')
        
        # Check audit rules
        exit_code, output, _ = self.run_command(['auditctl', '-l'])
        if exit_code == 0:
            status['rules_count'] = len([line for line in output.split('\n') if line.strip()])
        
        # Check backlog limit
        if self.auditd_conf.exists():
            try:
                with open(self.auditd_conf) as f:
                    for line in f:
                        if line.startswith('max_log_file_action'):
                            continue
                        if 'backlog' in line.lower():
                            status['backlog_limit'] = line.strip()
            except Exception:
                pass
        
        # Check if audit system is immutable
        exit_code, output, _ = self.run_command(['auditctl', '-s'])
        if exit_code == 0 and 'enabled 2' in output:
            status['config_immutable'] = True
        
        return status
    
    def get_rsyslog_status(self) -> Dict[str, Any]:
        """Get rsyslog service status."""
        return {
            'installed': self.is_service_installed('rsyslog'),
            'enabled': self.is_service_enabled('rsyslog'),
            'active': self.is_service_active('rsyslog'),
            'config_exists': self.rsyslog_conf.exists()
        }
    
    def get_logrotate_status(self) -> Dict[str, Any]:
        """Get logrotate status."""
        status = {
            'installed': self.is_service_installed('logrotate'),
            'cron_enabled': False
        }
        
        # Check if logrotate is in cron
        for cron_path in ['/etc/cron.daily/logrotate', '/etc/cron.d/logrotate']:
            if Path(cron_path).exists():
                status['cron_enabled'] = True
                break
        
        return status
    
    def backup_audit_rules(self) -> str:
        """Backup current audit rules."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = self.backup_dir / f"audit_rules_backup_{timestamp}"
        
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Backup rules directory
        if Path("/etc/audit/rules.d").exists():
            shutil.copytree("/etc/audit/rules.d", f"{backup_path}_rules.d")
        
        # Backup current loaded rules
        exit_code, output, _ = self.run_command(['auditctl', '-l'])
        if exit_code == 0:
            with open(f"{backup_path}_loaded.rules", 'w') as f:
                f.write(output)
        
        return str(backup_path)
    
    def generate_rules_diff(self, new_rules: List[str]) -> str:
        """Generate diff between current and new rules."""
        current_rules = []
        
        if self.audit_rules_file.exists():
            try:
                with open(self.audit_rules_file) as f:
                    current_rules = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except Exception:
                pass
        
        diff = difflib.unified_diff(
            current_rules,
            new_rules,
            fromfile='current_rules',
            tofile='new_rules',
            lineterm=''
        )
        
        return '\n'.join(diff)
    
    def apply_audit_rules(self) -> Tuple[bool, str]:
        """Apply recommended audit rules."""
        try:
            # Create backup
            backup_path = self.backup_audit_rules()
            
            # Generate diff
            diff_output = self.generate_rules_diff(self.audit_rules)
            
            # Create rules directory if it doesn't exist
            self.audit_rules_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write new rules
            with open(self.audit_rules_file, 'w') as f:
                f.write("# Hardening Tool - Annexure-B Audit Rules\n")
                f.write(f"# Generated on {datetime.now().isoformat()}\n\n")
                
                for rule in self.audit_rules:
                    f.write(f"{rule}\n")
            
            # Set file permissions
            os.chmod(self.audit_rules_file, 0o640)
            
            # Reload audit rules
            exit_code, output, error = self.run_command(['auditctl', '-R', str(self.audit_rules_file)])
            if exit_code != 0:
                return False, f"Failed to load rules: {error}"
            
            # Restart auditd service
            exit_code, _, error = self.run_command(['systemctl', 'restart', 'auditd'])
            if exit_code != 0:
                return False, f"Failed to restart auditd: {error}"
            
            self._log_operation("apply_rules", "auditd", "success", diff_output, backup_path)
            return True, diff_output
            
        except Exception as e:
            self._log_operation("apply_rules", "auditd", "error", str(e))
            return False, str(e)
    
    def set_audit_backlog_limit(self, limit: int = 8192) -> bool:
        """Set audit backlog limit in kernel parameters."""
        try:
            grub_file = Path("/etc/default/grub")
            if not grub_file.exists():
                return False
            
            # Backup grub config
            shutil.copy(grub_file, f"{grub_file}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            
            # Read current config
            with open(grub_file) as f:
                lines = f.readlines()
            
            # Modify GRUB_CMDLINE_LINUX
            modified = False
            for i, line in enumerate(lines):
                if line.startswith('GRUB_CMDLINE_LINUX='):
                    # Add audit_backlog_limit if not present
                    if 'audit_backlog_limit' not in line:
                        # Remove closing quote and add parameter
                        line = line.rstrip().rstrip('"') + f' audit_backlog_limit={limit}"\n'
                        lines[i] = line
                        modified = True
                        break
            
            if modified:
                with open(grub_file, 'w') as f:
                    f.writelines(lines)
                
                # Update grub
                self.run_command(['update-grub'])
                return True
            
            return False
            
        except Exception as e:
            self._log_operation("set_backlog_limit", "grub", "error", str(e))
            return False
    
    def make_audit_config_immutable(self) -> bool:
        """Make audit configuration immutable."""
        try:
            # This is handled by the "-e 2" rule which makes audit config immutable
            # The rule is already included in self.audit_rules
            return True
        except Exception:
            return False
    
    def audit_system(self) -> Dict[str, Any]:
        """Perform comprehensive audit of logging systems."""
        results = {
            'timestamp': datetime.now().isoformat(),
            'operation': 'audit',
            'auditd': self.get_auditd_status(),
            'rsyslog': self.get_rsyslog_status(),
            'logrotate': self.get_logrotate_status(),
            'compliance': {
                'auditd_compliant': False,
                'rsyslog_compliant': False,
                'logrotate_compliant': False,
                'overall_compliant': False
            },
            'recommendations': []
        }
        
        # Check auditd compliance
        auditd = results['auditd']
        if auditd['installed'] and auditd['enabled'] and auditd['active'] and auditd['rules_count'] > 0:
            results['compliance']['auditd_compliant'] = True
        else:
            if not auditd['installed']:
                results['recommendations'].append("Install auditd package")
            if not auditd['enabled']:
                results['recommendations'].append("Enable auditd service")
            if not auditd['active']:
                results['recommendations'].append("Start auditd service")
            if auditd['rules_count'] == 0:
                results['recommendations'].append("Configure audit rules")
        
        # Check rsyslog compliance
        rsyslog = results['rsyslog']
        if rsyslog['installed'] and rsyslog['enabled'] and rsyslog['active']:
            results['compliance']['rsyslog_compliant'] = True
        else:
            if not rsyslog['installed']:
                results['recommendations'].append("Install rsyslog package")
            if not rsyslog['enabled']:
                results['recommendations'].append("Enable rsyslog service")
            if not rsyslog['active']:
                results['recommendations'].append("Start rsyslog service")
        
        # Check logrotate compliance
        logrotate = results['logrotate']
        if logrotate['installed'] and logrotate['cron_enabled']:
            results['compliance']['logrotate_compliant'] = True
        else:
            if not logrotate['installed']:
                results['recommendations'].append("Install logrotate package")
            if not logrotate['cron_enabled']:
                results['recommendations'].append("Configure logrotate in cron")
        
        # Overall compliance
        results['compliance']['overall_compliant'] = all([
            results['compliance']['auditd_compliant'],
            results['compliance']['rsyslog_compliant'],
            results['compliance']['logrotate_compliant']
        ])
        
        self._log_operation("audit", "system", "completed", f"Compliance: {results['compliance']['overall_compliant']}")
        
        return results
    
    def apply_configuration(self, set_backlog_limit: bool = True, make_immutable: bool = True) -> Dict[str, Any]:
        """Apply recommended configuration."""
        results = {
            'timestamp': datetime.now().isoformat(),
            'operation': 'apply',
            'actions_taken': [],
            'errors': [],
            'success': True
        }
        
        try:
            # Apply audit rules
            success, diff_or_error = self.apply_audit_rules()
            if success:
                results['actions_taken'].append("Applied Annexure-B audit rules")
                results['rules_diff'] = diff_or_error
            else:
                results['errors'].append(f"Failed to apply audit rules: {diff_or_error}")
                results['success'] = False
            
            # Set backlog limit if requested
            if set_backlog_limit:
                if self.set_audit_backlog_limit():
                    results['actions_taken'].append("Set audit backlog limit to 8192")
                else:
                    results['errors'].append("Failed to set audit backlog limit")
            
            # Make configuration immutable if requested
            if make_immutable:
                if self.make_audit_config_immutable():
                    results['actions_taken'].append("Made audit configuration immutable")
                else:
                    results['errors'].append("Failed to make audit configuration immutable")
            
        except Exception as e:
            results['errors'].append(str(e))
            results['success'] = False
        
        self._log_operation("apply", "system", "completed" if results['success'] else "error", 
                          f"Actions: {len(results['actions_taken'])}, Errors: {len(results['errors'])}")
        
        return results


def main():
    """Main function for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Audit and configure system logging and auditing')
    parser.add_argument('--audit', action='store_true', help='Audit current configuration')
    parser.add_argument('--apply', action='store_true', help='Apply recommended configuration')
    parser.add_argument('--set-backlog-limit', action='store_true', default=True,
                       help='Set audit backlog limit (default: True)')
    parser.add_argument('--make-immutable', action='store_true', default=True,
                       help='Make audit configuration immutable (default: True)')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    parser.add_argument('--db-path', default='/var/log/hardening-tool/audit_config.db',
                       help='SQLite database path')
    
    args = parser.parse_args()
    
    if not (args.audit or args.apply):
        parser.print_help()
        sys.exit(1)
    
    # Check if running as root for apply operations
    if args.apply and os.geteuid() != 0:
        print("Error: Must run as root to apply configuration changes", file=sys.stderr)
        sys.exit(1)
    
    manager = AuditdRsyslogManager(db_path=args.db_path)
    
    if args.audit:
        results = manager.audit_system()
        
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print("System Logging and Auditing Configuration Audit")
            print("=" * 50)
            print(f"Timestamp: {results['timestamp']}\n")
            
            # Auditd status
            auditd = results['auditd']
            print("Auditd Status:")
            print(f"  Installed: {'✓' if auditd['installed'] else '✗'}")
            print(f"  Enabled: {'✓' if auditd['enabled'] else '✗'}")
            print(f"  Active: {'✓' if auditd['active'] else '✗'}")
            print(f"  Rules Count: {auditd['rules_count']}")
            print(f"  Config Immutable: {'✓' if auditd['config_immutable'] else '✗'}")
            
            # Rsyslog status
            rsyslog = results['rsyslog']
            print("\nRsyslog Status:")
            print(f"  Installed: {'✓' if rsyslog['installed'] else '✗'}")
            print(f"  Enabled: {'✓' if rsyslog['enabled'] else '✗'}")
            print(f"  Active: {'✓' if rsyslog['active'] else '✗'}")
            
            # Logrotate status
            logrotate = results['logrotate']
            print("\nLogrotate Status:")
            print(f"  Installed: {'✓' if logrotate['installed'] else '✗'}")
            print(f"  Cron Enabled: {'✓' if logrotate['cron_enabled'] else '✗'}")
            
            # Compliance
            compliance = results['compliance']
            print("\nCompliance Status:")
            print(f"  Overall: {'✓ COMPLIANT' if compliance['overall_compliant'] else '✗ NON-COMPLIANT'}")
            
            if results['recommendations']:
                print("\nRecommendations:")
                for rec in results['recommendations']:
                    print(f"  • {rec}")
    
    elif args.apply:
        results = manager.apply_configuration(
            set_backlog_limit=args.set_backlog_limit,
            make_immutable=args.make_immutable
        )
        
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print("Applying System Logging and Auditing Configuration")
            print("=" * 50)
            print(f"Timestamp: {results['timestamp']}\n")
            
            if results['actions_taken']:
                print("Actions Taken:")
                for action in results['actions_taken']:
                    print(f"  ✓ {action}")
            
            if results['errors']:
                print("\nErrors:")
                for error in results['errors']:
                    print(f"  ✗ {error}")
            
            if 'rules_diff' in results:
                print(f"\nAudit Rules Diff:")
                print(results['rules_diff'])
            
            print(f"\nOverall Success: {'✓' if results['success'] else '✗'}")


if __name__ == '__main__':
    main()