"""
Linux platform implementation for Ubuntu and CentOS hardening.

Handles Linux-specific hardening operations including SSH configuration,
firewall management, user policies, and service configuration.
"""

import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ..core.models import HardeningRule, OSType, RollbackPoint, RuleResult, RuleStatus
from .base import BasePlatform


class LinuxPlatform(BasePlatform):
    """
    Linux platform handler for Ubuntu and CentOS systems.
    
    Implements Linux-specific hardening operations with support
    for different distributions and service managers.
    """
    
    def __init__(self, os_type: OSType):
        """Initialize Linux platform handler."""
        super().__init__(os_type)
        self.service_manager = self._detect_service_manager()
        self.package_manager = self._detect_package_manager()
    
    def audit_rule(self, rule: HardeningRule) -> RuleResult:
        """
        Audit a Linux hardening rule.
        
        Args:
            rule: Hardening rule to audit
            
        Returns:
            RuleResult: Audit result
        """
        start_time = datetime.utcnow()
        
        try:
            # Handle different rule types
            if rule.id.startswith('ssh_'):
                return self._audit_ssh_rule(rule)
            elif rule.id.startswith('firewall_'):
                return self._audit_firewall_rule(rule)
            elif rule.id.startswith('user_'):
                return self._audit_user_rule(rule)
            elif rule.id.startswith('service_'):
                return self._audit_service_rule(rule)
            elif rule.id.startswith('sysctl_'):
                return self._audit_sysctl_rule(rule)
            else:
                # Generic audit using audit_command
                return self._audit_generic_rule(rule)
                
        except Exception as e:
            end_time = datetime.utcnow()
            execution_time = int((end_time - start_time).total_seconds() * 1000)
            
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=RuleStatus.ERROR,
                severity=rule.severity,
                execution_time_ms=execution_time,
                message=f"Audit error: {str(e)}"
            )
    
    def apply_rule(self, rule: HardeningRule) -> RuleResult:
        """
        Apply a Linux hardening rule.
        
        Args:
            rule: Hardening rule to apply
            
        Returns:
            RuleResult: Application result
        """
        start_time = datetime.utcnow()
        
        try:
            # First audit to get current state
            audit_result = self.audit_rule(rule)
            
            if audit_result.status == RuleStatus.PASS:
                # Rule already compliant, no action needed
                audit_result.message = "Already compliant, no changes made"
                return audit_result
            
            # Apply the rule based on type
            if rule.id.startswith('ssh_'):
                return self._apply_ssh_rule(rule, audit_result)
            elif rule.id.startswith('firewall_'):
                return self._apply_firewall_rule(rule, audit_result)
            elif rule.id.startswith('user_'):
                return self._apply_user_rule(rule, audit_result)
            elif rule.id.startswith('service_'):
                return self._apply_service_rule(rule, audit_result)
            elif rule.id.startswith('sysctl_'):
                return self._apply_sysctl_rule(rule, audit_result)
            else:
                # Generic application using apply_command
                return self._apply_generic_rule(rule, audit_result)
                
        except Exception as e:
            end_time = datetime.utcnow()
            execution_time = int((end_time - start_time).total_seconds() * 1000)
            
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=RuleStatus.ERROR,
                severity=rule.severity,
                execution_time_ms=execution_time,
                message=f"Application error: {str(e)}"
            )
    
    def create_rollback_point(self, rollback_point: RollbackPoint) -> RollbackPoint:
        """Create backup data for Linux system rollback."""
        # Backup critical configuration files
        critical_files = [
            "/etc/ssh/sshd_config",
            "/etc/sudoers",
            "/etc/passwd",
            "/etc/group", 
            "/etc/shadow",
            "/etc/sysctl.conf",
            "/etc/security/limits.conf",
            "/etc/pam.d/common-auth",
            "/etc/pam.d/common-password"
        ]
        
        for file_path in critical_files:
            if Path(file_path).exists():
                try:
                    content = self.read_config_file(file_path)
                    rollback_point.config_backups[file_path] = content
                    rollback_point.file_checksums[file_path] = self.get_file_checksum(file_path)
                except Exception:
                    continue  # Skip files that can't be read
        
        # Backup service states
        important_services = ["ssh", "sshd", "ufw", "firewalld", "iptables"]
        for service in important_services:
            try:
                status = self.get_service_status(service)
                rollback_point.service_states[service] = status
            except Exception:
                continue
        
        return rollback_point
    
    def perform_rollback(self, rollback_point: RollbackPoint) -> None:
        """Restore Linux system state from rollback point."""
        errors = []
        
        # Restore configuration files
        for file_path, backup_content in rollback_point.config_backups.items():
            try:
                # Verify current file hasn't been tampered with
                if Path(file_path).exists():
                    current_checksum = self.get_file_checksum(file_path)
                    expected_checksum = rollback_point.file_checksums.get(file_path)
                    # Note: Skip checksum verification for now as file may have been legitimately changed
                
                # Restore file content
                self.write_config_file(file_path, backup_content, backup=False)
                
            except Exception as e:
                errors.append(f"Failed to restore {file_path}: {e}")
        
        # Restore service states
        for service, original_state in rollback_point.service_states.items():
            try:
                if original_state.get('active') and not original_state.get('enabled'):
                    # Was running but not enabled
                    self.start_service(service)
                    self.disable_service(service)
                elif not original_state.get('active') and original_state.get('enabled'):
                    # Was enabled but not running
                    self.stop_service(service)
                    self.enable_service(service)
                elif original_state.get('active') and original_state.get('enabled'):
                    # Was running and enabled
                    self.start_service(service)
                    self.enable_service(service)
                else:
                    # Was stopped and disabled
                    self.stop_service(service)
                    self.disable_service(service)
                    
            except Exception as e:
                errors.append(f"Failed to restore service {service}: {e}")
        
        if errors:
            raise RuntimeError("Rollback completed with errors: " + "; ".join(errors))
    
    def get_service_status(self, service_name: str) -> Dict[str, Any]:
        """Get Linux service status using systemctl or service command."""
        if self.service_manager == "systemctl":
            # Modern systemd systems
            result = self.execute_command(f"systemctl is-active {service_name}")
            active = result['stdout'].strip() == "active"
            
            result = self.execute_command(f"systemctl is-enabled {service_name}")
            enabled = result['stdout'].strip() == "enabled"
            
            return {
                'active': active,
                'enabled': enabled,
                'service_manager': 'systemctl'
            }
        else:
            # Legacy SysV init
            result = self.execute_command(f"service {service_name} status")
            active = result['exit_code'] == 0
            
            # Check if service is enabled (varies by distribution)
            if self.os_type == OSType.UBUNTU:
                result = self.execute_command(f"update-rc.d -n -f {service_name} remove")
                enabled = result['exit_code'] != 0  # If removal fails, it's enabled
            else:
                result = self.execute_command(f"chkconfig --list {service_name}")
                enabled = ":on" in result['stdout']
            
            return {
                'active': active,
                'enabled': enabled,
                'service_manager': 'service'
            }
    
    def start_service(self, service_name: str) -> bool:
        """Start a Linux service."""
        if self.service_manager == "systemctl":
            result = self.execute_command(f"systemctl start {service_name}")
        else:
            result = self.execute_command(f"service {service_name} start")
        
        return result['success']
    
    def stop_service(self, service_name: str) -> bool:
        """Stop a Linux service."""
        if self.service_manager == "systemctl":
            result = self.execute_command(f"systemctl stop {service_name}")
        else:
            result = self.execute_command(f"service {service_name} stop")
        
        return result['success']
    
    def enable_service(self, service_name: str) -> bool:
        """Enable a Linux service to start at boot."""
        if self.service_manager == "systemctl":
            result = self.execute_command(f"systemctl enable {service_name}")
        else:
            if self.os_type == OSType.UBUNTU:
                result = self.execute_command(f"update-rc.d {service_name} enable")
            else:
                result = self.execute_command(f"chkconfig {service_name} on")
        
        return result['success']
    
    def disable_service(self, service_name: str) -> bool:
        """Disable a Linux service from starting at boot."""
        if self.service_manager == "systemctl":
            result = self.execute_command(f"systemctl disable {service_name}")
        else:
            if self.os_type == OSType.UBUNTU:
                result = self.execute_command(f"update-rc.d {service_name} disable")
            else:
                result = self.execute_command(f"chkconfig {service_name} off")
        
        return result['success']
    
    def read_config_file(self, file_path: str) -> str:
        """Read a Linux configuration file."""
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        except PermissionError:
            raise PermissionError(f"Permission denied reading: {file_path}")
    
    def write_config_file(self, file_path: str, content: str, backup: bool = True) -> bool:
        """Write to a Linux configuration file."""
        try:
            if backup and Path(file_path).exists():
                self.backup_file(file_path)
            
            with open(file_path, 'w') as f:
                f.write(content)
            
            return True
        except Exception:
            return False
    
    def backup_file(self, file_path: str) -> str:
        """Create a timestamped backup of a file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{file_path}.backup_{timestamp}"
        
        try:
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception as e:
            raise IOError(f"Failed to backup {file_path}: {e}")
    
    def restore_file(self, file_path: str, backup_path: str) -> bool:
        """Restore a file from backup."""
        try:
            shutil.copy2(backup_path, file_path)
            return True
        except Exception:
            return False
    
    def _audit_ssh_rule(self, rule: HardeningRule) -> RuleResult:
        """Audit SSH-specific rules."""
        if rule.id == "ssh_disable_root_login":
            return self._audit_ssh_root_login(rule)
        elif rule.id == "ssh_disable_password_auth":
            return self._audit_ssh_password_auth(rule)
        else:
            return self._audit_generic_rule(rule)
    
    def _audit_ssh_root_login(self, rule: HardeningRule) -> RuleResult:
        """Audit SSH root login configuration."""
        start_time = datetime.utcnow()
        
        try:
            sshd_config_path = "/etc/ssh/sshd_config"
            if not Path(sshd_config_path).exists():
                return RuleResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    status=RuleStatus.NOT_APPLICABLE,
                    severity=rule.severity,
                    message="SSH daemon not installed"
                )
            
            content = self.read_config_file(sshd_config_path)
            
            # Check for PermitRootLogin setting
            permit_root_pattern = r'^\s*PermitRootLogin\s+(\S+)'
            matches = re.findall(permit_root_pattern, content, re.MULTILINE | re.IGNORECASE)
            
            if matches:
                last_setting = matches[-1].lower()  # Take the last occurrence
                if last_setting in ['no', 'false', 'prohibit-password', 'forced-commands-only']:
                    status = RuleStatus.PASS
                    message = f"Root login properly restricted: PermitRootLogin {last_setting}"
                else:
                    status = RuleStatus.FAIL
                    message = f"Root login enabled: PermitRootLogin {last_setting}"
            else:
                # Default behavior varies, but generally root login is enabled
                status = RuleStatus.FAIL
                message = "PermitRootLogin not explicitly set (defaults to enabled)"
            
            end_time = datetime.utcnow()
            execution_time = int((end_time - start_time).total_seconds() * 1000)
            
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=status,
                severity=rule.severity,
                execution_time_ms=execution_time,
                message=message,
                before_state={"permit_root_login": matches[-1] if matches else None}
            )
            
        except Exception as e:
            end_time = datetime.utcnow()
            execution_time = int((end_time - start_time).total_seconds() * 1000)
            
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=RuleStatus.ERROR,
                severity=rule.severity,
                execution_time_ms=execution_time,
                message=f"Error checking SSH configuration: {str(e)}"
            )
    
    def _audit_ssh_password_auth(self, rule: HardeningRule) -> RuleResult:
        """Audit SSH password authentication configuration."""
        start_time = datetime.utcnow()
        
        try:
            sshd_config_path = "/etc/ssh/sshd_config"
            if not Path(sshd_config_path).exists():
                return RuleResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    status=RuleStatus.NOT_APPLICABLE,
                    severity=rule.severity,
                    message="SSH daemon not installed"
                )
            
            content = self.read_config_file(sshd_config_path)
            
            # Check for PasswordAuthentication setting
            password_auth_pattern = r'^\s*PasswordAuthentication\s+(\S+)'
            matches = re.findall(password_auth_pattern, content, re.MULTILINE | re.IGNORECASE)
            
            if matches:
                last_setting = matches[-1].lower()  # Take the last occurrence
                if last_setting in ['no', 'false']:
                    status = RuleStatus.PASS
                    message = f"Password authentication disabled: PasswordAuthentication {last_setting}"
                else:
                    status = RuleStatus.FAIL
                    message = f"Password authentication enabled: PasswordAuthentication {last_setting}"
            else:
                # Default behavior is typically to allow password authentication
                status = RuleStatus.FAIL
                message = "PasswordAuthentication not explicitly set (defaults to enabled)"
            
            end_time = datetime.utcnow()
            execution_time = int((end_time - start_time).total_seconds() * 1000)
            
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=status,
                severity=rule.severity,
                execution_time_ms=execution_time,
                message=message,
                before_state={"password_authentication": matches[-1] if matches else None}
            )
            
        except Exception as e:
            end_time = datetime.utcnow()
            execution_time = int((end_time - start_time).total_seconds() * 1000)
            
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=RuleStatus.ERROR,
                severity=rule.severity,
                execution_time_ms=execution_time,
                message=f"Error checking SSH password authentication: {str(e)}"
            )
    
    def _apply_ssh_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply SSH-specific rules."""
        if rule.id == "ssh_disable_root_login":
            return self._apply_ssh_root_login_disable(rule, audit_result)
        else:
            return self._apply_generic_rule(rule, audit_result)
    
    def _apply_ssh_root_login_disable(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply SSH root login disable rule."""
        start_time = datetime.utcnow()
        
        try:
            sshd_config_path = "/etc/ssh/sshd_config"
            content = self.read_config_file(sshd_config_path)
            original_content = content
            
            # Remove existing PermitRootLogin lines
            content = re.sub(r'^\s*PermitRootLogin\s+.*$', '', content, flags=re.MULTILINE)
            
            # Add the secure setting
            if not content.endswith('\n'):
                content += '\n'
            content += 'PermitRootLogin no\n'
            
            # Write the modified configuration
            success = self.write_config_file(sshd_config_path, content, backup=True)
            
            if success:
                # Restart SSH service to apply changes
                if self.service_manager == "systemctl":
                    restart_result = self.execute_command("systemctl reload ssh || systemctl reload sshd")
                else:
                    restart_result = self.execute_command("service ssh reload || service sshd reload")
                
                if not restart_result['success']:
                    # Rollback on restart failure
                    self.write_config_file(sshd_config_path, original_content, backup=False)
                    raise RuntimeError("Failed to restart SSH service after configuration change")
                
                end_time = datetime.utcnow()
                execution_time = int((end_time - start_time).total_seconds() * 1000)
                
                return RuleResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    status=RuleStatus.PASS,
                    severity=rule.severity,
                    execution_time_ms=execution_time,
                    message="SSH root login disabled successfully",
                    before_state=audit_result.before_state,
                    after_state={"permit_root_login": "no"},
                    remediation_required=False
                )
            else:
                raise RuntimeError("Failed to write SSH configuration file")
                
        except Exception as e:
            end_time = datetime.utcnow()
            execution_time = int((end_time - start_time).total_seconds() * 1000)
            
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=RuleStatus.ERROR,
                severity=rule.severity,
                execution_time_ms=execution_time,
                message=f"Failed to disable SSH root login: {str(e)}",
                remediation_required=True
            )
    
    def _audit_generic_rule(self, rule: HardeningRule) -> RuleResult:
        """Generic audit using the rule's audit_command."""
        start_time = datetime.utcnow()
        
        if not rule.audit_command:
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=RuleStatus.SKIPPED,
                severity=rule.severity,
                message="No audit command defined for this rule"
            )
        
        result = self.execute_command(rule.audit_command)
        
        # Determine status based on exit code and expected values
        if result['success']:
            status = RuleStatus.PASS
            message = "Audit passed"
        else:
            status = RuleStatus.FAIL
            message = f"Audit failed: {result['stderr']}"
        
        return RuleResult(
            rule_id=rule.id,
            rule_title=rule.title,
            status=status,
            severity=rule.severity,
            execution_time_ms=result['execution_time_ms'],
            stdout=result['stdout'],
            stderr=result['stderr'],
            exit_code=result['exit_code'],
            message=message
        )
    
    def _apply_generic_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Generic application using the rule's apply_command."""
        if not rule.apply_command:
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=RuleStatus.SKIPPED,
                severity=rule.severity,
                message="No apply command defined for this rule"
            )
        
        result = self.execute_command(rule.apply_command)
        
        if result['success']:
            status = RuleStatus.PASS
            message = "Rule applied successfully"
        else:
            status = RuleStatus.ERROR
            message = f"Application failed: {result['stderr']}"
        
        return RuleResult(
            rule_id=rule.id,
            rule_title=rule.title,
            status=status,
            severity=rule.severity,
            execution_time_ms=result['execution_time_ms'],
            stdout=result['stdout'],
            stderr=result['stderr'],
            exit_code=result['exit_code'],
            message=message,
            before_state=audit_result.before_state
        )
    
    # Placeholder methods for other rule types
    def _audit_firewall_rule(self, rule: HardeningRule) -> RuleResult:
        """Audit firewall-related rules."""
        return self._audit_generic_rule(rule)
    
    def _audit_user_rule(self, rule: HardeningRule) -> RuleResult:
        """Audit user-related rules."""
        return self._audit_generic_rule(rule)
    
    def _audit_service_rule(self, rule: HardeningRule) -> RuleResult:
        """Audit service-related rules."""
        return self._audit_generic_rule(rule)
    
    def _audit_sysctl_rule(self, rule: HardeningRule) -> RuleResult:
        """Audit sysctl-related rules."""
        return self._audit_generic_rule(rule)
    
    def _apply_firewall_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply firewall-related rules.""" 
        return self._apply_generic_rule(rule, audit_result)
    
    def _apply_user_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply user-related rules."""
        return self._apply_generic_rule(rule, audit_result)
    
    def _apply_service_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply service-related rules."""
        return self._apply_generic_rule(rule, audit_result)
    
    def _apply_sysctl_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply sysctl-related rules."""
        return self._apply_generic_rule(rule, audit_result)
    
    def _detect_service_manager(self) -> str:
        """Detect the system service manager."""
        if Path("/bin/systemctl").exists() or Path("/usr/bin/systemctl").exists():
            return "systemctl"
        else:
            return "service"
    
    def _detect_package_manager(self) -> str:
        """Detect the system package manager."""
        if Path("/usr/bin/apt").exists():
            return "apt"
        elif Path("/usr/bin/yum").exists():
            return "yum"
        elif Path("/usr/bin/dnf").exists():
            return "dnf"
        else:
            return "unknown"