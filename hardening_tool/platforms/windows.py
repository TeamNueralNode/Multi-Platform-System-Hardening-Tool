"""
Windows platform implementation for Windows 10/11 hardening.

Handles Windows-specific hardening operations including registry modifications,
PowerShell execution, SMB configuration, and Windows Defender settings.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ..core.models import HardeningRule, OSType, RollbackPoint, RuleResult, RuleStatus
from .base import BasePlatform


class WindowsPlatform(BasePlatform):
    """
    Windows platform handler for Windows 10/11 systems.
    
    Implements Windows-specific hardening operations using PowerShell,
    registry modifications, and Windows management tools.
    """
    
    def __init__(self, os_type: OSType):
        """Initialize Windows platform handler."""
        super().__init__(os_type)
        self.powershell_path = self._find_powershell()
    
    def audit_rule(self, rule: HardeningRule) -> RuleResult:
        """
        Audit a Windows hardening rule.
        
        Args:
            rule: Hardening rule to audit
            
        Returns:
            RuleResult: Audit result
        """
        start_time = datetime.utcnow()
        
        try:
            # Handle different rule types
            if rule.id.startswith('smb_'):
                return self._audit_smb_rule(rule)
            elif rule.id.startswith('registry_'):
                return self._audit_registry_rule(rule)
            elif rule.id.startswith('firewall_'):
                return self._audit_windows_firewall_rule(rule)
            elif rule.id.startswith('uac_'):
                return self._audit_uac_rule(rule)
            elif rule.id.startswith('defender_'):
                return self._audit_defender_rule(rule)
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
        Apply a Windows hardening rule.
        
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
            if rule.id.startswith('smb_'):
                return self._apply_smb_rule(rule, audit_result)
            elif rule.id.startswith('registry_'):
                return self._apply_registry_rule(rule, audit_result)
            elif rule.id.startswith('firewall_'):
                return self._apply_windows_firewall_rule(rule, audit_result)
            elif rule.id.startswith('uac_'):
                return self._apply_uac_rule(rule, audit_result)
            elif rule.id.startswith('defender_'):
                return self._apply_defender_rule(rule, audit_result)
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
        """Create backup data for Windows system rollback."""
        # Backup critical registry keys
        critical_registry_keys = [
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
        ]
        
        for reg_key in critical_registry_keys:
            try:
                values = self._export_registry_key(reg_key)
                rollback_point.registry_backups[reg_key] = values
            except Exception:
                continue  # Skip keys that can't be read
        
        # Backup Windows services states
        important_services = ["LanmanServer", "Spooler", "WinDefend", "MpsSvc"]
        for service in important_services:
            try:
                status = self.get_service_status(service)
                rollback_point.service_states[service] = status
            except Exception:
                continue
        
        return rollback_point
    
    def perform_rollback(self, rollback_point: RollbackPoint) -> None:
        """Restore Windows system state from rollback point."""
        errors = []
        
        # Restore registry values
        for reg_key, values in rollback_point.registry_backups.items():
            try:
                self._import_registry_key(reg_key, values)
            except Exception as e:
                errors.append(f"Failed to restore registry key {reg_key}: {e}")
        
        # Restore service states
        for service, original_state in rollback_point.service_states.items():
            try:
                if original_state.get('running') and original_state.get('start_type') == 'Automatic':
                    self.start_service(service)
                    self._set_service_startup_type(service, 'Automatic')
                elif not original_state.get('running') and original_state.get('start_type') == 'Disabled':
                    self.stop_service(service)
                    self._set_service_startup_type(service, 'Disabled')
                # Handle other combinations as needed
            except Exception as e:
                errors.append(f"Failed to restore service {service}: {e}")
        
        if errors:
            raise RuntimeError("Rollback completed with errors: " + "; ".join(errors))
    
    def get_service_status(self, service_name: str) -> Dict[str, Any]:
        """Get Windows service status using PowerShell."""
        ps_script = f"""
        $service = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
        if ($service) {{
            $startType = (Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'").StartMode
            @{{
                'running' = ($service.Status -eq 'Running')
                'status' = $service.Status
                'start_type' = $startType
            }} | ConvertTo-Json -Compress
        }} else {{
            @{{'error' = 'Service not found'}} | ConvertTo-Json -Compress
        }}
        """
        
        result = self._execute_powershell(ps_script)
        
        if result['success']:
            try:
                return json.loads(result['stdout'])
            except json.JSONDecodeError:
                return {'error': 'Failed to parse service status'}
        else:
            return {'error': result['stderr']}
    
    def start_service(self, service_name: str) -> bool:
        """Start a Windows service."""
        ps_script = f"Start-Service -Name '{service_name}' -ErrorAction Stop"
        result = self._execute_powershell(ps_script)
        return result['success']
    
    def stop_service(self, service_name: str) -> bool:
        """Stop a Windows service."""
        ps_script = f"Stop-Service -Name '{service_name}' -Force -ErrorAction Stop"
        result = self._execute_powershell(ps_script)
        return result['success']
    
    def enable_service(self, service_name: str) -> bool:
        """Enable a Windows service (set to Automatic startup)."""
        return self._set_service_startup_type(service_name, 'Automatic')
    
    def disable_service(self, service_name: str) -> bool:
        """Disable a Windows service."""
        return self._set_service_startup_type(service_name, 'Disabled')
    
    def read_config_file(self, file_path: str) -> str:
        """Read a Windows configuration file."""
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                return f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        except PermissionError:
            raise PermissionError(f"Permission denied reading: {file_path}")
    
    def write_config_file(self, file_path: str, content: str, backup: bool = True) -> bool:
        """Write to a Windows configuration file."""
        try:
            if backup and Path(file_path).exists():
                self.backup_file(file_path)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True
        except Exception:
            return False
    
    def backup_file(self, file_path: str) -> str:
        """Create a timestamped backup of a file."""
        import shutil
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{file_path}.backup_{timestamp}"
        
        try:
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception as e:
            raise IOError(f"Failed to backup {file_path}: {e}")
    
    def restore_file(self, file_path: str, backup_path: str) -> bool:
        """Restore a file from backup."""
        import shutil
        
        try:
            shutil.copy2(backup_path, file_path)
            return True
        except Exception:
            return False
    
    def _audit_smb_rule(self, rule: HardeningRule) -> RuleResult:
        """Audit SMB-specific rules."""
        if rule.id == "smb_disable_v1":
            return self._audit_smb_v1_disable(rule)
        else:
            return self._audit_generic_rule(rule)
    
    def _audit_smb_v1_disable(self, rule: HardeningRule) -> RuleResult:
        """Audit SMBv1 disable configuration."""
        start_time = datetime.utcnow()
        
        try:
            # Check if SMBv1 is disabled via PowerShell
            ps_script = """
            $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            if ($smbv1) {
                @{
                    'feature_state' = $smbv1.State
                    'feature_enabled' = ($smbv1.State -eq 'Enabled')
                } | ConvertTo-Json -Compress
            } else {
                # Check registry as fallback
                $regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters'
                $smbv1Value = Get-ItemProperty -Path $regPath -Name 'SMB1' -ErrorAction SilentlyContinue
                @{
                    'registry_value' = if ($smbv1Value) { $smbv1Value.SMB1 } else { $null }
                    'registry_enabled' = if ($smbv1Value) { $smbv1Value.SMB1 -ne 0 } else { $true }
                } | ConvertTo-Json -Compress
            }
            """
            
            result = self._execute_powershell(ps_script)
            
            if result['success']:
                data = json.loads(result['stdout'])
                
                # Determine if SMBv1 is disabled
                if 'feature_enabled' in data:
                    smb_enabled = data['feature_enabled']
                    status_info = f"Feature state: {data['feature_state']}"
                elif 'registry_enabled' in data:
                    smb_enabled = data['registry_enabled']
                    reg_value = data['registry_value']
                    status_info = f"Registry value: {reg_value}"
                else:
                    smb_enabled = True  # Assume enabled if can't determine
                    status_info = "Unable to determine SMBv1 state"
                
                if smb_enabled:
                    status = RuleStatus.FAIL
                    message = f"SMBv1 is enabled - {status_info}"
                else:
                    status = RuleStatus.PASS
                    message = f"SMBv1 is disabled - {status_info}"
                
                end_time = datetime.utcnow()
                execution_time = int((end_time - start_time).total_seconds() * 1000)
                
                return RuleResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    status=status,
                    severity=rule.severity,
                    execution_time_ms=execution_time,
                    message=message,
                    before_state=data
                )
            else:
                raise RuntimeError(f"PowerShell execution failed: {result['stderr']}")
                
        except Exception as e:
            end_time = datetime.utcnow()
            execution_time = int((end_time - start_time).total_seconds() * 1000)
            
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=RuleStatus.ERROR,
                severity=rule.severity,
                execution_time_ms=execution_time,
                message=f"Error checking SMBv1 status: {str(e)}"
            )
    
    def _apply_smb_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply SMB-specific rules."""
        if rule.id == "smb_disable_v1":
            return self._apply_smb_v1_disable(rule, audit_result)
        else:
            return self._apply_generic_rule(rule, audit_result)
    
    def _apply_smb_v1_disable(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply SMBv1 disable rule."""
        start_time = datetime.utcnow()
        
        try:
            # Disable SMBv1 using PowerShell
            ps_script = """
            try {
                # Try to disable via Windows Features first
                $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
                if ($feature -and $feature.State -eq 'Enabled') {
                    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
                    Write-Output 'SMBv1 disabled via Windows Features'
                } else {
                    # Fallback to registry method
                    $regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters'
                    Set-ItemProperty -Path $regPath -Name 'SMB1' -Value 0 -Type DWord -Force
                    Write-Output 'SMBv1 disabled via registry'
                }
                
                # Also disable SMBv1 client
                $clientRegPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10'
                Set-ItemProperty -Path $clientRegPath -Name 'Start' -Value 4 -Type DWord -Force
                
                Write-Output 'SMBv1 client disabled'
            } catch {
                Write-Error $_.Exception.Message
                exit 1
            }
            """
            
            result = self._execute_powershell(ps_script)
            
            if result['success']:
                end_time = datetime.utcnow()
                execution_time = int((end_time - start_time).total_seconds() * 1000)
                
                return RuleResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    status=RuleStatus.PASS,
                    severity=rule.severity,
                    execution_time_ms=execution_time,
                    message="SMBv1 disabled successfully (restart may be required)",
                    before_state=audit_result.before_state,
                    after_state={"smb1_disabled": True},
                    stdout=result['stdout'],
                    remediation_required=False
                )
            else:
                raise RuntimeError(f"Failed to disable SMBv1: {result['stderr']}")
                
        except Exception as e:
            end_time = datetime.utcnow()
            execution_time = int((end_time - start_time).total_seconds() * 1000)
            
            return RuleResult(
                rule_id=rule.id,
                rule_title=rule.title,
                status=RuleStatus.ERROR,
                severity=rule.severity,
                execution_time_ms=execution_time,
                message=f"Failed to disable SMBv1: {str(e)}",
                remediation_required=True
            )
    
    def _execute_powershell(self, script: str) -> Dict[str, Any]:
        """Execute a PowerShell script and return results."""
        try:
            cmd = [
                self.powershell_path,
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-Command', script
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False
            )
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode,
                'success': result.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            return {
                'stdout': '',
                'stderr': 'PowerShell script timed out',
                'exit_code': -1,
                'success': False
            }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1,
                'success': False
            }
    
    def _export_registry_key(self, reg_key: str) -> Dict[str, Any]:
        """Export registry key values."""
        ps_script = f"""
        try {{
            $values = @{{}}
            $key = Get-Item -Path 'Registry::{reg_key}' -ErrorAction Stop
            foreach ($valueName in $key.GetValueNames()) {{
                $value = $key.GetValue($valueName)
                $valueType = $key.GetValueKind($valueName)
                $values[$valueName] = @{{
                    'value' = $value
                    'type' = $valueType.ToString()
                }}
            }}
            $values | ConvertTo-Json -Compress
        }} catch {{
            Write-Error $_.Exception.Message
            exit 1
        }}
        """
        
        result = self._execute_powershell(ps_script)
        
        if result['success']:
            return json.loads(result['stdout'])
        else:
            raise RuntimeError(f"Failed to export registry key {reg_key}: {result['stderr']}")
    
    def _import_registry_key(self, reg_key: str, values: Dict[str, Any]) -> None:
        """Import registry key values."""
        for value_name, value_data in values.items():
            ps_script = f"""
            try {{
                $regPath = 'Registry::{reg_key}'
                $valueName = '{value_name}'
                $valueData = '{value_data["value"]}'
                $valueType = '{value_data["type"]}'
                
                Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType -Force
            }} catch {{
                Write-Error $_.Exception.Message
                exit 1
            }}
            """
            
            result = self._execute_powershell(ps_script)
            if not result['success']:
                raise RuntimeError(f"Failed to set registry value {value_name}: {result['stderr']}")
    
    def _set_service_startup_type(self, service_name: str, startup_type: str) -> bool:
        """Set Windows service startup type."""
        ps_script = f"Set-Service -Name '{service_name}' -StartupType '{startup_type}' -ErrorAction Stop"
        result = self._execute_powershell(ps_script)
        return result['success']
    
    def _find_powershell(self) -> str:
        """Find PowerShell executable path."""
        # Try PowerShell 7+ first, then Windows PowerShell
        possible_paths = [
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            r"C:\Program Files (x86)\PowerShell\7\pwsh.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
        ]
        
        for path in possible_paths:
            if Path(path).exists():
                return path
        
        # Fallback to PATH lookup
        return "powershell.exe"
    
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
        
        # Execute as PowerShell if it looks like PowerShell syntax
        if rule.audit_command.startswith('$') or 'Get-' in rule.audit_command:
            result = self._execute_powershell(rule.audit_command)
        else:
            result = self.execute_command(rule.audit_command)
        
        # Determine status based on exit code and expected values
        if result['success']:
            status = RuleStatus.PASS
            message = "Audit passed"
        else:
            status = RuleStatus.FAIL
            message = f"Audit failed: {result['stderr']}"
        
        end_time = datetime.utcnow()
        execution_time = int((end_time - start_time).total_seconds() * 1000)
        
        return RuleResult(
            rule_id=rule.id,
            rule_title=rule.title,
            status=status,
            severity=rule.severity,
            execution_time_ms=execution_time,
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
        
        # Execute as PowerShell if it looks like PowerShell syntax
        if rule.apply_command.startswith('$') or 'Set-' in rule.apply_command:
            result = self._execute_powershell(rule.apply_command)
        else:
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
            execution_time_ms=result.get('execution_time_ms', 0),
            stdout=result['stdout'],
            stderr=result['stderr'],
            exit_code=result['exit_code'],
            message=message,
            before_state=audit_result.before_state
        )
    
    # Placeholder methods for other rule types
    def _audit_registry_rule(self, rule: HardeningRule) -> RuleResult:
        """Audit registry-related rules."""
        return self._audit_generic_rule(rule)
    
    def _audit_windows_firewall_rule(self, rule: HardeningRule) -> RuleResult:
        """Audit Windows Firewall rules."""
        return self._audit_generic_rule(rule)
    
    def _audit_uac_rule(self, rule: HardeningRule) -> RuleResult:
        """Audit UAC-related rules."""
        return self._audit_generic_rule(rule)
    
    def _audit_defender_rule(self, rule: HardeningRule) -> RuleResult:
        """Audit Windows Defender rules."""
        return self._audit_generic_rule(rule)
    
    def _apply_registry_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply registry-related rules."""
        return self._apply_generic_rule(rule, audit_result)
    
    def _apply_windows_firewall_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply Windows Firewall rules."""
        return self._apply_generic_rule(rule, audit_result)
    
    def _apply_uac_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply UAC-related rules."""
        return self._apply_generic_rule(rule, audit_result)
    
    def _apply_defender_rule(self, rule: HardeningRule, audit_result: RuleResult) -> RuleResult:
        """Apply Windows Defender rules."""
        return self._apply_generic_rule(rule, audit_result)