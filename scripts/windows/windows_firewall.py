import json
import sqlite3
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

class WindowsFirewallManager:
    """Windows Firewall management module for Annexure-A compliance."""
    
    def __init__(self, db_path: str = "hardening_results.db"):
        self.db_path = db_path
        self.desired_settings = {
            "Private": {
                "State": "ON",
                "InboundAction": "Block",
                "OutboundAction": "Allow",
                "LoggingEnabled": "Yes",
                "LogFilePath": "%SystemRoot%\\System32\\LogFiles\\Firewall\\privatefw.log",
                "LogMaxFileSize": 16384,  # KB
                "LogDroppedPackets": "Yes",
                "LogAllowedConnections": "Yes"
            },
            "Public": {
                "State": "ON", 
                "InboundAction": "Block",
                "OutboundAction": "Allow",
                "LoggingEnabled": "Yes",
                "LogFilePath": "%SystemRoot%\\System32\\LogFiles\\Firewall\\publicfw.log",
                "LogMaxFileSize": 16384,  # KB
                "LogDroppedPackets": "Yes",
                "LogAllowedConnections": "Yes"
            }
        }
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for storing results."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS firewall_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        profile_name TEXT NOT NULL,
                        setting_name TEXT NOT NULL,
                        original_value TEXT,
                        applied_value TEXT,
                        compliant BOOLEAN,
                        operation TEXT NOT NULL
                    )
                """)
                conn.commit()
        except Exception as e:
            logging.error(f"Failed to initialize database: {e}")
    
    def _run_powershell_command(self, command: str) -> Dict[str, Any]:
        """Execute PowerShell command and return parsed result."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", command],
                capture_output=True,
                text=True,
                check=True
            )
            return {"success": True, "output": result.stdout.strip(), "error": None}
        except subprocess.CalledProcessError as e:
            return {"success": False, "output": None, "error": e.stderr}
        except Exception as e:
            return {"success": False, "output": None, "error": str(e)}
    
    def _run_netsh_command(self, command: str) -> Dict[str, Any]:
        """Execute netsh command and return parsed result."""
        try:
            result = subprocess.run(
                ["netsh"] + command.split(),
                capture_output=True,
                text=True,
                check=True
            )
            return {"success": True, "output": result.stdout.strip(), "error": None}
        except subprocess.CalledProcessError as e:
            return {"success": False, "output": None, "error": e.stderr}
        except Exception as e:
            return {"success": False, "output": None, "error": str(e)}
    
    def get_firewall_profile_settings(self) -> Dict[str, Dict[str, Any]]:
        """Get current firewall settings for Private and Public profiles."""
        profiles = {}
        
        for profile_name in ["Private", "Public"]:
            try:
                # Try PowerShell method first
                ps_command = f"""
                $profile = Get-NetFirewallProfile -Profile {profile_name}
                $logging = Get-NetFirewallProfile -Profile {profile_name} | Select-Object -ExpandProperty LoggingSettings
                @{{
                    'State' = if($profile.Enabled) {{'ON'}} else {{'OFF'}}
                    'InboundAction' = $profile.DefaultInboundAction
                    'OutboundAction' = $profile.DefaultOutboundAction
                    'LoggingEnabled' = if($profile.LogAllowed -or $profile.LogBlocked) {{'Yes'}} else {{'No'}}
                    'LogFilePath' = $profile.LogFileName
                    'LogMaxFileSize' = $profile.LogMaxSizeKilobytes
                    'LogDroppedPackets' = if($profile.LogBlocked) {{'Yes'}} else {{'No'}}
                    'LogAllowedConnections' = if($profile.LogAllowed) {{'Yes'}} else {{'No'}}
                }} | ConvertTo-Json
                """
                
                ps_result = self._run_powershell_command(ps_command)
                
                if ps_result["success"]:
                    profiles[profile_name] = json.loads(ps_result["output"])
                else:
                    # Fallback to netsh method
                    netsh_result = self._get_profile_via_netsh(profile_name)
                    if netsh_result:
                        profiles[profile_name] = netsh_result
                    else:
                        raise Exception(f"Failed to get {profile_name} profile via both methods")
                        
            except Exception as e:
                logging.error(f"Failed to get {profile_name} profile settings: {e}")
                profiles[profile_name] = {}
        
        return profiles
    
    def _get_profile_via_netsh(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Get firewall profile settings using netsh command."""
        try:
            # Get basic firewall state
            netsh_result = self._run_netsh_command(f"advfirewall show {profile_name.lower()}profile")
            
            if not netsh_result["success"]:
                return None
            
            output = netsh_result["output"]
            settings = {}
            
            # Parse netsh output
            for line in output.split('\n'):
                line = line.strip()
                if "State" in line and "ON" in line:
                    settings["State"] = "ON"
                elif "State" in line and "OFF" in line:
                    settings["State"] = "OFF"
                elif "Inbound connections" in line:
                    if "Block" in line:
                        settings["InboundAction"] = "Block"
                    elif "Allow" in line:
                        settings["InboundAction"] = "Allow"
                elif "Outbound connections" in line:
                    if "Block" in line:
                        settings["OutboundAction"] = "Block" 
                    elif "Allow" in line:
                        settings["OutboundAction"] = "Allow"
            
            # Get logging settings
            logging_result = self._run_netsh_command(f"advfirewall show {profile_name.lower()}profile logging")
            
            if logging_result["success"]:
                log_output = logging_result["output"]
                settings["LoggingEnabled"] = "Yes" if "Yes" in log_output else "No"
                
                for line in log_output.split('\n'):
                    line = line.strip()
                    if "File name" in line:
                        settings["LogFilePath"] = line.split(":")[-1].strip()
                    elif "Max file size" in line:
                        try:
                            size_kb = int(line.split(":")[-1].strip().split()[0])
                            settings["LogMaxFileSize"] = size_kb
                        except:
                            settings["LogMaxFileSize"] = 0
                    elif "Log dropped packets" in line:
                        settings["LogDroppedPackets"] = "Yes" if "Yes" in line else "No"
                    elif "Log successful connections" in line:
                        settings["LogAllowedConnections"] = "Yes" if "Yes" in line else "No"
            
            return settings
            
        except Exception as e:
            logging.error(f"Failed to get {profile_name} profile via netsh: {e}")
            return None
    
    def audit_firewall_settings(self) -> Dict[str, Any]:
        """Audit current firewall settings against Annexure-A requirements."""
        current_settings = self.get_firewall_profile_settings()
        audit_results = {
            "audit_timestamp": datetime.now().isoformat(),
            "profiles": {}
        }
        
        for profile_name in ["Private", "Public"]:
            profile_results = {
                "profile_name": profile_name,
                "settings": [],
                "compliant": True
            }
            
            current_profile = current_settings.get(profile_name, {})
            desired_profile = self.desired_settings[profile_name]
            
            for setting_name, desired_value in desired_profile.items():
                current_value = current_profile.get(setting_name, "Unknown")
                
                # Special handling for log file size (minimum requirement)
                if setting_name == "LogMaxFileSize":
                    compliant = isinstance(current_value, (int, float)) and current_value >= desired_value
                else:
                    compliant = str(current_value).upper() == str(desired_value).upper()
                
                if not compliant:
                    profile_results["compliant"] = False
                
                setting_result = {
                    "rule_id": f"firewall_{profile_name.lower()}_{setting_name.lower()}",
                    "setting_name": setting_name,
                    "current_value": current_value,
                    "desired_value": desired_value,
                    "compliant": compliant,
                    "description": self._get_setting_description(setting_name)
                }
                
                profile_results["settings"].append(setting_result)
            
            audit_results["profiles"][profile_name] = profile_results
        
        return audit_results
    
    def _get_setting_description(self, setting_name: str) -> str:
        """Get human-readable description for firewall setting."""
        descriptions = {
            "State": "Firewall enabled/disabled state",
            "InboundAction": "Default action for inbound connections", 
            "OutboundAction": "Default action for outbound connections",
            "LoggingEnabled": "Firewall logging enabled/disabled",
            "LogFilePath": "Path to firewall log file",
            "LogMaxFileSize": "Maximum log file size in KB",
            "LogDroppedPackets": "Log dropped packets enabled/disabled",
            "LogAllowedConnections": "Log successful connections enabled/disabled"
        }
        return descriptions.get(setting_name, f"Firewall setting: {setting_name}")
    
    def save_manifest(self, original_settings: Dict[str, Dict[str, Any]], 
                     applied_settings: Dict[str, Dict[str, Any]]) -> str:
        """Save rollback manifest to JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        manifest_file = f"firewall_rollback_manifest_{timestamp}.json"
        
        manifest_data = {
            "timestamp": datetime.now().isoformat(),
            "backup_type": "windows_firewall_settings",
            "original_settings": original_settings,
            "applied_settings": applied_settings
        }
        
        try:
            with open(manifest_file, 'w') as f:
                json.dump(manifest_data, f, indent=2)
            
            logging.info(f"Rollback manifest saved to: {manifest_file}")
            return manifest_file
            
        except Exception as e:
            logging.error(f"Failed to save manifest: {e}")
            return ""
    
    def apply_firewall_settings(self, create_manifest: bool = True) -> Dict[str, Any]:
        """Apply Annexure-A firewall settings and record changes."""
        # Get current settings for backup
        original_settings = self.get_firewall_profile_settings()
        
        # Check compliance first
        audit_results = self.audit_firewall_settings()
        
        apply_results = {
            "apply_timestamp": datetime.now().isoformat(),
            "changes_made": [],
            "errors": [],
            "manifest_file": ""
        }
        
        changes_needed = False
        for profile_name, profile_data in audit_results["profiles"].items():
            if not profile_data["compliant"]:
                changes_needed = True
                break
        
        if not changes_needed:
            apply_results["message"] = "Firewall settings are already compliant"
            return apply_results
        
        # Apply settings for each profile
        for profile_name in ["Private", "Public"]:
            profile_changes = self._apply_profile_settings(profile_name, original_settings.get(profile_name, {}))
            apply_results["changes_made"].extend(profile_changes["changes"])
            apply_results["errors"].extend(profile_changes["errors"])
        
        # Get final settings after changes
        final_settings = self.get_firewall_profile_settings()
        
        # Save manifest for rollback
        if create_manifest:
            manifest_file = self.save_manifest(original_settings, final_settings)
            apply_results["manifest_file"] = manifest_file
        
        # Record results in database
        self._record_results_to_db(original_settings, final_settings, "apply")
        
        return apply_results
    
    def _apply_profile_settings(self, profile_name: str, original_settings: Dict[str, Any]) -> Dict[str, List[str]]:
        """Apply firewall settings for a specific profile."""
        changes = []
        errors = []
        desired_settings = self.desired_settings[profile_name]
        
        try:
            # Enable firewall
            if original_settings.get("State") != "ON":
                ps_command = f"Set-NetFirewallProfile -Profile {profile_name} -Enabled True"
                result = self._run_powershell_command(ps_command)
                
                if result["success"]:
                    changes.append(f"{profile_name}: Enabled firewall")
                else:
                    # Fallback to netsh
                    netsh_result = self._run_netsh_command(f"advfirewall set {profile_name.lower()}profile state on")
                    if netsh_result["success"]:
                        changes.append(f"{profile_name}: Enabled firewall (netsh)")
                    else:
                        errors.append(f"{profile_name}: Failed to enable firewall")
            
            # Set inbound action to block
            if original_settings.get("InboundAction") != "Block":
                ps_command = f"Set-NetFirewallProfile -Profile {profile_name} -DefaultInboundAction Block"
                result = self._run_powershell_command(ps_command)
                
                if result["success"]:
                    changes.append(f"{profile_name}: Set inbound action to Block")
                else:
                    netsh_result = self._run_netsh_command(f"advfirewall set {profile_name.lower()}profile firewallpolicy blockinbound,allowoutbound")
                    if netsh_result["success"]:
                        changes.append(f"{profile_name}: Set inbound action to Block (netsh)")
                    else:
                        errors.append(f"{profile_name}: Failed to set inbound action")
            
            # Set outbound action to allow
            if original_settings.get("OutboundAction") != "Allow":
                ps_command = f"Set-NetFirewallProfile -Profile {profile_name} -DefaultOutboundAction Allow"
                result = self._run_powershell_command(ps_command)
                
                if result["success"]:
                    changes.append(f"{profile_name}: Set outbound action to Allow")
                else:
                    errors.append(f"{profile_name}: Failed to set outbound action via PowerShell")
            
            # Configure logging
            log_changes = self._configure_logging(profile_name, original_settings)
            changes.extend(log_changes["changes"])
            errors.extend(log_changes["errors"])
            
        except Exception as e:
            errors.append(f"{profile_name}: Unexpected error - {str(e)}")
        
        return {"changes": changes, "errors": errors}
    
    def _configure_logging(self, profile_name: str, original_settings: Dict[str, Any]) -> Dict[str, List[str]]:
        """Configure firewall logging settings for a profile."""
        changes = []
        errors = []
        desired = self.desired_settings[profile_name]
        
        try:
            # Enable logging for allowed and blocked connections
            ps_command = f"""
            Set-NetFirewallProfile -Profile {profile_name} -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes {desired['LogMaxFileSize']}
            """
            
            result = self._run_powershell_command(ps_command)
            
            if result["success"]:
                changes.append(f"{profile_name}: Configured logging (allowed/blocked packets, max size {desired['LogMaxFileSize']}KB)")
            else:
                # Fallback to netsh commands
                netsh_commands = [
                    f"advfirewall set {profile_name.lower()}profile logging allowedconnections yes",
                    f"advfirewall set {profile_name.lower()}profile logging droppedconnections yes", 
                    f"advfirewall set {profile_name.lower()}profile logging maxfilesize {desired['LogMaxFileSize']}"
                ]
                
                for cmd in netsh_commands:
                    netsh_result = self._run_netsh_command(cmd)
                    if not netsh_result["success"]:
                        errors.append(f"{profile_name}: Failed to configure logging via netsh: {cmd}")
                
                if not errors:
                    changes.append(f"{profile_name}: Configured logging via netsh")
            
        except Exception as e:
            errors.append(f"{profile_name}: Failed to configure logging - {str(e)}")
        
        return {"changes": changes, "errors": errors}
    
    def _record_results_to_db(self, original_settings: Dict[str, Dict[str, Any]], 
                             final_settings: Dict[str, Dict[str, Any]], operation: str):
        """Record firewall configuration results to SQLite database."""
        try:
            timestamp = datetime.now().isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for profile_name in ["Private", "Public"]:
                    original_profile = original_settings.get(profile_name, {})
                    final_profile = final_settings.get(profile_name, {})
                    desired_profile = self.desired_settings[profile_name]
                    
                    for setting_name, desired_value in desired_profile.items():
                        original_value = str(original_profile.get(setting_name, "Unknown"))
                        applied_value = str(final_profile.get(setting_name, "Unknown"))
                        
                        # Determine compliance
                        if setting_name == "LogMaxFileSize":
                            compliant = isinstance(final_profile.get(setting_name), (int, float)) and final_profile.get(setting_name, 0) >= desired_value
                        else:
                            compliant = applied_value.upper() == str(desired_value).upper()
                        
                        cursor.execute("""
                            INSERT INTO firewall_results 
                            (timestamp, profile_name, setting_name, original_value, applied_value, compliant, operation)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (timestamp, profile_name, setting_name, original_value, applied_value, compliant, operation))
                
                conn.commit()
                
        except Exception as e:
            logging.error(f"Failed to record results to database: {e}")
    
    def rollback_from_manifest(self, manifest_file: str) -> Dict[str, Any]:
        """Rollback firewall settings from a manifest file."""
        if not Path(manifest_file).exists():
            return {"success": False, "error": f"Manifest file not found: {manifest_file}"}
        
        try:
            with open(manifest_file, 'r') as f:
                manifest_data = json.load(f)
            
            original_settings = manifest_data["original_settings"]
            rollback_results = {
                "rollback_timestamp": datetime.now().isoformat(),
                "changes_made": [],
                "errors": []
            }
            
            # Restore settings for each profile
            for profile_name, profile_settings in original_settings.items():
                profile_changes = self._restore_profile_settings(profile_name, profile_settings)
                rollback_results["changes_made"].extend(profile_changes["changes"])
                rollback_results["errors"].extend(profile_changes["errors"])
            
            # Record rollback in database
            current_settings = self.get_firewall_profile_settings()
            self._record_results_to_db(current_settings, original_settings, "rollback")
            
            rollback_results["success"] = len(rollback_results["errors"]) == 0
            return rollback_results
            
        except Exception as e:
            return {"success": False, "error": f"Failed to rollback from manifest: {str(e)}"}
    
    def _restore_profile_settings(self, profile_name: str, original_settings: Dict[str, Any]) -> Dict[str, List[str]]:
        """Restore firewall settings for a specific profile from original values."""
        changes = []
        errors = []
        
        try:
            # Restore firewall state
            state = "True" if original_settings.get("State") == "ON" else "False"
            ps_command = f"Set-NetFirewallProfile -Profile {profile_name} -Enabled {state}"
            
            result = self._run_powershell_command(ps_command)
            if result["success"]:
                changes.append(f"{profile_name}: Restored firewall state to {original_settings.get('State')}")
            else:
                errors.append(f"{profile_name}: Failed to restore firewall state")
            
            # Restore inbound action
            if "InboundAction" in original_settings:
                ps_command = f"Set-NetFirewallProfile -Profile {profile_name} -DefaultInboundAction {original_settings['InboundAction']}"
                result = self._run_powershell_command(ps_command)
                if result["success"]:
                    changes.append(f"{profile_name}: Restored inbound action to {original_settings['InboundAction']}")
                else:
                    errors.append(f"{profile_name}: Failed to restore inbound action")
            
            # Restore outbound action
            if "OutboundAction" in original_settings:
                ps_command = f"Set-NetFirewallProfile -Profile {profile_name} -DefaultOutboundAction {original_settings['OutboundAction']}"
                result = self._run_powershell_command(ps_command)
                if result["success"]:
                    changes.append(f"{profile_name}: Restored outbound action to {original_settings['OutboundAction']}")
                else:
                    errors.append(f"{profile_name}: Failed to restore outbound action")
            
            # Restore logging settings
            log_allowed = "True" if original_settings.get("LogAllowedConnections") == "Yes" else "False"
            log_blocked = "True" if original_settings.get("LogDroppedPackets") == "Yes" else "False"
            max_size = original_settings.get("LogMaxFileSize", 4096)
            
            ps_command = f"Set-NetFirewallProfile -Profile {profile_name} -LogAllowed {log_allowed} -LogBlocked {log_blocked} -LogMaxSizeKilobytes {max_size}"
            result = self._run_powershell_command(ps_command)
            
            if result["success"]:
                changes.append(f"{profile_name}: Restored logging settings")
            else:
                errors.append(f"{profile_name}: Failed to restore logging settings")
            
        except Exception as e:
            errors.append(f"{profile_name}: Unexpected error during restore - {str(e)}")
        
        return {"changes": changes, "errors": errors}


def audit_windows_firewall() -> Dict[str, Any]:
    """Audit Windows Firewall settings against Annexure-A requirements."""
    firewall_manager = WindowsFirewallManager()
    return firewall_manager.audit_firewall_settings()


def apply_firewall_settings() -> Dict[str, Any]:
    """Apply Annexure-A Windows Firewall settings."""
    firewall_manager = WindowsFirewallManager()
    return firewall_manager.apply_firewall_settings()


def rollback_firewall_settings(manifest_file: str) -> Dict[str, Any]:
    """Rollback Windows Firewall settings from manifest file."""
    firewall_manager = WindowsFirewallManager()
    return firewall_manager.rollback_from_manifest(manifest_file)