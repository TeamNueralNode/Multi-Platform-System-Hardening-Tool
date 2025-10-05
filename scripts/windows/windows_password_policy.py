import json
import subprocess
import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional

def audit_password_policy() -> Dict[str, Any]:
    """
    Audit Windows password policy against Annexure-A requirements.
    Returns JSON with current vs desired values and compliance status.
    """
    rule_id = "windows_password_policy_audit"
    
    desired_values = {
        "enforce_password_history": 24,
        "maximum_password_age": 90,
        "minimum_password_age": 1,
        "minimum_password_length": 12,
        "password_complexity": True,
        "store_passwords_reversible": False
    }
    
    current_values = {}
    compliant = True
    
    try:
        # Get current password policy using PowerShell
        ps_cmd = """
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        if (-not $policy) {
            # Fallback to net accounts for local policy
            $netAccounts = net accounts
            $policy = @{
                PasswordHistoryCount = ($netAccounts | Select-String "Length of password history" | ForEach-Object { ($_.Line -split ":\s*")[1] })
                MaxPasswordAge = ($netAccounts | Select-String "Maximum password age" | ForEach-Object { 
                    $days = ($_.Line -split ":\s*")[1]
                    if ($days -eq "Never") { 0 } else { [int]$days }
                })
                MinPasswordAge = ($netAccounts | Select-String "Minimum password age" | ForEach-Object { ($_.Line -split ":\s*")[1] })
                MinPasswordLength = ($netAccounts | Select-String "Minimum password length" | ForEach-Object { ($_.Line -split ":\s*")[1] })
            }
            # Get complexity from secedit
            secedit /export /cfg $env:TEMP\\secpol.cfg /quiet
            $complexity = Select-String "PasswordComplexity" $env:TEMP\\secpol.cfg | ForEach-Object { ($_.Line -split "=")[1].Trim() -eq "1" }
            $reversible = Select-String "ClearTextPassword" $env:TEMP\\secpol.cfg | ForEach-Object { ($_.Line -split "=")[1].Trim() -eq "1" }
            Remove-Item $env:TEMP\\secpol.cfg -Force -ErrorAction SilentlyContinue
            
            $policy | Add-Member -NotePropertyName ComplexityEnabled -NotePropertyValue $complexity
            $policy | Add-Member -NotePropertyName ReversibleEncryptionEnabled -NotePropertyValue $reversible
        }
        
        @{
            enforce_password_history = [int]$policy.PasswordHistoryCount
            maximum_password_age = if($policy.MaxPasswordAge.Days) { [int]$policy.MaxPasswordAge.Days } else { [int]$policy.MaxPasswordAge }
            minimum_password_age = if($policy.MinPasswordAge.Days) { [int]$policy.MinPasswordAge.Days } else { [int]$policy.MinPasswordAge }
            minimum_password_length = [int]$policy.MinPasswordLength
            password_complexity = [bool]$policy.ComplexityEnabled
            store_passwords_reversible = [bool]$policy.ReversibleEncryptionEnabled
        } | ConvertTo-Json
        """
        
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            check=True
        )
        
        current_values = json.loads(result.stdout.strip())
        
        # Check compliance
        for key, desired in desired_values.items():
            if current_values.get(key) != desired:
                compliant = False
                
    except subprocess.CalledProcessError as e:
        logging.error(f"PowerShell command failed: {e.stderr}")
        compliant = False
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse PowerShell output: {e}")
        compliant = False
    except Exception as e:
        logging.error(f"Unexpected error during audit: {e}")
        compliant = False
        
    return {
        "rule_id": rule_id,
        "current_values": current_values,
        "desired_values": desired_values,
        "compliant": compliant
    }

def apply_password_policy(rollback_manifest_path: Optional[str] = None) -> bool:
    """
    Apply Windows password policy changes, backing up current settings.
    Only changes non-compliant settings.
    """
    if not rollback_manifest_path:
        rollback_manifest_path = f"password_policy_rollback_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        # First audit to get current state
        audit_result = audit_password_policy()
        current_values = audit_result["current_values"]
        desired_values = audit_result["desired_values"]
        
        if audit_result["compliant"]:
            logging.info("Password policy is already compliant")
            return True
            
        # Create rollback manifest
        rollback_data = {
            "timestamp": datetime.now().isoformat(),
            "rule_id": "windows_password_policy_apply",
            "original_values": current_values.copy()
        }
        
        with open(rollback_manifest_path, 'w') as f:
            json.dump(rollback_data, f, indent=2)
            
        changes_made = []
        
        # Apply changes for non-compliant settings
        for setting, desired_value in desired_values.items():
            current_value = current_values.get(setting)
            
            if current_value != desired_value:
                try:
                    if setting == "enforce_password_history":
                        cmd = f"Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount {desired_value}"
                        fallback_cmd = f"net accounts /uniquepw:{desired_value}"
                        
                    elif setting == "maximum_password_age":
                        cmd = f"Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge (New-TimeSpan -Days {desired_value})"
                        fallback_cmd = f"net accounts /maxpwage:{desired_value}"
                        
                    elif setting == "minimum_password_age":
                        cmd = f"Set-ADDefaultDomainPasswordPolicy -MinPasswordAge (New-TimeSpan -Days {desired_value})"
                        fallback_cmd = f"net accounts /minpwage:{desired_value}"
                        
                    elif setting == "minimum_password_length":
                        cmd = f"Set-ADDefaultDomainPasswordPolicy -MinPasswordLength {desired_value}"
                        fallback_cmd = f"net accounts /minpwlen:{desired_value}"
                        
                    elif setting == "password_complexity":
                        cmd = f"Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled ${str(desired_value).lower()}"
                        secedit_value = "1" if desired_value else "0"
                        fallback_cmd = f'secedit /configure /cfg (echo "[System Access]`nPasswordComplexity = {secedit_value}" | Out-File -FilePath $env:TEMP\\temp_secpol.inf -Encoding ASCII; echo $env:TEMP\\temp_secpol.inf) /db secedit.sdb'
                        
                    elif setting == "store_passwords_reversible":
                        cmd = f"Set-ADDefaultDomainPasswordPolicy -ReversibleEncryptionEnabled ${str(desired_value).lower()}"
                        secedit_value = "1" if desired_value else "0"
                        fallback_cmd = f'secedit /configure /cfg (echo "[System Access]`nClearTextPassword = {secedit_value}" | Out-File -FilePath $env:TEMP\\temp_secpol.inf -Encoding ASCII; echo $env:TEMP\\temp_secpol.inf) /db secedit.sdb'
                    
                    # Try AD command first, fallback to local policy
                    ps_cmd = f"""
                    try {{
                        {cmd}
                        Write-Host "AD policy updated for {setting}"
                    }} catch {{
                        try {{
                            {fallback_cmd}
                            Write-Host "Local policy updated for {setting}"
                        }} catch {{
                            Write-Error "Failed to update {setting}: $_"
                            throw
                        }}
                    }}
                    """
                    
                    result = subprocess.run(
                        ["powershell", "-Command", ps_cmd],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    
                    changes_made.append(f"{setting}: {current_value} -> {desired_value}")
                    logging.info(f"Updated {setting} from {current_value} to {desired_value}")
                    
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to update {setting}: {e.stderr}")
                    return False
                    
        if changes_made:
            logging.info(f"Password policy changes applied: {', '.join(changes_made)}")
            logging.info(f"Rollback manifest saved to: {rollback_manifest_path}")
        
        return True
        
    except Exception as e:
        logging.error(f"Failed to apply password policy: {e}")
        return False

def rollback_password_policy(rollback_manifest_path: str) -> bool:
    """
    Restore password policy settings from rollback manifest.
    """
    if not os.path.exists(rollback_manifest_path):
        logging.error(f"Rollback manifest not found: {rollback_manifest_path}")
        return False
        
    try:
        with open(rollback_manifest_path, 'r') as f:
            rollback_data = json.load(f)
            
        original_values = rollback_data["original_values"]
        
        changes_made = []
        
        for setting, original_value in original_values.items():
            try:
                if setting == "enforce_password_history":
                    cmd = f"Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount {original_value}"
                    fallback_cmd = f"net accounts /uniquepw:{original_value}"
                    
                elif setting == "maximum_password_age":
                    if original_value == 0:
                        cmd = "Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge $null"
                        fallback_cmd = "net accounts /maxpwage:unlimited"
                    else:
                        cmd = f"Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge (New-TimeSpan -Days {original_value})"
                        fallback_cmd = f"net accounts /maxpwage:{original_value}"
                        
                elif setting == "minimum_password_age":
                    cmd = f"Set-ADDefaultDomainPasswordPolicy -MinPasswordAge (New-TimeSpan -Days {original_value})"
                    fallback_cmd = f"net accounts /minpwage:{original_value}"
                    
                elif setting == "minimum_password_length":
                    cmd = f"Set-ADDefaultDomainPasswordPolicy -MinPasswordLength {original_value}"
                    fallback_cmd = f"net accounts /minpwlen:{original_value}"
                    
                elif setting == "password_complexity":
                    cmd = f"Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled ${str(original_value).lower()}"
                    secedit_value = "1" if original_value else "0"
                    fallback_cmd = f'secedit /configure /cfg (echo "[System Access]`nPasswordComplexity = {secedit_value}" | Out-File -FilePath $env:TEMP\\temp_secpol.inf -Encoding ASCII; echo $env:TEMP\\temp_secpol.inf) /db secedit.sdb'
                    
                elif setting == "store_passwords_reversible":
                    cmd = f"Set-ADDefaultDomainPasswordPolicy -ReversibleEncryptionEnabled ${str(original_value).lower()}"
                    secedit_value = "1" if original_value else "0"
                    fallback_cmd = f'secedit /configure /cfg (echo "[System Access]`nClearTextPassword = {secedit_value}" | Out-File -FilePath $env:TEMP\\temp_secpol.inf -Encoding ASCII; echo $env:TEMP\\temp_secpol.inf) /db secedit.sdb'
                
                ps_cmd = f"""
                try {{
                    {cmd}
                    Write-Host "AD policy restored for {setting}"
                }} catch {{
                    try {{
                        {fallback_cmd}
                        Write-Host "Local policy restored for {setting}"
                    }} catch {{
                        Write-Error "Failed to restore {setting}: $_"
                        throw
                    }}
                }}
                """
                
                result = subprocess.run(
                    ["powershell", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                changes_made.append(f"{setting}: restored to {original_value}")
                logging.info(f"Restored {setting} to {original_value}")
                
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to restore {setting}: {e.stderr}")
                return False
                
        if changes_made:
            logging.info(f"Password policy rollback completed: {', '.join(changes_made)}")
            
        return True
        
    except Exception as e:
        logging.error(f"Failed to rollback password policy: {e}")
        return False