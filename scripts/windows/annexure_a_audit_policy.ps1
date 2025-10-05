# Annexure-A Advanced Audit Policy Configuration - PowerShell Functions
# Audit subcategories per Annexure-A requirements

# Check current audit policy for all subcategories
function Get-CurrentAuditPolicy {
    auditpol /get /category:* | Out-String
}

# Check specific audit subcategory
function Get-AuditSubcategory($subcategory) {
    auditpol /get /subcategory:"$subcategory"
}

# Set Credential Validation auditing (Account Logon)
function Set-CredentialValidationAudit {
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
    Write-Host "Set Credential Validation: Success and Failure" -ForegroundColor Green
}

# Set Kerberos Authentication Service auditing (Account Logon) 
function Set-KerberosAuthAudit {
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
    Write-Host "Set Kerberos Authentication Service: Success and Failure" -ForegroundColor Green
}

# Set Account Lockout auditing (Account Management)
function Set-AccountLockoutAudit {
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
    Write-Host "Set User Account Management: Success and Failure" -ForegroundColor Green
}

# Set Security Group Management auditing (Account Management)
function Set-SecurityGroupAudit {
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
    Write-Host "Set Security Group Management: Success and Failure" -ForegroundColor Green
}

# Set Process Creation auditing (Detailed Tracking)
function Set-ProcessCreationAudit {
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
    Write-Host "Set Process Creation: Success only" -ForegroundColor Green
}

# Set Process Termination auditing (Detailed Tracking)
function Set-ProcessTerminationAudit {
    auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable
    Write-Host "Set Process Termination: Success only" -ForegroundColor Green
}

# Set Directory Service Changes auditing (DS Access)
function Set-DirectoryServiceAudit {
    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
    Write-Host "Set Directory Service Changes: Success and Failure" -ForegroundColor Green
}

# Set Logon auditing (Logon/Logoff)
function Set-LogonAudit {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    Write-Host "Set Logon Events: Success and Failure" -ForegroundColor Green
}

# Set Logoff auditing (Logon/Logoff)
function Set-LogoffAudit {
    auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
    Write-Host "Set Logoff Events: Success only" -ForegroundColor Green
}

# Set Special Logon auditing (Logon/Logoff)
function Set-SpecialLogonAudit {
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable
    Write-Host "Set Special Logon: Success only" -ForegroundColor Green
}

# Set Object Access - File System auditing
function Set-FileSystemAudit {
    auditpol /set /subcategory:"File System" /success:enable /failure:enable
    Write-Host "Set File System Access: Success and Failure" -ForegroundColor Green
}

# Set Object Access - Registry auditing
function Set-RegistryAudit {
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable
    Write-Host "Set Registry Access: Success and Failure" -ForegroundColor Green
}

# Set Audit Policy Change auditing (Policy Change)
function Set-AuditPolicyChangeAudit {
    auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
    Write-Host "Set Audit Policy Change: Success and Failure" -ForegroundColor Green
}

# Set Authentication Policy Change auditing (Policy Change)
function Set-AuthPolicyChangeAudit {
    auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:disable
    Write-Host "Set Authentication Policy Change: Success only" -ForegroundColor Green
}

# Set Sensitive Privilege Use auditing (Privilege Use)
function Set-SensitivePrivilegeAudit {
    auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
    Write-Host "Set Sensitive Privilege Use: Success and Failure" -ForegroundColor Green
}

# Set Security System Extension auditing (System)
function Set-SecuritySystemAudit {
    auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
    Write-Host "Set Security System Extension: Success and Failure" -ForegroundColor Green
}

# Set System Integrity auditing (System)
function Set-SystemIntegrityAudit {
    auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
    Write-Host "Set System Integrity: Success and Failure" -ForegroundColor Green
}

# Apply all Annexure-A required audit settings
function Set-AnnexureAAuditPolicy {
    Write-Host "Applying Annexure-A Advanced Audit Policy Configuration..." -ForegroundColor Cyan
    
    # Account Logon
    Set-CredentialValidationAudit
    Set-KerberosAuthAudit
    
    # Account Management
    Set-AccountLockoutAudit
    Set-SecurityGroupAudit
    
    # Detailed Tracking
    Set-ProcessCreationAudit
    Set-ProcessTerminationAudit
    
    # DS Access (if domain controller)
    if ((Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed") {
        Set-DirectoryServiceAudit
    }
    
    # Logon/Logoff
    Set-LogonAudit
    Set-LogoffAudit
    Set-SpecialLogonAudit
    
    # Object Access
    Set-FileSystemAudit
    Set-RegistryAudit
    
    # Policy Change
    Set-AuditPolicyChangeAudit
    Set-AuthPolicyChangeAudit
    
    # Privilege Use
    Set-SensitivePrivilegeAudit
    
    # System
    Set-SecuritySystemAudit
    Set-SystemIntegrityAudit
    
    Write-Host "Annexure-A audit policy configuration completed!" -ForegroundColor Green
}

# Export current audit policy to CSV file
function Export-AuditPolicy($filePath = "audit_policy_backup.csv") {
    auditpol /backup /file:$filePath
    Write-Host "Audit policy exported to: $filePath" -ForegroundColor Green
}

# Import audit policy from CSV file
function Import-AuditPolicy($filePath) {
    if (Test-Path $filePath) {
        auditpol /restore /file:$filePath
        Write-Host "Audit policy restored from: $filePath" -ForegroundColor Green
    } else {
        Write-Error "Backup file not found: $filePath"
    }
}

# Get audit policy compliance report
function Get-AuditComplianceReport {
    $report = @"
Annexure-A Advanced Audit Policy Compliance Report
Generated: $(Get-Date)

Account Logon Events:
$(auditpol /get /subcategory:"Credential Validation")
$(auditpol /get /subcategory:"Kerberos Authentication Service")

Account Management:
$(auditpol /get /subcategory:"User Account Management")
$(auditpol /get /subcategory:"Security Group Management")

Detailed Tracking:
$(auditpol /get /subcategory:"Process Creation")
$(auditpol /get /subcategory:"Process Termination")

Logon/Logoff:
$(auditpol /get /subcategory:"Logon")
$(auditpol /get /subcategory:"Logoff")
$(auditpol /get /subcategory:"Special Logon")

Object Access:
$(auditpol /get /subcategory:"File System")
$(auditpol /get /subcategory:"Registry")

Policy Change:
$(auditpol /get /subcategory:"Audit Policy Change")
$(auditpol /get /subcategory:"Authentication Policy Change")

Privilege Use:
$(auditpol /get /subcategory:"Sensitive Privilege Use")

System:
$(auditpol /get /subcategory:"Security System Extension")
$(auditpol /get /subcategory:"System Integrity")
"@
    
    return $report
}

# Quick check for critical audit settings compliance
function Test-AuditCompliance {
    $requiredSettings = @{
        "Credential Validation" = "Success and Failure"
        "Process Creation" = "Success"
        "Logon" = "Success and Failure"
        "Audit Policy Change" = "Success and Failure"
        "Sensitive Privilege Use" = "Success and Failure"
    }
    
    $compliant = $true
    
    foreach ($setting in $requiredSettings.Keys) {
        $current = (auditpol /get /subcategory:"$setting" | Select-String "Success and Failure|Success").Matches.Value
        $expected = $requiredSettings[$setting]
        
        if ($current -notlike "*$expected*") {
            Write-Warning "$setting - Expected: $expected, Current: $current"
            $compliant = $false
        } else {
            Write-Host "$setting - Compliant" -ForegroundColor Green
        }
    }
    
    return $compliant
}

# One-liner to apply all settings and create backup
function Deploy-AnnexureAAudit {
    Export-AuditPolicy "audit_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"; Set-AnnexureAAuditPolicy
}