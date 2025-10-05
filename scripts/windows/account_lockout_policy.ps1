# Account Lockout Policy Management Script
# Usage: .\account_lockout_policy.ps1 [-audit] [-apply] [-rollback <backup_file>]

param(
    [switch]$Audit,
    [switch]$Apply,
    [string]$Rollback
)

# Policy requirements
$DesiredPolicy = @{
    "lockout_duration" = 15  # minutes
    "lockout_threshold" = 5  # attempts
    "admin_lockout_enabled" = $true
}

function Get-CurrentLockoutPolicy {
    $policy = @{}
    
    try {
        # Try Active Directory first
        $adPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        if ($adPolicy) {
            $policy.lockout_duration = if ($adPolicy.LockoutDuration.TotalMinutes -eq 0) { 0 } else { [int]$adPolicy.LockoutDuration.TotalMinutes }
            $policy.lockout_threshold = [int]$adPolicy.LockoutThreshold
        } else {
            # Fallback to local policy
            $netAccounts = net accounts
            $durationLine = $netAccounts | Select-String "Lockout duration"
            $thresholdLine = $netAccounts | Select-String "Lockout threshold"
            
            if ($durationLine) {
                $durationValue = ($durationLine.Line -split ":\s*")[1].Trim()
                $policy.lockout_duration = if ($durationValue -eq "Never") { 0 } else { [int]$durationValue }
            }
            
            if ($thresholdLine) {
                $thresholdValue = ($thresholdLine.Line -split ":\s*")[1].Trim()
                $policy.lockout_threshold = if ($thresholdValue -eq "Never") { 0 } else { [int]$thresholdValue }
            }
        }
        
        # Get Administrator lockout policy from security policy
        $tempFile = "$env:TEMP\secpol_export.inf"
        secedit /export /cfg $tempFile /quiet
        $adminLockoutLine = Select-String "EnableAdminAccount" $tempFile -ErrorAction SilentlyContinue
        if ($adminLockoutLine) {
            $policy.admin_lockout_enabled = ($adminLockoutLine.Line -split "=")[1].Trim() -eq "1"
        } else {
            # Default assumption - admin lockout typically disabled by default
            $policy.admin_lockout_enabled = $false
        }
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Error "Failed to retrieve current lockout policy: $_"
        return $null
    }
    
    return $policy
}

function Test-PolicyCompliance {
    param($CurrentPolicy, $DesiredPolicy)
    
    $results = @()
    
    # Test lockout duration
    $durationCompliant = $CurrentPolicy.lockout_duration -ge $DesiredPolicy.lockout_duration
    $results += @{
        "rule_id" = "lockout_duration"
        "current" = $CurrentPolicy.lockout_duration
        "desired" = ">= $($DesiredPolicy.lockout_duration) minutes"
        "compliant" = $durationCompliant
    }
    
    # Test lockout threshold
    $thresholdCompliant = ($CurrentPolicy.lockout_threshold -le $DesiredPolicy.lockout_threshold) -and ($CurrentPolicy.lockout_threshold -ne 0)
    $results += @{
        "rule_id" = "lockout_threshold"
        "current" = $CurrentPolicy.lockout_threshold
        "desired" = "<= $($DesiredPolicy.lockout_threshold) attempts and != 0"
        "compliant" = $thresholdCompliant
    }
    
    # Test admin lockout
    $adminCompliant = $CurrentPolicy.admin_lockout_enabled -eq $DesiredPolicy.admin_lockout_enabled
    $results += @{
        "rule_id" = "admin_lockout_enabled"
        "current" = $CurrentPolicy.admin_lockout_enabled
        "desired" = $DesiredPolicy.admin_lockout_enabled
        "compliant" = $adminCompliant
        "note" = if (-not $adminCompliant) { "Manual verification may be required for Administrator account lockout policy" } else { $null }
    }
    
    return $results
}

function Save-PolicyBackup {
    param($CurrentPolicy)
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = "lockout_policy_backup_$timestamp.json"
    
    try {
        # Save JSON backup
        $backupData = @{
            "timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            "policy" = $CurrentPolicy
            "backup_type" = "account_lockout_policy"
        }
        
        $backupData | ConvertTo-Json -Depth 3 | Out-File -FilePath $backupFile -Encoding UTF8
        
        # Also save security policy export for complete rollback
        $infBackup = "lockout_policy_backup_$timestamp.inf"
        secedit /export /cfg $infBackup /quiet
        
        Write-Host "Policy backup saved to: $backupFile and $infBackup" -ForegroundColor Green
        return @($backupFile, $infBackup)
        
    } catch {
        Write-Error "Failed to save policy backup: $_"
        return $null
    }
}

function Apply-LockoutPolicy {
    param($CurrentPolicy, $DesiredPolicy)
    
    $changes = @()
    
    try {
        # Apply lockout duration if needed
        if ($CurrentPolicy.lockout_duration -lt $DesiredPolicy.lockout_duration) {
            try {
                Set-ADDefaultDomainPasswordPolicy -LockoutDuration (New-TimeSpan -Minutes $DesiredPolicy.lockout_duration) -ErrorAction Stop
                $changes += "lockout_duration: $($CurrentPolicy.lockout_duration) -> $($DesiredPolicy.lockout_duration) minutes"
            } catch {
                # Fallback to net accounts
                $result = net accounts /lockoutduration:$($DesiredPolicy.lockout_duration)
                if ($LASTEXITCODE -eq 0) {
                    $changes += "lockout_duration: $($CurrentPolicy.lockout_duration) -> $($DesiredPolicy.lockout_duration) minutes (local policy)"
                } else {
                    throw "Failed to set lockout duration: $result"
                }
            }
        }
        
        # Apply lockout threshold if needed
        $thresholdNeedsChange = ($CurrentPolicy.lockout_threshold -gt $DesiredPolicy.lockout_threshold) -or ($CurrentPolicy.lockout_threshold -eq 0)
        if ($thresholdNeedsChange) {
            try {
                Set-ADDefaultDomainPasswordPolicy -LockoutThreshold $DesiredPolicy.lockout_threshold -ErrorAction Stop
                $changes += "lockout_threshold: $($CurrentPolicy.lockout_threshold) -> $($DesiredPolicy.lockout_threshold) attempts"
            } catch {
                # Fallback to net accounts
                $result = net accounts /lockoutthreshold:$($DesiredPolicy.lockout_threshold)
                if ($LASTEXITCODE -eq 0) {
                    $changes += "lockout_threshold: $($CurrentPolicy.lockout_threshold) -> $($DesiredPolicy.lockout_threshold) attempts (local policy)"
                } else {
                    throw "Failed to set lockout threshold: $result"
                }
            }
        }
        
        # Apply admin lockout policy if needed
        if ($CurrentPolicy.admin_lockout_enabled -ne $DesiredPolicy.admin_lockout_enabled) {
            $tempInfFile = "$env:TEMP\lockout_policy_temp.inf"
            $adminValue = if ($DesiredPolicy.admin_lockout_enabled) { "1" } else { "0" }
            
            @"
[Unicode]
Unicode=yes
[System Access]
EnableAdminAccount = $adminValue
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File -FilePath $tempInfFile -Encoding Unicode
            
            $result = secedit /configure /cfg $tempInfFile /db secedit.sdb /quiet
            if ($LASTEXITCODE -eq 0) {
                $changes += "admin_lockout_enabled: $($CurrentPolicy.admin_lockout_enabled) -> $($DesiredPolicy.admin_lockout_enabled)"
                Write-Warning "Administrator account lockout policy changed. Manual verification recommended."
            } else {
                Write-Warning "Failed to apply administrator lockout policy. Manual configuration may be required."
            }
            
            Remove-Item $tempInfFile -Force -ErrorAction SilentlyContinue
        }
        
        return $changes
        
    } catch {
        Write-Error "Failed to apply lockout policy: $_"
        return $null
    }
}

function Restore-PolicyFromBackup {
    param($BackupFile)
    
    if (-not (Test-Path $BackupFile)) {
        Write-Error "Backup file not found: $BackupFile"
        return $false
    }
    
    try {
        if ($BackupFile.EndsWith('.json')) {
            # Restore from JSON backup
            $backupData = Get-Content $BackupFile | ConvertFrom-Json
            $originalPolicy = $backupData.policy
            
            # Restore each setting
            try {
                Set-ADDefaultDomainPasswordPolicy -LockoutDuration (New-TimeSpan -Minutes $originalPolicy.lockout_duration) -LockoutThreshold $originalPolicy.lockout_threshold -ErrorAction Stop
                Write-Host "Domain policy restored from backup" -ForegroundColor Green
            } catch {
                # Fallback to net accounts
                net accounts /lockoutduration:$($originalPolicy.lockout_duration) | Out-Null
                net accounts /lockoutthreshold:$($originalPolicy.lockout_threshold) | Out-Null
                Write-Host "Local policy restored from backup" -ForegroundColor Green
            }
            
            # Restore admin policy if available
            if ($originalPolicy.PSObject.Properties.Name -contains 'admin_lockout_enabled') {
                $tempInfFile = "$env:TEMP\restore_policy_temp.inf"
                $adminValue = if ($originalPolicy.admin_lockout_enabled) { "1" } else { "0" }
                
                @"
[Unicode]
Unicode=yes
[System Access]
EnableAdminAccount = $adminValue
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File -FilePath $tempInfFile -Encoding Unicode
                
                secedit /configure /cfg $tempInfFile /db secedit.sdb /quiet
                Remove-Item $tempInfFile -Force -ErrorAction SilentlyContinue
                Write-Host "Administrator lockout policy restored" -ForegroundColor Green
            }
            
        } elseif ($BackupFile.EndsWith('.inf')) {
            # Restore from INF backup (complete security policy restore)
            $result = secedit /configure /cfg $BackupFile /db secedit.sdb /quiet
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Security policy restored from INF backup: $BackupFile" -ForegroundColor Green
            } else {
                throw "secedit failed with exit code $LASTEXITCODE"
            }
        } else {
            throw "Unsupported backup file format. Use .json or .inf files."
        }
        
        return $true
        
    } catch {
        Write-Error "Failed to restore policy from backup: $_"
        return $false
    }
}

# Main execution logic
function Main {
    if (-not ($Audit -or $Apply -or $Rollback)) {
        Write-Host "Account Lockout Policy Management Script" -ForegroundColor Cyan
        Write-Host "Usage: .\account_lockout_policy.ps1 [-audit] [-apply] [-rollback <backup_file>]" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Options:"
        Write-Host "  -audit                 Audit current lockout policy compliance"
        Write-Host "  -apply                 Apply recommended lockout policy settings"
        Write-Host "  -rollback <backup>     Restore policy from backup file"
        return
    }
    
    if ($Rollback) {
        Write-Host "Restoring account lockout policy from backup..." -ForegroundColor Yellow
        $success = Restore-PolicyFromBackup -BackupFile $Rollback
        if ($success) {
            Write-Host "Policy rollback completed successfully" -ForegroundColor Green
        } else {
            Write-Host "Policy rollback failed" -ForegroundColor Red
            exit 1
        }
        return
    }
    
    # Get current policy
    $currentPolicy = Get-CurrentLockoutPolicy
    if (-not $currentPolicy) {
        Write-Error "Failed to retrieve current policy"
        exit 1
    }
    
    if ($Audit) {
        Write-Host "Auditing account lockout policy..." -ForegroundColor Yellow
        $complianceResults = Test-PolicyCompliance -CurrentPolicy $currentPolicy -DesiredPolicy $DesiredPolicy
        
        # Output JSON results
        $complianceResults | ConvertTo-Json -Depth 3 | Write-Output
        
        # Summary
        $compliantCount = ($complianceResults | Where-Object { $_.compliant }).Count
        $totalCount = $complianceResults.Count
        Write-Host "`nCompliance Summary: $compliantCount/$totalCount rules compliant" -ForegroundColor $(if ($compliantCount -eq $totalCount) { "Green" } else { "Yellow" })
    }
    
    if ($Apply) {
        Write-Host "Applying account lockout policy..." -ForegroundColor Yellow
        
        # Check compliance first
        $complianceResults = Test-PolicyCompliance -CurrentPolicy $currentPolicy -DesiredPolicy $DesiredPolicy
        $nonCompliantRules = $complianceResults | Where-Object { -not $_.compliant }
        
        if ($nonCompliantRules.Count -eq 0) {
            Write-Host "Policy is already compliant. No changes needed." -ForegroundColor Green
            return
        }
        
        # Save backup before making changes
        $backupFiles = Save-PolicyBackup -CurrentPolicy $currentPolicy
        if (-not $backupFiles) {
            Write-Error "Failed to create backup. Aborting policy application."
            exit 1
        }
        
        # Apply changes
        $changes = Apply-LockoutPolicy -CurrentPolicy $currentPolicy -DesiredPolicy $DesiredPolicy
        
        if ($changes) {
            Write-Host "`nPolicy changes applied:" -ForegroundColor Green
            $changes | ForEach-Object { Write-Host "  • $_" -ForegroundColor White }
            Write-Host "`nBackup files created:" -ForegroundColor Cyan
            $backupFiles | ForEach-Object { Write-Host "  • $_" -ForegroundColor White }
        } else {
            Write-Host "No changes were applied" -ForegroundColor Yellow
        }
    }
}

# Execute main function
Main