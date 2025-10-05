# Disable Services Script - Annexure-A System Services Management
# Usage: .\disable_services.ps1 [-audit] [-apply] [-rollback <manifest_file>]

param(
    [switch]$Audit,
    [switch]$Apply,
    [string]$Rollback
)

# Services to be disabled according to Annexure-A
$ServicesToDisable = @(
    @{ Name = "bthserv"; DisplayName = "Bluetooth Support Service"; Reason = "Reduces attack surface for wireless connections" },
    @{ Name = "RemoteRegistry"; DisplayName = "Remote Registry"; Reason = "Prevents remote registry access" },
    @{ Name = "WinRM"; DisplayName = "Windows Remote Management"; Reason = "Disables remote PowerShell access" },
    @{ Name = "WMPNetworkSvc"; DisplayName = "Windows Media Player Network Sharing Service"; Reason = "Prevents media sharing vulnerabilities" },
    @{ Name = "Browser"; DisplayName = "Computer Browser"; Reason = "Disables network browsing service" },
    @{ Name = "TrkWks"; DisplayName = "Distributed Link Tracking Client"; Reason = "Reduces information disclosure" },
    @{ Name = "MSDTC"; DisplayName = "Distributed Transaction Coordinator"; Reason = "Minimizes distributed computing attack surface" },
    @{ Name = "MSiSCSI"; DisplayName = "Microsoft iSCSI Initiator Service"; Reason = "Disables iSCSI if not required" },
    @{ Name = "NetTcpPortSharing"; DisplayName = "Net.Tcp Port Sharing Service"; Reason = "Prevents TCP port sharing vulnerabilities" },
    @{ Name = "simptcp"; DisplayName = "Simple TCP/IP Services"; Reason = "Disables legacy TCP services" },
    @{ Name = "SNMP"; DisplayName = "SNMP Service"; Reason = "Prevents SNMP information disclosure" },
    @{ Name = "SSDPSRV"; DisplayName = "SSDP Discovery"; Reason = "Disables UPnP discovery service" },
    @{ Name = "upnphost"; DisplayName = "UPnP Device Host"; Reason = "Prevents UPnP security vulnerabilities" },
    @{ Name = "WAS"; DisplayName = "Windows Process Activation Service"; Reason = "Disables IIS process activation if not needed" },
    @{ Name = "W3SVC"; DisplayName = "World Wide Web Publishing Service"; Reason = "Disables IIS web server if not needed" },
    @{ Name = "XblAuthManager"; DisplayName = "Xbox Live Auth Manager"; Reason = "Gaming service not required on servers" },
    @{ Name = "XblGameSave"; DisplayName = "Xbox Live Game Save Service"; Reason = "Gaming service not required on servers" },
    @{ Name = "XboxNetApiSvc"; DisplayName = "Xbox Live Networking Service"; Reason = "Gaming service not required on servers" }
)

function Get-ServiceStatus {
    param($ServiceList)
    
    $serviceStatus = @()
    
    foreach ($svc in $ServiceList) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            
            if ($service) {
                $serviceInfo = @{
                    "service_name" = $svc.Name
                    "display_name" = $svc.DisplayName
                    "current_status" = $service.Status.ToString()
                    "current_startup_type" = (Get-WmiObject -Class Win32_Service -Filter "Name='$($svc.Name)'").StartMode
                    "desired_status" = "Stopped"
                    "desired_startup_type" = "Disabled"
                    "compliant" = ($service.Status -eq "Stopped" -and (Get-WmiObject -Class Win32_Service -Filter "Name='$($svc.Name)'").StartMode -eq "Disabled")
                    "reason" = $svc.Reason
                    "exists" = $true
                }
            } else {
                $serviceInfo = @{
                    "service_name" = $svc.Name
                    "display_name" = $svc.DisplayName
                    "current_status" = "Not Installed"
                    "current_startup_type" = "Not Installed"
                    "desired_status" = "Stopped"
                    "desired_startup_type" = "Disabled"
                    "compliant" = $true
                    "reason" = $svc.Reason
                    "exists" = $false
                }
            }
            
            $serviceStatus += $serviceInfo
        } catch {
            Write-Error "Failed to get status for service $($svc.Name): $_"
        }
    }
    
    return $serviceStatus
}

function Save-ServiceManifest {
    param($ServiceStatus)
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $manifestFile = "services_backup_manifest_$timestamp.json"
    
    try {
        $manifest = @{
            "timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            "backup_type" = "service_configuration"
            "services" = @()
        }
        
        foreach ($svc in $ServiceStatus) {
            if ($svc.exists) {
                $manifest.services += @{
                    "service_name" = $svc.service_name
                    "display_name" = $svc.display_name
                    "original_status" = $svc.current_status
                    "original_startup_type" = $svc.current_startup_type
                }
            }
        }
        
        $manifest | ConvertTo-Json -Depth 3 | Out-File -FilePath $manifestFile -Encoding UTF8
        Write-Host "Service manifest saved to: $manifestFile" -ForegroundColor Green
        return $manifestFile
        
    } catch {
        Write-Error "Failed to save service manifest: $_"
        return $null
    }
}

function Disable-ServicesFromList {
    param($ServiceStatus)
    
    $changes = @()
    $errors = @()
    
    foreach ($svc in $ServiceStatus) {
        if (-not $svc.exists) {
            Write-Host "Service $($svc.service_name) not installed - skipping" -ForegroundColor Yellow
            continue
        }
        
        if ($svc.compliant) {
            Write-Host "Service $($svc.service_name) already compliant - skipping" -ForegroundColor Green
            continue
        }
        
        try {
            $service = Get-Service -Name $svc.service_name
            
            # Stop the service if it's running
            if ($service.Status -eq "Running") {
                Write-Host "Stopping service: $($svc.display_name)" -ForegroundColor Yellow
                Stop-Service -Name $svc.service_name -Force -ErrorAction Stop
                $changes += "Stopped: $($svc.display_name)"
            }
            
            # Disable the service startup type
            $currentStartupType = (Get-WmiObject -Class Win32_Service -Filter "Name='$($svc.service_name)'").StartMode
            if ($currentStartupType -ne "Disabled") {
                Write-Host "Disabling service: $($svc.display_name)" -ForegroundColor Yellow
                Set-Service -Name $svc.service_name -StartupType Disabled -ErrorAction Stop
                $changes += "Disabled: $($svc.display_name) (was $currentStartupType)"
            }
            
        } catch {
            $errorMsg = "Failed to disable service $($svc.service_name): $_"
            Write-Error $errorMsg
            $errors += $errorMsg
        }
    }
    
    return @{
        "changes" = $changes
        "errors" = $errors
    }
}

function Restore-ServicesFromManifest {
    param($ManifestFile)
    
    if (-not (Test-Path $ManifestFile)) {
        Write-Error "Manifest file not found: $ManifestFile"
        return $false
    }
    
    try {
        $manifest = Get-Content $ManifestFile | ConvertFrom-Json
        $restored = @()
        $errors = @()
        
        foreach ($svc in $manifest.services) {
            try {
                $service = Get-Service -Name $svc.service_name -ErrorAction SilentlyContinue
                
                if (-not $service) {
                    Write-Warning "Service $($svc.service_name) not found - skipping restoration"
                    continue
                }
                
                # Restore startup type
                if ($svc.original_startup_type -ne "Disabled") {
                    Write-Host "Restoring startup type for $($svc.display_name): $($svc.original_startup_type)" -ForegroundColor Yellow
                    
                    $startupType = switch ($svc.original_startup_type) {
                        "Auto" { "Automatic" }
                        "Manual" { "Manual" }
                        "Disabled" { "Disabled" }
                        default { $svc.original_startup_type }
                    }
                    
                    Set-Service -Name $svc.service_name -StartupType $startupType -ErrorAction Stop
                    $restored += "Restored startup type: $($svc.display_name) to $startupType"
                }
                
                # Restore service status if it was running
                if ($svc.original_status -eq "Running" -and $svc.original_startup_type -ne "Disabled") {
                    Write-Host "Starting service: $($svc.display_name)" -ForegroundColor Yellow
                    Start-Service -Name $svc.service_name -ErrorAction Stop
                    $restored += "Started: $($svc.display_name)"
                }
                
            } catch {
                $errorMsg = "Failed to restore service $($svc.service_name): $_"
                Write-Error $errorMsg
                $errors += $errorMsg
            }
        }
        
        if ($restored.Count -gt 0) {
            Write-Host "`nServices restored:" -ForegroundColor Green
            $restored | ForEach-Object { Write-Host "  • $_" -ForegroundColor White }
        }
        
        if ($errors.Count -gt 0) {
            Write-Host "`nErrors during restoration:" -ForegroundColor Red
            $errors | ForEach-Object { Write-Host "  • $_" -ForegroundColor White }
        }
        
        return $errors.Count -eq 0
        
    } catch {
        Write-Error "Failed to restore services from manifest: $_"
        return $false
    }
}

function Main {
    if (-not ($Audit -or $Apply -or $Rollback)) {
        Write-Host "Annexure-A System Services Management Script" -ForegroundColor Cyan
        Write-Host "Usage: .\disable_services.ps1 [-audit] [-apply] [-rollback <manifest_file>]" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Options:"
        Write-Host "  -audit                    Audit current service states"
        Write-Host "  -apply                    Disable non-compliant services"
        Write-Host "  -rollback <manifest>      Restore services from backup manifest"
        Write-Host ""
        Write-Host "Services managed by this script:"
        foreach ($svc in $ServicesToDisable) {
            Write-Host "  • $($svc.DisplayName) ($($svc.Name))" -ForegroundColor Gray
        }
        return
    }
    
    if ($Rollback) {
        Write-Host "Restoring services from manifest..." -ForegroundColor Yellow
        $success = Restore-ServicesFromManifest -ManifestFile $Rollback
        if ($success) {
            Write-Host "Service restoration completed successfully" -ForegroundColor Green
        } else {
            Write-Host "Service restoration completed with errors" -ForegroundColor Yellow
        }
        return
    }
    
    # Get current service status
    Write-Host "Analyzing system services..." -ForegroundColor Yellow
    $serviceStatus = Get-ServiceStatus -ServiceList $ServicesToDisable
    
    if ($Audit) {
        Write-Host "Auditing Annexure-A system services..." -ForegroundColor Yellow
        
        # Output JSON audit results
        $auditResults = @{
            "audit_timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            "total_services" = $serviceStatus.Count
            "compliant_services" = ($serviceStatus | Where-Object { $_.compliant }).Count
            "non_compliant_services" = ($serviceStatus | Where-Object { -not $_.compliant -and $_.exists }).Count
            "not_installed_services" = ($serviceStatus | Where-Object { -not $_.exists }).Count
            "services" = $serviceStatus
        }
        
        $auditResults | ConvertTo-Json -Depth 4 | Write-Output
        
        # Summary
        Write-Host "`nService Compliance Summary:" -ForegroundColor Cyan
        Write-Host "  Total services checked: $($auditResults.total_services)" -ForegroundColor White
        Write-Host "  Compliant: $($auditResults.compliant_services)" -ForegroundColor Green
        Write-Host "  Non-compliant: $($auditResults.non_compliant_services)" -ForegroundColor $(if ($auditResults.non_compliant_services -eq 0) { "Green" } else { "Red" })
        Write-Host "  Not installed: $($auditResults.not_installed_services)" -ForegroundColor Yellow
    }
    
    if ($Apply) {
        Write-Host "Applying Annexure-A service hardening..." -ForegroundColor Yellow
        
        # Check if any changes are needed
        $nonCompliantServices = $serviceStatus | Where-Object { -not $_.compliant -and $_.exists }
        
        if ($nonCompliantServices.Count -eq 0) {
            Write-Host "All services are already compliant. No changes needed." -ForegroundColor Green
            return
        }
        
        # Save backup manifest
        $manifestFile = Save-ServiceManifest -ServiceStatus $serviceStatus
        if (-not $manifestFile) {
            Write-Error "Failed to create backup manifest. Aborting service changes."
            return
        }
        
        # Apply service changes
        $result = Disable-ServicesFromList -ServiceStatus $serviceStatus
        
        if ($result.changes.Count -gt 0) {
            Write-Host "`nService changes applied:" -ForegroundColor Green
            $result.changes | ForEach-Object { Write-Host "  • $_" -ForegroundColor White }
        }
        
        if ($result.errors.Count -gt 0) {
            Write-Host "`nErrors encountered:" -ForegroundColor Red
            $result.errors | ForEach-Object { Write-Host "  • $_" -ForegroundColor White }
        }
        
        Write-Host "`nBackup manifest created: $manifestFile" -ForegroundColor Cyan
        Write-Host "Use this file with -rollback to restore original service states" -ForegroundColor Gray
    }
}

# Execute main function
Main