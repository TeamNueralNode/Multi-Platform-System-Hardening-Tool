# Testing Guide for Multi-Platform System Hardening Tool

This guide provides comprehensive testing procedures for validating all aspects of the hardening tool functionality.

## Quick Start Testing

### 1. Setup Validation
# Security Hardening Tool - Testing Guide

This document provides comprehensive testing guidance for the Multi-Platform System Hardening Tool, including automated CI/CD testing and manual testing procedures for Windows, Ubuntu, and CentOS systems.

## Table of Contents

- [Overview](#overview)
- [Automated Testing (CI/CD)](#automated-testing-cicd)
- [Local Docker Testing](#local-docker-testing) 
- [Windows Testing Setup](#windows-testing-setup)
- [Manual Testing Procedures](#manual-testing-procedures)
- [Test Coverage](#test-coverage)
- [Troubleshooting](#troubleshooting)

## Overview

The testing strategy encompasses:

- **Automated CI/CD**: GitHub Actions workflow for continuous integration
- **Docker Compose**: Local containerized testing for Linux platforms
- **Manual Testing**: Procedures for Windows and comprehensive system testing
- **Dry-Run Operations**: Safe testing without system modifications
- **Comprehensive Reporting**: JSON and PDF report generation

## Automated Testing (CI/CD)

### GitHub Actions Workflow

The CI pipeline (`.github/workflows/ci-security-tests.yml`) provides:

**Test Matrix:**
- Ubuntu 20.04 container testing
- CentOS 7 container testing  
- Multiple security categories: SSH, PAM, System, Firewall
- Code quality checks (flake8, mypy, bandit)

**Trigger Conditions:**
```yaml
# Automatic triggers
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * 0'  # Weekly on Sundays

# Manual trigger with options
workflow_dispatch:
  inputs:
    test_level:
      type: choice
      options: [basic, comprehensive, audit-only]
```

**Test Categories:**

1. **Code Quality & Unit Tests**
   - Python linting and type checking
   - Security vulnerability scanning
   - Dependency validation

2. **Ubuntu 20.04 Security Tests**
   - SSH hardening rules
   - PAM password policies
   - System configuration audits
   - UFW firewall rules

3. **CentOS 7 Security Tests**
   - SSH security configuration
   - PAM authentication policies
   - System hardening checks
   - Firewalld configuration

4. **Comprehensive Testing**
   - Cross-platform result aggregation
   - Detailed compliance reporting
   - Performance benchmarking

### Running CI Tests

**Automatic Execution:**
```bash
# Tests run automatically on:
git push origin main
git push origin develop

# Or create pull request to main branch
```

**Manual Execution:**
```bash
# Navigate to Actions tab in GitHub repository
# Click "Run workflow" on "Security Hardening Tool CI Tests"
# Select test level: basic/comprehensive/audit-only
```

**Viewing Results:**
- GitHub Actions logs provide real-time execution details
- Test artifacts (JSON reports) available for download
- Comprehensive test summary generated for each run

## Local Docker Testing

### Docker Compose Setup

Use Docker Compose for local testing across Linux platforms:

```bash
# Run complete test suite
docker-compose -f docker-compose.test.yml up --build

# Run specific platform
docker-compose -f docker-compose.test.yml up ubuntu-test
docker-compose -f docker-compose.test.yml up centos-test

# Run in background and collect results
docker-compose -f docker-compose.test.yml up -d
docker-compose -f docker-compose.test.yml logs -f test-collector
```

### Test Containers

**Ubuntu 20.04 Test Environment:**
- Full Ubuntu 20.04 with systemd
- SSH, UFW, audit, PAM packages
- Test user with sudo privileges
- Automated security rule testing

**CentOS 7 Test Environment:**
- CentOS 7 with systemd support
- SSH, firewalld, audit, PAM packages
- RHEL-compatible security testing
- Service management capabilities

**Test Result Collection:**
- Automated result aggregation
- JSON report generation
- Human-readable summaries
- Volume-mounted result persistence

### Local Testing Commands

```bash
# Build test environments
docker-compose -f docker-compose.test.yml build

# Run Ubuntu tests only
docker-compose -f docker-compose.test.yml run ubuntu-test

# Run CentOS tests only  
docker-compose -f docker-compose.test.yml run centos-test

# Interactive testing session
docker-compose -f docker-compose.test.yml run ubuntu-test bash

# Clean up test environments
docker-compose -f docker-compose.test.yml down -v
```

### Accessing Test Results

```bash
# Copy results from running containers
docker cp hardening-tool-ubuntu-test:/tmp/ubuntu_test_summary.json ./results/
docker cp hardening-tool-centos-test:/tmp/centos_test_summary.json ./results/

# View results in test-results volume
docker volume inspect docker-compose_test-results
```

## Windows Testing Setup

### Prerequisites

**Windows Environment Requirements:**
- Windows 10/11 Pro/Enterprise (Home edition limited)
- PowerShell 5.1+ (PowerShell 7+ recommended)
- Administrative privileges
- Windows Sandbox or Hyper-V (for safe testing)

**Recommended Testing Environments:**

1. **Windows Sandbox** (Recommended for development)
2. **Hyper-V Virtual Machines** (Production-like testing)
3. **VMware Workstation/VirtualBox** (Cross-platform compatibility)

### Windows Sandbox Setup

**Enable Windows Sandbox:**
```powershell
# Run as Administrator
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
```

**Create Sandbox Configuration (`HardeningTest.wsb`):**
```xml
<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\path\to\Multi-Platform-System-Hardening-Tool</HostFolder>
      <SandboxFolder>C:\HardeningTool</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File C:\HardeningTool\scripts\sandbox-setup.ps1</Command>
  </LogonCommand>
</Configuration>
```

### PowerShell DSC Configuration

**DSC Configuration for Test Environment:**
```powershell
# TestEnvironment.ps1
Configuration HardeningTestEnvironment {
    param (
        [string[]]$ComputerName = 'localhost'
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node $ComputerName {
        # Enable necessary Windows features for testing
        WindowsFeature AuditPolicyManagement {
            Name = "RSAT-Feature-Tools-GP-auditpol"
            Ensure = "Present"
        }
        
        WindowsFeature SecurityPolicy {
            Name = "RSAT-ADDS-Tools"
            Ensure = "Present"
        }
        
        # Create test users
        User TestUser {
            UserName = "HardeningTestUser"
            Password = (ConvertTo-SecureString "Test123!@#" -AsPlainText -Force)
            Ensure = "Present"
            PasswordNeverExpires = $false
        }
        
        # Configure test registry settings
        Registry TestPolicyKey {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\HardeningTool\Test"
            ValueName = "TestEnvironment"
            ValueData = "Enabled"
            ValueType = "String"
            Ensure = "Present"
        }
    }
}

# Apply configuration
HardeningTestEnvironment -OutputPath C:\DSC\
Start-DscConfiguration -Path C:\DSC\ -Wait -Verbose
```

### VM Setup Notes

**Hyper-V Quick Create:**
```powershell
# Create Windows 11 VM for testing
New-VM -Name "HardeningTest-Win11" -MemoryStartupBytes 4GB -Generation 2
Set-VM -Name "HardeningTest-Win11" -ProcessorCount 2
New-VHD -Path "C:\VMs\HardeningTest-Win11.vhdx" -SizeBytes 60GB -Dynamic
Add-VMHardDiskDrive -VMName "HardeningTest-Win11" -Path "C:\VMs\HardeningTest-Win11.vhdx"
```

**VMware/VirtualBox Settings:**
- **RAM**: Minimum 4GB (8GB recommended)
- **Storage**: 60GB+ dynamic disk
- **Network**: NAT or Bridged (for updates)
- **Snapshots**: Create baseline snapshot before testing
- **Guest Additions**: Install for better integration

### Windows Testing Commands

**Setup Test Environment:**
```powershell
# Run as Administrator
cd C:\path\to\Multi-Platform-System-Hardening-Tool

# Install Python dependencies
pip install -e ".[dev]"

# Validate setup
python setup_and_test.py
```

**Execute Windows Security Tests:**
```powershell
# Audit Windows security policies
python -m hardening_tool.cli audit --rules windows_password_policy,windows_account_lockout --dry-run --output-format json --output windows_audit_results.json

# Test Windows firewall rules
python -m hardening_tool.cli audit --rules windows_firewall_enable,windows_firewall_default_action --dry-run --output-format json --output windows_firewall_audit.json

# Dry-run apply operations
python -m hardening_tool.cli apply --rules windows_password_policy,windows_account_lockout --dry-run --output-format json --output windows_apply_dryrun.json

# Generate Windows security report
python pdf_report_generator.py windows_test_run_001 --db-path hardening_tool.db --output windows_security_report.pdf
```

## Manual Testing Procedures

### Pre-Testing Checklist

**Before Running Tests:**
- [ ] Create system backups/snapshots
- [ ] Document baseline system configuration
- [ ] Ensure administrative/root privileges
- [ ] Verify network connectivity
- [ ] Close unnecessary applications

**Test Environment Validation:**
```bash
# Linux systems
python3 setup_and_test.py
sudo -v  # Verify sudo access

# Windows systems  
python setup_and_test.py
# Verify "Run as Administrator" mode
```

### Comprehensive Test Execution

**1. Setup Phase:**
```bash
# Generate sample rules
python3 -c "
from hardening_tool.rules.loader import RuleLoader
import os
os.makedirs('rules/definitions', exist_ok=True)
loader = RuleLoader('rules/definitions')
loader._create_sample_rules()
print('Sample rules created')
"

# Verify rule generation
ls -la rules/definitions/
```

**2. Audit Phase:**
```bash
# Run comprehensive audit (safe - read-only)
python3 -m hardening_tool.cli audit --all-rules --dry-run --output-format json --output comprehensive_audit.json

# Category-specific audits
python3 -m hardening_tool.cli audit --category ssh --dry-run --output-format json --output ssh_audit.json
python3 -m hardening_tool.cli audit --category pam --dry-run --output-format json --output pam_audit.json
python3 -m hardening_tool.cli audit --category firewall --dry-run --output-format json --output firewall_audit.json
```

**3. Apply Phase (Dry-Run):**
```bash
# Test apply operations without making changes
python3 -m hardening_tool.cli apply --category ssh --dry-run --output-format json --output ssh_apply_dryrun.json
python3 -m hardening_tool.cli apply --rules ssh_disable_root_login,ssh_disable_password_auth --dry-run --output-format json --output specific_rules_dryrun.json
```

**4. Rollback Testing:**
```bash
# Test rollback point creation (if apply was actually run)
python3 -m hardening_tool.cli rollback --list
python3 -m hardening_tool.cli rollback --point-id <rollback_point_id> --dry-run
```

### Custom Rule Testing

**Create Test Rule:**
```yaml
# rules/definitions/test_custom_rules.yaml
rules:
  - id: "test_custom_rule"
    title: "Test Custom Security Rule"
    platforms: ["ubuntu", "centos", "windows"]
    categories: ["test"]
    severity: "low"
    cis_benchmark: "Test-1.1.1"
    audit_command: "echo 'Audit test rule'"
    apply_command: "echo 'Apply test rule'"
    rollback_command: "echo 'Rollback test rule'"
```

**Test Custom Rule:**
```bash
python3 -m hardening_tool.cli audit --rules test_custom_rule --dry-run
python3 -m hardening_tool.cli apply --rules test_custom_rule --dry-run
```

## Test Coverage

### Security Categories Tested

**SSH Hardening:**
- Root login disabled
- Password authentication disabled
- Maximum authentication attempts
- Protocol version enforcement
- Key-based authentication only

**PAM (Pluggable Authentication Modules):**
- Password complexity requirements
- Password history enforcement
- Account lockout policies
- Login attempt monitoring
- Session management

**System Configuration:**
- Unused filesystem disabling
- Boot loader security
- File permission enforcement
- Service hardening
- Kernel parameter tuning

**Firewall Configuration:**
- Default deny policies
- Service-specific rules
- Logging configuration
- Port management
- Network segmentation

### Platform Coverage

**Ubuntu 20.04:**
- UFW firewall management
- systemd service controls
- APT package management
- Ubuntu-specific security features

**CentOS 7:**
- firewalld configuration
- systemd service management
- YUM package handling
- RHEL-compatible features

**Windows 10/11:**
- Group Policy settings
- Windows Firewall rules
- Local Security Policy
- Registry-based configurations

### Test Result Validation

**Expected Outputs:**
- JSON result files with rule status
- PDF compliance reports
- Database entries for audit trails
- Rollback point creation records

**Success Criteria:**
- All audit operations complete without errors
- Dry-run apply operations execute safely
- JSON outputs contain expected data structure
- Database integrity maintained
- No unauthorized system modifications during dry-run

## Troubleshooting

### Common Issues

**Permission Errors:**
```bash
# Linux - ensure sudo access
sudo -v
sudo python3 -m hardening_tool.cli audit --all-rules --dry-run

# Windows - ensure Administrator mode
# Right-click PowerShell -> "Run as Administrator"
```

**Missing Dependencies:**
```bash
# Install missing Python packages  
pip install -e ".[dev]"

# Ubuntu - install system packages
sudo apt-get update
sudo apt-get install python3-dev libpam-dev

# CentOS - install system packages
sudo yum install python3-devel pam-devel
```

**Docker Issues:**
```bash
# Reset Docker environment
docker-compose -f docker-compose.test.yml down -v
docker system prune -f
docker-compose -f docker-compose.test.yml up --build
```

**Database Issues:**
```bash
# Reset database for clean testing
rm -f hardening_tool.db
python3 -c "
from hardening_tool.database.manager import DatabaseManager
db = DatabaseManager('hardening_tool.db')
db.initialize_database()
print('Database initialized')
"
```

### Debug Mode

**Enable Verbose Logging:**
```bash
export HARDENING_TOOL_DEBUG=1
python3 -m hardening_tool.cli audit --all-rules --dry-run --verbose
```

**Manual Rule Testing:**
```bash
# Test individual rule components
python3 -c "
from hardening_tool.rules.loader import RuleLoader
loader = RuleLoader('rules/definitions')
rules = loader.load_rules()
for rule in rules[:3]:  # Test first 3 rules
    print(f'Rule: {rule.id} - {rule.title}')
"
```

### Support and Reporting

**Test Failure Reporting:**
1. Collect all JSON output files
2. Include system information (`uname -a` on Linux, `systeminfo` on Windows)
3. Provide complete error logs
4. Include test environment details (VM, container, physical)

**Performance Issues:**
- Monitor resource usage during tests
- Check disk space for rollback point storage
- Verify network connectivity for updates
- Consider test parallelization limits

---

## Quick Start Testing

**For immediate testing:**

```bash
# 1. Setup
git clone <repository>
cd Multi-Platform-System-Hardening-Tool
pip install -e ".[dev]"

# 2. Run basic tests
python3 setup_and_test.py

# 3. Docker testing (Linux)
docker-compose -f docker-compose.test.yml up --build

# 4. Manual audit testing
python3 -m hardening_tool.cli audit --all-rules --dry-run --output-format json --output test_results.json

# 5. View results
cat test_results.json | python3 -m json.tool
```

This comprehensive testing approach ensures the security hardening tool functions correctly across all supported platforms while maintaining system safety through extensive dry-run testing.

### 2. Basic Functionality Test
```bash
# Test system detection
hardening-tool audit --format summary

# Test rule listing
hardening-tool rules list
hardening-tool rules list --platform ubuntu
hardening-tool rules list --severity high

# Test specific rule details
hardening-tool rules show ssh_disable_root_login
```

## Core Functionality Testing

### Audit Testing
```bash
# Full system audit
hardening-tool audit

# Category-specific audit
hardening-tool audit --categories ssh
hardening-tool audit --categories ssh,firewall

# Rule-specific audit
hardening-tool audit --rules ssh_disable_root_login
hardening-tool audit --rules ssh_disable_root_login,ssh_disable_password_auth

# Output format testing
hardening-tool audit --format table
hardening-tool audit --format summary
hardening-tool audit --output audit_results.json --format json

# Verify JSON output
cat audit_results.json | python -m json.tool
```

### Apply Testing (Requires sudo)
```bash
# Dry run testing (safe)
sudo ./venv/bin/python -m hardening_tool.cli apply --dry-run
sudo ./venv/bin/python -m hardening_tool.cli apply --dry-run --categories ssh
sudo ./venv/bin/python -m hardening_tool.cli apply --dry-run --rules ssh_disable_password_auth

# Interactive testing
sudo ./venv/bin/python -m hardening_tool.cli apply --interactive

# Force mode (skip confirmations)
sudo ./venv/bin/python -m hardening_tool.cli apply --force --dry-run

# Custom rollback point
sudo ./venv/bin/python -m hardening_tool.cli apply --rollback-point "Before SSH hardening test"
```

### Rollback Testing (Requires sudo)
```bash
# List rollback points
sudo ./venv/bin/python -m hardening_tool.cli rollback --list-points

# Perform rollback (replace with actual run ID)
sudo ./venv/bin/python -m hardening_tool.cli rollback --run-id YOUR_RUN_ID_HERE
```

## Database Testing

### Check Database Operations
```bash
# Find database location
python -c "from hardening_tool.database.manager import DatabaseManager; dm = DatabaseManager(); print(f'Database: {dm.db_path}')"

# Verify database exists and has tables
sqlite3 ~/.local/share/hardening-tool/hardening.db ".tables"

# Check run records
sqlite3 ~/.local/share/hardening-tool/hardening.db "SELECT run_id, operation, started_at, overall_score FROM hardening_runs;"

# Check rule results
sqlite3 ~/.local/share/hardening-tool/hardening.db "SELECT rule_id, status, severity, message FROM rule_results LIMIT 5;"
```

## Error Condition Testing

### Permission Testing
```bash
# Test without sudo (should fail)
hardening-tool apply --dry-run

# Test with invalid user
sudo -u nobody hardening-tool audit 2>&1 | head -5
```

### Invalid Input Testing
```bash
# Invalid categories
hardening-tool audit --categories invalid_category

# Invalid rules
hardening-tool audit --rules non_existent_rule

# Invalid platform filter
hardening-tool rules list --platform invalid_os

# Invalid severity filter
hardening-tool rules list --severity invalid_severity

# Invalid output paths
hardening-tool audit --output /root/cannot_write_here.json 2>&1 | head -3
```

### System State Testing
```bash
# Test with missing SSH
sudo systemctl stop ssh 2>/dev/null || true
sudo systemctl disable ssh 2>/dev/null || true
hardening-tool audit
sudo systemctl enable ssh 2>/dev/null || true
sudo systemctl start ssh 2>/dev/null || true

# Test with modified SSH config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null || true
echo "# Test comment" | sudo tee -a /etc/ssh/sshd_config >/dev/null 2>&1 || true
hardening-tool audit --rules ssh_disable_root_login
sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config 2>/dev/null || true
```

## Performance Testing

### Large Rule Sets
```bash
# Time audit operations
time hardening-tool audit
time hardening-tool audit --categories ssh

# Memory usage monitoring
/usr/bin/time -v hardening-tool audit 2>&1 | grep -E "(Maximum resident|User time|System time)"
```

### Concurrent Operations
```bash
# Test multiple audits (should be safe)
hardening-tool audit & hardening-tool audit & wait

# Check database integrity after concurrent operations
sqlite3 ~/.local/share/hardening-tool/hardening.db "PRAGMA integrity_check;"
```

## Platform-Specific Testing

### Ubuntu/Debian Specific
```bash
# Test package manager detection
python -c "from hardening_tool.platforms.linux import LinuxPlatform; from hardening_tool.core.models import OSType; lp = LinuxPlatform(OSType.UBUNTU); print(f'Package manager: {lp.package_manager}')"

# Test service manager detection
python -c "from hardening_tool.platforms.linux import LinuxPlatform; from hardening_tool.core.models import OSType; lp = LinuxPlatform(OSType.UBUNTU); print(f'Service manager: {lp.service_manager}')"

# Test SSH configuration paths
ls -la /etc/ssh/sshd_config
hardening-tool audit --rules ssh_disable_root_login
```

### Cross-Platform Rule Testing
```bash
# Test Windows rules on Linux (should show NOT_APPLICABLE)
hardening-tool rules list --platform windows

# Test rule platform filtering
hardening-tool audit --rules smb_disable_v1
```

## Security Testing

### Configuration Backup Testing
```bash
# Check if backups are created
sudo ./venv/bin/python -m hardening_tool.cli apply --dry-run --rules ssh_disable_root_login
find /tmp -name "*sshd_config*" -mtime -1 2>/dev/null | head -3

# Verify backup integrity
sudo ./venv/bin/python -c "
from hardening_tool.platforms.linux import LinuxPlatform
from hardening_tool.core.models import OSType
lp = LinuxPlatform(OSType.UBUNTU)
original = lp.read_config_file('/etc/ssh/sshd_config')
backup_path = lp.backup_file('/etc/ssh/sshd_config')
backup = lp.read_config_file(backup_path)
print(f'Backup integrity: {original == backup}')
print(f'Backup path: {backup_path}')
"
```

### Rollback Data Encryption
```bash
# Check rollback points are encrypted
sudo ./venv/bin/python -c "
from hardening_tool.database.manager import DatabaseManager
dm = DatabaseManager()
points = dm.get_rollback_points()
if points:
    print(f'Rollback points: {len(points)}')
    print(f'Encrypted: {points[0].encrypted}')
else:
    print('No rollback points found')
"
```

## Integration Testing

### End-to-End Workflow
```bash
#!/bin/bash
echo "=== End-to-End Integration Test ==="

echo "1. Initial audit..."
hardening-tool audit --format summary

echo "2. Apply hardening with rollback..."
sudo ./venv/bin/python -m hardening_tool.cli apply --interactive --rollback-point "Integration test"

echo "3. Verify changes..."
hardening-tool audit --format summary

echo "4. List rollback points..."
sudo ./venv/bin/python -m hardening_tool.cli rollback --list-points

echo "=== Integration test complete ==="
```

### Rule Development Testing
```bash
# Test custom rule creation
mkdir -p test_rules
cat > test_rules/test_rule.yaml << 'EOF'
rules:
  - id: "test_custom_rule"
    title: "Test Custom Rule"
    description: "A test rule for validation"
    severity: "low"
    platforms: ["ubuntu"]
    categories: ["test"]
    audit_command: "echo 'test audit'"
    apply_command: "echo 'test apply'"
EOF

# Test with custom rules directory
hardening-tool --help  # Check if custom rules loading is supported
```

## Continuous Integration Testing

### Automated Test Script
```bash
#!/bin/bash
# Save as: test_all.sh
set -e

echo "Starting comprehensive hardening tool tests..."

# Setup tests
echo "✓ Setup validation"
python setup_and_test.py > /dev/null

# Basic functionality
echo "✓ Basic audit test"
hardening-tool audit --format summary > /dev/null

echo "✓ Rules listing test"
hardening-tool rules list > /dev/null

echo "✓ Dry run test"
sudo ./venv/bin/python -m hardening_tool.cli apply --dry-run --force > /dev/null

# Error handling
echo "✓ Permission error test"
if hardening-tool apply --dry-run 2>/dev/null; then
    echo "ERROR: Should have failed without sudo"
    exit 1
fi

# Database integrity
echo "✓ Database integrity test"
sqlite3 ~/.local/share/hardening-tool/hardening.db "PRAGMA integrity_check;" | grep -q "ok"

echo "All tests passed! ✅"
```

### Make it executable and run:
```bash
chmod +x test_all.sh
./test_all.sh
```

## Debugging and Troubleshooting

### Enable Verbose Logging
```bash
# Run with verbose output
hardening-tool --verbose audit

# Check logs location
python -c "
import platform
from pathlib import Path
if platform.system() == 'Windows':
    log_dir = Path.home() / 'AppData' / 'Roaming' / 'hardening-tool'
else:
    log_dir = Path.home() / '.local' / 'share' / 'hardening-tool'
print(f'Logs directory: {log_dir}')
"
```

### Python-Level Debugging
```python
# Interactive testing in Python
from hardening_tool import HardeningTool
from hardening_tool.utils.os_detection import detect_os

# Test OS detection
system_info = detect_os()
print(f"Detected: {system_info.os_type} {system_info.os_version}")

# Test rule loading
tool = HardeningTool()
rules = tool.get_available_rules()
print(f"Available rules: {len(rules)}")

# Test audit
result = tool.audit()
print(f"Audit score: {result.overall_score}%")
```

## Test Coverage Verification

### Check Test Results
```bash
# Verify all major components tested
echo "=== Test Coverage Summary ==="
echo "✓ Setup and installation"
echo "✓ OS detection and validation" 
echo "✓ Rule loading and filtering"
echo "✓ Audit functionality"
echo "✓ Apply operations (dry-run)"
echo "✓ Database operations"
echo "✓ CLI interface"
echo "✓ Error handling"
echo "✓ Permission checking"
echo "✓ JSON serialization"
echo "✓ Configuration backup"
echo "✓ Rollback points"

# Check for any missed components
grep -r "TODO\|FIXME\|XXX" hardening_tool/ || echo "No outstanding TODOs found"
```

## Performance Benchmarks
```bash
# Basic performance tests
echo "=== Performance Benchmarks ==="

echo "Audit time:"
time hardening-tool audit > /dev/null

echo "Rule listing time:"
time hardening-tool rules list > /dev/null

echo "Database size:"
du -h ~/.local/share/hardening-tool/hardening.db 2>/dev/null || echo "Database not found"

echo "Memory usage:"
/usr/bin/time -f "Peak memory: %M KB" hardening-tool audit > /dev/null
```

This comprehensive testing approach ensures all aspects of the hardening tool are validated and working correctly. Run these tests after any code changes to maintain system reliability and security.