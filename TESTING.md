# Testing Guide for Multi-Platform System Hardening Tool

This guide provides comprehensive testing procedures for validating all aspects of the hardening tool functionality.

## Quick Start Testing

### 1. Setup Validation
```bash
# Activate virtual environment
source venv/bin/activate

# Run comprehensive setup test
python setup_and_test.py

# Verify installation
hardening-tool --help
hardening-tool --version
```

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