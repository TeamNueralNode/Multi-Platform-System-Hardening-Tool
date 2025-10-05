# Quick Testing Commands Summary

## Essential Testing Commands

### 1. Basic Functionality
```bash
# Full system validation
python setup_and_test.py

# Run comprehensive automated tests
./test_comprehensive.sh

# Basic audit
hardening-tool audit

# List all rules
hardening-tool rules list
```

### 2. Safe Testing (No System Changes)
```bash
# Dry run (shows what would be done)
sudo ./venv/bin/python -m hardening_tool.cli apply --dry-run

# Test specific categories
hardening-tool audit --categories ssh

# Test JSON output
hardening-tool audit --output results.json --format json
```

### 3. Advanced Testing (Makes System Changes)
```bash
# Interactive mode (asks for confirmation)
sudo ./venv/bin/python -m hardening_tool.cli apply --interactive

# Check rollback points
sudo ./venv/bin/python -m hardening_tool.cli rollback --list-points

# Rollback changes (replace with actual run ID)
sudo ./venv/bin/python -m hardening_tool.cli rollback --run-id YOUR_RUN_ID
```

### 4. Verification Testing
```bash
# Check database operations
sqlite3 ~/.local/share/hardening-tool/hardening.db ".tables"
sqlite3 ~/.local/share/hardening-tool/hardening.db "SELECT * FROM hardening_runs ORDER BY started_at DESC LIMIT 3;"

# Verify rule details
hardening-tool rules show ssh_disable_root_login

# Test error handling
hardening-tool apply --dry-run  # Should fail without sudo
```

## Test Status: ✅ ALL TESTS PASSED

- ✅ Setup validation
- ✅ Audit functionality  
- ✅ Rule management
- ✅ JSON output
- ✅ Permission checking
- ✅ Error handling
- ✅ Database operations
- ✅ Performance (< 2 seconds)

## Next Steps

1. **Production Testing**: Install SSH and test real hardening
2. **Multi-Platform**: Test on CentOS/Windows if available
3. **Custom Rules**: Create your own hardening rules
4. **Integration**: Integrate with your CI/CD pipeline