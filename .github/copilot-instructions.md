# Copilot Instructions for Multi-Platform System Hardening Tool

## Project Overview

This is a **security-focused Python application** that automatically audits and applies hardening rules to Windows (10/11), Ubuntu (20.04+), and CentOS (7+) systems based on CIS Benchmarks and NTRO requirements.

**Key Architecture Principles:**
- **Platform abstraction**: `hardening_tool/platforms/` contains OS-specific implementations inheriting from `base.py`
- **Rule-driven design**: YAML rule definitions in `hardening_tool/rules/definitions/` drive all hardening operations
- **Database-backed**: SQLite stores all runs, results, and encrypted rollback data in `hardening_tool/database/`
- **CLI-first**: Rich terminal interface via Click in `hardening_tool/cli.py` with future GUI support

## Development Workflow

### Adding New Hardening Rules
1. **Create YAML rule definitions** in `hardening_tool/rules/definitions/[platform]_[category].yaml`
2. **Follow rule ID convention**: `{category}_{specific_action}` (e.g., `ssh_disable_root_login`)
3. **Implement platform-specific logic** in respective `platforms/[platform].py` files
4. **Test with**: `hardening-tool audit --rules your_rule_id` and `hardening-tool apply --dry-run --rules your_rule_id`

### Platform Implementation Pattern
Each platform class in `hardening_tool/platforms/` must implement:
- `audit_rule()` - Read-only compliance checking
- `apply_rule()` - Make actual system changes  
- `create_rollback_point()` - Backup critical configs before changes
- `perform_rollback()` - Restore from rollback point

**Example rule implementation flow:**
```python
def _audit_ssh_rule(self, rule: HardeningRule) -> RuleResult:
    # 1. Read current config state
    # 2. Compare against rule expectations  
    # 3. Return PASS/FAIL/ERROR status with details
```

### Database Schema Understanding
- `hardening_runs` table stores execution metadata and summary stats
- `rule_results` table contains individual rule outcomes with before/after state
- `rollback_points` table holds encrypted backup data for system restoration
- Use `DatabaseManager` class - never directly access SQLite

### Security Considerations
- **Rollback data is encrypted** using Fernet (AES) in `database/manager.py`
- **Admin privileges required** for system modifications - checked in CLI
- **File backups created automatically** before any configuration changes
- **Command injection prevention** via proper shell escaping in platform implementations

## Code Patterns & Conventions

### Error Handling
Always wrap platform operations in try/catch and return appropriate `RuleResult` with status ERROR:
```python
try:
    result = self.execute_command(command)
    return RuleResult(status=RuleStatus.PASS, ...)
except Exception as e:
    return RuleResult(status=RuleStatus.ERROR, message=f"Failed: {e}")
```

### CLI Development
- Use `@click.option()` for all parameters with clear help text
- Implement `--dry-run` mode for all destructive operations
- Use `Rich` console for formatted output (tables, progress bars, colored text)
- Always check admin privileges before system modifications

### Rule YAML Structure
```yaml
rules:
  - id: "unique_rule_identifier" 
    title: "Human-readable description"
    platforms: ["ubuntu", "centos", "windows"]
    categories: ["ssh", "firewall", "etc"]
    severity: "critical|high|medium|low"
    cis_benchmark: "Section reference"
    audit_command: "Optional shell command for generic rules"
    apply_command: "Optional shell command for generic rules"
```

### Testing Approach
- **Unit tests**: Mock platform operations, test rule logic in isolation
- **Integration tests**: Use Docker containers for Linux testing
- **Windows testing**: Requires Windows sandbox or VM environment
- **Always test rollback functionality** - critical for production safety

## Key Files & Their Purpose

- `hardening_tool/core/orchestrator.py` - Main business logic coordinator
- `hardening_tool/core/models.py` - Pydantic data models for type safety
- `hardening_tool/cli.py` - Complete CLI interface with Rich formatting
- `hardening_tool/platforms/factory.py` - Platform selection and instantiation
- `hardening_tool/rules/loader.py` - YAML rule parsing and filtering
- `hardening_tool/utils/os_detection.py` - Robust OS detection across platforms
- `hardening_tool/reporting/generator.py` - PDF/HTML report generation

## Dependencies & Build

- **Core**: `pydantic`, `click`, `rich`, `sqlalchemy`, `cryptography`
- **Reporting**: `weasyprint`, `jinja2` for PDF generation
- **Optional GUI**: `PySide6` (not yet implemented)
- **Build**: Use `pyinstaller` for standalone executables per platform

### Development Setup
```bash
pip install -e ".[dev]"  # Install with dev dependencies
pre-commit install        # Setup code quality hooks
pytest                    # Run test suite
```

## Security & Production Notes

- **Never run hardening rules on production without testing**
- **Always create rollback points** before applying changes
- **Validate rule definitions** - malformed YAML can cause runtime errors
- **Monitor disk space** - rollback points and logs can accumulate
- **Windows requires UAC elevation** - handle gracefully in CLI
- **Linux requires root/sudo** - check permissions before operations

## Extension Points

To add support for new platforms:
1. Create new platform class inheriting from `BasePlatform`
2. Register in `PlatformFactory._platforms` mapping
3. Add OS detection logic to `utils/os_detection.py` 
4. Create platform-specific rule definitions in `rules/definitions/`

Remember: This tool makes **system-level security changes**. Always prioritize safety, rollback capability, and clear user communication about what changes will be made.