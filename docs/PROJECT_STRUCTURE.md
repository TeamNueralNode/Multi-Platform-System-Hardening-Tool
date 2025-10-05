# Project Structure

This document outlines the organized structure of the Multi-Platform System Hardening Tool after cleanup.

## Root Directory

```
Multi-Platform-System-Hardening-Tool/
├── .git/                        # Git repository data
├── .github/                     # GitHub workflows and templates
├── .gitignore                   # Git ignore patterns
├── LICENSE                      # MIT License
├── README.md                    # Main project documentation
├── pyproject.toml              # Python project configuration
├── setup_and_test.py           # Automated setup and validation script
├── gui.py                      # Flask web interface
├── build_release.sh            # Release build automation
├── docker-compose.test.yml     # Docker testing infrastructure
├── Dockerfile.*                # Docker images for testing
├── hardening_tool/             # Main Python package
├── scripts/                    # Platform-specific helper scripts
├── utilities/                  # Standalone utility scripts
└── docs/                       # Project documentation
```

## Core Package Structure (`hardening_tool/`)

The main Python package containing all core functionality:

```
hardening_tool/
├── __init__.py                 # Package initialization
├── cli.py                      # Command-line interface
├── core/                       # Core business logic
│   ├── __init__.py
│   ├── models.py              # Pydantic data models
│   └── orchestrator.py        # Main orchestration logic
├── database/                   # Database management
│   ├── __init__.py
│   └── manager.py             # SQLite database operations
├── platforms/                  # OS-specific implementations
│   ├── __init__.py
│   ├── base.py                # Base platform interface
│   ├── factory.py             # Platform factory
│   ├── linux.py               # Linux hardening implementation
│   └── windows.py             # Windows hardening implementation
├── reporting/                  # Report generation
│   ├── __init__.py
│   └── generator.py           # PDF/HTML report generator
├── rules/                      # Rule management
│   ├── __init__.py
│   └── loader.py              # YAML rule loader and processor
└── utils/                      # Shared utilities
    ├── __init__.py
    └── os_detection.py         # OS detection and validation
```

## Scripts Directory (`scripts/`)

Platform-specific helper scripts organized by target platform:

```
scripts/
├── linux/                     # Linux-specific scripts
│   ├── apply_mount_options.sh # File system mount hardening
│   ├── apply_pam_pwquality.sh # PAM password quality enforcement  
│   ├── disable_kernel_modules.sh # Kernel module management
│   ├── harden_sshd.sh         # SSH daemon hardening
│   ├── shadow_hardening.sh    # Password and account hardening
│   └── setup_dev_env.sh       # Development environment setup
├── windows/                    # Windows-specific scripts
│   ├── account_lockout_policy.ps1 # Account lockout policies
│   ├── annexure_a_audit_policy.ps1 # Audit policy configuration
│   ├── disable_services.ps1   # Service management
│   ├── windows_firewall.py    # Windows Firewall management
│   ├── windows_password_policy.py # Password policy enforcement
│   └── windows_user_rights.yaml # User rights assignments
└── testing/                    # Testing automation scripts
    ├── test_comprehensive.sh   # Comprehensive test suite
    ├── test_final_validation.sh # Final validation tests
    ├── test_rule_coverage.sh   # Rule coverage analysis
    └── test_unit_framework.sh  # Unit testing framework
```

## Utilities Directory (`utilities/`)

Standalone utility scripts for specialized tasks:

```
utilities/
├── audit_mount_options.py     # File system mount auditing
├── auditd_rsyslog_config.py   # Audit daemon and syslog configuration
├── generate_rules.py          # Rule generation utilities
├── hardener_core.py           # Core hardening utilities
├── pam_pwquality_audit.py     # PAM quality auditing
├── pdf_report_generator.py    # PDF report generation utility
└── ufw_enforcer.py            # UFW firewall enforcement
```

## Documentation Directory (`docs/`)

Project documentation and guides:

```
docs/
├── CI_BUILD_NOTES.md          # Continuous integration notes
├── CLEANUP_SUMMARY.md         # Cleanup process documentation
├── PRODUCTION_CHECKLIST.md    # Production deployment checklist
├── PROJECT_STRUCTURE.md       # This file
├── RULE_EXPANSION.md          # Rule system documentation
├── TESTING.md                 # Testing procedures
├── TESTING_QUICK.md           # Quick testing guide
└── UNIT_TESTING.md            # Unit testing framework
```

## Key Benefits of This Structure

### 🔧 **Modularity**
- Clear separation between core logic, platform implementations, and utilities
- Each component has a specific responsibility and interface

### 📁 **Organization** 
- Platform-specific scripts grouped logically
- Documentation consolidated in one location
- Utilities separated from core package code

### 🔄 **Maintainability**
- Easy to locate and modify specific functionality
- Clear dependency relationships
- Standardized naming conventions

### 🚀 **Scalability**
- New platforms can be added easily to `hardening_tool/platforms/`
- Additional helper scripts go into appropriate `scripts/` subdirectories
- New utilities can be added to `utilities/` directory

### 📦 **Distribution**
- Core package (`hardening_tool/`) can be distributed via PyPI
- Scripts and utilities can be bundled with releases
- Docker testing infrastructure is self-contained

## Usage Patterns

### Core Package Usage
```bash
# Install the core package
pip install -e .

# Use via CLI
hardening-tool audit --platform linux
hardening-tool apply --rules ssh_hardening

# Use via Python API
from hardening_tool.core.orchestrator import HardeningTool
```

### Direct Script Usage
```bash
# Run platform-specific scripts directly
./scripts/linux/shadow_hardening.sh --audit-only
./scripts/linux/harden_sshd.sh --dry-run
```

### Utility Script Usage
```bash
# Use standalone utilities
python utilities/pam_pwquality_audit.py
python utilities/pdf_report_generator.py --input audit_results.json
```

This structure provides a clean, maintainable, and scalable foundation for the security hardening tool while preserving all functionality and making it easier to extend and distribute.