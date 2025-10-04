# Multi-Platform System Hardening Tool

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An automated security compliance enforcer for Windows (10/11), Ubuntu (20.04+), and CentOS (7+) based on CIS Benchmarks and NTRO SIH Problem Statement ID 25237.

## 🚀 Features

- **Multi-Platform Support**: Windows, Ubuntu, and CentOS
- **Automated OS Detection**: Automatically detects target operating system
- **CIS Benchmark Compliance**: Implements security hardening based on CIS standards
- **Audit & Apply**: Comprehensive before/after compliance reporting
- **Rollback Capability**: Safe rollback to previous configurations
- **Dual Interface**: Command-line interface with optional GUI
- **Detailed Reporting**: PDF reports with timestamps and severity ratings
- **Secure by Design**: Encrypted backups and secure configuration handling

## 🏗️ Architecture

```
hardening_tool/
├── core/              # Core orchestration and business logic
├── platforms/         # OS-specific hardening modules
├── database/          # SQLite schemas and data models
├── reporting/         # PDF generation and templates
├── rules/             # Hardening rule definitions (YAML)
├── gui/              # Optional PySide6 GUI (future)
└── utils/            # Shared utilities and helpers
```

## 🛠️ Installation

### From Source
```bash
git clone https://github.com/amey/Multi-Platform_System_Hardening_Tool.git
cd Multi-Platform_System_Hardening_Tool
pip install -e .
```

### Development Setup
```bash
pip install -e ".[dev]"
pre-commit install
```

## 📖 Usage

### Command Line Interface

```bash
# Audit current system compliance
hardening-tool audit

# Apply hardening rules (with confirmation)
hardening-tool apply --interactive

# Apply specific rule categories
hardening-tool apply --categories ssh,firewall,users

# Rollback to previous state
hardening-tool rollback --run-id 12345

# Generate compliance report
hardening-tool report --format pdf --output compliance_report.pdf

# List available rules
hardening-tool rules list --platform linux

# Show rule details
hardening-tool rules show ssh_disable_root_login
```

### Programmatic Usage

```python
from hardening_tool import HardeningTool

tool = HardeningTool()
results = tool.audit()
print(f"Compliance: {results.overall_score}%")

# Apply hardening with rollback capability
tool.apply(categories=['ssh', 'firewall'], create_rollback=True)
```

## 🔧 Configuration

Configuration files are stored in:
- Linux: `~/.config/hardening-tool/`
- Windows: `%APPDATA%/hardening-tool/`

### Example Configuration (`config.yaml`)

```yaml
hardening:
  backup_location: "/var/backups/hardening-tool"
  max_rollback_points: 10
  
reporting:
  include_remediation_steps: true
  severity_threshold: "medium"
  
platforms:
  linux:
    ssh_config_path: "/etc/ssh/sshd_config"
  windows:
    use_powershell_dsc: false
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=hardening_tool

# Test specific platform
pytest tests/test_linux.py

# Integration tests (requires Docker)
pytest tests/integration/
```

## 📦 Building

```bash
# Build standalone executables
pip install -e ".[build]"

# Linux binary
pyinstaller scripts/build_linux.spec

# Windows binary (on Windows)
pyinstaller scripts/build_windows.spec
```

## 🔒 Security Considerations

- All configuration backups are encrypted using AES-256
- Administrative privileges required for system modifications
- Rollback points include checksums for integrity verification
- Audit logs are tamper-evident with cryptographic signatures

## 📊 Supported Rules

### Linux (Ubuntu/CentOS)
- SSH hardening (disable root login, key-only auth, etc.)
- Firewall configuration (UFW/firewalld)
- User account policies
- File system permissions
- Kernel parameter tuning
- Service configuration

### Windows
- SMB protocol security
- Windows Firewall rules
- User Account Control (UAC)
- Registry security settings
- PowerShell execution policies
- Windows Defender configuration

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and add tests
4. Run quality checks: `black . && ruff . && mypy .`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎯 Roadmap

- [ ] Web-based dashboard
- [ ] Custom rule creation interface
- [ ] Integration with SIEM systems
- [ ] Compliance framework extensions (NIST, ISO 27001)
- [ ] Cloud platform support (AWS, Azure, GCP)

---

**Note**: This tool makes system-level changes. Always test in a non-production environment first and ensure you have proper backups.# Multi-Platform-System-Hardening-Tool
