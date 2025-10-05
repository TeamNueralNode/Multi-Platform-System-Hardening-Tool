# CI/CD Notes for Multi-Platform System Hardening Tool Release Builds

## GitHub Actions Workflow for Release Builds

### Recommended Workflow Structure

```yaml
# .github/workflows/release-build.yml
name: Build Release Artifacts

on:
  release:
    types: [created]
  workflow_dispatch:
    inputs:
      version:
        description: 'Release version (e.g., 1.0.0)'
        required: true
        default: '1.0.0'

jobs:
  # Linux Build Job
  build-linux:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: Build Linux Release
      run: |
        chmod +x build_release.sh
        ./build_release.sh linux
    - name: Upload Linux Artifact
      uses: actions/upload-artifact@v3
      with:
        name: linux-release
        path: releases/*linux*

  # Windows Build Job
  build-windows:
    runs-on: windows-latest
    steps:
    - uses: actions/checkout@v4
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: Build Windows Release
      shell: bash
      run: |
        chmod +x build_release.sh
        ./build_release.sh windows
    - name: Upload Windows Artifact
      uses: actions/upload-artifact@v3
      with:
        name: windows-release
        path: releases/*windows*

  # Release Job
  create-release:
    needs: [build-linux, build-windows]
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    steps:
    - name: Download All Artifacts
      uses: actions/download-artifact@v3
    - name: Upload to GitHub Release
      uses: softprops/action-gh-release@v1
      with:
        files: |
          linux-release/*
          windows-release/*
```

## Build Script Usage

### Local Development Builds
```bash
# Make executable
chmod +x build_release.sh

# Build all platforms (requires dependencies)
./build_release.sh

# Build specific platform
./build_release.sh linux
./build_release.sh windows

# Clean build artifacts
./build_release.sh clean
```

### Cross-Platform Considerations

#### Linux Builds
- **Native Linux**: Full support on any Linux distribution
- **macOS/Windows**: Cross-compilation possible but limited
- **Dependencies**: Standard Python packages work well
- **Size**: Typically smaller executables

#### Windows Builds
- **Native Windows**: Best compatibility and features
- **Cross-compilation**: Limited wine support (not recommended for production)
- **GitHub Actions**: Use `windows-latest` runner for reliable builds
- **Dependencies**: May require Windows-specific packages

### PyInstaller Configuration Notes

#### Bundled Resources
The script automatically bundles:
- **YAML Rules**: `hardening_tool/rules/definitions/*.yaml`
- **Helper Scripts**: `*.sh`, `*.ps1`, individual Python scripts
- **Templates**: `report_template.html`
- **Documentation**: `README.md`, `TESTING.md`, `LICENSE`

#### Hidden Imports
Critical modules explicitly imported:
- All hardening_tool submodules
- Platform-specific modules (winreg, pwd, grp)
- Third-party dependencies (pydantic, click, rich, yaml)

#### Exclusions
Excluded to reduce size:
- GUI frameworks (tkinter)
- Data science libraries (numpy, pandas, matplotlib)
- Machine learning frameworks (torch, tensorflow)

### Version Management

#### Automatic Version Detection
```bash
# From pyproject.toml
version = grep -E '^version\s*=' pyproject.toml | cut -d'"' -f2

# With git commit hash
commit_hash = git rev-parse --short HEAD

# Build timestamp
timestamp = date +"%Y%m%d_%H%M%S"
```

#### Version File Integration
Creates `hardening_tool/version_info.py` with:
- Version string
- Build timestamp  
- Git commit hash
- Platform information
- Python version

### Release Artifact Structure

```
releases/
├── hardening-tool-v1.0.0-20241005_143022-linux-x64.tar.gz
├── hardening-tool-v1.0.0-20241005_143022-windows-x64.zip
├── checksums-v1.0.0.txt
└── RELEASE_NOTES-v1.0.0.md

# Extracted structure:
hardening-tool-linux/
├── hardening-tool              # Main executable
├── _internal/                  # PyInstaller dependencies
├── rules/definitions/          # YAML rule files
├── scripts/                    # Helper scripts (.sh, .ps1)
├── report_template.html        # Report template
├── README.md                   # Documentation
├── TESTING.md
└── LICENSE

hardening-tool-windows/
├── hardening-tool.exe          # Main executable  
├── _internal/                  # PyInstaller dependencies
├── rules/definitions/          # YAML rule files
├── scripts/                    # Helper scripts (.sh, .ps1)
├── report_template.html        # Report template
├── README.md                   # Documentation
├── TESTING.md
└── LICENSE
```

### Security Considerations

#### Code Signing
```bash
# Windows (requires certificate)
signtool sign /f certificate.p12 /p password /t http://timestamp.digicert.com hardening-tool.exe

# macOS (requires Apple Developer cert)
codesign -s "Developer ID Application: Your Name" hardening-tool
```

#### Antivirus False Positives
- **UPX Compression**: Disabled to reduce false positives
- **Obfuscation**: Minimal to maintain transparency
- **VirusTotal**: Check releases before distribution
- **Whitelisting**: Provide hashes for corporate environments

### Distribution Strategy

#### GitHub Releases
```bash
# Upload using GitHub CLI
gh release create v1.0.0 \
  releases/*.tar.gz \
  releases/*.zip \
  releases/checksums-*.txt \
  releases/RELEASE_NOTES-*.md \
  --title "System Hardening Tool v1.0.0" \
  --notes-file releases/RELEASE_NOTES-v1.0.0.md
```

#### Package Managers
- **Homebrew** (macOS/Linux): Create formula
- **Chocolatey** (Windows): Create package
- **APT/YUM** (Linux): Create repository packages
- **Snap/Flatpak** (Linux): Containerized distribution

### Testing Release Builds

#### Automated Testing
```bash
# Extract and test executable
tar -xzf releases/hardening-tool-*-linux-x64.tar.gz
cd hardening-tool-linux/

# Basic functionality tests
./hardening-tool --version
./hardening-tool audit --help
./hardening-tool --debug audit --dry-run

# Integration with existing test suite
./hardening-tool audit --output test_results.json --format json
```

#### Manual Validation
1. **Install on clean systems** (VMs recommended)
2. **Test all major features** (audit, apply dry-run, rollback list)
3. **Verify bundled resources** (rules, scripts, templates accessible)
4. **Check performance** (startup time, memory usage)
5. **Validate security** (no unnecessary network calls, proper permissions)

### Build Optimization

#### Size Reduction
```bash
# Exclude unnecessary modules in spec file
excludes = [
    'tkinter', 'matplotlib', 'numpy', 'pandas', 'scipy',
    'PIL', 'cv2', 'torch', 'tensorflow'
]

# Strip debug symbols (Linux)
strip hardening-tool

# Use --optimize flag
python -O -m PyInstaller spec_file.spec
```

#### Performance Optimization
- **Lazy imports**: Import heavy modules only when needed
- **Startup optimization**: Cache frequently used data
- **Resource compression**: Compress bundled YAML/templates
- **Memory management**: Explicit cleanup of large objects

### Troubleshooting Build Issues

#### Common Problems
1. **Missing modules**: Add to `hiddenimports` in spec file
2. **Resource not found**: Check data file paths in spec
3. **Permission errors**: Verify script permissions and paths
4. **Size too large**: Review exclusions and optimize dependencies
5. **Cross-platform issues**: Test on actual target platforms

#### Debug Builds
```bash
# Enable debug output
python -m PyInstaller --debug=all spec_file.spec

# Test import resolution
python -c "
import PyInstaller.utils.hooks
print(PyInstaller.utils.hooks.collect_all('hardening_tool'))
"

# Verify bundled files
python -c "
import sys
if hasattr(sys, '_MEIPASS'):
    import os
    print('Bundled files:', os.listdir(sys._MEIPASS))
"
```

This comprehensive build system ensures reliable, secure, and distributable executables across all supported platforms while maintaining the tool's security-focused architecture.