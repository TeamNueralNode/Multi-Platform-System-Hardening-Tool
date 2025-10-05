#!/bin/bash
# build_release.sh - Multi-Platform System Hardening Tool Release Builder
# Packages the Python orchestrator into platform-specific executables using PyInstaller
# Supports Linux native builds and Windows cross-compilation with GitHub Actions

set -euo pipefail

# ============================================================================
# Configuration and Variables
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"
BUILD_DIR="${PROJECT_DIR}/build"
DIST_DIR="${PROJECT_DIR}/dist"
RELEASE_DIR="${PROJECT_DIR}/releases"

# Version detection
if [[ -f "${PROJECT_DIR}/pyproject.toml" ]]; then
    VERSION=$(grep -E '^version\s*=' "${PROJECT_DIR}/pyproject.toml" | cut -d'"' -f2 || echo "0.1.0")
else
    VERSION="0.1.0"
fi

# Build configuration
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1-2)
BUILD_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Platform detection
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    HOST_PLATFORM="linux"
    EXECUTABLE_EXT=""
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    HOST_PLATFORM="windows"
    EXECUTABLE_EXT=".exe"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    HOST_PLATFORM="macos"
    EXECUTABLE_EXT=""
else
    HOST_PLATFORM="unknown"
    EXECUTABLE_EXT=""
fi

echo "=== Multi-Platform System Hardening Tool - Release Builder ==="
echo "Version: ${VERSION}"
echo "Build Timestamp: ${BUILD_TIMESTAMP}"
echo "Commit: ${COMMIT_HASH}"
echo "Host Platform: ${HOST_PLATFORM}"
echo "Python Version: ${PYTHON_VERSION}"
echo ""

# ============================================================================
# Helper Functions
# ============================================================================

log() {
    echo "[$(date +'%H:%M:%S')] $*" >&2
}

error() {
    echo "[ERROR] $*" >&2
    exit 1
}

cleanup() {
    log "Cleaning up build directories..."
    rm -rf "${BUILD_DIR}" "${DIST_DIR}"
    mkdir -p "${BUILD_DIR}" "${DIST_DIR}" "${RELEASE_DIR}"
}

check_dependencies() {
    log "Checking build dependencies..."
    
    # Check Python and pip
    command -v python3 >/dev/null 2>&1 || error "python3 is required"
    command -v pip3 >/dev/null 2>&1 || error "pip3 is required"
    
    # Check git for version info
    command -v git >/dev/null 2>&1 || log "Warning: git not found, using default version info"
    
    # Install PyInstaller if not available
    if ! python3 -c "import PyInstaller" 2>/dev/null; then
        log "Installing PyInstaller..."
        pip3 install pyinstaller
    fi
    
    # Install project dependencies
    log "Installing project dependencies..."
    pip3 install -e ".[dev]" >/dev/null 2>&1 || error "Failed to install project dependencies"
    
    log "Dependencies check complete ✓"
}

create_spec_file() {
    local platform=$1
    local spec_file="${BUILD_DIR}/hardening-tool-${platform}.spec"
    
    log "Creating PyInstaller spec file for ${platform}: ${spec_file}" >&2
    
    cat > "${spec_file}" << EOF
# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for Multi-Platform System Hardening Tool - ${platform}
Generated on: ${BUILD_TIMESTAMP}
Version: ${VERSION}
"""

import os
import sys
from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT
from pathlib import Path

# Project paths
project_root = Path('${PROJECT_DIR}').resolve()
hardening_tool_path = project_root / 'hardening_tool'

# ============================================================================
# Data Files and Resources
# ============================================================================

# YAML rule definitions
rule_files = []
rules_dir = project_root / 'hardening_tool' / 'rules' / 'definitions'
if rules_dir.exists():
    for yaml_file in rules_dir.glob('*.yaml'):
        rule_files.append((str(yaml_file), 'rules/definitions'))

# Sample rules if definitions don't exist
if not rule_files:
    # Create sample rules directory structure in build
    sample_rules = [
        ('hardening_tool/rules/__init__.py', 'rules'),
        ('hardening_tool/rules/loader.py', 'rules'),
    ]
    rule_files.extend(sample_rules)

# Helper scripts
script_files = []

# PowerShell scripts (for all platforms - might be needed for Windows rules on Linux audit)
ps_scripts = list((project_root / 'scripts').glob('*.ps1')) if (project_root / 'scripts').exists() else []
for ps_script in ps_scripts:
    script_files.append((str(ps_script), 'scripts'))

# Bash scripts  
bash_scripts = list((project_root / 'scripts').glob('*.sh')) if (project_root / 'scripts').exists() else []
for bash_script in bash_scripts:
    script_files.append((str(bash_script), 'scripts'))

# Individual helper scripts in project root
helper_scripts = [
    'pam_pwquality_audit.py',
    'apply_pam_pwquality.sh', 
    'shadow_hardening.sh',
    'generate_rules.py',
    'pdf_report_generator.py'
]

for helper in helper_scripts:
    helper_path = project_root / helper
    if helper_path.exists():
        script_files.append((str(helper_path), '.'))

# Configuration and template files
config_files = []

# HTML report template
template_path = project_root / 'report_template.html'
if template_path.exists():
    config_files.append((str(template_path), '.'))

# README and documentation
doc_files = []
for doc in ['README.md', 'TESTING.md', 'LICENSE']:
    doc_path = project_root / doc
    if doc_path.exists():
        doc_files.append((str(doc_path), '.'))

# ============================================================================
# PyInstaller Analysis
# ============================================================================

# Hidden imports - add modules that PyInstaller might miss
hidden_imports = [
    'hardening_tool',
    'hardening_tool.cli',
    'hardening_tool.core',
    'hardening_tool.core.orchestrator', 
    'hardening_tool.core.models',
    'hardening_tool.platforms',
    'hardening_tool.platforms.factory',
    'hardening_tool.platforms.linux',
    'hardening_tool.platforms.windows',
    'hardening_tool.platforms.base',
    'hardening_tool.rules',
    'hardening_tool.rules.loader',
    'hardening_tool.database',
    'hardening_tool.database.manager',
    'hardening_tool.utils',
    'hardening_tool.utils.os_detection',
    'hardening_tool.reporting',
    'hardening_tool.reporting.generator',
    'pydantic',
    'click',
    'rich',
    'yaml',
    'sqlite3',
    'cryptography',
    'jinja2',
]

# Platform-specific hidden imports
if '${platform}' == 'windows':
    hidden_imports.extend([
        'winreg',
        'wmi',
        'pywin32',
        'win32api',
        'win32con',
        'win32security',
    ])
elif '${platform}' == 'linux':
    hidden_imports.extend([
        'pwd',
        'grp',
        'spwd',
    ])

# Collect all data files
datas = rule_files + script_files + config_files + doc_files

a = Analysis(
    ['${PROJECT_DIR}/hardening_tool/cli.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy', 
        'pandas',
        'scipy',
        'PIL',
        'cv2',
        'torch',
        'tensorflow',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='hardening-tool${EXECUTABLE_EXT}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # Disable UPX compression to avoid antivirus false positives
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add icon file if available
    version_file=None,  # Add version file for Windows if needed
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='hardening-tool-${platform}',
)
EOF

    echo "${spec_file}"
}

create_version_info() {
    local platform=$1
    local version_file="${BUILD_DIR}/version_info.py"
    
    log "Creating version info file for ${platform}"
    
    cat > "${version_file}" << EOF
"""
Version information for Multi-Platform System Hardening Tool
Generated during build process
"""

__version__ = "${VERSION}"
__build_timestamp__ = "${BUILD_TIMESTAMP}"
__commit_hash__ = "${COMMIT_HASH}"
__platform__ = "${platform}"
__python_version__ = "${PYTHON_VERSION}"

BUILD_INFO = {
    'version': __version__,
    'build_timestamp': __build_timestamp__, 
    'commit_hash': __commit_hash__,
    'platform': __platform__,
    'python_version': __python_version__,
}
EOF
    
    # Copy to hardening_tool directory
    cp "${version_file}" "${PROJECT_DIR}/hardening_tool/"
}

build_linux() {
    log "Building Linux executable..."
    
    if [[ "${HOST_PLATFORM}" != "linux" ]]; then
        log "Warning: Cross-compiling Linux build on non-Linux platform may have limitations"
    fi
    
    create_version_info "linux"
    local spec_file=$(create_spec_file "linux")
    
    log "Running PyInstaller for Linux build..."
    python3 -m PyInstaller \
        --clean \
        --noconfirm \
        --workpath="${BUILD_DIR}/linux" \
        --distpath="${DIST_DIR}" \
        "${spec_file}"
    
    if [[ ! -f "${DIST_DIR}/hardening-tool-linux/hardening-tool" ]]; then
        error "Linux build failed - executable not found"
    fi
    
    log "Linux build completed ✓"
}

build_windows() {
    log "Building Windows executable..."
    
    if [[ "${HOST_PLATFORM}" == "linux" ]]; then
        log "Cross-compiling Windows build on Linux - checking wine setup..."
        
        # Check if wine is available for cross-compilation
        if command -v wine >/dev/null 2>&1; then
            log "Wine detected - attempting cross-compilation"
            build_windows_with_wine
        else
            log "Wine not available - skipping Windows build"
            log "Use GitHub Actions or Windows host for Windows builds"
            return 0
        fi
    else
        build_windows_native
    fi
}

build_windows_native() {
    log "Building Windows executable natively..."
    
    create_version_info "windows"
    local spec_file=$(create_spec_file "windows")
    
    # Create Windows-specific version file if on Windows
    if [[ "${HOST_PLATFORM}" == "windows" ]]; then
        create_windows_version_file
    fi
    
    log "Running PyInstaller for Windows build..."
    python3 -m PyInstaller \
        --clean \
        --noconfirm \
        --workpath="${BUILD_DIR}/windows" \
        --distpath="${DIST_DIR}" \
        "${spec_file}"
    
    if [[ ! -f "${DIST_DIR}/hardening-tool-windows/hardening-tool.exe" ]]; then
        error "Windows build failed - executable not found"
    fi
    
    log "Windows build completed ✓"
}

build_windows_with_wine() {
    log "Attempting Windows cross-compilation with Wine..."
    
    # Install Windows Python in wine if not present
    if ! wine python.exe --version >/dev/null 2>&1; then
        log "Installing Python in Wine environment..."
        # This is complex and often problematic - recommend GitHub Actions instead
        log "Wine Python setup required - recommend using GitHub Actions for Windows builds"
        return 0
    fi
    
    create_version_info "windows"
    local spec_file=$(create_spec_file "windows")
    
    log "Running PyInstaller through Wine..."
    wine python.exe -m PyInstaller \
        --clean \
        --noconfirm \
        --workpath="${BUILD_DIR}/windows" \
        --distpath="${DIST_DIR}" \
        "${spec_file}"
    
    log "Wine cross-compilation completed (experimental) ✓"
}

create_windows_version_file() {
    local version_file="${BUILD_DIR}/version.txt"
    
    cat > "${version_file}" << EOF
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=($(echo ${VERSION} | tr '.' ','),0),
    prodvers=($(echo ${VERSION} | tr '.' ','),0),
    mask=0x3f,
    flags=0x0,
    OS=0x4,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          '040904b0',
          [
            StringStruct('CompanyName', 'Multi-Platform Security Tools'),
            StringStruct('FileDescription', 'System Hardening Tool'),
            StringStruct('FileVersion', '${VERSION}'),
            StringStruct('InternalName', 'hardening-tool'),
            StringStruct('LegalCopyright', 'Open Source License'),
            StringStruct('OriginalFilename', 'hardening-tool.exe'),
            StringStruct('ProductName', 'Multi-Platform System Hardening Tool'),
            StringStruct('ProductVersion', '${VERSION}')
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
EOF
}

create_helper_scripts() {
    log "Creating bundled helper scripts..."
    
    # Ensure scripts directory exists in dist
    local linux_scripts="${DIST_DIR}/hardening-tool-linux/scripts"
    local windows_scripts="${DIST_DIR}/hardening-tool-windows/scripts"
    
    mkdir -p "${linux_scripts}" "${windows_scripts}" 2>/dev/null || true
    
    # Create wrapper scripts that locate bundled resources
    create_resource_finder_script
    
    log "Helper scripts bundled ✓"
}

create_resource_finder_script() {
    # Python script to find bundled resources at runtime
    local finder_script="${PROJECT_DIR}/hardening_tool/resource_finder.py"
    
    cat > "${finder_script}" << 'EOF'
"""
Resource finder for PyInstaller bundled applications.
Locates YAML rules, scripts, and other bundled resources at runtime.
"""

import os
import sys
from pathlib import Path
from typing import Optional, List


def get_bundle_dir() -> Path:
    """Get the directory containing bundled resources."""
    if hasattr(sys, '_MEIPASS'):
        # Running as PyInstaller bundle
        return Path(sys._MEIPASS)
    else:
        # Running as normal Python script
        return Path(__file__).parent.parent


def find_rules_directory() -> Optional[Path]:
    """Find the rules definitions directory."""
    bundle_dir = get_bundle_dir()
    
    # Try bundled rules first
    rules_dir = bundle_dir / 'rules' / 'definitions'
    if rules_dir.exists():
        return rules_dir
    
    # Try relative to script location
    script_dir = Path(__file__).parent.parent
    rules_dir = script_dir / 'hardening_tool' / 'rules' / 'definitions'
    if rules_dir.exists():
        return rules_dir
    
    # Try current working directory
    rules_dir = Path.cwd() / 'rules' / 'definitions'
    if rules_dir.exists():
        return rules_dir
    
    return None


def find_script_file(script_name: str) -> Optional[Path]:
    """Find a bundled script file."""
    bundle_dir = get_bundle_dir()
    
    # Try bundled scripts
    script_path = bundle_dir / 'scripts' / script_name
    if script_path.exists():
        return script_path
    
    # Try bundle root
    script_path = bundle_dir / script_name
    if script_path.exists():
        return script_path
    
    # Try relative to current location
    script_dir = Path(__file__).parent.parent
    script_path = script_dir / script_name
    if script_path.exists():
        return script_path
    
    return None


def find_template_file(template_name: str) -> Optional[Path]:
    """Find a bundled template file."""
    bundle_dir = get_bundle_dir()
    
    # Try bundle root
    template_path = bundle_dir / template_name
    if template_path.exists():
        return template_path
    
    # Try relative to script location
    script_dir = Path(__file__).parent.parent
    template_path = script_dir / template_name
    if template_path.exists():
        return template_path
    
    return None


def list_bundled_resources() -> dict:
    """List all bundled resources for debugging."""
    bundle_dir = get_bundle_dir()
    
    resources = {
        'bundle_dir': str(bundle_dir),
        'rules': [],
        'scripts': [],
        'templates': [],
        'docs': []
    }
    
    # Find rules
    rules_dir = find_rules_directory()
    if rules_dir:
        resources['rules'] = [str(f) for f in rules_dir.glob('*.yaml')]
    
    # Find scripts
    scripts_dir = bundle_dir / 'scripts'
    if scripts_dir.exists():
        resources['scripts'] = [str(f) for f in scripts_dir.iterdir() if f.is_file()]
    
    # Find templates
    for template in ['report_template.html']:
        template_path = find_template_file(template)
        if template_path:
            resources['templates'].append(str(template_path))
    
    # Find docs
    for doc in ['README.md', 'TESTING.md', 'LICENSE']:
        doc_path = bundle_dir / doc
        if doc_path.exists():
            resources['docs'].append(str(doc_path))
    
    return resources
EOF
    
    log "Resource finder script created ✓"
}

package_releases() {
    log "Packaging release artifacts..."
    
    local release_name="hardening-tool-v${VERSION}-${BUILD_TIMESTAMP}"
    
    # Package Linux build
    if [[ -d "${DIST_DIR}/hardening-tool-linux" ]]; then
        log "Packaging Linux release..."
        
        cd "${DIST_DIR}"
        tar -czf "${RELEASE_DIR}/${release_name}-linux-x64.tar.gz" \
            hardening-tool-linux/
        
        log "Linux package: ${RELEASE_DIR}/${release_name}-linux-x64.tar.gz ✓"
    fi
    
    # Package Windows build  
    if [[ -d "${DIST_DIR}/hardening-tool-windows" ]]; then
        log "Packaging Windows release..."
        
        cd "${DIST_DIR}"
        if command -v zip >/dev/null 2>&1; then
            zip -r "${RELEASE_DIR}/${release_name}-windows-x64.zip" \
                hardening-tool-windows/
        else
            tar -czf "${RELEASE_DIR}/${release_name}-windows-x64.tar.gz" \
                hardening-tool-windows/
        fi
        
        log "Windows package created ✓"
    fi
    
    cd "${PROJECT_DIR}"
}

create_checksums() {
    log "Creating checksums for release artifacts..."
    
    cd "${RELEASE_DIR}"
    
    # Create checksums file
    local checksums_file="checksums-v${VERSION}.txt"
    
    echo "# Multi-Platform System Hardening Tool v${VERSION}" > "${checksums_file}"
    echo "# Generated: ${BUILD_TIMESTAMP}" >> "${checksums_file}"
    echo "# Commit: ${COMMIT_HASH}" >> "${checksums_file}"
    echo "" >> "${checksums_file}"
    
    for file in *.tar.gz *.zip; do
        if [[ -f "$file" ]]; then
            if command -v sha256sum >/dev/null 2>&1; then
                sha256sum "$file" >> "${checksums_file}"
            elif command -v shasum >/dev/null 2>&1; then
                shasum -a 256 "$file" >> "${checksums_file}"
            fi
        fi
    done 2>/dev/null
    
    log "Checksums created: ${RELEASE_DIR}/${checksums_file} ✓"
    
    cd "${PROJECT_DIR}"
}

create_release_notes() {
    log "Creating release notes..."
    
    local release_notes="${RELEASE_DIR}/RELEASE_NOTES-v${VERSION}.md"
    
    cat > "${release_notes}" << EOF
# Multi-Platform System Hardening Tool v${VERSION}

**Release Date:** $(date +"%Y-%m-%d")  
**Build Timestamp:** ${BUILD_TIMESTAMP}  
**Commit Hash:** ${COMMIT_HASH}  

## 📦 Release Artifacts

EOF
    
    # List all release files
    cd "${RELEASE_DIR}"
    for file in *.tar.gz *.zip; do
        if [[ -f "$file" ]]; then
            local size=$(du -h "$file" | cut -f1)
            echo "- \`$file\` (${size})" >> "${release_notes}"
        fi
    done 2>/dev/null
    
    cat >> "${release_notes}" << EOF

## 🚀 Installation

### Linux
\`\`\`bash
# Download and extract
tar -xzf hardening-tool-v${VERSION}-*-linux-x64.tar.gz
cd hardening-tool-linux/

# Run (requires sudo for apply operations)
./hardening-tool audit --help
sudo ./hardening-tool apply --dry-run
\`\`\`

### Windows
\`\`\`powershell
# Extract ZIP file  
# Run as Administrator for apply operations
.\hardening-tool.exe audit --help
.\hardening-tool.exe apply --dry-run
\`\`\`

## 🛡️ Security Features

- **Multi-platform support**: Ubuntu 20.04+, CentOS 7+, Windows 10/11
- **CIS Benchmark compliance**: Automated security rule implementation
- **Safe operations**: Comprehensive dry-run and rollback capabilities
- **Audit trails**: SQLite database with encrypted rollback points
- **Comprehensive reporting**: JSON and PDF compliance reports

## 📋 System Requirements

- **Linux**: Any modern Linux distribution with systemd
- **Windows**: Windows 10/11 (Administrator privileges required for hardening)
- **Memory**: Minimum 512MB RAM
- **Disk**: 100MB+ free space for installation and logs
- **Network**: Internet access for updates (optional)

## 🔧 Usage Examples

\`\`\`bash
# System audit
./hardening-tool audit --format table

# Category-specific hardening
sudo ./hardening-tool apply --category ssh --interactive

# Specific rules
sudo ./hardening-tool apply --rules ssh_disable_root_login,pam_password_complexity

# Rollback operations  
sudo ./hardening-tool rollback --list-points
sudo ./hardening-tool rollback --run-id <run_id>

# Generate compliance report
./hardening-tool audit --output compliance_report.json
\`\`\`

## 📚 Documentation

- **Testing Guide**: See \`TESTING.md\` in release package
- **Rule Definitions**: YAML files in \`rules/definitions/\` directory
- **Helper Scripts**: Platform-specific scripts in \`scripts/\` directory

## ⚠️ Important Notes

1. **Always test in non-production environments first**
2. **Create system backups before applying hardening rules**
3. **Use \`--dry-run\` flag to preview changes without modification**
4. **Administrator/root privileges required for system modifications**
5. **Review rule definitions before applying to understand changes**

## 🐛 Issue Reporting

Report issues at: https://github.com/TeamNueralNode/Multi-Platform-System-Hardening-Tool/issues

Include:
- Operating system and version
- Full command executed
- Error messages and logs
- Steps to reproduce

---

Built with PyInstaller on $(uname -a 2>/dev/null || echo "Build system")
EOF
    
    log "Release notes created: ${RELEASE_DIR}/RELEASE_NOTES-v${VERSION}.md ✓"
    
    cd "${PROJECT_DIR}"
}

show_build_summary() {
    log "=== Build Summary ==="
    echo ""
    echo "Version: ${VERSION}"
    echo "Build Timestamp: ${BUILD_TIMESTAMP}" 
    echo "Commit Hash: ${COMMIT_HASH}"
    echo ""
    
    if [[ -d "${RELEASE_DIR}" ]]; then
        echo "Release artifacts:"
        ls -lh "${RELEASE_DIR}/"
        echo ""
        
        echo "Total release size:"
        du -sh "${RELEASE_DIR}"
    fi
    
    echo ""
    log "Build completed successfully! ✅"
    echo ""
    echo "Next steps:"
    echo "1. Test the executables in target environments"
    echo "2. Upload to GitHub Releases or distribution server" 
    echo "3. Update documentation with new version"
    echo "4. Announce release to users"
    echo ""
}

# ============================================================================
# Main Build Process  
# ============================================================================

main() {
    local build_target="${1:-all}"
    
    case "${build_target}" in
        "linux")
            log "Building Linux target only..."
            cleanup
            check_dependencies
            build_linux
            create_helper_scripts
            package_releases
            create_checksums
            create_release_notes
            show_build_summary
            ;;
        "windows")
            log "Building Windows target only..."
            cleanup
            check_dependencies 
            build_windows
            create_helper_scripts
            package_releases
            create_checksums
            create_release_notes
            show_build_summary
            ;;
        "all"|"")
            log "Building all targets..."
            cleanup
            check_dependencies
            
            # Build platforms
            build_linux
            build_windows
            
            create_helper_scripts
            package_releases
            create_checksums
            create_release_notes
            show_build_summary
            ;;
        "clean")
            log "Cleaning build directories..."
            rm -rf "${BUILD_DIR}" "${DIST_DIR}"
            log "Clean completed ✓"
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [target]"
            echo ""
            echo "Targets:"
            echo "  all      Build all platforms (default)"
            echo "  linux    Build Linux executable only"
            echo "  windows  Build Windows executable only"
            echo "  clean    Clean build directories"
            echo "  help     Show this help message"
            echo ""
            exit 0
            ;;
        *)
            error "Unknown build target: ${build_target}. Use 'help' for usage."
            ;;
    esac
}

# Trap cleanup on script exit
trap cleanup EXIT

# Run main function with all arguments
main "$@"