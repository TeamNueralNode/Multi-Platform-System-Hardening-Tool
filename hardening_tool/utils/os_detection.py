"""
Operating System detection utilities.

Provides robust OS detection for Windows, Ubuntu, and CentOS systems
with version information and architecture details.
"""

import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

from ..core.models import OSType, SystemInfo


def detect_os() -> SystemInfo:
    """
    Detect the current operating system and gather system information.
    
    Returns:
        SystemInfo: Comprehensive system information including OS type, version, etc.
    
    Raises:
        RuntimeError: If OS detection fails or OS is not supported.
    """
    system = platform.system().lower()
    hostname = platform.node()
    architecture = platform.machine()
    
    if system == "windows":
        return _detect_windows(hostname, architecture)
    elif system == "linux":
        return _detect_linux(hostname, architecture)
    else:
        # Fallback for unsupported systems
        return SystemInfo(
            os_type=OSType.UNKNOWN,
            os_version=platform.release(),
            architecture=architecture,
            hostname=hostname,
            kernel_version=platform.release()
        )


def _detect_windows(hostname: str, architecture: str) -> SystemInfo:
    """Detect Windows version and build information."""
    try:
        # Get Windows version using platform module
        version_info = platform.win32_ver()
        os_version = f"{version_info[0]} {version_info[1]}"
        
        # Try to get more detailed version info via PowerShell
        try:
            result = subprocess.run([
                "powershell", "-Command",
                "(Get-WmiObject -Class Win32_OperatingSystem).Caption"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout.strip():
                os_version = result.stdout.strip()
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass  # Fall back to platform.win32_ver()
        
        return SystemInfo(
            os_type=OSType.WINDOWS,
            os_version=os_version,
            architecture=architecture,
            hostname=hostname,
            kernel_version=platform.release()
        )
        
    except Exception as e:
        raise RuntimeError(f"Failed to detect Windows system info: {e}")


def _detect_linux(hostname: str, architecture: str) -> SystemInfo:
    """Detect Linux distribution (Ubuntu or CentOS) and version."""
    try:
        # Check for os-release file (modern distributions)
        os_release_path = Path("/etc/os-release")
        if os_release_path.exists():
            os_info = _parse_os_release(os_release_path)
            os_type = _determine_linux_type(os_info)
            os_version = os_info.get("VERSION", os_info.get("VERSION_ID", "Unknown"))
        else:
            # Fallback methods for older systems
            os_type, os_version = _detect_linux_fallback()
        
        # Get kernel version
        kernel_version = platform.release()
        
        return SystemInfo(
            os_type=os_type,
            os_version=os_version,
            architecture=architecture,
            hostname=hostname,
            kernel_version=kernel_version
        )
        
    except Exception as e:
        raise RuntimeError(f"Failed to detect Linux system info: {e}")


def _parse_os_release(os_release_path: Path) -> dict:
    """Parse /etc/os-release file into a dictionary."""
    os_info = {}
    
    try:
        with open(os_release_path, 'r') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    # Remove quotes from value
                    value = value.strip('"\'')
                    os_info[key] = value
    except IOError as e:
        raise RuntimeError(f"Cannot read {os_release_path}: {e}")
    
    return os_info


def _determine_linux_type(os_info: dict) -> OSType:
    """Determine Linux distribution type from os-release information."""
    id_field = os_info.get("ID", "").lower()
    id_like = os_info.get("ID_LIKE", "").lower()
    name = os_info.get("NAME", "").lower()
    
    # Check for Ubuntu
    if "ubuntu" in id_field or "ubuntu" in name:
        return OSType.UBUNTU
    
    # Check for CentOS/RHEL
    if any(distro in id_field for distro in ["centos", "rhel", "redhat"]):
        return OSType.CENTOS
    
    # Check ID_LIKE for compatibility
    if "ubuntu" in id_like or "debian" in id_like:
        return OSType.UBUNTU
    elif any(distro in id_like for distro in ["rhel", "fedora", "centos"]):
        return OSType.CENTOS
    
    # If we can't determine, return UNKNOWN
    return OSType.UNKNOWN


def _detect_linux_fallback() -> Tuple[OSType, str]:
    """Fallback Linux detection for older systems without os-release."""
    
    # Check for CentOS/RHEL release files
    centos_files = ["/etc/centos-release", "/etc/redhat-release"]
    for release_file in centos_files:
        if Path(release_file).exists():
            try:
                with open(release_file, 'r') as f:
                    content = f.read().strip()
                    return OSType.CENTOS, content
            except IOError:
                continue
    
    # Check for Ubuntu via lsb_release
    try:
        result = subprocess.run(
            ["lsb_release", "-d"], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        if result.returncode == 0:
            description = result.stdout.strip()
            if "ubuntu" in description.lower():
                return OSType.UBUNTU, description.split(":", 1)[1].strip()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        pass
    
    # Final fallback
    return OSType.UNKNOWN, "Unknown Linux Distribution"


def is_admin() -> bool:
    """
    Check if the current process has administrative privileges.
    
    Returns:
        bool: True if running with admin/root privileges, False otherwise.
    """
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        # Unix-like systems
        import os
        return os.geteuid() == 0


def get_package_manager() -> Optional[str]:
    """
    Detect the system package manager.
    
    Returns:
        Optional[str]: Package manager command (apt, yum, dnf, etc.) or None if not found.
    """
    package_managers = [
        "apt",      # Ubuntu/Debian
        "yum",      # CentOS 7/RHEL 7
        "dnf",      # CentOS 8+/Fedora
        "zypper",   # openSUSE
        "pacman",   # Arch Linux
    ]
    
    for pm in package_managers:
        try:
            result = subprocess.run(
                ["which", pm], 
                capture_output=True, 
                timeout=5
            )
            if result.returncode == 0:
                return pm
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            continue
    
    return None


def get_service_manager() -> Optional[str]:
    """
    Detect the system service manager.
    
    Returns:
        Optional[str]: Service manager (systemctl, service, etc.) or None if not found.
    """
    # Check for systemd first (most modern systems)
    if Path("/bin/systemctl").exists() or Path("/usr/bin/systemctl").exists():
        return "systemctl"
    
    # Fallback to SysV init
    if Path("/sbin/service").exists() or Path("/usr/sbin/service").exists():
        return "service"
    
    return None


def validate_supported_os(system_info: SystemInfo) -> bool:
    """
    Validate that the detected OS is supported by the hardening tool.
    
    Args:
        system_info: SystemInfo object from detect_os()
    
    Returns:
        bool: True if OS is supported, False otherwise.
    """
    supported_os = {OSType.WINDOWS, OSType.UBUNTU, OSType.CENTOS}
    return system_info.os_type in supported_os