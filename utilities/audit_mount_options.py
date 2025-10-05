#!/usr/bin/env python3
"""
Mount Options Audit Module
Checks filesystem mount options for security compliance
"""

import json
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


def run_command(command: List[str]) -> Tuple[int, str, str]:
    """Execute command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def get_mount_info() -> Dict[str, Dict]:
    """Get current mount information from /proc/mounts and findmnt."""
    mount_info = {}
    
    # Parse /proc/mounts
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]
                    mount_info[mountpoint] = {
                        'device': device,
                        'fstype': fstype,
                        'options': set(options.split(',')),
                        'is_separate_partition': True
                    }
    except Exception as e:
        print(f"Error reading /proc/mounts: {e}")
    
    # Get additional info from findmnt for better device detection
    exit_code, stdout, stderr = run_command(['findmnt', '--raw', '--noheadings', '--output', 'SOURCE,TARGET,OPTIONS'])
    if exit_code == 0:
        for line in stdout.split('\n'):
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 3:
                    source, target = parts[0], parts[1]
                    options = ' '.join(parts[2:]) if len(parts) > 2 else ''
                    
                    if target in mount_info:
                        mount_info[target]['findmnt_source'] = source
                        if options:
                            mount_info[target]['findmnt_options'] = set(options.split(','))
    
    return mount_info


def is_separate_partition(path: str, mount_info: Dict[str, Dict]) -> Tuple[bool, str]:
    """Check if path is on a separate partition."""
    path = Path(path).resolve()
    
    # Check if exact mount exists
    if str(path) in mount_info:
        device = mount_info[str(path)].get('device', 'unknown')
        return True, device
    
    # Find the closest parent mountpoint
    current = path
    while current != current.parent:
        if str(current) in mount_info:
            device = mount_info[str(current)].get('device', 'unknown')
            # If it's the root filesystem, it's not a separate partition for this path
            if str(current) == '/':
                return False, device
            return True, device
        current = current.parent
    
    # Default to root filesystem
    root_device = mount_info.get('/', {}).get('device', 'unknown')
    return False, root_device


def get_current_mount_options(path: str, mount_info: Dict[str, Dict]) -> Set[str]:
    """Get current mount options for a path."""
    path = Path(path).resolve()
    
    # Check if exact mount exists
    if str(path) in mount_info:
        return mount_info[str(path)].get('options', set())
    
    # Find the closest parent mountpoint
    current = path
    while current != current.parent:
        if str(current) in mount_info:
            return mount_info[str(current)].get('options', set())
        current = current.parent
    
    # Default to root filesystem options
    return mount_info.get('/', {}).get('options', set())


def get_desired_mount_options(path: str) -> Set[str]:
    """Get desired security mount options for a path."""
    path_lower = path.lower()
    
    # Base security options for most paths
    base_options = {'nodev', 'nosuid'}
    
    # Paths that should also have noexec
    noexec_paths = {'/tmp', '/dev/shm', '/var/tmp'}
    
    # Special cases
    if any(path_lower.startswith(noexec_path) for noexec_path in noexec_paths):
        return base_options | {'noexec'}
    elif '/home' in path_lower:
        return {'nodev'}  # Home typically needs exec for user programs
    elif '/var/log' in path_lower:
        return base_options | {'noexec'}
    elif path_lower == '/var':
        return {'nodev'}  # /var needs exec for many system programs
    else:
        return base_options


def audit_mount_options(paths: List[str]) -> Dict:
    """
    Audit mount options for specified paths.
    
    Args:
        paths: List of paths to audit (e.g., ['/tmp', '/dev/shm', '/home'])
    
    Returns:
        JSON structure with audit results
    """
    results = {
        'timestamp': datetime.now().isoformat(),
        'operation': 'audit_mount_options',
        'paths': []
    }
    
    # Get current mount information
    mount_info = get_mount_info()
    
    for path in paths:
        try:
            # Resolve path
            resolved_path = str(Path(path).resolve())
            
            # Check if path exists
            path_exists = Path(resolved_path).exists()
            
            # Check if it's a separate partition
            is_separate, device = is_separate_partition(resolved_path, mount_info)
            
            # Get current mount options
            current_options = get_current_mount_options(resolved_path, mount_info)
            
            # Get desired mount options
            desired_options = get_desired_mount_options(resolved_path)
            
            # Check compliance
            missing_options = desired_options - current_options
            compliant = len(missing_options) == 0
            
            # Determine action needed
            if not path_exists:
                action = "path does not exist"
            elif not is_separate:
                action = "not a separate partition - cannot enforce mount options"
            elif compliant:
                action = "compliant"
            else:
                action = f"add options: {', '.join(sorted(missing_options))}"
            
            path_result = {
                'path': resolved_path,
                'exists': path_exists,
                'is_separate_partition': is_separate,
                'device': device,
                'current_options': sorted(list(current_options)),
                'desired_options': sorted(list(desired_options)),
                'missing_options': sorted(list(missing_options)),
                'compliant': compliant,
                'action': action
            }
            
            results['paths'].append(path_result)
            
        except Exception as e:
            error_result = {
                'path': path,
                'error': str(e),
                'compliant': False,
                'action': 'error occurred during audit'
            }
            results['paths'].append(error_result)
    
    return results


def main():
    """Main function for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Audit mount options for security compliance')
    parser.add_argument('paths', nargs='*', 
                       default=['/tmp', '/dev/shm', '/home', '/var', '/var/tmp', '/var/log', '/var/log/audit'],
                       help='Paths to audit (default: common security-sensitive paths)')
    parser.add_argument('--json', action='store_true', help='Output only JSON')
    
    args = parser.parse_args()
    
    results = audit_mount_options(args.paths)
    
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"Mount Options Audit Report - {results['timestamp']}")
        print("=" * 60)
        
        for path_result in results['paths']:
            path = path_result['path']
            print(f"\nPath: {path}")
            
            if 'error' in path_result:
                print(f"  ERROR: {path_result['error']}")
                continue
                
            print(f"  Exists: {path_result['exists']}")
            print(f"  Separate Partition: {path_result['is_separate_partition']}")
            if path_result['is_separate_partition']:
                print(f"  Device: {path_result['device']}")
            print(f"  Current Options: {', '.join(path_result['current_options']) or 'none'}")
            print(f"  Desired Options: {', '.join(path_result['desired_options'])}")
            
            if path_result['compliant']:
                print("  Status: ✓ COMPLIANT")
            else:
                print(f"  Status: ✗ NON-COMPLIANT")
                print(f"  Action: {path_result['action']}")


if __name__ == '__main__':
    main()