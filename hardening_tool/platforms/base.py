"""
Base platform interface for hardening operations.

Defines the common interface that all platform-specific
hardening modules must implement.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from ..core.models import HardeningRule, OSType, RollbackPoint, RuleResult


class BasePlatform(ABC):
    """
    Abstract base class for platform-specific hardening operations.
    
    All platform implementations (Windows, Linux variants) must inherit
    from this class and implement the required methods.
    """
    
    def __init__(self, os_type: OSType):
        """
        Initialize platform handler.
        
        Args:
            os_type: Operating system type this handler supports
        """
        self.os_type = os_type
    
    @abstractmethod
    def audit_rule(self, rule: HardeningRule) -> RuleResult:
        """
        Audit a hardening rule without making changes.
        
        Args:
            rule: Hardening rule to audit
            
        Returns:
            RuleResult: Result of the audit operation
        """
        pass
    
    @abstractmethod
    def apply_rule(self, rule: HardeningRule) -> RuleResult:
        """
        Apply a hardening rule to the system.
        
        Args:
            rule: Hardening rule to apply
            
        Returns:
            RuleResult: Result of the application operation
        """
        pass
    
    @abstractmethod
    def create_rollback_point(self, rollback_point: RollbackPoint) -> RollbackPoint:
        """
        Create backup data for rollback purposes.
        
        Args:
            rollback_point: Rollback point to populate with backup data
            
        Returns:
            RollbackPoint: Updated rollback point with backup data
        """
        pass
    
    @abstractmethod
    def perform_rollback(self, rollback_point: RollbackPoint) -> None:
        """
        Restore system state from a rollback point.
        
        Args:
            rollback_point: Rollback point containing backup data
            
        Raises:
            RuntimeError: If rollback operation fails
        """
        pass
    
    @abstractmethod
    def get_service_status(self, service_name: str) -> Dict[str, Any]:
        """
        Get the status of a system service.
        
        Args:
            service_name: Name of the service to check
            
        Returns:
            Dict[str, Any]: Service status information
        """
        pass
    
    @abstractmethod
    def start_service(self, service_name: str) -> bool:
        """
        Start a system service.
        
        Args:
            service_name: Name of the service to start
            
        Returns:
            bool: True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def stop_service(self, service_name: str) -> bool:
        """
        Stop a system service.
        
        Args:
            service_name: Name of the service to stop
            
        Returns:
            bool: True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def enable_service(self, service_name: str) -> bool:
        """
        Enable a system service to start at boot.
        
        Args:
            service_name: Name of the service to enable
            
        Returns:
            bool: True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def disable_service(self, service_name: str) -> bool:
        """
        Disable a system service from starting at boot.
        
        Args:
            service_name: Name of the service to disable
            
        Returns:
            bool: True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def read_config_file(self, file_path: str) -> str:
        """
        Read contents of a configuration file.
        
        Args:
            file_path: Path to the configuration file
            
        Returns:
            str: File contents
            
        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If access is denied
        """
        pass
    
    @abstractmethod
    def write_config_file(self, file_path: str, content: str, backup: bool = True) -> bool:
        """
        Write contents to a configuration file.
        
        Args:
            file_path: Path to the configuration file
            content: New file contents
            backup: Whether to create a backup before writing
            
        Returns:
            bool: True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def backup_file(self, file_path: str) -> str:
        """
        Create a backup of a file.
        
        Args:
            file_path: Path to the file to backup
            
        Returns:
            str: Path to the backup file
            
        Raises:
            IOError: If backup operation fails
        """
        pass
    
    @abstractmethod
    def restore_file(self, file_path: str, backup_path: str) -> bool:
        """
        Restore a file from backup.
        
        Args:
            file_path: Path to restore the file to
            backup_path: Path to the backup file
            
        Returns:
            bool: True if successful, False otherwise
        """
        pass
    
    def execute_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute a system command with timeout.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            Dict[str, Any]: Execution result with stdout, stderr, and exit code
        """
        import subprocess
        import shlex
        from datetime import datetime
        
        start_time = datetime.utcnow()
        
        try:
            # Split command safely
            if isinstance(command, str):
                cmd_args = shlex.split(command)
            else:
                cmd_args = command
            
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            end_time = datetime.utcnow()
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode,
                'execution_time_ms': execution_time_ms,
                'success': result.returncode == 0
            }
            
        except subprocess.TimeoutExpired as e:
            return {
                'stdout': '',
                'stderr': f'Command timed out after {timeout} seconds',
                'exit_code': -1,
                'execution_time_ms': timeout * 1000,
                'success': False
            }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1,
                'execution_time_ms': 0,
                'success': False
            }
    
    def check_file_exists(self, file_path: str) -> bool:
        """
        Check if a file exists.
        
        Args:
            file_path: Path to check
            
        Returns:
            bool: True if file exists, False otherwise
        """
        from pathlib import Path
        return Path(file_path).exists()
    
    def get_file_checksum(self, file_path: str) -> str:
        """
        Calculate SHA256 checksum of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: SHA256 checksum as hex string
            
        Raises:
            FileNotFoundError: If file doesn't exist
        """
        import hashlib
        from pathlib import Path
        
        if not Path(file_path).exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()