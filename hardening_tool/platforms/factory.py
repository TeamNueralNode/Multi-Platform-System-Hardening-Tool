"""
Platform factory for creating OS-specific hardening handlers.

Provides a unified interface for accessing platform-specific
hardening implementations for Windows, Ubuntu, and CentOS.
"""

from typing import Dict, Type

from ..core.models import OSType
from .base import BasePlatform
from .linux import LinuxPlatform
from .windows import WindowsPlatform


class PlatformFactory:
    """
    Factory class for creating platform-specific hardening handlers.
    
    Provides a centralized way to get the appropriate platform handler
    based on the detected operating system.
    """
    
    _platforms: Dict[OSType, Type[BasePlatform]] = {
        OSType.UBUNTU: LinuxPlatform,
        OSType.CENTOS: LinuxPlatform,
        OSType.WINDOWS: WindowsPlatform,
    }
    
    @classmethod
    def get_platform(cls, os_type: OSType) -> BasePlatform:
        """
        Get platform handler for the specified OS type.
        
        Args:
            os_type: Operating system type
            
        Returns:
            BasePlatform: Platform-specific handler instance
            
        Raises:
            ValueError: If OS type is not supported
        """
        if os_type not in cls._platforms:
            raise ValueError(f"Unsupported platform: {os_type}")
        
        platform_class = cls._platforms[os_type]
        return platform_class(os_type)
    
    @classmethod
    def get_supported_platforms(cls) -> list[OSType]:
        """
        Get list of supported platform types.
        
        Returns:
            list[OSType]: List of supported operating systems
        """
        return list(cls._platforms.keys())
    
    @classmethod
    def register_platform(cls, os_type: OSType, platform_class: Type[BasePlatform]) -> None:
        """
        Register a new platform handler.
        
        Args:
            os_type: Operating system type to register for
            platform_class: Platform handler class
        """
        cls._platforms[os_type] = platform_class