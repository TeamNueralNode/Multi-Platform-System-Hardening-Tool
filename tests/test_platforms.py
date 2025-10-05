"""
Unit tests for platform implementations.

Tests platform-specific functionality including OS detection,
rule auditing, and system modifications.
"""

import pytest
from unittest.mock import Mock, patch, mock_open
import subprocess

from hardening_tool.platforms.factory import PlatformFactory
from hardening_tool.platforms.linux import LinuxPlatform
from hardening_tool.platforms.windows import WindowsPlatform
from hardening_tool.core.models import HardeningRule, RuleStatus, SystemInfo


class TestPlatformFactory:
    """Test platform factory functionality."""
    
    def test_get_platform_ubuntu(self):
        """Test getting Ubuntu platform."""
        platform = PlatformFactory.get_platform("ubuntu")
        assert isinstance(platform, LinuxPlatform)
    
    def test_get_platform_centos(self):
        """Test getting CentOS platform.""" 
        platform = PlatformFactory.get_platform("centos")
        assert isinstance(platform, LinuxPlatform)
    
    def test_get_platform_windows(self):
        """Test getting Windows platform."""
        platform = PlatformFactory.get_platform("windows")
        assert isinstance(platform, WindowsPlatform)
    
    def test_unsupported_platform(self):
        """Test unsupported platform raises error."""
        with pytest.raises(ValueError, match="Unsupported platform"):
            PlatformFactory.get_platform("macos")
    
    def test_supported_platforms_list(self):
        """Test getting list of supported platforms."""
        platforms = PlatformFactory.get_supported_platforms()
        assert "ubuntu" in platforms
        assert "centos" in platforms 
        assert "windows" in platforms
        assert len(platforms) >= 3


class TestLinuxPlatform:
    """Test Linux platform implementation."""
    
    @pytest.fixture
    def linux_platform(self):
        """Create Linux platform instance."""
        return LinuxPlatform("ubuntu")
    
    @patch('subprocess.run')
    def test_execute_command_success(self, mock_run, linux_platform):
        """Test successful command execution."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="command output",
            stderr=""
        )
        
        result = linux_platform.execute_command("test command")
        
        assert result.returncode == 0
        assert result.stdout == "command output"
        mock_run.assert_called_once()
    
    @patch('subprocess.run')  
    def test_execute_command_failure(self, mock_run, linux_platform):
        """Test failed command execution."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "test", "error output")
        
        result = linux_platform.execute_command("failing command")
        
        assert result.returncode == 1
        assert "error output" in result.stderr
    
    @patch('builtins.open', new_callable=mock_open, read_data="Port 22\nPermitRootLogin yes\n")
    def test_audit_ssh_root_login_fail(self, mock_file, linux_platform):
        """Test SSH root login audit - should fail."""
        rule = HardeningRule(
            id="ssh_disable_root_login",
            title="Disable SSH Root Login",
            description="Test rule",
            platforms=["ubuntu"],
            categories=["ssh"],
            severity="high"
        )
        
        result = linux_platform.audit_rule(rule)
        
        assert result.status == RuleStatus.FAIL
        assert "PermitRootLogin" in result.message
        assert result.rule_id == "ssh_disable_root_login"
    
    @patch('builtins.open', new_callable=mock_open, read_data="Port 22\nPermitRootLogin no\n")
    def test_audit_ssh_root_login_pass(self, mock_file, linux_platform):
        """Test SSH root login audit - should pass."""
        rule = HardeningRule(
            id="ssh_disable_root_login", 
            title="Disable SSH Root Login",
            description="Test rule",
            platforms=["ubuntu"],
            categories=["ssh"],
            severity="high"
        )
        
        result = linux_platform.audit_rule(rule)
        
        assert result.status == RuleStatus.PASS
        assert "disabled" in result.message.lower()
    
    @patch('builtins.open', new_callable=mock_open, read_data="Port 22\nPasswordAuthentication no\n")
    def test_audit_ssh_password_auth_pass(self, mock_file, linux_platform):
        """Test SSH password authentication audit - should pass."""
        rule = HardeningRule(
            id="ssh_disable_password_auth",
            title="Disable SSH Password Authentication", 
            description="Test rule",
            platforms=["ubuntu"],
            categories=["ssh"],
            severity="medium"
        )
        
        result = linux_platform.audit_rule(rule)
        
        assert result.status == RuleStatus.PASS
        assert "disabled" in result.message.lower()
    
    @patch('builtins.open', side_effect=FileNotFoundError)
    def test_audit_ssh_config_missing(self, mock_file, linux_platform):
        """Test SSH audit when config file is missing."""
        rule = HardeningRule(
            id="ssh_disable_root_login",
            title="Disable SSH Root Login",
            description="Test rule", 
            platforms=["ubuntu"],
            categories=["ssh"],
            severity="high"
        )
        
        result = linux_platform.audit_rule(rule)
        
        assert result.status == RuleStatus.ERROR
        assert "not found" in result.message.lower()
    
    def test_unsupported_rule_category(self, linux_platform):
        """Test audit of unsupported rule category."""
        rule = HardeningRule(
            id="unsupported_rule",
            title="Unsupported Rule", 
            description="Test rule",
            platforms=["ubuntu"],
            categories=["unsupported"],
            severity="low"
        )
        
        result = linux_platform.audit_rule(rule)
        
        assert result.status == RuleStatus.ERROR
        assert "not supported" in result.message.lower()
    
    @patch('platform.system', return_value='Linux')
    @patch('platform.release', return_value='6.8.0-40-generic')
    @patch('platform.machine', return_value='x86_64')
    @patch('platform.node', return_value='test-host')
    @patch('psutil.virtual_memory')
    @patch('psutil.cpu_count')
    @patch('subprocess.run')
    def test_get_system_info(self, mock_run, mock_cpu, mock_memory, 
                           mock_node, mock_machine, mock_release, mock_system, 
                           linux_platform):
        """Test getting system information."""
        # Mock system info
        mock_memory.return_value = Mock(total=8589934592)
        mock_cpu.return_value = 4
        mock_run.return_value = Mock(
            stdout="Ubuntu 24.04.3 LTS",
            returncode=0
        )
        
        system_info = linux_platform.get_system_info()
        
        assert isinstance(system_info, SystemInfo)
        assert system_info.architecture == "x86_64"
        assert system_info.hostname == "test-host"
        assert system_info.total_memory == 8589934592
        assert system_info.cpu_count == 4
    
    @patch('builtins.open', new_callable=mock_open, read_data="PermitRootLogin yes\n")
    @patch('shutil.copy2')
    @patch('subprocess.run')
    def test_apply_ssh_rule_success(self, mock_run, mock_copy, mock_file, linux_platform):
        """Test successful SSH rule application."""
        rule = HardeningRule(
            id="ssh_disable_root_login",
            title="Disable SSH Root Login",
            description="Test rule",
            platforms=["ubuntu"],
            categories=["ssh"], 
            severity="high"
        )
        
        # Mock successful command execution
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        
        result = linux_platform.apply_rule(rule, dry_run=False)
        
        assert result.status == RuleStatus.PASS
        assert "applied" in result.message.lower()
        
        # Verify file operations were called
        mock_copy.assert_called()  # Backup created
        mock_file.assert_called()  # File was opened for writing
    
    def test_create_rollback_point(self, linux_platform):
        """Test rollback point creation."""
        rollback = linux_platform.create_rollback_point("test-run-001")
        
        assert rollback is not None
        assert rollback.run_id == "test-run-001"
        assert rollback.rollback_id.startswith("rollback-")
        assert isinstance(rollback.config_backups, dict)
        assert isinstance(rollback.service_states, dict)


class TestWindowsPlatform:
    """Test Windows platform implementation."""
    
    @pytest.fixture
    def windows_platform(self):
        """Create Windows platform instance."""
        return WindowsPlatform("windows")
    
    @patch('subprocess.run')
    def test_execute_command_powershell(self, mock_run, windows_platform):
        """Test PowerShell command execution."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="PowerShell output",
            stderr=""
        )
        
        result = windows_platform.execute_command("Get-Service")
        
        assert result.returncode == 0
        assert result.stdout == "PowerShell output"
        # Verify PowerShell was used
        args = mock_run.call_args[0][0]
        assert "powershell" in args[0].lower() or "pwsh" in args[0].lower()
    
    def test_get_system_info_windows(self, windows_platform):
        """Test Windows system info detection."""
        with patch('platform.system', return_value='Windows'), \
             patch('platform.release', return_value='10'), \
             patch('platform.machine', return_value='AMD64'), \
             patch('platform.node', return_value='WIN-HOST'), \
             patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.cpu_count', return_value=8):
            
            mock_memory.return_value = Mock(total=17179869184)  # 16GB
            
            system_info = windows_platform.get_system_info()
            
            assert system_info.os_type == "windows"
            assert system_info.architecture == "AMD64"
            assert system_info.hostname == "WIN-HOST"
            assert system_info.total_memory == 17179869184
            assert system_info.cpu_count == 8
    
    def test_windows_rule_not_implemented(self, windows_platform):
        """Test Windows rule implementation placeholder."""
        rule = HardeningRule(
            id="windows_test_rule",
            title="Windows Test Rule",
            description="Test rule",
            platforms=["windows"],
            categories=["system"],
            severity="medium"
        )
        
        # Most Windows rules should return "not implemented" for now
        result = windows_platform.audit_rule(rule)
        
        # This will depend on actual implementation
        # For now, expecting not implemented
        assert result.status in [RuleStatus.ERROR, RuleStatus.SKIP]


class TestPlatformIntegration:
    """Integration tests for platform functionality."""
    
    def test_platform_rule_compatibility(self):
        """Test platform and rule compatibility checking."""
        # Ubuntu should support SSH rules
        ubuntu_platform = PlatformFactory.get_platform("ubuntu")
        ssh_rule = HardeningRule(
            id="ssh_test",
            title="SSH Test",
            description="Test SSH rule",
            platforms=["ubuntu", "centos"],
            categories=["ssh"],
            severity="high"
        )
        
        # This should not raise an error
        result = ubuntu_platform.audit_rule(ssh_rule)
        assert result is not None
        assert result.rule_id == "ssh_test"
    
    def test_cross_platform_rule_filtering(self):
        """Test that rules are properly filtered by platform."""
        # Create rules for different platforms
        linux_rule = HardeningRule(
            id="linux_only",
            title="Linux Only Rule",
            description="Linux specific rule",
            platforms=["ubuntu", "centos"],
            categories=["system"],
            severity="medium"
        )
        
        windows_rule = HardeningRule(
            id="windows_only", 
            title="Windows Only Rule",
            description="Windows specific rule",
            platforms=["windows"],
            categories=["system"], 
            severity="medium"
        )
        
        # Linux platform should handle Linux rule
        linux_platform = PlatformFactory.get_platform("ubuntu")
        result = linux_platform.audit_rule(linux_rule)
        assert result.rule_id == "linux_only"
        
        # Windows platform should handle Windows rule
        windows_platform = PlatformFactory.get_platform("windows")
        result = windows_platform.audit_rule(windows_rule)
        assert result.rule_id == "windows_only"