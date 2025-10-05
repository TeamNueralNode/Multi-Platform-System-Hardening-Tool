"""
Unit tests for core data models.

Tests the Pydantic models that define the data structures
used throughout the hardening tool.
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from hardening_tool.core.models import (
    SystemInfo, HardeningRule, RuleResult, HardeningRun, 
    RollbackPoint, RuleStatus, RuleSeverity
)


class TestSystemInfo:
    """Test SystemInfo model."""
    
    def test_valid_system_info_creation(self):
        """Test creating valid SystemInfo instance."""
        system_info = SystemInfo(
            os_type="ubuntu",
            os_version="24.04.3 LTS",
            architecture="x86_64",
            hostname="test-host",
            kernel_version="6.8.0-40-generic"
        )
        
        assert system_info.os_type == "ubuntu"
        assert system_info.os_version == "24.04.3 LTS"
        assert system_info.architecture == "x86_64"
        assert system_info.hostname == "test-host"
        assert system_info.kernel_version == "6.8.0-40-generic"
    
    def test_system_info_model_dump(self):
        """Test SystemInfo serialization."""
        system_info = SystemInfo(
            os_type="ubuntu",
            os_version="24.04.3 LTS", 
            architecture="x86_64",
            hostname="test-host",
            kernel_version="6.8.0-40-generic"
        )
        
        data = system_info.model_dump()
        assert isinstance(data, dict)
        assert data["os_type"] == "ubuntu"
        assert data["hostname"] == "test-host"
    
    def test_invalid_system_info(self):
        """Test SystemInfo validation."""
        with pytest.raises(ValidationError):
            SystemInfo(
                os_type="",  # Empty string should fail
                os_version="24.04.3 LTS",
                architecture="x86_64",
                hostname="test-host",
                kernel_version="6.8.0-40-generic",
                total_memory=8589934592,
                cpu_count=4
            )


class TestHardeningRule:
    """Test HardeningRule model."""
    
    def test_valid_rule_creation(self):
        """Test creating valid HardeningRule instance."""
        rule = HardeningRule(
            id="ssh_disable_root_login",
            title="Disable SSH Root Login",
            description="Prevents direct root login via SSH",
            platforms=["ubuntu", "centos"],
            categories=["ssh"],
            severity="high",
            cis_benchmark="5.2.8",
            remediation="Set PermitRootLogin no in /etc/ssh/sshd_config"
        )
        
        assert rule.id == "ssh_disable_root_login"
        assert rule.title == "Disable SSH Root Login"
        assert "ubuntu" in rule.platforms
        assert "ssh" in rule.categories
        assert rule.severity == "high"
    
    def test_rule_serialization(self):
        """Test HardeningRule serialization."""
        rule = HardeningRule(
            id="test_rule",
            title="Test Rule",
            description="Test description",
            platforms=["ubuntu"],
            categories=["test"],
            severity="medium"
        )
        
        data = rule.model_dump()
        assert isinstance(data, dict)
        assert data["id"] == "test_rule"
        assert data["platforms"] == ["ubuntu"]
    
    def test_invalid_severity(self):
        """Test invalid severity validation."""
        with pytest.raises(ValidationError):
            HardeningRule(
                id="test_rule",
                title="Test Rule",
                description="Test description",
                platforms=["ubuntu"],
                categories=["test"],
                severity="invalid_severity"  # Should fail validation
            )


class TestRuleResult:
    """Test RuleResult model."""
    
    def test_valid_rule_result(self):
        """Test creating valid RuleResult."""
        result = RuleResult(
            rule_id="ssh_disable_root_login",
            rule_title="Disable SSH Root Login",
            status=RuleStatus.PASS,
            severity=RuleSeverity.HIGH,
            message="SSH root login is disabled",
            before_state={"PermitRootLogin": "yes"},
            after_state={"PermitRootLogin": "no"},
            execution_time_ms=123
        )
        
        assert result.rule_id == "ssh_disable_root_login"
        assert result.status == RuleStatus.PASS
        assert result.execution_time_ms == 123
        assert result.before_state["PermitRootLogin"] == "yes"
    
    def test_rule_result_without_states(self):
        """Test RuleResult without before/after states."""
        result = RuleResult(
            rule_id="test_rule",
            rule_title="Test Rule",
            status=RuleStatus.FAIL,
            severity=RuleSeverity.MEDIUM,
            message="Rule failed",
            execution_time_ms=50
        )
        
        assert result.rule_id == "test_rule"
        assert result.status == RuleStatus.FAIL
        assert result.before_state is None
        assert result.after_state is None
    
    def test_rule_status_enum(self):
        """Test RuleStatus enum values."""
        assert RuleStatus.PASS.value == "pass"
        assert RuleStatus.FAIL.value == "fail"
        assert RuleStatus.ERROR.value == "error"
        assert RuleStatus.SKIPPED.value == "skipped"


class TestHardeningRun:
    """Test HardeningRun model."""
    
    def test_valid_hardening_run(self, mock_system_info):
        """Test creating valid HardeningRun."""
        run = HardeningRun(
            run_id="test-run-001",
            operation="audit",
            started_at=datetime.now(),
            system_info=mock_system_info,
            categories=["ssh"],
            rule_ids=["ssh_disable_root_login"],
            total_rules=1,
            passed_rules=1,
            failed_rules=0,
            error_rules=0,
            skipped_rules=0,
            success=True,
            overall_score=100.0
        )
        
        assert run.run_id == "test-run-001"
        assert run.operation == "audit"
        assert run.total_rules == 1
        assert run.overall_score == 100.0
        assert run.success is True
    
    def test_hardening_run_completed_at(self, mock_system_info):
        """Test HardeningRun with completion time."""
        start_time = datetime.now()
        run = HardeningRun(
            run_id="test-run-002",
            operation="apply",
            started_at=start_time,
            system_info=mock_system_info,
            categories=["ssh"],
            rule_ids=["ssh_disable_root_login"],
            total_rules=1,
            passed_rules=0,
            failed_rules=1,
            error_rules=0,
            skipped_rules=0,
            success=False,
            overall_score=0.0
        )
        
        # Mark as completed
        run.completed_at = datetime.now()
        
        assert run.completed_at is not None
        assert run.completed_at >= run.started_at
        assert run.success is False
    
    def test_run_serialization(self, mock_system_info):
        """Test HardeningRun serialization."""
        run = HardeningRun(
            run_id="test-run-003",
            operation="audit",
            started_at=datetime.now(),
            system_info=mock_system_info,
            categories=["ssh"],
            rule_ids=["ssh_disable_root_login"],
            total_rules=1,
            passed_rules=1,
            failed_rules=0,
            error_rules=0,
            skipped_rules=0,
            success=True,
            overall_score=100.0
        )
        
        data = run.model_dump()
        assert isinstance(data, dict)
        assert data["run_id"] == "test-run-003"
        assert isinstance(data["system_info"], dict)


class TestRollbackPoint:
    """Test RollbackPoint model."""
    
    def test_valid_rollback_point(self, mock_system_info):
        """Test creating valid RollbackPoint."""
        rollback = RollbackPoint(
            rollback_id="rollback-001",
            created_at=datetime.now(),
            run_id="test-run-001",
            system_info=mock_system_info,
            config_backups={
                "/etc/ssh/sshd_config": "original content"
            },
            registry_backups={},
            service_states={"ssh": "active"},
            file_checksums={
                "/etc/ssh/sshd_config": "abc123def456"
            }
        )
        
        assert rollback.rollback_id == "rollback-001"
        assert rollback.run_id == "test-run-001"
        assert "/etc/ssh/sshd_config" in rollback.config_backups
        assert rollback.service_states["ssh"] == "active"
    
    def test_rollback_serialization(self, mock_system_info):
        """Test RollbackPoint serialization."""
        rollback = RollbackPoint(
            rollback_id="rollback-002",
            created_at=datetime.now(),
            run_id="test-run-002",
            system_info=mock_system_info,
            config_backups={},
            registry_backups={},
            service_states={},
            file_checksums={}
        )
        
        data = rollback.model_dump()
        assert isinstance(data, dict)
        assert data["rollback_id"] == "rollback-002"
        assert isinstance(data["system_info"], dict)