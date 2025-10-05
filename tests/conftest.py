"""
Test fixtures and utilities for the hardening tool test suite.

Provides common fixtures, mock objects, and helper functions
used across multiple test modules.
"""

import pytest
import tempfile
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch
from datetime import datetime

from hardening_tool.core.models import (
    SystemInfo, HardeningRule, RuleResult, HardeningRun, RuleStatus, RuleSeverity
)
from hardening_tool.database.manager import DatabaseManager


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    
    # Initialize database
    db = DatabaseManager(db_path)
    db.initialize()
    
    yield db
    
    # Cleanup
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def mock_system_info():
    """Create a mock SystemInfo object."""
    return SystemInfo(
        os_type="ubuntu",
        os_version="24.04.3 LTS",
        architecture="x86_64",
        hostname="test-host",
        kernel_version="6.8.0-40-generic"
    )


@pytest.fixture
def sample_ssh_rule():
    """Create a sample SSH hardening rule."""
    return HardeningRule(
        id="ssh_disable_root_login",
        title="Disable SSH Root Login",
        description="Prevents direct root login via SSH",
        platforms=["ubuntu", "centos"],
        categories=["ssh"],
        severity="high",
        cis_benchmark="5.2.8",
        remediation="Set PermitRootLogin no in /etc/ssh/sshd_config"
    )


@pytest.fixture
def sample_rule_result():
    """Create a sample rule result."""
    return RuleResult(
        rule_id="ssh_disable_root_login",
        rule_title="Disable SSH Root Login",
        status=RuleStatus.PASS,
        severity=RuleSeverity.HIGH,
        message="SSH root login is disabled",
        before_state={"PermitRootLogin": "yes"},
        after_state={"PermitRootLogin": "no"},
        execution_time_ms=123
    )


@pytest.fixture
def mock_hardening_run(mock_system_info):
    """Create a mock hardening run."""
    return HardeningRun(
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


@pytest.fixture
def mock_platform():
    """Create a mock platform implementation."""
    platform = Mock()
    platform.get_system_info.return_value = SystemInfo(
        os_type="ubuntu",
        os_version="24.04.3 LTS",
        architecture="x86_64",
        hostname="test-host",
        kernel_version="6.8.0-40-generic",
        total_memory=8589934592,
        cpu_count=4
    )
    return platform


class MockSSHConfig:
    """Mock SSH configuration for testing."""
    
    def __init__(self, config_content: str = ""):
        self.content = config_content
        self.path = "/etc/ssh/sshd_config"
    
    def read_config(self) -> dict:
        """Parse SSH config content into dict."""
        config = {}
        for line in self.content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if ' ' in line:
                    key, value = line.split(' ', 1)
                    config[key] = value
        return config


@pytest.fixture
def mock_ssh_config():
    """Create mock SSH configuration."""
    return MockSSHConfig("""
# SSH Configuration
Port 22
Protocol 2
PermitRootLogin yes
PasswordAuthentication no
PubkeyAuthentication yes
""")


def create_test_rule(rule_id: str = "test_rule", status: RuleStatus = RuleStatus.PASS) -> HardeningRule:
    """Helper function to create test rules."""
    return HardeningRule(
        id=rule_id,
        title=f"Test Rule {rule_id}",
        description=f"Description for {rule_id}",
        platforms=["ubuntu"],
        categories=["test"],
        severity="medium"
    )


def assert_database_integrity(db: DatabaseManager):
    """Verify database integrity and schema."""
    conn = sqlite3.connect(str(db.db_path))
    cursor = conn.cursor()
    
    # Check tables exist
    tables = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    table_names = [t[0] for t in tables]
    
    assert 'hardening_runs' in table_names
    assert 'rule_results' in table_names
    assert 'rollback_points' in table_names
    
    conn.close()


# Test data constants
SAMPLE_SSH_CONFIG = """
Port 22
Protocol 2
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
PasswordAuthentication no
"""

EXPECTED_SSH_CONFIG_HARDENED = """
Port 22
Protocol 2
LoginGraceTime 120
PermitRootLogin no
StrictModes yes
PasswordAuthentication no
"""