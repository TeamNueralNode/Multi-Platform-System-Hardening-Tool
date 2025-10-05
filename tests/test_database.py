"""
Unit tests for database manager.

Tests SQLite operations, data storage/retrieval, and 
encryption functionality for rollback points.
"""

import pytest
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from hardening_tool.database.manager import DatabaseManager
from hardening_tool.core.models import (
    SystemInfo, HardeningRun, RuleResult, RollbackPoint, RuleStatus
)


class TestDatabaseManager:
    """Test DatabaseManager functionality."""
    
    def test_database_initialization(self, temp_db):
        """Test database initialization and schema creation."""
        assert temp_db.db_path.exists()
        
        # Verify tables exist
        conn = sqlite3.connect(str(temp_db.db_path))
        cursor = conn.cursor()
        
        tables = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t[0] for t in tables]
        
        assert 'hardening_runs' in table_names
        assert 'rule_results' in table_names
        assert 'rollback_points' in table_names
        
        conn.close()
    
    def test_save_and_retrieve_run(self, temp_db, mock_hardening_run):
        """Test saving and retrieving hardening runs."""
        # Save run
        temp_db.save_run(mock_hardening_run)
        
        # Retrieve run
        retrieved_run = temp_db.get_latest_run()
        
        assert retrieved_run is not None
        assert retrieved_run.run_id == mock_hardening_run.run_id
        assert retrieved_run.operation == mock_hardening_run.operation
        assert retrieved_run.total_rules == mock_hardening_run.total_rules
        assert retrieved_run.overall_score == mock_hardening_run.overall_score
    
    def test_save_rule_results(self, temp_db, mock_hardening_run, sample_rule_result):
        """Test saving rule results."""
        # Save run first
        temp_db.save_run(mock_hardening_run)
        
        # Save rule result
        temp_db.save_rule_result(mock_hardening_run.run_id, sample_rule_result)
        
        # Verify result was saved
        conn = sqlite3.connect(str(temp_db.db_path))
        cursor = conn.cursor()
        
        results = cursor.execute(
            "SELECT * FROM rule_results WHERE run_id = ?",
            (mock_hardening_run.run_id,)
        ).fetchall()
        
        assert len(results) == 1
        result = results[0]
        assert result[1] == sample_rule_result.rule_id  # rule_id column
        assert result[2] == sample_rule_result.status.value  # status column
        
        conn.close()
    
    def test_json_serialization_with_datetime(self, temp_db):
        """Test JSON serialization handles datetime objects."""
        # Create system info with current datetime
        system_info = SystemInfo(
            os_type="ubuntu",
            os_version="24.04.3 LTS",
            architecture="x86_64", 
            hostname="test-host",
            kernel_version="6.8.0-40-generic",
            total_memory=8589934592,
            cpu_count=4
        )
        
        # Create run with datetime
        now = datetime.now()
        run = HardeningRun(
            run_id="datetime-test",
            operation="audit",
            started_at=now,
            system_info=system_info,
            categories=["test"],
            rule_ids=["test_rule"],
            total_rules=1,
            passed_rules=1,
            failed_rules=0,
            error_rules=0,
            skipped_rules=0,
            success=True,
            overall_score=100.0
        )
        run.completed_at = now
        
        # This should not raise JSON serialization error
        temp_db.save_run(run)
        
        # Verify retrieval works
        retrieved_run = temp_db.get_latest_run()
        assert retrieved_run is not None
        assert retrieved_run.run_id == "datetime-test"
    
    def test_rule_result_with_complex_states(self, temp_db, mock_hardening_run):
        """Test saving rule results with complex before/after states."""
        # Save run first
        temp_db.save_run(mock_hardening_run)
        
        # Create rule result with complex state data
        complex_result = RuleResult(
            rule_id="complex_rule",
            status=RuleStatus.PASS,
            message="Complex rule applied successfully",
            before_state={
                "config": {
                    "PermitRootLogin": "yes",
                    "PasswordAuthentication": "yes"
                },
                "timestamp": datetime.now(),
                "services": ["ssh", "sshd"]
            },
            after_state={
                "config": {
                    "PermitRootLogin": "no", 
                    "PasswordAuthentication": "no"
                },
                "timestamp": datetime.now(),
                "services": ["ssh", "sshd"]
            },
            execution_time=1.234
        )
        
        # This should handle complex nested data with datetime
        temp_db.save_rule_result(mock_hardening_run.run_id, complex_result)
        
        # Verify it was saved
        conn = sqlite3.connect(str(temp_db.db_path))
        cursor = conn.cursor()
        
        results = cursor.execute(
            "SELECT rule_id, before_state, after_state FROM rule_results WHERE rule_id = ?",
            ("complex_rule",)
        ).fetchall()
        
        assert len(results) == 1
        result = results[0]
        assert result[0] == "complex_rule"
        
        # Verify JSON can be parsed
        before_state = json.loads(result[1])
        after_state = json.loads(result[2])
        
        assert before_state["config"]["PermitRootLogin"] == "yes"
        assert after_state["config"]["PermitRootLogin"] == "no"
        
        conn.close()
    
    def test_rollback_point_creation(self, temp_db, mock_system_info):
        """Test creating and storing rollback points."""
        rollback = RollbackPoint(
            rollback_id="test-rollback-001",
            created_at=datetime.now(),
            run_id="test-run-001",
            system_info=mock_system_info,
            config_backups={
                "/etc/ssh/sshd_config": "Port 22\nPermitRootLogin yes\n",
                "/etc/hosts": "127.0.0.1 localhost\n"
            },
            registry_backups={},
            service_states={
                "ssh": "active",
                "nginx": "inactive"
            },
            file_checksums={
                "/etc/ssh/sshd_config": "abc123def456",
                "/etc/hosts": "789xyz012"
            }
        )
        
        # Save rollback point
        temp_db.save_rollback_point(rollback)
        
        # Verify it was saved and encrypted
        conn = sqlite3.connect(str(temp_db.db_path))
        cursor = conn.cursor()
        
        results = cursor.execute(
            "SELECT rollback_id, encrypted_config_data FROM rollback_points WHERE rollback_id = ?",
            ("test-rollback-001",)
        ).fetchall()
        
        assert len(results) == 1
        result = results[0]
        assert result[0] == "test-rollback-001"
        
        # Encrypted data should not be readable as plain text
        encrypted_data = result[1]
        assert encrypted_data is not None
        assert b"gAAAAA" in encrypted_data  # Fernet prefix
        
        conn.close()
    
    def test_encryption_key_persistence(self):
        """Test encryption key is generated and persisted."""
        # Create first database instance
        with pytest.warns(None) as warnings:
            db1 = DatabaseManager()
            db1.initialize()
            key1 = db1.encryption_key
        
        # Create second database instance (should use same key)
        db2 = DatabaseManager()
        db2.initialize()
        key2 = db2.encryption_key
        
        # Keys should be the same
        assert key1 == key2
        
        # Cleanup
        key_path = db1.db_path.parent / "encryption.key"
        key_path.unlink(missing_ok=True)
        db1.db_path.unlink(missing_ok=True)
    
    def test_database_run_statistics(self, temp_db):
        """Test database statistics and run counting."""
        # Create multiple test runs
        system_info = SystemInfo(
            os_type="ubuntu",
            os_version="24.04.3 LTS",
            architecture="x86_64",
            hostname="test-host", 
            kernel_version="6.8.0-40-generic",
            total_memory=8589934592,
            cpu_count=4
        )
        
        for i in range(5):
            run = HardeningRun(
                run_id=f"stats-test-{i:03d}",
                operation="audit" if i % 2 == 0 else "apply",
                started_at=datetime.now(),
                system_info=system_info,
                categories=["test"],
                rule_ids=[f"test_rule_{i}"],
                total_rules=1,
                passed_rules=1 if i < 3 else 0,
                failed_rules=0 if i < 3 else 1,
                error_rules=0,
                skipped_rules=0,
                success=i < 3,
                overall_score=100.0 if i < 3 else 0.0
            )
            temp_db.save_run(run)
        
        # Check database statistics
        conn = sqlite3.connect(str(temp_db.db_path))
        cursor = conn.cursor()
        
        # Count total runs
        total_runs = cursor.execute("SELECT COUNT(*) FROM hardening_runs").fetchone()[0]
        assert total_runs == 5
        
        # Count successful runs
        successful_runs = cursor.execute(
            "SELECT COUNT(*) FROM hardening_runs WHERE success = 1"
        ).fetchone()[0]
        assert successful_runs == 3
        
        # Count audit vs apply operations
        audit_runs = cursor.execute(
            "SELECT COUNT(*) FROM hardening_runs WHERE operation = 'audit'"
        ).fetchone()[0]
        apply_runs = cursor.execute(
            "SELECT COUNT(*) FROM hardening_runs WHERE operation = 'apply'"
        ).fetchone()[0]
        
        assert audit_runs == 3  # Runs 0, 2, 4
        assert apply_runs == 2   # Runs 1, 3
        
        conn.close()


class TestDatabaseIntegration:
    """Integration tests for database operations."""
    
    def test_complete_audit_workflow(self, temp_db):
        """Test complete audit workflow from start to finish."""
        # Create system info
        system_info = SystemInfo(
            os_type="ubuntu",
            os_version="24.04.3 LTS",
            architecture="x86_64",
            hostname="integration-test",
            kernel_version="6.8.0-40-generic", 
            total_memory=8589934592,
            cpu_count=4
        )
        
        # Create hardening run
        run = HardeningRun(
            run_id="integration-audit-001",
            operation="audit",
            started_at=datetime.now(),
            system_info=system_info,
            categories=["ssh", "firewall"],
            rule_ids=["ssh_disable_root_login", "ssh_disable_password_auth"],
            total_rules=2,
            passed_rules=1,
            failed_rules=1,
            error_rules=0,
            skipped_rules=0,
            success=True,
            overall_score=50.0
        )
        
        # Save run
        temp_db.save_run(run)
        
        # Create and save rule results
        results = [
            RuleResult(
                rule_id="ssh_disable_root_login",
                status=RuleStatus.FAIL,
                message="Root login is enabled",
                before_state={"PermitRootLogin": "yes"},
                execution_time=0.1
            ),
            RuleResult(
                rule_id="ssh_disable_password_auth", 
                status=RuleStatus.PASS,
                message="Password auth is disabled",
                before_state={"PasswordAuthentication": "no"},
                execution_time=0.05
            )
        ]
        
        for result in results:
            temp_db.save_rule_result(run.run_id, result)
        
        # Mark run as completed
        run.completed_at = datetime.now()
        temp_db.save_run(run)  # Update with completion time
        
        # Verify everything was saved correctly
        retrieved_run = temp_db.get_latest_run()
        assert retrieved_run.run_id == "integration-audit-001"
        assert retrieved_run.completed_at is not None
        
        # Verify rule results
        conn = sqlite3.connect(str(temp_db.db_path))
        cursor = conn.cursor()
        
        saved_results = cursor.execute(
            "SELECT rule_id, status FROM rule_results WHERE run_id = ? ORDER BY rule_id",
            (run.run_id,)
        ).fetchall()
        
        assert len(saved_results) == 2
        assert saved_results[0][0] == "ssh_disable_password_auth"  # Alphabetical order
        assert saved_results[0][1] == "PASS"
        assert saved_results[1][0] == "ssh_disable_root_login" 
        assert saved_results[1][1] == "FAIL"
        
        conn.close()