"""
Database manager for SQLite operations.

Handles storage of hardening runs, rule results, and rollback points
with encryption for sensitive backup data.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from cryptography.fernet import Fernet

from ..core.models import HardeningRun, RollbackPoint, SystemInfo


class DatabaseManager:
    """
    Manages SQLite database operations for the hardening tool.
    
    Provides secure storage for runs, results, and rollback data
    with automatic encryption of sensitive information.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file (uses default if None)
        """
        if db_path:
            self.db_path = Path(db_path)
        else:
            # Default database location based on OS
            import platform
            if platform.system() == "Windows":
                data_dir = Path.home() / "AppData" / "Roaming" / "hardening-tool"
            else:
                data_dir = Path.home() / ".local" / "share" / "hardening-tool"
            
            data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = data_dir / "hardening.db"
        
        # Initialize encryption key for rollback data
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher = Fernet(self.encryption_key)
    
    def _json_serializer(self, obj):
        """JSON serializer for datetime objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    def initialize(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                -- Hardening runs table
                CREATE TABLE IF NOT EXISTS hardening_runs (
                    run_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    system_info_json TEXT NOT NULL,
                    categories_json TEXT,
                    rule_ids_json TEXT,
                    total_rules INTEGER DEFAULT 0,
                    passed_rules INTEGER DEFAULT 0,
                    failed_rules INTEGER DEFAULT 0,
                    error_rules INTEGER DEFAULT 0,
                    skipped_rules INTEGER DEFAULT 0,
                    success BOOLEAN DEFAULT FALSE,
                    overall_score REAL DEFAULT 0.0
                );
                
                -- Rule results table
                CREATE TABLE IF NOT EXISTS rule_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    executed_at TEXT NOT NULL,
                    execution_time_ms INTEGER,
                    before_state_json TEXT,
                    after_state_json TEXT,
                    stdout TEXT,
                    stderr TEXT,
                    exit_code INTEGER,
                    message TEXT,
                    remediation_required BOOLEAN DEFAULT FALSE,
                    rollback_data_json TEXT,
                    FOREIGN KEY (run_id) REFERENCES hardening_runs (run_id)
                );
                
                -- Rollback points table
                CREATE TABLE IF NOT EXISTS rollback_points (
                    rollback_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    system_info_json TEXT NOT NULL,
                    config_backups_encrypted BLOB,
                    registry_backups_encrypted BLOB,
                    service_states_json TEXT,
                    description TEXT,
                    file_checksums_json TEXT,
                    encrypted BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (run_id) REFERENCES hardening_runs (run_id)
                );
                
                -- Indexes for performance
                CREATE INDEX IF NOT EXISTS idx_runs_started_at ON hardening_runs(started_at);
                CREATE INDEX IF NOT EXISTS idx_results_run_id ON rule_results(run_id);
                CREATE INDEX IF NOT EXISTS idx_results_rule_id ON rule_results(rule_id);
                CREATE INDEX IF NOT EXISTS idx_rollback_run_id ON rollback_points(run_id);
                CREATE INDEX IF NOT EXISTS idx_rollback_created_at ON rollback_points(created_at);
            """)
    
    def save_run(self, run: HardeningRun) -> None:
        """
        Save a hardening run and its results to the database.
        
        Args:
            run: Complete hardening run with results
        """
        with sqlite3.connect(self.db_path) as conn:
            # Insert run record
            conn.execute("""
                INSERT OR REPLACE INTO hardening_runs (
                    run_id, operation, started_at, completed_at, system_info_json,
                    categories_json, rule_ids_json, total_rules, passed_rules,
                    failed_rules, error_rules, skipped_rules, success, overall_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run.run_id,
                run.operation,
                run.started_at.isoformat(),
                run.completed_at.isoformat() if run.completed_at else None,
                json.dumps(run.system_info.model_dump(), default=self._json_serializer),
                json.dumps(run.categories),
                json.dumps(run.rule_ids),
                run.total_rules,
                run.passed_rules,
                run.failed_rules,
                run.error_rules,
                run.skipped_rules,
                run.success,
                run.overall_score
            ))
            
            # Delete existing results for this run (if any)
            conn.execute("DELETE FROM rule_results WHERE run_id = ?", (run.run_id,))
            
            # Insert rule results
            for result in run.rule_results:
                conn.execute("""
                    INSERT INTO rule_results (
                        run_id, rule_id, rule_title, status, severity, executed_at,
                        execution_time_ms, before_state_json, after_state_json,
                        stdout, stderr, exit_code, message, remediation_required,
                        rollback_data_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    run.run_id,
                    result.rule_id,
                    result.rule_title,
                    result.status.value,
                    result.severity.value,
                    result.executed_at.isoformat(),
                    result.execution_time_ms,
                    json.dumps(result.before_state, default=self._json_serializer) if result.before_state else None,
                    json.dumps(result.after_state, default=self._json_serializer) if result.after_state else None,
                    result.stdout,
                    result.stderr,
                    result.exit_code,
                    result.message,
                    result.remediation_required,
                    json.dumps(result.rollback_data, default=self._json_serializer) if result.rollback_data else None
                ))
    
    def save_rollback_point(self, rollback_point: RollbackPoint) -> None:
        """
        Save a rollback point with encrypted backup data.
        
        Args:
            rollback_point: Rollback point with backup data
        """
        with sqlite3.connect(self.db_path) as conn:
            # Encrypt sensitive backup data
            config_backups_encrypted = None
            registry_backups_encrypted = None
            
            if rollback_point.config_backups:
                config_json = json.dumps(rollback_point.config_backups, default=self._json_serializer)
                config_backups_encrypted = self.cipher.encrypt(config_json.encode())
            
            if rollback_point.registry_backups:
                registry_json = json.dumps(rollback_point.registry_backups, default=self._json_serializer)
                registry_backups_encrypted = self.cipher.encrypt(registry_json.encode())
            
            conn.execute("""
                INSERT OR REPLACE INTO rollback_points (
                    rollback_id, created_at, run_id, system_info_json,
                    config_backups_encrypted, registry_backups_encrypted,
                    service_states_json, description, file_checksums_json, encrypted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rollback_point.rollback_id,
                rollback_point.created_at.isoformat(),
                rollback_point.run_id,
                json.dumps(rollback_point.system_info.model_dump(), default=self._json_serializer),
                config_backups_encrypted,
                registry_backups_encrypted,
                json.dumps(rollback_point.service_states, default=self._json_serializer),
                rollback_point.description,
                json.dumps(rollback_point.file_checksums, default=self._json_serializer),
                rollback_point.encrypted
            ))
    
    def get_run(self, run_id: str) -> Optional[HardeningRun]:
        """
        Retrieve a hardening run by ID.
        
        Args:
            run_id: Unique run identifier
            
        Returns:
            Optional[HardeningRun]: Run data if found, None otherwise
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Get run data
            run_row = conn.execute("""
                SELECT * FROM hardening_runs WHERE run_id = ?
            """, (run_id,)).fetchone()
            
            if not run_row:
                return None
            
            # Get rule results
            result_rows = conn.execute("""
                SELECT * FROM rule_results WHERE run_id = ? ORDER BY executed_at
            """, (run_id,)).fetchall()
            
            return self._build_hardening_run(run_row, result_rows)
    
    def get_latest_run(self) -> Optional[HardeningRun]:
        """
        Get the most recent hardening run.
        
        Returns:
            Optional[HardeningRun]: Latest run data if found, None otherwise
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Get latest run
            run_row = conn.execute("""
                SELECT * FROM hardening_runs 
                ORDER BY started_at DESC LIMIT 1
            """).fetchone()
            
            if not run_row:
                return None
            
            # Get rule results
            result_rows = conn.execute("""
                SELECT * FROM rule_results WHERE run_id = ? ORDER BY executed_at
            """, (run_row['run_id'],)).fetchall()
            
            return self._build_hardening_run(run_row, result_rows)
    
    def get_rollback_points(self) -> List[RollbackPoint]:
        """
        Get all available rollback points.
        
        Returns:
            List[RollbackPoint]: Available rollback points ordered by creation date
        """
        rollback_points = []
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            rows = conn.execute("""
                SELECT * FROM rollback_points ORDER BY created_at DESC
            """).fetchall()
            
            for row in rows:
                rollback_point = self._build_rollback_point(row)
                rollback_points.append(rollback_point)
        
        return rollback_points
    
    def get_rollback_point(self, run_id: str) -> Optional[RollbackPoint]:
        """
        Get rollback point for a specific run.
        
        Args:
            run_id: Run identifier to get rollback point for
            
        Returns:
            Optional[RollbackPoint]: Rollback point if found, None otherwise
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            row = conn.execute("""
                SELECT * FROM rollback_points WHERE run_id = ?
            """, (run_id,)).fetchone()
            
            if not row:
                return None
            
            return self._build_rollback_point(row)
    
    def cleanup_old_rollbacks(self, max_points: int = 10) -> None:
        """
        Clean up old rollback points to save space.
        
        Args:
            max_points: Maximum number of rollback points to keep
        """
        with sqlite3.connect(self.db_path) as conn:
            # Delete oldest rollback points beyond the limit
            conn.execute("""
                DELETE FROM rollback_points WHERE rollback_id IN (
                    SELECT rollback_id FROM rollback_points 
                    ORDER BY created_at DESC LIMIT -1 OFFSET ?
                )
            """, (max_points,))
    
    def _build_hardening_run(self, run_row, result_rows) -> HardeningRun:
        """Build HardeningRun object from database rows."""
        from ..core.models import RuleResult, RuleStatus, RuleSeverity
        
        # Parse system info
        system_info_dict = json.loads(run_row['system_info_json'])
        system_info = SystemInfo(**system_info_dict)
        
        # Build rule results
        rule_results = []
        for result_row in result_rows:
            rule_result = RuleResult(
                rule_id=result_row['rule_id'],
                rule_title=result_row['rule_title'],
                status=RuleStatus(result_row['status']),
                severity=RuleSeverity(result_row['severity']),
                executed_at=datetime.fromisoformat(result_row['executed_at']),
                execution_time_ms=result_row['execution_time_ms'],
                before_state=json.loads(result_row['before_state_json']) if result_row['before_state_json'] else None,
                after_state=json.loads(result_row['after_state_json']) if result_row['after_state_json'] else None,
                stdout=result_row['stdout'],
                stderr=result_row['stderr'],
                exit_code=result_row['exit_code'],
                message=result_row['message'],
                remediation_required=bool(result_row['remediation_required']),
                rollback_data=json.loads(result_row['rollback_data_json']) if result_row['rollback_data_json'] else None
            )
            rule_results.append(rule_result)
        
        # Build run object
        run = HardeningRun(
            run_id=run_row['run_id'],
            operation=run_row['operation'],
            started_at=datetime.fromisoformat(run_row['started_at']),
            completed_at=datetime.fromisoformat(run_row['completed_at']) if run_row['completed_at'] else None,
            system_info=system_info,
            categories=json.loads(run_row['categories_json']) if run_row['categories_json'] else [],
            rule_ids=json.loads(run_row['rule_ids_json']) if run_row['rule_ids_json'] else [],
            rule_results=rule_results,
            total_rules=run_row['total_rules'],
            passed_rules=run_row['passed_rules'],
            failed_rules=run_row['failed_rules'],
            error_rules=run_row['error_rules'],
            skipped_rules=run_row['skipped_rules'],
            success=bool(run_row['success']),
            overall_score=run_row['overall_score']
        )
        
        return run
    
    def _build_rollback_point(self, row) -> RollbackPoint:
        """Build RollbackPoint object from database row."""
        system_info_dict = json.loads(row['system_info_json'])
        system_info = SystemInfo(**system_info_dict)
        
        # Decrypt backup data if encrypted
        config_backups = {}
        registry_backups = {}
        
        if row['config_backups_encrypted']:
            try:
                decrypted_config = self.cipher.decrypt(row['config_backups_encrypted'])
                config_backups = json.loads(decrypted_config.decode())
            except Exception:
                pass  # Handle decryption errors gracefully
        
        if row['registry_backups_encrypted']:
            try:
                decrypted_registry = self.cipher.decrypt(row['registry_backups_encrypted'])
                registry_backups = json.loads(decrypted_registry.decode())
            except Exception:
                pass
        
        rollback_point = RollbackPoint(
            rollback_id=row['rollback_id'],
            created_at=datetime.fromisoformat(row['created_at']),
            run_id=row['run_id'],
            system_info=system_info,
            config_backups=config_backups,
            registry_backups=registry_backups,
            service_states=json.loads(row['service_states_json']) if row['service_states_json'] else {},
            description=row['description'],
            file_checksums=json.loads(row['file_checksums_json']) if row['file_checksums_json'] else {},
            encrypted=bool(row['encrypted'])
        )
        
        return rollback_point
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get existing encryption key or create a new one."""
        key_path = self.db_path.parent / ".encryption_key"
        
        if key_path.exists():
            try:
                with open(key_path, 'rb') as f:
                    return f.read()
            except Exception:
                pass  # Create new key if reading fails
        
        # Create new encryption key
        key = Fernet.generate_key()
        
        try:
            # Save key with restricted permissions
            key_path.touch(mode=0o600)
            with open(key_path, 'wb') as f:
                f.write(key)
        except Exception:
            pass  # Continue with in-memory key if saving fails
        
        return key