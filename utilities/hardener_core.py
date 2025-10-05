#!/usr/bin/env python3
"""
Hardening Tool Core Orchestrator
Main orchestrator for system hardening operations with SQLite backend
"""

import os
import sys
import json
import sqlite3
import yaml
import subprocess
import platform
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class RuleStatus(Enum):
    """Rule execution status enumeration."""
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"
    APPLIED = "applied"


class OSType(Enum):
    """Supported operating system types."""
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"


@dataclass
class RuleResult:
    """Result of a single rule execution."""
    rule_id: str
    status: RuleStatus
    message: str
    current_value: str = ""
    expected_value: str = ""
    execution_time: float = 0.0
    error_details: str = ""
    remediation_applied: bool = False


@dataclass
class HardeningRun:
    """Hardening operation run information."""
    run_id: str
    operation_type: str  # audit, apply, rollback
    os_type: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"
    rules_total: int = 0
    rules_passed: int = 0
    rules_failed: int = 0
    rules_applied: int = 0
    rules_errors: int = 0
    rules_skipped: int = 0


class DatabaseManager:
    """Manages SQLite database operations for hardening runs."""
    
    def __init__(self, db_path: str = "hardening_tool.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                -- Hardening runs table
                CREATE TABLE IF NOT EXISTS hardening_runs (
                    run_id TEXT PRIMARY KEY,
                    operation_type TEXT NOT NULL,
                    os_type TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    rules_total INTEGER DEFAULT 0,
                    rules_passed INTEGER DEFAULT 0,
                    rules_failed INTEGER DEFAULT 0,
                    rules_applied INTEGER DEFAULT 0,
                    rules_errors INTEGER DEFAULT 0,
                    rules_skipped INTEGER DEFAULT 0,
                    summary_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Rule results table
                CREATE TABLE IF NOT EXISTS rule_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    current_value TEXT,
                    expected_value TEXT,
                    execution_time REAL DEFAULT 0.0,
                    error_details TEXT,
                    remediation_applied BOOLEAN DEFAULT 0,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (run_id) REFERENCES hardening_runs(run_id)
                );
                
                -- Rollback manifest table
                CREATE TABLE IF NOT EXISTS rollback_manifest (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    backup_type TEXT NOT NULL,  -- file, registry, command
                    backup_path TEXT,
                    backup_data TEXT,  -- JSON encoded backup data
                    rollback_command TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (run_id) REFERENCES hardening_runs(run_id)
                );
                
                -- Run metadata table for additional tracking
                CREATE TABLE IF NOT EXISTS run_metadata (
                    run_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT,
                    PRIMARY KEY (run_id, key),
                    FOREIGN KEY (run_id) REFERENCES hardening_runs(run_id)
                );
                
                -- Indexes for performance
                CREATE INDEX IF NOT EXISTS idx_rule_results_run_id ON rule_results(run_id);
                CREATE INDEX IF NOT EXISTS idx_rule_results_rule_id ON rule_results(rule_id);
                CREATE INDEX IF NOT EXISTS idx_rollback_manifest_run_id ON rollback_manifest(run_id);
                CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON hardening_runs(start_time);
            """)
    
    def save_run(self, run: HardeningRun) -> None:
        """Save or update hardening run information."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO hardening_runs 
                (run_id, operation_type, os_type, start_time, end_time, status, 
                 rules_total, rules_passed, rules_failed, rules_applied, rules_errors, rules_skipped)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run.run_id, run.operation_type, run.os_type, 
                run.start_time.isoformat(), 
                run.end_time.isoformat() if run.end_time else None,
                run.status, run.rules_total, run.rules_passed, 
                run.rules_failed, run.rules_applied, run.rules_errors, run.rules_skipped
            ))
    
    def save_rule_result(self, run_id: str, result: RuleResult) -> None:
        """Save rule execution result."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO rule_results 
                (run_id, rule_id, status, message, current_value, expected_value, 
                 execution_time, error_details, remediation_applied)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run_id, result.rule_id, result.status.value, result.message,
                result.current_value, result.expected_value, result.execution_time,
                result.error_details, result.remediation_applied
            ))
    
    def save_rollback_entry(self, run_id: str, rule_id: str, backup_type: str,
                           backup_path: str = "", backup_data: str = "",
                           rollback_command: str = "") -> None:
        """Save rollback information for a rule."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO rollback_manifest 
                (run_id, rule_id, backup_type, backup_path, backup_data, rollback_command)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (run_id, rule_id, backup_type, backup_path, backup_data, rollback_command))
    
    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Get hardening run information."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM hardening_runs WHERE run_id = ?", (run_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_run_results(self, run_id: str) -> List[Dict[str, Any]]:
        """Get all rule results for a run."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM rule_results WHERE run_id = ? ORDER BY timestamp", (run_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_rollback_manifest(self, run_id: str) -> List[Dict[str, Any]]:
        """Get rollback manifest for a run."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM rollback_manifest WHERE run_id = ? ORDER BY created_at DESC
            """, (run_id,))
            return [dict(row) for row in cursor.fetchall()]


class OSDetector:
    """Detects operating system type and version."""
    
    @staticmethod
    def detect_os() -> Tuple[OSType, str]:
        """Detect operating system type and version."""
        system = platform.system().lower()
        
        if system == "windows":
            version = platform.version()
            return OSType.WINDOWS, f"Windows {version}"
        elif system == "linux":
            try:
                # Try to get distribution info
                with open("/etc/os-release") as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith("PRETTY_NAME"):
                            version = line.split("=")[1].strip().strip('"')
                            return OSType.LINUX, version
            except FileNotFoundError:
                pass
            
            version = platform.version()
            return OSType.LINUX, f"Linux {version}"
        else:
            return OSType.UNKNOWN, f"Unknown ({system})"


class RuleLoader:
    """Loads and manages security rules from YAML files."""
    
    def __init__(self, rules_dir: str = "rules/definitions"):
        self.rules_dir = Path(rules_dir)
    
    def load_rules_for_os(self, os_type: OSType) -> List[Dict[str, Any]]:
        """Load security rules for specific operating system."""
        rules = []
        
        if os_type == OSType.WINDOWS:
            rules_file = self.rules_dir / "windows_security_rules.yaml"
        elif os_type == OSType.LINUX:
            rules_file = self.rules_dir / "linux_security_rules.yaml"
        else:
            return rules
        
        if not rules_file.exists():
            return rules
        
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict) and 'rules' in data:
                    return data['rules']
        except Exception as e:
            print(f"Error loading rules from {rules_file}: {e}")
        
        return rules


class CommandExecutor:
    """Executes system commands safely."""
    
    @staticmethod
    def execute_command(command: str, timeout: int = 30, shell: bool = True) -> Tuple[int, str, str]:
        """Execute a system command and return exit code, stdout, stderr."""
        try:
            if platform.system().lower() == "windows":
                # Use PowerShell for Windows commands
                if not command.startswith("powershell") and not command.startswith("cmd"):
                    command = f"powershell -Command \"{command}\""
            
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        
        except subprocess.TimeoutExpired:
            return 1, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return 1, "", str(e)


class HardeningOrchestrator:
    """Main orchestrator for hardening operations."""
    
    def __init__(self, db_path: str = "hardening_tool.db", rules_dir: str = "rules/definitions"):
        self.db = DatabaseManager(db_path)
        self.rule_loader = RuleLoader(rules_dir)
        self.executor = CommandExecutor()
        self.os_type, self.os_version = OSDetector.detect_os()
    
    def execute_rule_check(self, rule: Dict[str, Any]) -> RuleResult:
        """Execute check command for a rule."""
        rule_id = rule.get('id', 'unknown')
        check_command = rule.get('check_command', '')
        expected_value = rule.get('desired_value', '')
        
        if not check_command:
            return RuleResult(
                rule_id=rule_id,
                status=RuleStatus.SKIPPED,
                message="No check command provided",
                expected_value=expected_value
            )
        
        start_time = datetime.now()
        
        try:
            exit_code, stdout, stderr = self.executor.execute_command(check_command)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            current_value = stdout if stdout else stderr
            
            # Determine if rule passes based on exit code and expected value
            if exit_code == 0:
                if expected_value and current_value:
                    # Compare values if both are provided
                    if str(expected_value).lower() in str(current_value).lower():
                        status = RuleStatus.PASS
                        message = "Rule compliant"
                    else:
                        status = RuleStatus.FAIL
                        message = f"Expected '{expected_value}', got '{current_value}'"
                else:
                    status = RuleStatus.PASS
                    message = "Check command executed successfully"
            else:
                status = RuleStatus.FAIL
                message = f"Check failed: {stderr if stderr else 'Command failed'}"
            
            return RuleResult(
                rule_id=rule_id,
                status=status,
                message=message,
                current_value=current_value,
                expected_value=expected_value,
                execution_time=execution_time,
                error_details=stderr if exit_code != 0 else ""
            )
        
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            return RuleResult(
                rule_id=rule_id,
                status=RuleStatus.ERROR,
                message=f"Error executing check: {str(e)}",
                expected_value=expected_value,
                execution_time=execution_time,
                error_details=str(e)
            )
    
    def execute_rule_remediation(self, rule: Dict[str, Any], run_id: str) -> RuleResult:
        """Execute remediation command for a rule."""
        rule_id = rule.get('id', 'unknown')
        remediate_command = rule.get('remediate_command', '')
        expected_value = rule.get('desired_value', '')
        
        if not remediate_command:
            return RuleResult(
                rule_id=rule_id,
                status=RuleStatus.SKIPPED,
                message="No remediation command provided",
                expected_value=expected_value
            )
        
        if rule.get('manual_flag', False):
            return RuleResult(
                rule_id=rule_id,
                status=RuleStatus.SKIPPED,
                message="Manual remediation required",
                expected_value=expected_value
            )
        
        # Create rollback entry before applying remediation
        self.create_rollback_entry(rule, run_id)
        
        start_time = datetime.now()
        
        try:
            exit_code, stdout, stderr = self.executor.execute_command(remediate_command)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            if exit_code == 0:
                # Verify remediation by running check again
                check_result = self.execute_rule_check(rule)
                
                if check_result.status == RuleStatus.PASS:
                    return RuleResult(
                        rule_id=rule_id,
                        status=RuleStatus.APPLIED,
                        message="Remediation applied successfully",
                        current_value=check_result.current_value,
                        expected_value=expected_value,
                        execution_time=execution_time,
                        remediation_applied=True
                    )
                else:
                    return RuleResult(
                        rule_id=rule_id,
                        status=RuleStatus.ERROR,
                        message=f"Remediation applied but verification failed: {check_result.message}",
                        expected_value=expected_value,
                        execution_time=execution_time,
                        error_details=check_result.message
                    )
            else:
                return RuleResult(
                    rule_id=rule_id,
                    status=RuleStatus.ERROR,
                    message=f"Remediation failed: {stderr if stderr else 'Command failed'}",
                    expected_value=expected_value,
                    execution_time=execution_time,
                    error_details=stderr
                )
        
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            return RuleResult(
                rule_id=rule_id,
                status=RuleStatus.ERROR,
                message=f"Error executing remediation: {str(e)}",
                expected_value=expected_value,
                execution_time=execution_time,
                error_details=str(e)
            )
    
    def create_rollback_entry(self, rule: Dict[str, Any], run_id: str) -> None:
        """Create rollback entry for a rule before applying remediation."""
        rule_id = rule.get('id', 'unknown')
        
        # Get current state before remediation
        current_check = self.execute_rule_check(rule)
        
        # Store current state as backup data
        backup_data = {
            'current_value': current_check.current_value,
            'timestamp': datetime.now().isoformat(),
            'rule_title': rule.get('title', ''),
            'rollback_instructions': rule.get('rollback_instructions', '')
        }
        
        self.db.save_rollback_entry(
            run_id=run_id,
            rule_id=rule_id,
            backup_type='state',
            backup_data=json.dumps(backup_data),
            rollback_command=rule.get('rollback_instructions', '')
        )
    
    def audit_system(self, rule_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform system audit against security rules."""
        run_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        # Initialize run
        run = HardeningRun(
            run_id=run_id,
            operation_type="audit",
            os_type=self.os_type.value,
            start_time=start_time
        )
        
        # Load rules for current OS
        rules = self.rule_loader.load_rules_for_os(self.os_type)
        
        if rule_filter:
            rules = [rule for rule in rules if rule.get('id') in rule_filter]
        
        run.rules_total = len(rules)
        self.db.save_run(run)
        
        # Execute audit for each rule
        results = []
        for rule in rules:
            result = self.execute_rule_check(rule)
            results.append(result)
            self.db.save_rule_result(run_id, result)
            
            # Update counters
            if result.status == RuleStatus.PASS:
                run.rules_passed += 1
            elif result.status == RuleStatus.FAIL:
                run.rules_failed += 1
            elif result.status == RuleStatus.ERROR:
                run.rules_errors += 1
            elif result.status == RuleStatus.SKIPPED:
                run.rules_skipped += 1
        
        # Finalize run
        run.end_time = datetime.now()
        run.status = "completed"
        self.db.save_run(run)
        
        # Generate summary
        summary = {
            'run_id': run_id,
            'operation': 'audit',
            'os_type': self.os_type.value,
            'os_version': self.os_version,
            'start_time': start_time.isoformat(),
            'end_time': run.end_time.isoformat(),
            'duration_seconds': (run.end_time - start_time).total_seconds(),
            'rules_total': run.rules_total,
            'rules_passed': run.rules_passed,
            'rules_failed': run.rules_failed,
            'rules_errors': run.rules_errors,
            'rules_skipped': run.rules_skipped,
            'compliance_percentage': (run.rules_passed / run.rules_total * 100) if run.rules_total > 0 else 0,
            'results': [
                {
                    'rule_id': r.rule_id,
                    'status': r.status.value,
                    'message': r.message,
                    'current_value': r.current_value,
                    'expected_value': r.expected_value
                } for r in results
            ]
        }
        
        return summary
    
    def apply_hardening(self, rule_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """Apply hardening rules to the system."""
        run_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        # Initialize run
        run = HardeningRun(
            run_id=run_id,
            operation_type="apply",
            os_type=self.os_type.value,
            start_time=start_time
        )
        
        # Load rules for current OS
        rules = self.rule_loader.load_rules_for_os(self.os_type)
        
        if rule_filter:
            rules = [rule for rule in rules if rule.get('id') in rule_filter]
        
        run.rules_total = len(rules)
        self.db.save_run(run)
        
        # Execute apply for each rule
        results = []
        for rule in rules:
            # First check current state
            check_result = self.execute_rule_check(rule)
            
            if check_result.status == RuleStatus.PASS:
                # Rule already compliant, no action needed
                results.append(check_result)
                run.rules_passed += 1
            elif check_result.status == RuleStatus.FAIL:
                # Rule needs remediation
                remediation_result = self.execute_rule_remediation(rule, run_id)
                results.append(remediation_result)
                
                if remediation_result.status == RuleStatus.APPLIED:
                    run.rules_applied += 1
                else:
                    run.rules_errors += 1
            else:
                # Error or skipped
                results.append(check_result)
                if check_result.status == RuleStatus.ERROR:
                    run.rules_errors += 1
                else:
                    run.rules_skipped += 1
            
            self.db.save_rule_result(run_id, results[-1])
        
        # Finalize run
        run.end_time = datetime.now()
        run.status = "completed"
        self.db.save_run(run)
        
        # Generate summary
        summary = {
            'run_id': run_id,
            'operation': 'apply',
            'os_type': self.os_type.value,
            'os_version': self.os_version,
            'start_time': start_time.isoformat(),
            'end_time': run.end_time.isoformat(),
            'duration_seconds': (run.end_time - start_time).total_seconds(),
            'rules_total': run.rules_total,
            'rules_passed': run.rules_passed,
            'rules_applied': run.rules_applied,
            'rules_errors': run.rules_errors,
            'rules_skipped': run.rules_skipped,
            'results': [
                {
                    'rule_id': r.rule_id,
                    'status': r.status.value,
                    'message': r.message,
                    'remediation_applied': r.remediation_applied
                } for r in results
            ]
        }
        
        return summary
    
    def rollback_run(self, run_id: str) -> Dict[str, Any]:
        """Rollback changes from a specific hardening run."""
        start_time = datetime.now()
        
        # Get original run information
        original_run = self.db.get_run(run_id)
        if not original_run:
            return {
                'success': False,
                'error': f'Run {run_id} not found',
                'timestamp': start_time.isoformat()
            }
        
        # Get rollback manifest
        rollback_entries = self.db.get_rollback_manifest(run_id)
        
        if not rollback_entries:
            return {
                'success': False,
                'error': f'No rollback entries found for run {run_id}',
                'timestamp': start_time.isoformat()
            }
        
        # Create new rollback run
        rollback_run_id = str(uuid.uuid4())
        rollback_run = HardeningRun(
            run_id=rollback_run_id,
            operation_type="rollback",
            os_type=self.os_type.value,
            start_time=start_time
        )
        
        rollback_run.rules_total = len(rollback_entries)
        self.db.save_run(rollback_run)
        
        # Process rollback entries
        rollback_results = []
        for entry in rollback_entries:
            rule_id = entry['rule_id']
            rollback_command = entry['rollback_command']
            
            if rollback_command and rollback_command != "":
                try:
                    exit_code, stdout, stderr = self.executor.execute_command(rollback_command)
                    
                    if exit_code == 0:
                        result = RuleResult(
                            rule_id=rule_id,
                            status=RuleStatus.APPLIED,
                            message="Rollback applied successfully",
                            current_value=stdout
                        )
                        rollback_run.rules_applied += 1
                    else:
                        result = RuleResult(
                            rule_id=rule_id,
                            status=RuleStatus.ERROR,
                            message=f"Rollback failed: {stderr}",
                            error_details=stderr
                        )
                        rollback_run.rules_errors += 1
                except Exception as e:
                    result = RuleResult(
                        rule_id=rule_id,
                        status=RuleStatus.ERROR,
                        message=f"Rollback error: {str(e)}",
                        error_details=str(e)
                    )
                    rollback_run.rules_errors += 1
            else:
                result = RuleResult(
                    rule_id=rule_id,
                    status=RuleStatus.SKIPPED,
                    message="No rollback command available"
                )
                rollback_run.rules_skipped += 1
            
            rollback_results.append(result)
            self.db.save_rule_result(rollback_run_id, result)
        
        # Finalize rollback run
        rollback_run.end_time = datetime.now()
        rollback_run.status = "completed"
        self.db.save_run(rollback_run)
        
        return {
            'success': True,
            'rollback_run_id': rollback_run_id,
            'original_run_id': run_id,
            'operation': 'rollback',
            'start_time': start_time.isoformat(),
            'end_time': rollback_run.end_time.isoformat(),
            'entries_processed': len(rollback_entries),
            'entries_applied': rollback_run.rules_applied,
            'entries_failed': rollback_run.rules_errors,
            'entries_skipped': rollback_run.rules_skipped,
            'results': [
                {
                    'rule_id': r.rule_id,
                    'status': r.status.value,
                    'message': r.message
                } for r in rollback_results
            ]
        }
    
    def generate_pdf_placeholder(self, run_id: str) -> str:
        """Generate PDF report placeholder entry."""
        run_data = self.db.get_run(run_id)
        if not run_data:
            return f"PDF Report placeholder for run {run_id} - Run not found"
        
        pdf_content = f"""
        HARDENING TOOL REPORT
        =====================
        
        Run ID: {run_id}
        Operation: {run_data['operation_type'].upper()}
        OS Type: {run_data['os_type'].title()}
        Start Time: {run_data['start_time']}
        End Time: {run_data['end_time']}
        Status: {run_data['status'].upper()}
        
        SUMMARY
        -------
        Total Rules: {run_data['rules_total']}
        Passed: {run_data['rules_passed']}
        Failed: {run_data['rules_failed']}
        Applied: {run_data['rules_applied']}
        Errors: {run_data['rules_errors']}
        Skipped: {run_data['rules_skipped']}
        
        Compliance: {(run_data['rules_passed'] / run_data['rules_total'] * 100):.1f}% if run_data['rules_total'] > 0 else 0%
        
        [Detailed results would be included in actual PDF report]
        """
        
        return pdf_content


def main():
    """Main CLI function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='System Hardening Tool')
    parser.add_argument('--audit', action='store_true', help='Perform system audit')
    parser.add_argument('--apply', action='store_true', help='Apply hardening rules')
    parser.add_argument('--rollback', type=str, help='Rollback specific run by ID')
    parser.add_argument('--rules', nargs='*', help='Filter specific rules by ID')
    parser.add_argument('--db-path', default='hardening_tool.db', help='Database file path')
    parser.add_argument('--rules-dir', default='rules/definitions', help='Rules directory path')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    
    args = parser.parse_args()
    
    if not any([args.audit, args.apply, args.rollback]):
        parser.print_help()
        return 1
    
    orchestrator = HardeningOrchestrator(db_path=args.db_path, rules_dir=args.rules_dir)
    
    try:
        if args.audit:
            result = orchestrator.audit_system(rule_filter=args.rules)
        elif args.apply:
            result = orchestrator.apply_hardening(rule_filter=args.rules)
        elif args.rollback:
            result = orchestrator.rollback_run(args.rollback)
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Operation: {result.get('operation', 'unknown').upper()}")
            if 'run_id' in result:
                print(f"Run ID: {result['run_id']}")
                print(f"OS: {result.get('os_type', 'unknown')} ({result.get('os_version', 'unknown')})")
                print(f"Duration: {result.get('duration_seconds', 0):.2f} seconds")
                
                if result.get('operation') == 'audit':
                    print(f"Compliance: {result.get('compliance_percentage', 0):.1f}%")
                
                print(f"Rules Total: {result.get('rules_total', 0)}")
                print(f"Rules Passed: {result.get('rules_passed', 0)}")
                if 'rules_applied' in result:
                    print(f"Rules Applied: {result.get('rules_applied', 0)}")
                print(f"Rules Failed: {result.get('rules_failed', 0)}")
                print(f"Rules Errors: {result.get('rules_errors', 0)}")
                print(f"Rules Skipped: {result.get('rules_skipped', 0)}")
                
                # Generate PDF placeholder
                pdf_placeholder = orchestrator.generate_pdf_placeholder(result['run_id'])
                print(f"\nPDF Report Preview:\n{pdf_placeholder}")
            else:
                print(f"Success: {result.get('success', False)}")
                if 'error' in result:
                    print(f"Error: {result['error']}")
        
        return 0
    
    except Exception as e:
        if args.json:
            error_result = {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            print(json.dumps(error_result, indent=2))
        else:
            print(f"Error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())