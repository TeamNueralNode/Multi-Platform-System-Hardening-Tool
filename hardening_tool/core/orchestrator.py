"""
Core orchestrator for the Multi-Platform System Hardening Tool.

The HardeningTool class coordinates all hardening operations including
audit, apply, rollback, and reporting across different platforms.
"""

import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from ..core.models import (
    HardeningResult, HardeningRun, HardeningRule, OSType, 
    RollbackPoint, RuleResult, RuleSeverity, SystemInfo
)
from ..database.manager import DatabaseManager
from ..platforms.factory import PlatformFactory
from ..rules.loader import RuleLoader
from ..utils.os_detection import detect_os
from ..reporting.generator import ReportGenerator


class HardeningTool:
    """
    Main orchestrator class for system hardening operations.
    
    Coordinates platform-specific modules, database operations, 
    rule management, and reporting functionality.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the hardening tool.
        
        Args:
            config_path: Path to configuration file (optional)
        """
        self.system_info = detect_os()
        self.db_manager = DatabaseManager()
        self.rule_loader = RuleLoader()
        self.platform_factory = PlatformFactory()
        self.report_generator = ReportGenerator()
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize database
        self.db_manager.initialize()
        
    def audit(self, categories: Optional[List[str]] = None, 
              rule_ids: Optional[List[str]] = None) -> HardeningResult:
        """
        Perform a read-only audit of system compliance.
        
        Args:
            categories: List of rule categories to audit
            rule_ids: List of specific rule IDs to audit
            
        Returns:
            HardeningResult: Complete audit results
        """
        # Create new run record
        run = HardeningRun(
            run_id=str(uuid.uuid4()),
            operation="audit",
            system_info=self.system_info,
            categories=categories or [],
            rule_ids=rule_ids or []
        )
        
        # Load applicable rules
        rules = self._get_applicable_rules(categories, rule_ids)
        
        # Get platform handler
        platform = self.platform_factory.get_platform(self.system_info.os_type)
        
        # Execute audit for each rule
        for rule in rules:
            try:
                result = platform.audit_rule(rule)
                run.rule_results.append(result)
            except Exception as e:
                # Create error result for failed rule
                error_result = RuleResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    status="error",
                    severity=rule.severity,
                    message=f"Audit failed: {str(e)}"
                )
                run.rule_results.append(error_result)
        
        # Calculate summary statistics
        run.completed_at = datetime.utcnow()
        run.calculate_summary()
        
        # Save run to database
        self.db_manager.save_run(run)
        
        return HardeningResult(run=run)
    
    def apply(self, categories: Optional[List[str]] = None,
              rule_ids: Optional[List[str]] = None,
              interactive: bool = False,
              dry_run: bool = False,
              rollback_description: Optional[str] = None) -> HardeningResult:
        """
        Apply hardening rules to the system.
        
        Args:
            categories: List of rule categories to apply
            rule_ids: List of specific rule IDs to apply
            interactive: Prompt for confirmation before each rule
            dry_run: Show what would be done without applying
            rollback_description: Custom description for rollback point
            
        Returns:
            HardeningResult: Complete application results
        """
        # Create rollback point before making changes
        rollback_point = None
        if not dry_run:
            rollback_point = self._create_rollback_point(rollback_description)
        
        # Create new run record
        run = HardeningRun(
            run_id=str(uuid.uuid4()),
            operation="apply" if not dry_run else "dry_run",
            system_info=self.system_info,
            categories=categories or [],
            rule_ids=rule_ids or []
        )
        
        # Load applicable rules
        rules = self._get_applicable_rules(categories, rule_ids)
        
        # Get platform handler
        platform = self.platform_factory.get_platform(self.system_info.os_type)
        
        # Execute application for each rule
        for rule in rules:
            try:
                if interactive and not dry_run:
                    # TODO: Add interactive confirmation
                    pass
                
                if dry_run:
                    result = platform.audit_rule(rule)
                    # Mark as what would be done
                    if result.status == "fail":
                        result.message = f"Would apply: {rule.title}"
                else:
                    result = platform.apply_rule(rule)
                
                run.rule_results.append(result)
                
            except Exception as e:
                error_result = RuleResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    status="error",
                    severity=rule.severity,
                    message=f"Application failed: {str(e)}"
                )
                run.rule_results.append(error_result)
        
        # Calculate summary statistics
        run.completed_at = datetime.utcnow()
        run.calculate_summary()
        
        # Save run to database
        self.db_manager.save_run(run)
        
        # Link rollback point to run
        if rollback_point:
            rollback_point.run_id = run.run_id
            self.db_manager.save_rollback_point(rollback_point)
        
        return HardeningResult(run=run)
    
    def rollback(self, run_id: str) -> HardeningResult:
        """
        Rollback system changes to a previous state.
        
        Args:
            run_id: ID of the run to rollback to
            
        Returns:
            HardeningResult: Rollback operation results
        """
        # Get rollback point
        rollback_point = self.db_manager.get_rollback_point(run_id)
        if not rollback_point:
            raise ValueError(f"No rollback point found for run {run_id}")
        
        # Create new run record for rollback
        run = HardeningRun(
            run_id=str(uuid.uuid4()),
            operation="rollback",
            system_info=self.system_info
        )
        
        # Get platform handler
        platform = self.platform_factory.get_platform(self.system_info.os_type)
        
        # Execute rollback
        try:
            platform.perform_rollback(rollback_point)
            
            # Create success result
            result = RuleResult(
                rule_id="rollback",
                rule_title=f"Rollback to {run_id}",
                status="pass",
                severity="info",
                message="System successfully rolled back"
            )
            run.rule_results.append(result)
            
        except Exception as e:
            error_result = RuleResult(
                rule_id="rollback",
                rule_title=f"Rollback to {run_id}",
                status="error",
                severity="critical",
                message=f"Rollback failed: {str(e)}"
            )
            run.rule_results.append(error_result)
        
        # Calculate summary and save
        run.completed_at = datetime.utcnow()
        run.calculate_summary()
        self.db_manager.save_run(run)
        
        return HardeningResult(run=run)
    
    def get_available_rules(self, platform: Optional[OSType] = None,
                          category: Optional[str] = None,
                          severity: Optional[RuleSeverity] = None) -> List[HardeningRule]:
        """
        Get list of available hardening rules with optional filtering.
        
        Args:
            platform: Filter by platform type
            category: Filter by rule category
            severity: Filter by severity level
            
        Returns:
            List[HardeningRule]: Filtered list of available rules
        """
        return self.rule_loader.get_rules(
            platform=platform or self.system_info.os_type,
            category=category,
            severity=severity
        )
    
    def get_rule_details(self, rule_id: str) -> HardeningRule:
        """
        Get detailed information about a specific rule.
        
        Args:
            rule_id: Unique rule identifier
            
        Returns:
            HardeningRule: Complete rule definition
            
        Raises:
            ValueError: If rule is not found
        """
        rule = self.rule_loader.get_rule_by_id(rule_id)
        if not rule:
            raise ValueError(f"Rule not found: {rule_id}")
        return rule
    
    def get_rollback_points(self) -> List[RollbackPoint]:
        """
        Get list of available rollback points.
        
        Returns:
            List[RollbackPoint]: Available rollback points
        """
        return self.db_manager.get_rollback_points()
    
    def generate_report(self, run_id: Optional[str] = None,
                       format: str = "pdf",
                       output_path: Optional[str] = None,
                       template_path: Optional[str] = None) -> str:
        """
        Generate a compliance report.
        
        Args:
            run_id: Specific run to report on (latest if None)
            format: Report format (pdf, html, json)
            output_path: Output file path
            template_path: Custom template path
            
        Returns:
            str: Path to generated report
        """
        # Get run data
        if run_id:
            run = self.db_manager.get_run(run_id)
        else:
            run = self.db_manager.get_latest_run()
        
        if not run:
            raise ValueError("No hardening runs found")
        
        # Generate report
        return self.report_generator.generate_report(
            run=run,
            format=format,
            output_path=output_path,
            template_path=template_path
        )
    
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from file or use defaults."""
        default_config = {
            "hardening": {
                "backup_location": "/var/backups/hardening-tool",
                "max_rollback_points": 10
            },
            "reporting": {
                "include_remediation_steps": True,
                "severity_threshold": "medium"
            },
            "platforms": {
                "linux": {
                    "ssh_config_path": "/etc/ssh/sshd_config"
                },
                "windows": {
                    "use_powershell_dsc": False
                }
            }
        }
        
        if config_path and Path(config_path).exists():
            import yaml
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                # Merge with defaults
                default_config.update(user_config)
            except Exception:
                pass  # Use defaults if config loading fails
        
        return default_config
    
    def _get_applicable_rules(self, categories: Optional[List[str]], 
                            rule_ids: Optional[List[str]]) -> List[HardeningRule]:
        """Get rules applicable to current system and filters."""
        if rule_ids:
            # Get specific rules by ID
            rules = []
            for rule_id in rule_ids:
                rule = self.rule_loader.get_rule_by_id(rule_id)
                if rule and self.system_info.os_type in rule.platforms:
                    rules.append(rule)
            return rules
        else:
            # Get all rules for platform, optionally filtered by category
            return self.rule_loader.get_rules(
                platform=self.system_info.os_type,
                category=categories[0] if categories and len(categories) == 1 else None
            )
    
    def _create_rollback_point(self, description: Optional[str]) -> RollbackPoint:
        """Create a rollback point before applying changes."""
        rollback_point = RollbackPoint(
            rollback_id=str(uuid.uuid4()),
            run_id="",  # Will be set after run is created
            system_info=self.system_info,
            description=description or f"Auto-generated rollback point - {datetime.utcnow().isoformat()}"
        )
        
        # Get platform handler to create backups
        platform = self.platform_factory.get_platform(self.system_info.os_type)
        
        try:
            # Create backups of critical configuration files
            rollback_point = platform.create_rollback_point(rollback_point)
        except Exception as e:
            raise RuntimeError(f"Failed to create rollback point: {e}")
        
        return rollback_point