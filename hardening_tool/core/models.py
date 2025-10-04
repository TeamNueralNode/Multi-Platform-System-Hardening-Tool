"""
Data models for the hardening tool using Pydantic for validation.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator


class OSType(str, Enum):
    """Supported operating system types."""
    WINDOWS = "windows"
    UBUNTU = "ubuntu"
    CENTOS = "centos"
    UNKNOWN = "unknown"


class RuleSeverity(str, Enum):
    """Rule severity levels based on security impact."""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleStatus(str, Enum):
    """Execution status of a hardening rule."""
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


class SystemInfo(BaseModel):
    """System information detected during runtime."""
    os_type: OSType
    os_version: str
    architecture: str
    hostname: str
    kernel_version: Optional[str] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class HardeningRule(BaseModel):
    """Definition of a hardening rule."""
    id: str = Field(..., description="Unique rule identifier")
    title: str = Field(..., description="Human-readable rule title")
    description: str = Field(..., description="Detailed rule description")
    severity: RuleSeverity = Field(..., description="Security impact level")
    platforms: List[OSType] = Field(..., description="Supported operating systems")
    categories: List[str] = Field(default_factory=list, description="Rule categories (e.g., ssh, firewall)")
    cis_benchmark: Optional[str] = Field(None, description="CIS Benchmark reference")
    ntro_reference: Optional[str] = Field(None, description="NTRO Annexure reference")
    remediation_steps: List[str] = Field(default_factory=list, description="Manual remediation instructions")
    
    # Execution parameters
    audit_command: Optional[str] = Field(None, description="Command to check current state")
    apply_command: Optional[str] = Field(None, description="Command to apply hardening")
    rollback_command: Optional[str] = Field(None, description="Command to rollback changes")
    
    # File-based operations
    config_files: List[str] = Field(default_factory=list, description="Configuration files to modify")
    backup_files: List[str] = Field(default_factory=list, description="Files to backup before changes")
    
    # Validation
    expected_values: Dict[str, Any] = Field(default_factory=dict, description="Expected configuration values")
    
    @validator('platforms')
    def validate_platforms(cls, v):
        """Ensure at least one platform is specified."""
        if not v:
            raise ValueError("At least one platform must be specified")
        return v


class RuleResult(BaseModel):
    """Result of executing a hardening rule."""
    rule_id: str
    rule_title: str
    status: RuleStatus
    severity: RuleSeverity
    
    # Execution details
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    execution_time_ms: Optional[int] = None
    
    # Before/after state
    before_state: Optional[Dict[str, Any]] = None
    after_state: Optional[Dict[str, Any]] = None
    
    # Output and errors
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_code: Optional[int] = None
    
    # Additional context
    message: Optional[str] = None
    remediation_required: bool = False
    rollback_data: Optional[Dict[str, Any]] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class HardeningRun(BaseModel):
    """Complete hardening execution run."""
    run_id: str = Field(..., description="Unique run identifier")
    operation: str = Field(..., description="Operation type: audit, apply, or rollback")
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    
    # System context
    system_info: SystemInfo
    
    # Execution parameters
    categories: List[str] = Field(default_factory=list, description="Rule categories executed")
    rule_ids: List[str] = Field(default_factory=list, description="Specific rules executed")
    
    # Results
    rule_results: List[RuleResult] = Field(default_factory=list)
    
    # Summary statistics
    total_rules: int = 0
    passed_rules: int = 0
    failed_rules: int = 0
    error_rules: int = 0
    skipped_rules: int = 0
    
    # Overall status
    success: bool = False
    overall_score: float = 0.0  # Percentage of passed rules
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def calculate_summary(self) -> None:
        """Calculate summary statistics from rule results."""
        self.total_rules = len(self.rule_results)
        self.passed_rules = sum(1 for r in self.rule_results if r.status == RuleStatus.PASS)
        self.failed_rules = sum(1 for r in self.rule_results if r.status == RuleStatus.FAIL)
        self.error_rules = sum(1 for r in self.rule_results if r.status == RuleStatus.ERROR)
        self.skipped_rules = sum(1 for r in self.rule_results if r.status == RuleStatus.SKIPPED)
        
        # Calculate overall score (exclude skipped and N/A rules)
        applicable_rules = self.total_rules - self.skipped_rules - sum(
            1 for r in self.rule_results if r.status == RuleStatus.NOT_APPLICABLE
        )
        
        if applicable_rules > 0:
            self.overall_score = (self.passed_rules / applicable_rules) * 100.0
        else:
            self.overall_score = 100.0
            
        self.success = self.error_rules == 0 and self.failed_rules == 0


class HardeningResult(BaseModel):
    """Main result object for hardening operations."""
    run: HardeningRun
    
    # Convenience properties
    @property
    def passed(self) -> bool:
        """Whether the hardening run was successful."""
        return self.run.success
    
    @property
    def overall_score(self) -> float:
        """Overall compliance score percentage."""
        return self.run.overall_score
    
    @property
    def failed_rules(self) -> List[RuleResult]:
        """List of rules that failed."""
        return [r for r in self.run.rule_results if r.status == RuleStatus.FAIL]
    
    @property
    def critical_failures(self) -> List[RuleResult]:
        """List of critical severity failures."""
        return [r for r in self.failed_rules if r.severity == RuleSeverity.CRITICAL]


class RollbackPoint(BaseModel):
    """Represents a point-in-time snapshot for rollback."""
    rollback_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    run_id: str  # Associated hardening run
    system_info: SystemInfo
    
    # Backup data
    config_backups: Dict[str, str] = Field(default_factory=dict, description="File path -> backup content")
    registry_backups: Dict[str, Any] = Field(default_factory=dict, description="Windows registry backups")
    service_states: Dict[str, str] = Field(default_factory=dict, description="Service states before changes")
    
    # Metadata
    description: Optional[str] = None
    file_checksums: Dict[str, str] = Field(default_factory=dict, description="File integrity checksums")
    encrypted: bool = False
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }