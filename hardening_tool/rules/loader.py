"""
Rule loader for managing hardening rule definitions.

Loads hardening rules from YAML files and provides filtering
and lookup functionality for platform-specific rules.
"""

from pathlib import Path
from typing import List, Optional

import yaml

from ..core.models import HardeningRule, OSType, RuleSeverity


class RuleLoader:
    """
    Manages loading and filtering of hardening rules.
    
    Loads rules from YAML definition files and provides
    methods to filter and retrieve rules based on platform,
    category, and other criteria.
    """
    
    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize rule loader.
        
        Args:
            rules_dir: Directory containing rule YAML files (uses default if None)
        """
        if rules_dir:
            self.rules_dir = Path(rules_dir)
        else:
            # Default to rules directory in package
            self.rules_dir = Path(__file__).parent / "definitions"
        
        self._rules_cache: Optional[List[HardeningRule]] = None
    
    def get_rules(self, platform: Optional[OSType] = None,
                  category: Optional[str] = None,
                  severity: Optional[RuleSeverity] = None) -> List[HardeningRule]:
        """
        Get hardening rules with optional filtering.
        
        Args:
            platform: Filter by platform type
            category: Filter by rule category
            severity: Filter by severity level
            
        Returns:
            List[HardeningRule]: Filtered list of rules
        """
        rules = self._load_all_rules()
        
        # Apply filters
        if platform:
            rules = [r for r in rules if platform in r.platforms]
        
        if category:
            rules = [r for r in rules if category in r.categories]
        
        if severity:
            rules = [r for r in rules if r.severity == severity]
        
        return rules
    
    def get_rule_by_id(self, rule_id: str) -> Optional[HardeningRule]:
        """
        Get a specific rule by its ID.
        
        Args:
            rule_id: Unique rule identifier
            
        Returns:
            Optional[HardeningRule]: Rule if found, None otherwise
        """
        rules = self._load_all_rules()
        
        for rule in rules:
            if rule.id == rule_id:
                return rule
        
        return None
    
    def reload_rules(self) -> None:
        """Force reload of rules from files."""
        self._rules_cache = None
    
    def _load_all_rules(self) -> List[HardeningRule]:
        """Load all rules from YAML files with caching."""
        if self._rules_cache is not None:
            return self._rules_cache
        
        rules = []
        
        # Create rules directory with sample rules if it doesn't exist
        if not self.rules_dir.exists():
            self._create_sample_rules()
        
        # Load rules from YAML files
        for yaml_file in self.rules_dir.glob("*.yaml"):
            try:
                with open(yaml_file, 'r') as f:
                    data = yaml.safe_load(f)
                
                # Handle both single rule and multiple rules in one file
                if isinstance(data, dict) and 'rules' in data:
                    # Multiple rules format
                    for rule_data in data['rules']:
                        rule = self._parse_rule(rule_data)
                        if rule:
                            rules.append(rule)
                elif isinstance(data, dict):
                    # Single rule format
                    rule = self._parse_rule(data)
                    if rule:
                        rules.append(rule)
                elif isinstance(data, list):
                    # List of rules
                    for rule_data in data:
                        rule = self._parse_rule(rule_data)
                        if rule:
                            rules.append(rule)
                            
            except Exception as e:
                # Log error but continue loading other files
                print(f"Warning: Failed to load rules from {yaml_file}: {e}")
                continue
        
        self._rules_cache = rules
        return rules
    
    def _parse_rule(self, rule_data: dict) -> Optional[HardeningRule]:
        """Parse a rule dictionary into a HardeningRule object."""
        try:
            # Convert platform strings to OSType enums
            platforms = []
            for platform_str in rule_data.get('platforms', []):
                try:
                    platforms.append(OSType(platform_str.lower()))
                except ValueError:
                    continue  # Skip invalid platforms
            
            # Convert severity string to enum
            severity_str = rule_data.get('severity', 'medium')
            try:
                severity = RuleSeverity(severity_str.lower())
            except ValueError:
                severity = RuleSeverity.MEDIUM
            
            rule = HardeningRule(
                id=rule_data['id'],
                title=rule_data['title'],
                description=rule_data.get('description', ''),
                severity=severity,
                platforms=platforms,
                categories=rule_data.get('categories', []),
                cis_benchmark=rule_data.get('cis_benchmark'),
                ntro_reference=rule_data.get('ntro_reference'),
                remediation_steps=rule_data.get('remediation_steps', []),
                audit_command=rule_data.get('audit_command'),
                apply_command=rule_data.get('apply_command'),
                rollback_command=rule_data.get('rollback_command'),
                config_files=rule_data.get('config_files', []),
                backup_files=rule_data.get('backup_files', []),
                expected_values=rule_data.get('expected_values', {})
            )
            
            return rule
            
        except KeyError as e:
            print(f"Warning: Rule missing required field {e}: {rule_data}")
            return None
        except Exception as e:
            print(f"Warning: Failed to parse rule {rule_data.get('id', 'unknown')}: {e}")
            return None
    
    def _create_sample_rules(self) -> None:
        """Create sample rule files if rules directory doesn't exist."""
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Create Linux SSH rules
        linux_ssh_rules = {
            "rules": [
                {
                    "id": "ssh_disable_root_login",
                    "title": "Disable SSH Root Login",
                    "description": "Disable direct root login via SSH to prevent unauthorized access",
                    "severity": "high",
                    "platforms": ["ubuntu", "centos"],
                    "categories": ["ssh", "authentication"],
                    "cis_benchmark": "5.2.8",
                    "ntro_reference": "Annexure-A: SSH Hardening",
                    "remediation_steps": [
                        "Edit /etc/ssh/sshd_config",
                        "Set 'PermitRootLogin no'",
                        "Restart SSH service"
                    ],
                    "config_files": ["/etc/ssh/sshd_config"],
                    "backup_files": ["/etc/ssh/sshd_config"],
                    "expected_values": {
                        "PermitRootLogin": "no"
                    }
                },
                {
                    "id": "ssh_disable_password_auth",
                    "title": "Disable SSH Password Authentication",
                    "description": "Force SSH key-based authentication only",
                    "severity": "medium",
                    "platforms": ["ubuntu", "centos"],
                    "categories": ["ssh", "authentication"],
                    "cis_benchmark": "5.2.10",
                    "audit_command": "grep -E '^\\s*PasswordAuthentication\\s+no' /etc/ssh/sshd_config",
                    "apply_command": "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload sshd",
                    "config_files": ["/etc/ssh/sshd_config"]
                }
            ]
        }
        
        # Create Windows SMB rules
        windows_smb_rules = {
            "rules": [
                {
                    "id": "smb_disable_v1",
                    "title": "Disable SMBv1 Protocol",
                    "description": "Disable the insecure SMBv1 protocol to prevent exploitation",
                    "severity": "critical",
                    "platforms": ["windows"],
                    "categories": ["smb", "network"],
                    "cis_benchmark": "18.3.1",
                    "ntro_reference": "Annexure-B: Network Protocol Security",
                    "remediation_steps": [
                        "Open PowerShell as Administrator",
                        "Run: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
                        "Restart system when convenient"
                    ],
                    "expected_values": {
                        "SMB1Protocol": "Disabled"
                    }
                }
            ]
        }
        
        # Write sample rule files
        with open(self.rules_dir / "linux_ssh.yaml", 'w') as f:
            yaml.safe_dump(linux_ssh_rules, f, default_flow_style=False, indent=2)
        
        with open(self.rules_dir / "windows_smb.yaml", 'w') as f:
            yaml.safe_dump(windows_smb_rules, f, default_flow_style=False, indent=2)