"""
Multi-Platform System Hardening Tool

A comprehensive security compliance enforcer for Windows, Ubuntu, and CentOS
based on CIS Benchmarks and NTRO requirements.
"""

__version__ = "1.0.0"
__author__ = "Amey"

from .core.orchestrator import HardeningTool
from .core.models import HardeningResult, RuleResult

__all__ = ["HardeningTool", "HardeningResult", "RuleResult"]