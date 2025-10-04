"""
Report generator for compliance and hardening results.

Generates PDF, HTML, and JSON reports with detailed compliance
information, recommendations, and executive summaries.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from jinja2 import Template
from weasyprint import HTML, CSS

from ..core.models import HardeningRun, RuleStatus


class ReportGenerator:
    """
    Generates compliance reports in multiple formats.
    
    Creates professional reports with compliance scores,
    detailed findings, and remediation recommendations.
    """
    
    def __init__(self):
        """Initialize report generator."""
        self.templates_dir = Path(__file__).parent / "templates"
        self._ensure_templates_exist()
    
    def generate_report(self, run: HardeningRun,
                       format: str = "pdf",
                       output_path: Optional[str] = None,
                       template_path: Optional[str] = None) -> str:
        """
        Generate a compliance report.
        
        Args:
            run: Hardening run data to report on
            format: Report format (pdf, html, json)
            output_path: Output file path (auto-generated if None)
            template_path: Custom template file path
            
        Returns:
            str: Path to generated report file
        """
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"hardening_report_{timestamp}.{format}"
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        if format.lower() == "json":
            return self._generate_json_report(run, output_file)
        elif format.lower() == "html":
            return self._generate_html_report(run, output_file, template_path)
        elif format.lower() == "pdf":
            return self._generate_pdf_report(run, output_file, template_path)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def _generate_json_report(self, run: HardeningRun, output_file: Path) -> str:
        """Generate JSON format report."""
        report_data = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "report_type": "hardening_compliance",
                "version": "1.0"
            },
            "run_summary": {
                "run_id": run.run_id,
                "operation": run.operation,
                "started_at": run.started_at.isoformat(),
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                "overall_score": run.overall_score,
                "success": run.success
            },
            "system_info": run.system_info.dict(),
            "compliance_summary": {
                "total_rules": run.total_rules,
                "passed_rules": run.passed_rules,
                "failed_rules": run.failed_rules,
                "error_rules": run.error_rules,
                "skipped_rules": run.skipped_rules
            },
            "rule_results": [result.dict() for result in run.rule_results]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return str(output_file)
    
    def _generate_html_report(self, run: HardeningRun, output_file: Path, 
                            template_path: Optional[str] = None) -> str:
        """Generate HTML format report."""
        if template_path:
            template_file = Path(template_path)
        else:
            template_file = self.templates_dir / "compliance_report.html"
        
        with open(template_file, 'r') as f:
            template_content = f.read()
        
        template = Template(template_content)
        
        # Prepare data for template
        context = self._prepare_template_context(run)
        
        html_content = template.render(**context)
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return str(output_file)
    
    def _generate_pdf_report(self, run: HardeningRun, output_file: Path,
                           template_path: Optional[str] = None) -> str:
        """Generate PDF format report."""
        # First generate HTML
        html_file = output_file.with_suffix('.tmp.html')
        self._generate_html_report(run, html_file, template_path)
        
        try:
            # Convert HTML to PDF
            css_file = self.templates_dir / "report_styles.css"
            
            html_doc = HTML(filename=str(html_file))
            
            if css_file.exists():
                css = CSS(filename=str(css_file))
                html_doc.write_pdf(str(output_file), stylesheets=[css])
            else:
                html_doc.write_pdf(str(output_file))
            
            return str(output_file)
            
        finally:
            # Clean up temporary HTML file
            if html_file.exists():
                html_file.unlink()
    
    def _prepare_template_context(self, run: HardeningRun) -> Dict:
        """Prepare context data for template rendering."""
        # Categorize results
        passed_results = [r for r in run.rule_results if r.status == RuleStatus.PASS]
        failed_results = [r for r in run.rule_results if r.status == RuleStatus.FAIL]
        error_results = [r for r in run.rule_results if r.status == RuleStatus.ERROR]
        critical_failures = [r for r in failed_results if r.severity.value == "critical"]
        
        # Calculate compliance level
        if run.overall_score >= 90:
            compliance_level = "Excellent"
            compliance_color = "#28a745"
        elif run.overall_score >= 75:
            compliance_level = "Good"
            compliance_color = "#ffc107"
        elif run.overall_score >= 50:
            compliance_level = "Fair"
            compliance_color = "#fd7e14"
        else:
            compliance_level = "Poor"
            compliance_color = "#dc3545"
        
        return {
            "run": run,
            "report_generated_at": datetime.utcnow().strftime("%B %d, %Y at %I:%M %p UTC"),
            "passed_results": passed_results,
            "failed_results": failed_results,
            "error_results": error_results,
            "critical_failures": critical_failures,
            "compliance_level": compliance_level,
            "compliance_color": compliance_color,
            "has_failures": len(failed_results) > 0,
            "has_errors": len(error_results) > 0,
            "has_critical_failures": len(critical_failures) > 0
        }
    
    def _ensure_templates_exist(self) -> None:
        """Create default templates if they don't exist."""
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Create HTML template
        html_template = self.templates_dir / "compliance_report.html"
        if not html_template.exists():
            self._create_html_template(html_template)
        
        # Create CSS styles
        css_template = self.templates_dir / "report_styles.css"
        if not css_template.exists():
            self._create_css_template(css_template)
    
    def _create_html_template(self, template_file: Path) -> None:
        """Create default HTML template."""
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Hardening Compliance Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; border-bottom: 3px solid #007bff; padding-bottom: 20px; }
        .score-card { background: linear-gradient(135deg, {{ compliance_color }}, {{ compliance_color }}aa); color: white; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; }
        .score-number { font-size: 3em; font-weight: bold; margin: 10px 0; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; border-left: 4px solid #007bff; }
        .metric-value { font-size: 2em; font-weight: bold; color: #007bff; }
        .metric-label { color: #6c757d; text-transform: uppercase; font-size: 0.85em; }
        .section { margin: 30px 0; }
        .section-title { color: #343a40; border-bottom: 2px solid #007bff; padding-bottom: 10px; font-size: 1.5em; }
        .rule-item { background: #fff; border: 1px solid #dee2e6; border-radius: 6px; padding: 15px; margin: 10px 0; }
        .rule-header { display: flex; justify-content: between; align-items: center; margin-bottom: 10px; }
        .rule-title { font-weight: bold; color: #343a40; }
        .status-pass { background: #28a745; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .status-fail { background: #dc3545; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .status-error { background: #ffc107; color: #212529; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>System Hardening Compliance Report</h1>
            <p><strong>System:</strong> {{ run.system_info.hostname }} ({{ run.system_info.os_type.value.title() }} {{ run.system_info.os_version }})</p>
            <p><strong>Generated:</strong> {{ report_generated_at }}</p>
            <p><strong>Run ID:</strong> {{ run.run_id }}</p>
        </div>

        <div class="score-card">
            <h2>Overall Compliance Score</h2>
            <div class="score-number">{{ "%.1f"|format(run.overall_score) }}%</div>
            <div>{{ compliance_level }} Compliance</div>
        </div>

        <div class="metrics">
            <div class="metric">
                <div class="metric-value">{{ run.total_rules }}</div>
                <div class="metric-label">Total Rules</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #28a745;">{{ run.passed_rules }}</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #dc3545;">{{ run.failed_rules }}</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #ffc107;">{{ run.error_rules }}</div>
                <div class="metric-label">Errors</div>
            </div>
        </div>

        {% if has_critical_failures %}
        <div class="section">
            <h2 class="section-title" style="color: #dc3545;">🚨 Critical Failures</h2>
            {% for result in critical_failures %}
            <div class="rule-item" style="border-left: 4px solid #dc3545;">
                <div class="rule-header">
                    <span class="rule-title">{{ result.rule_title }}</span>
                    <span class="status-fail">CRITICAL</span>
                </div>
                <p><strong>Rule ID:</strong> {{ result.rule_id }}</p>
                {% if result.message %}
                <p><strong>Issue:</strong> {{ result.message }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if has_failures %}
        <div class="section">
            <h2 class="section-title">❌ Failed Rules</h2>
            {% for result in failed_results %}
            <div class="rule-item">
                <div class="rule-header">
                    <span class="rule-title">{{ result.rule_title }}</span>
                    <div>
                        <span class="severity-{{ result.severity.value }}">{{ result.severity.value.upper() }}</span>
                        <span class="status-fail">FAIL</span>
                    </div>
                </div>
                <p><strong>Rule ID:</strong> {{ result.rule_id }}</p>
                {% if result.message %}
                <p><strong>Issue:</strong> {{ result.message }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <div class="section">
            <h2 class="section-title">✅ Passed Rules</h2>
            {% for result in passed_results %}
            <div class="rule-item">
                <div class="rule-header">
                    <span class="rule-title">{{ result.rule_title }}</span>
                    <span class="status-pass">PASS</span>
                </div>
                <p><strong>Rule ID:</strong> {{ result.rule_id }}</p>
            </div>
            {% endfor %}
        </div>

        {% if has_errors %}
        <div class="section">
            <h2 class="section-title">⚠️ Execution Errors</h2>
            {% for result in error_results %}
            <div class="rule-item">
                <div class="rule-header">
                    <span class="rule-title">{{ result.rule_title }}</span>
                    <span class="status-error">ERROR</span>
                </div>
                <p><strong>Rule ID:</strong> {{ result.rule_id }}</p>
                {% if result.message %}
                <p><strong>Error:</strong> {{ result.message }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <div class="footer">
            <p>Report generated by Multi-Platform System Hardening Tool</p>
            <p>Based on CIS Benchmarks and NTRO Security Guidelines</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(template_file, 'w') as f:
            f.write(html_content)
    
    def _create_css_template(self, css_file: Path) -> None:
        """Create default CSS styles for PDF generation."""
        css_content = """
        @page {
            size: A4;
            margin: 1in;
        }
        
        body {
            font-family: 'DejaVu Sans', sans-serif;
            font-size: 12px;
            line-height: 1.4;
        }
        
        .container {
            max-width: none;
            margin: 0;
            padding: 0;
            background: white;
            box-shadow: none;
            border-radius: 0;
        }
        
        .page-break {
            page-break-before: always;
        }
        
        .no-break {
            page-break-inside: avoid;
        }
        """
        
        with open(css_file, 'w') as f:
            f.write(css_content)