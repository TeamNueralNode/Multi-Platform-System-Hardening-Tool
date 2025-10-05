#!/usr/bin/env python3
"""
PDF Report Generation Function
Renders hardening tool reports to PDF using HTML template and WeasyPrint
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False

try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


@dataclass
class RuleReportData:
    """Data structure for rule report information."""
    rule_id: str
    title: str
    description: str
    category: str
    severity: str
    status: str
    message: str
    current_value: str
    expected_value: str
    previous_value: str
    execution_time: float
    remediation_applied: bool


def get_run_data(run_id: str, db_path: str) -> Optional[Dict[str, Any]]:
    """Retrieve run data from SQLite database."""
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Get run information
            cursor = conn.execute("SELECT * FROM hardening_runs WHERE run_id = ?", (run_id,))
            run_row = cursor.fetchone()
            
            if not run_row:
                return None
            
            run_data = dict(run_row)
            
            # Get rule results
            cursor = conn.execute("""
                SELECT * FROM rule_results 
                WHERE run_id = ? 
                ORDER BY timestamp
            """, (run_id,))
            
            results = [dict(row) for row in cursor.fetchall()]
            run_data['results'] = results
            
            return run_data
            
    except Exception as e:
        print(f"Error retrieving run data: {e}")
        return None


def load_rule_definitions(rules_dir: str, os_type: str) -> Dict[str, Dict[str, Any]]:
    """Load rule definitions from YAML files."""
    rules_dict = {}
    
    try:
        import yaml
        
        if os_type.lower() == 'windows':
            rules_file = Path(rules_dir) / 'windows_security_rules.yaml'
        elif os_type.lower() == 'linux':
            rules_file = Path(rules_dir) / 'linux_security_rules.yaml'
        else:
            return rules_dict
        
        if rules_file.exists():
            with open(rules_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict) and 'rules' in data:
                    for rule in data['rules']:
                        rule_id = rule.get('id', '')
                        if rule_id:
                            rules_dict[rule_id] = rule
    
    except Exception as e:
        print(f"Warning: Could not load rule definitions: {e}")
    
    return rules_dict


def prepare_report_data(run_data: Dict[str, Any], rules_definitions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Prepare and structure data for report template."""
    
    # Calculate duration
    start_time = datetime.fromisoformat(run_data['start_time'])
    end_time = datetime.fromisoformat(run_data['end_time']) if run_data['end_time'] else start_time
    duration = (end_time - start_time).total_seconds()
    
    # Calculate compliance percentage
    total_rules = run_data.get('rules_total', 0)
    passed_rules = run_data.get('rules_passed', 0)
    compliance_percentage = (passed_rules / total_rules * 100) if total_rules > 0 else 0
    
    # Process rule results
    rules_by_category = defaultdict(list)
    
    for result in run_data.get('results', []):
        rule_id = result.get('rule_id', '')
        rule_def = rules_definitions.get(rule_id, {})
        
        # Get previous value from rollback data if available
        previous_value = "N/A"
        # Note: In a complete implementation, you might query rollback_manifest table
        # to get the previous value before remediation was applied
        
        rule_data = RuleReportData(
            rule_id=rule_id,
            title=rule_def.get('title', rule_id.replace('_', ' ').title()),
            description=rule_def.get('description', 'No description available'),
            category=rule_def.get('category', 'uncategorized'),
            severity=rule_def.get('severity', 'medium'),
            status=result.get('status', 'unknown'),
            message=result.get('message', ''),
            current_value=result.get('current_value', ''),
            expected_value=result.get('expected_value', ''),
            previous_value=previous_value,
            execution_time=result.get('execution_time', 0.0),
            remediation_applied=result.get('remediation_applied', False)
        )
        
        rules_by_category[rule_data.category].append(rule_data)
    
    # Sort categories and rules within categories
    sorted_categories = {}
    for category in sorted(rules_by_category.keys()):
        sorted_categories[category] = sorted(
            rules_by_category[category], 
            key=lambda x: (x.severity, x.rule_id)
        )
    
    # Prepare template data
    template_data = {
        'run_id': run_data['run_id'],
        'operation_type': run_data['operation_type'].upper(),
        'run_status': run_data['status'].upper(),
        'os_type': run_data['os_type'].title(),
        'os_version': 'Unknown',  # You might want to store this in run_metadata table
        'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
        'duration': f"{duration:.1f} seconds",
        'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'rules_total': run_data.get('rules_total', 0),
        'rules_passed': run_data.get('rules_passed', 0),
        'rules_failed': run_data.get('rules_failed', 0),
        'rules_applied': run_data.get('rules_applied', 0),
        'rules_errors': run_data.get('rules_errors', 0),
        'rules_skipped': run_data.get('rules_skipped', 0),
        'compliance_percentage': round(compliance_percentage, 1),
        'rules_by_category': sorted_categories
    }
    
    return template_data


def render_html_report(template_data: Dict[str, Any], template_path: str) -> str:
    """Render HTML report using Jinja2 template."""
    if not JINJA2_AVAILABLE:
        raise ImportError("Jinja2 is required for template rendering. Install with: pip install Jinja2")
    
    template_file = Path(template_path)
    
    if not template_file.exists():
        raise FileNotFoundError(f"Template file not found: {template_path}")
    
    # Setup Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(template_file.parent),
        autoescape=True
    )
    
    # Load template
    template = env.get_template(template_file.name)
    
    # Render template with data
    html_content = template.render(**template_data)
    
    return html_content


def render_pdf_report(run_id: str, db_path: str, out_pdf: str, 
                     template_path: str = "report_template.html",
                     rules_dir: str = "rules/definitions") -> bool:
    """
    Generate PDF report from hardening run data.
    
    Args:
        run_id: ID of the hardening run to report on
        db_path: Path to SQLite database file
        out_pdf: Output PDF file path
        template_path: Path to HTML template file
        rules_dir: Directory containing rule definition YAML files
    
    Returns:
        bool: True if report generation succeeded, False otherwise
    """
    
    try:
        # Check dependencies
        if not (WEASYPRINT_AVAILABLE or PDFKIT_AVAILABLE):
            raise ImportError(
                "Neither WeasyPrint nor pdfkit is available. "
                "Install one of: 'pip install weasyprint' or 'pip install pdfkit'"
            )
        
        # Retrieve run data from database
        print(f"Retrieving run data for ID: {run_id}")
        run_data = get_run_data(run_id, db_path)
        
        if not run_data:
            print(f"Error: Run ID '{run_id}' not found in database")
            return False
        
        # Load rule definitions
        print("Loading rule definitions...")
        os_type = run_data.get('os_type', 'unknown')
        rule_definitions = load_rule_definitions(rules_dir, os_type)
        
        # Prepare template data
        print("Preparing report data...")
        template_data = prepare_report_data(run_data, rule_definitions)
        
        # Render HTML content
        print("Rendering HTML template...")
        html_content = render_html_report(template_data, template_path)
        
        # Generate PDF
        print(f"Generating PDF: {out_pdf}")
        
        if WEASYPRINT_AVAILABLE:
            # Use WeasyPrint (preferred method)
            try:
                # Create CSS for better PDF formatting
                pdf_css = CSS(string="""
                    @page {
                        margin: 1in;
                        size: A4;
                        @bottom-center {
                            content: "Page " counter(page) " of " counter(pages);
                            font-size: 10px;
                            color: #666;
                        }
                    }
                    
                    .page-break {
                        page-break-before: always;
                    }
                    
                    .no-break {
                        page-break-inside: avoid;
                    }
                """)
                
                html_doc = HTML(string=html_content)
                html_doc.write_pdf(out_pdf, stylesheets=[pdf_css])
                
            except Exception as e:
                print(f"WeasyPrint failed: {e}")
                if PDFKIT_AVAILABLE:
                    print("Falling back to pdfkit...")
                    # Use pdfkit as fallback
                    pdfkit.from_string(html_content, out_pdf, options={
                        'page-size': 'A4',
                        'margin-top': '1in',
                        'margin-right': '1in',
                        'margin-bottom': '1in',
                        'margin-left': '1in',
                        'encoding': "UTF-8",
                        'no-outline': None,
                        'enable-local-file-access': None
                    })
                else:
                    raise
        
        elif PDFKIT_AVAILABLE:
            # Use pdfkit (requires wkhtmltopdf binary)
            pdfkit.from_string(html_content, out_pdf, options={
                'page-size': 'A4',
                'margin-top': '1in',
                'margin-right': '1in', 
                'margin-bottom': '1in',
                'margin-left': '1in',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None
            })
        
        print(f"PDF report generated successfully: {out_pdf}")
        
        # Verify output file exists and has content
        output_path = Path(out_pdf)
        if output_path.exists() and output_path.stat().st_size > 0:
            file_size = output_path.stat().st_size
            print(f"Report size: {file_size:,} bytes")
            return True
        else:
            print("Error: Output file is empty or was not created")
            return False
            
    except Exception as e:
        print(f"Error generating PDF report: {e}")
        return False


def main():
    """CLI function for testing PDF generation."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate PDF report from hardening run')
    parser.add_argument('run_id', help='Run ID to generate report for')
    parser.add_argument('--db-path', default='hardening_tool.db', help='Database file path')
    parser.add_argument('--output', '-o', default='hardening_report.pdf', help='Output PDF file')
    parser.add_argument('--template', default='report_template.html', help='HTML template file')
    parser.add_argument('--rules-dir', default='rules/definitions', help='Rules directory')
    
    args = parser.parse_args()
    
    success = render_pdf_report(
        run_id=args.run_id,
        db_path=args.db_path,
        out_pdf=args.output,
        template_path=args.template,
        rules_dir=args.rules_dir
    )
    
    if success:
        print("Report generation completed successfully!")
        return 0
    else:
        print("Report generation failed!")
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())