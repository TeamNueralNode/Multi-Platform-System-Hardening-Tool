#!/usr/bin/env python3
"""
Web GUI for Multi-Platform System Hardening Tool.

Provides web interface for rule management, audit/apply operations, and reporting.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, render_template_string, request, jsonify, send_file, redirect, url_for, flash

# Add hardening_tool to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from hardening_tool.core.orchestrator import HardeningOrchestrator
    from hardening_tool.rules.loader import RuleLoader
    from hardening_tool.database.manager import DatabaseManager
    from hardening_tool.utils.os_detection import detect_os
    ORCHESTRATOR_AVAILABLE = True
except ImportError:
    ORCHESTRATOR_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'hardening-tool-secret-key-change-in-production'

# Global state for live updates
live_logs = []
current_operation = None
operation_status = "idle"


class LogCapture:
    """Capture logs for live viewing in web interface."""
    
    def __init__(self):
        self.logs = []
        
    def add_log(self, level: str, message: str):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'message': message
        }
        self.logs.append(log_entry)
        live_logs.append(log_entry)
        
        # Keep only last 100 logs
        if len(live_logs) > 100:
            live_logs.pop(0)


log_capture = LogCapture()


def get_orchestrator():
    """Get orchestrator instance if available."""
    if ORCHESTRATOR_AVAILABLE:
        try:
            return HardeningOrchestrator()
        except Exception as e:
            log_capture.add_log('ERROR', f'Failed to create orchestrator: {e}')
    return None


def run_cli_command(args: List[str]) -> Dict:
    """Run CLI command and capture output."""
    try:
        cmd = [sys.executable, '-m', 'hardening_tool.cli'] + args
        log_capture.add_log('INFO', f'Running command: {" ".join(cmd)}')
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        
        if result.returncode == 0:
            log_capture.add_log('SUCCESS', 'Command completed successfully')
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {'output': result.stdout, 'success': True}
        else:
            log_capture.add_log('ERROR', f'Command failed: {result.stderr}')
            return {'error': result.stderr, 'success': False}
            
    except subprocess.TimeoutExpired:
        log_capture.add_log('ERROR', 'Command timed out')
        return {'error': 'Operation timed out', 'success': False}
    except Exception as e:
        log_capture.add_log('ERROR', f'Command execution failed: {e}')
        return {'error': str(e), 'success': False}


def get_available_rules():
    """Get available hardening rules."""
    if ORCHESTRATOR_AVAILABLE:
        try:
            orchestrator = get_orchestrator()
            if orchestrator:
                rules = orchestrator.rule_loader.load_rules()
                return [
                    {
                        'id': rule.id,
                        'title': rule.title,
                        'category': rule.categories[0] if rule.categories else 'unknown',
                        'severity': rule.severity,
                        'platforms': rule.platforms,
                        'description': rule.description
                    }
                    for rule in rules
                ]
        except Exception as e:
            log_capture.add_log('ERROR', f'Failed to load rules: {e}')
    
    # Fallback to CLI
    result = run_cli_command(['rules', 'list', '--format', 'json'])
    if result.get('success'):
        return result.get('rules', [])
    
    return []


def get_rule_categories():
    """Get available rule categories."""
    rules = get_available_rules()
    categories = {}
    
    for rule in rules:
        category = rule.get('category', 'unknown')
        if category not in categories:
            categories[category] = []
        categories[category].append(rule)
    
    return categories


def background_operation(operation_type: str, rule_ids: List[str] = None, categories: List[str] = None, dry_run: bool = True):
    """Run operation in background thread."""
    global current_operation, operation_status
    
    operation_status = "running"
    current_operation = {
        'type': operation_type,
        'start_time': datetime.now().isoformat(),
        'rule_ids': rule_ids,
        'categories': categories,
        'dry_run': dry_run
    }
    
    try:
        log_capture.add_log('INFO', f'Starting {operation_type} operation')
        
        # Build CLI command
        args = [operation_type]
        
        if rule_ids:
            args.extend(['--rules', ','.join(rule_ids)])
        
        if categories:
            args.extend(['--categories', ','.join(categories)])
        
        if dry_run:
            args.append('--dry-run')
        
        args.extend(['--format', 'json', '--output', '/tmp/hardening_operation_result.json'])
        
        # Run operation
        result = run_cli_command(args)
        
        if result.get('success'):
            log_capture.add_log('SUCCESS', f'{operation_type.capitalize()} operation completed successfully')
            current_operation['result'] = result
        else:
            log_capture.add_log('ERROR', f'{operation_type.capitalize()} operation failed: {result.get("error", "Unknown error")}')
            current_operation['error'] = result.get('error')
        
    except Exception as e:
        log_capture.add_log('ERROR', f'Background operation failed: {e}')
        current_operation['error'] = str(e)
    finally:
        operation_status = "completed"
        current_operation['end_time'] = datetime.now().isoformat()


# ============================================================================
# Flask Routes
# ============================================================================

@app.route('/')
def index():
    """Main dashboard."""
    system_info = detect_os() if ORCHESTRATOR_AVAILABLE else None
    categories = get_rule_categories()
    
    return render_template_string(INDEX_TEMPLATE, 
                                categories=categories,
                                system_info=system_info,
                                orchestrator_available=ORCHESTRATOR_AVAILABLE)


@app.route('/rules')
def rules():
    """Rules management page."""
    rules_list = get_available_rules()
    categories = get_rule_categories()
    
    return render_template_string(RULES_TEMPLATE, 
                                rules=rules_list,
                                categories=categories)


@app.route('/api/rules')
def api_rules():
    """API endpoint for rules."""
    return jsonify(get_available_rules())


@app.route('/api/categories')
def api_categories():
    """API endpoint for rule categories."""
    return jsonify(get_rule_categories())


@app.route('/api/system-info')
def api_system_info():
    """API endpoint for system information."""
    if ORCHESTRATOR_AVAILABLE:
        system_info = detect_os()
        return jsonify({
            'os_type': system_info.os_type.value,
            'os_version': system_info.os_version,
            'architecture': system_info.architecture
        })
    return jsonify({'error': 'System detection not available'})


@app.route('/api/audit', methods=['POST'])
def api_audit():
    """Run audit operation."""
    global operation_status
    
    if operation_status == "running":
        return jsonify({'error': 'Another operation is already running'}), 409
    
    data = request.get_json() or {}
    rule_ids = data.get('rule_ids', [])
    categories = data.get('categories', [])
    
    # Start background operation
    thread = threading.Thread(
        target=background_operation,
        args=('audit', rule_ids, categories, True)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({'message': 'Audit started', 'status': 'running'})


@app.route('/api/apply', methods=['POST'])
def api_apply():
    """Run apply operation."""
    global operation_status
    
    if operation_status == "running":
        return jsonify({'error': 'Another operation is already running'}), 409
    
    data = request.get_json() or {}
    rule_ids = data.get('rule_ids', [])
    categories = data.get('categories', [])
    dry_run = data.get('dry_run', True)
    
    # Start background operation
    thread = threading.Thread(
        target=background_operation,
        args=('apply', rule_ids, categories, dry_run)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({'message': 'Apply started', 'status': 'running'})


@app.route('/api/logs')
def api_logs():
    """Get live logs."""
    return jsonify({
        'logs': live_logs[-50:],  # Return last 50 logs
        'operation_status': operation_status,
        'current_operation': current_operation
    })


@app.route('/api/operation-status')
def api_operation_status():
    """Get current operation status."""
    return jsonify({
        'status': operation_status,
        'operation': current_operation
    })


@app.route('/logs')
def logs_page():
    """Live logs page."""
    return render_template_string(LOGS_TEMPLATE)


@app.route('/reports')
def reports_page():
    """Reports page."""
    # Get available reports from database
    reports = []
    if ORCHESTRATOR_AVAILABLE:
        try:
            db_manager = DatabaseManager()
            runs = db_manager.get_recent_runs(limit=10)
            reports = [
                {
                    'run_id': run.run_id,
                    'operation': run.operation,
                    'start_time': run.start_time,
                    'status': run.status,
                    'score': getattr(run, 'overall_score', 0)
                }
                for run in runs
            ]
        except Exception as e:
            log_capture.add_log('ERROR', f'Failed to load reports: {e}')
    
    return render_template_string(REPORTS_TEMPLATE, reports=reports)


@app.route('/api/generate-report/<run_id>')
def api_generate_report(run_id):
    """Generate PDF report for a run."""
    try:
        # Import PDF generator
        from pdf_report_generator import render_pdf_report
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_file.close()
        
        # Generate report
        success = render_pdf_report(
            run_id=run_id,
            db_path='hardening_tool.db',
            out_pdf=temp_file.name
        )
        
        if success:
            log_capture.add_log('SUCCESS', f'Report generated for run {run_id}')
            return send_file(
                temp_file.name,
                as_attachment=True,
                download_name=f'hardening-report-{run_id}.pdf',
                mimetype='application/pdf'
            )
        else:
            return jsonify({'error': 'Failed to generate report'}), 500
            
    except ImportError:
        return jsonify({'error': 'PDF report generator not available'}), 501
    except Exception as e:
        log_capture.add_log('ERROR', f'Report generation failed: {e}')
        return jsonify({'error': str(e)}), 500


# ============================================================================
# HTML Templates
# ============================================================================

INDEX_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>System Hardening Tool - Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .header { text-align: center; margin-bottom: 30px; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 15px; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
        .nav a:hover { background: #0056b3; }
        .card { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 6px; }
        .system-info { background: #e7f3ff; }
        .categories { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
        .category-card { background: #f8f9fa; border-left: 4px solid #28a745; }
        .btn { padding: 8px 16px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-primary { background: #007bff; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-warning { background: #ffc107; color: black; }
        .btn-danger { background: #dc3545; color: white; }
        .btn:hover { opacity: 0.8; }
        .operation-status { margin: 20px 0; padding: 15px; background: #fff3cd; border-radius: 6px; }
        .logs-preview { background: #f8f9fa; padding: 15px; border-radius: 6px; max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ System Hardening Tool</h1>
            <p>Multi-Platform Security Configuration Management</p>
        </div>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/rules">Rules</a>
            <a href="/logs">Live Logs</a>
            <a href="/reports">Reports</a>
        </div>
        
        {% if system_info %}
        <div class="card system-info">
            <h3>System Information</h3>
            <p><strong>OS Type:</strong> {{ system_info.os_type.value }}</p>
            <p><strong>OS Version:</strong> {{ system_info.os_version }}</p>
            <p><strong>Architecture:</strong> {{ system_info.architecture }}</p>
            <p><strong>Orchestrator:</strong> {{ "Available" if orchestrator_available else "CLI Only" }}</p>
        </div>
        {% endif %}
        
        <div class="card">
            <h3>Quick Actions</h3>
            <button class="btn btn-primary" onclick="runFullAudit()">🔍 Full System Audit</button>
            <button class="btn btn-warning" onclick="runDryRunApply()">🧪 Dry Run Apply (All Rules)</button>
            <button class="btn btn-success" onclick="viewLogs()">📋 View Live Logs</button>
            <button class="btn btn-danger" onclick="generateReport()">📄 Generate Latest Report</button>
        </div>
        
        <div class="operation-status" id="operationStatus" style="display: none;">
            <h4>Current Operation</h4>
            <p id="statusMessage">No operation running</p>
            <div id="progressInfo"></div>
        </div>
        
        <div class="card">
            <h3>Rule Categories ({{ categories|length }} categories)</h3>
            <div class="categories">
                {% for category, rules in categories.items() %}
                <div class="card category-card">
                    <h4>{{ category.replace('_', ' ').title() }}</h4>
                    <p>{{ rules|length }} rules</p>
                    <button class="btn btn-primary" onclick="auditCategory('{{ category }}')">Audit {{ category.title() }}</button>
                    <button class="btn btn-warning" onclick="applyCategory('{{ category }}')">Apply {{ category.title() }} (Dry Run)</button>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="card">
            <h3>Recent Logs</h3>
            <div class="logs-preview" id="logsPreview">
                Loading logs...
            </div>
        </div>
    </div>

    <script>
        function runFullAudit() {
            fetch('/api/audit', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({})
            })
            .then(response => response.json())
            .then(data => {
                alert('Full audit started. Check logs for progress.');
                updateStatus();
            });
        }
        
        function runDryRunApply() {
            if (confirm('Run dry-run apply on all rules? This will show what changes would be made.')) {
                fetch('/api/apply', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({dry_run: true})
                })
                .then(response => response.json())
                .then(data => {
                    alert('Dry-run apply started. Check logs for progress.');
                    updateStatus();
                });
            }
        }
        
        function auditCategory(category) {
            fetch('/api/audit', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({categories: [category]})
            })
            .then(response => response.json())
            .then(data => {
                alert(`Audit started for category: ${category}`);
                updateStatus();
            });
        }
        
        function applyCategory(category) {
            if (confirm(`Apply hardening rules for category: ${category}? (Dry run mode)`)) {
                fetch('/api/apply', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({categories: [category], dry_run: true})
                })
                .then(response => response.json())
                .then(data => {
                    alert(`Apply started for category: ${category}`);
                    updateStatus();
                });
            }
        }
        
        function viewLogs() {
            window.location.href = '/logs';
        }
        
        function generateReport() {
            alert('Report generation feature available in Reports section');
            window.location.href = '/reports';
        }
        
        function updateStatus() {
            fetch('/api/operation-status')
                .then(response => response.json())
                .then(data => {
                    const statusDiv = document.getElementById('operationStatus');
                    const messageEl = document.getElementById('statusMessage');
                    
                    if (data.status === 'running') {
                        statusDiv.style.display = 'block';
                        messageEl.textContent = `Running ${data.operation?.type} operation...`;
                    } else if (data.status === 'completed') {
                        statusDiv.style.display = 'block';
                        messageEl.textContent = 'Operation completed. Check logs for details.';
                        setTimeout(() => {
                            statusDiv.style.display = 'none';
                        }, 5000);
                    } else {
                        statusDiv.style.display = 'none';
                    }
                });
        }
        
        function updateLogs() {
            fetch('/api/logs')
                .then(response => response.json())
                .then(data => {
                    const logsDiv = document.getElementById('logsPreview');
                    if (data.logs && data.logs.length > 0) {
                        logsDiv.innerHTML = data.logs.slice(-10).map(log => 
                            `<div>[${log.timestamp}] ${log.level}: ${log.message}</div>`
                        ).join('');
                        logsDiv.scrollTop = logsDiv.scrollHeight;
                    }
                    
                    // Update operation status
                    updateStatus();
                });
        }
        
        // Update logs every 2 seconds
        setInterval(updateLogs, 2000);
        
        // Initial load
        updateLogs();
    </script>
</body>
</html>
'''

RULES_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>System Hardening Tool - Rules</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 15px; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
        .nav a:hover { background: #0056b3; }
        .search-box { width: 100%; padding: 10px; margin: 20px 0; border: 1px solid #ddd; border-radius: 4px; }
        .rule-card { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 6px; }
        .rule-header { display: flex; justify-content: between; align-items: center; }
        .rule-title { font-weight: bold; color: #333; }
        .rule-category { background: #007bff; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px; }
        .rule-severity { padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: black; }
        .severity-low { background: #28a745; color: white; }
        .rule-actions { margin-top: 10px; }
        .btn { padding: 6px 12px; margin: 2px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .btn-primary { background: #007bff; color: white; }
        .btn-warning { background: #ffc107; color: black; }
        .btn:hover { opacity: 0.8; }
        .selected-rules { position: fixed; bottom: 20px; right: 20px; background: white; padding: 15px; border: 2px solid #007bff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.2); }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Rules Management</h1>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/rules">Rules</a>
            <a href="/logs">Live Logs</a>
            <a href="/reports">Reports</a>
        </div>
        
        <input type="text" class="search-box" id="searchBox" placeholder="Search rules by ID, title, or category..." onkeyup="filterRules()">
        
        <div style="margin: 20px 0;">
            <strong>Total Rules: {{ rules|length }}</strong>
            <button class="btn btn-primary" onclick="selectAllVisible()">Select All Visible</button>
            <button class="btn btn-warning" onclick="clearSelection()">Clear Selection</button>
        </div>
        
        <div id="rulesContainer">
            {% for rule in rules %}
            <div class="rule-card" data-rule-id="{{ rule.id }}" data-category="{{ rule.category }}" data-title="{{ rule.title }}">
                <div class="rule-header">
                    <div>
                        <span class="rule-title">{{ rule.title }}</span>
                        <span class="rule-category">{{ rule.category }}</span>
                        <span class="rule-severity severity-{{ rule.severity }}">{{ rule.severity.upper() }}</span>
                    </div>
                    <input type="checkbox" class="rule-checkbox" value="{{ rule.id }}" onchange="updateSelection()">
                </div>
                <div style="margin: 8px 0; font-family: monospace; font-size: 12px; color: #666;">
                    ID: {{ rule.id }}
                </div>
                <div style="margin: 8px 0;">
                    {{ rule.description or 'No description available' }}
                </div>
                <div style="font-size: 12px; color: #888;">
                    Platforms: {{ rule.platforms|join(', ') }}
                </div>
                <div class="rule-actions">
                    <button class="btn btn-primary" onclick="auditRule('{{ rule.id }}')">Audit</button>
                    <button class="btn btn-warning" onclick="applyRule('{{ rule.id }}')">Apply (Dry Run)</button>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <div class="selected-rules" id="selectedRules" style="display: none;">
            <h4>Selected Rules (<span id="selectedCount">0</span>)</h4>
            <div id="selectedList"></div>
            <div style="margin-top: 10px;">
                <button class="btn btn-primary" onclick="auditSelected()">Audit Selected</button>
                <button class="btn btn-warning" onclick="applySelected()">Apply Selected (Dry Run)</button>
            </div>
        </div>
    </div>

    <script>
        let selectedRules = new Set();
        
        function filterRules() {
            const searchTerm = document.getElementById('searchBox').value.toLowerCase();
            const rules = document.querySelectorAll('.rule-card');
            
            rules.forEach(rule => {
                const ruleId = rule.dataset.ruleId.toLowerCase();
                const category = rule.dataset.category.toLowerCase();
                const title = rule.dataset.title.toLowerCase();
                
                if (ruleId.includes(searchTerm) || category.includes(searchTerm) || title.includes(searchTerm)) {
                    rule.style.display = 'block';
                } else {
                    rule.style.display = 'none';
                }
            });
        }
        
        function selectAllVisible() {
            const visibleCheckboxes = document.querySelectorAll('.rule-card:not([style*="display: none"]) .rule-checkbox');
            visibleCheckboxes.forEach(checkbox => {
                checkbox.checked = true;
                selectedRules.add(checkbox.value);
            });
            updateSelection();
        }
        
        function clearSelection() {
            selectedRules.clear();
            document.querySelectorAll('.rule-checkbox').forEach(checkbox => {
                checkbox.checked = false;
            });
            updateSelection();
        }
        
        function updateSelection() {
            selectedRules.clear();
            document.querySelectorAll('.rule-checkbox:checked').forEach(checkbox => {
                selectedRules.add(checkbox.value);
            });
            
            const selectedDiv = document.getElementById('selectedRules');
            const countSpan = document.getElementById('selectedCount');
            const listDiv = document.getElementById('selectedList');
            
            countSpan.textContent = selectedRules.size;
            
            if (selectedRules.size > 0) {
                selectedDiv.style.display = 'block';
                listDiv.innerHTML = Array.from(selectedRules).slice(0, 5).join('<br>') + 
                    (selectedRules.size > 5 ? '<br>...' : '');
            } else {
                selectedDiv.style.display = 'none';
            }
        }
        
        function auditRule(ruleId) {
            fetch('/api/audit', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({rule_ids: [ruleId]})
            })
            .then(response => response.json())
            .then(data => {
                alert(`Audit started for rule: ${ruleId}`);
            });
        }
        
        function applyRule(ruleId) {
            if (confirm(`Apply hardening rule: ${ruleId}? (Dry run mode)`)) {
                fetch('/api/apply', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({rule_ids: [ruleId], dry_run: true})
                })
                .then(response => response.json())
                .then(data => {
                    alert(`Apply started for rule: ${ruleId}`);
                });
            }
        }
        
        function auditSelected() {
            if (selectedRules.size === 0) {
                alert('No rules selected');
                return;
            }
            
            fetch('/api/audit', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({rule_ids: Array.from(selectedRules)})
            })
            .then(response => response.json())
            .then(data => {
                alert(`Audit started for ${selectedRules.size} selected rules`);
            });
        }
        
        function applySelected() {
            if (selectedRules.size === 0) {
                alert('No rules selected');
                return;
            }
            
            if (confirm(`Apply ${selectedRules.size} selected rules? (Dry run mode)`)) {
                fetch('/api/apply', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({rule_ids: Array.from(selectedRules), dry_run: true})
                })
                .then(response => response.json())
                .then(data => {
                    alert(`Apply started for ${selectedRules.size} selected rules`);
                });
            }
        }
    </script>
</body>
</html>
'''

LOGS_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>System Hardening Tool - Live Logs</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 15px; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
        .nav a:hover { background: #0056b3; }
        .logs-container { background: #1a1a1a; color: #00ff00; padding: 20px; border-radius: 6px; height: 500px; overflow-y: auto; font-family: monospace; font-size: 14px; }
        .log-entry { margin: 2px 0; }
        .log-INFO { color: #00ff00; }
        .log-SUCCESS { color: #00ff00; font-weight: bold; }
        .log-ERROR { color: #ff4444; font-weight: bold; }
        .log-WARNING { color: #ffaa00; }
        .controls { margin: 20px 0; }
        .btn { padding: 8px 16px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-primary { background: #007bff; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-warning { background: #ffc107; color: black; }
        .btn-danger { background: #dc3545; color: white; }
        .status-bar { background: #f8f9fa; padding: 10px; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Live Logs</h1>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/rules">Rules</a>
            <a href="/logs">Live Logs</a>
            <a href="/reports">Reports</a>
        </div>
        
        <div class="status-bar">
            <div id="operationStatus">Status: <span id="statusText">Idle</span></div>
            <div id="operationDetails"></div>
        </div>
        
        <div class="controls">
            <button class="btn btn-primary" onclick="clearLogs()">Clear Logs</button>
            <button class="btn btn-success" onclick="toggleAutoScroll()">Toggle Auto-Scroll</button>
            <button class="btn btn-warning" onclick="exportLogs()">Export Logs</button>
            <label>
                <input type="checkbox" id="autoRefresh" checked> Auto-Refresh (2s)
            </label>
        </div>
        
        <div class="logs-container" id="logsContainer">
            <div class="log-entry">Waiting for logs...</div>
        </div>
    </div>

    <script>
        let autoScroll = true;
        let logEntries = [];
        
        function updateLogs() {
            fetch('/api/logs')
                .then(response => response.json())
                .then(data => {
                    // Update operation status
                    const statusText = document.getElementById('statusText');
                    const operationDetails = document.getElementById('operationDetails');
                    
                    statusText.textContent = data.operation_status || 'Idle';
                    
                    if (data.current_operation) {
                        operationDetails.innerHTML = `
                            <div>Operation: ${data.current_operation.type || 'Unknown'}</div>
                            <div>Started: ${data.current_operation.start_time || 'Unknown'}</div>
                        `;
                    } else {
                        operationDetails.innerHTML = '';
                    }
                    
                    // Update logs
                    if (data.logs && data.logs.length > 0) {
                        const logsContainer = document.getElementById('logsContainer');
                        
                        // Clear if we have new logs
                        if (logEntries.length === 0 || data.logs.length < logEntries.length) {
                            logEntries = data.logs;
                            logsContainer.innerHTML = '';
                        } else {
                            // Add only new logs
                            const newLogs = data.logs.slice(logEntries.length);
                            logEntries = data.logs;
                            
                            newLogs.forEach(log => {
                                const logDiv = document.createElement('div');
                                logDiv.className = `log-entry log-${log.level}`;
                                logDiv.textContent = `[${log.timestamp}] ${log.level}: ${log.message}`;
                                logsContainer.appendChild(logDiv);
                            });
                        }
                        
                        if (logEntries.length === 0) {
                            data.logs.forEach(log => {
                                const logDiv = document.createElement('div');
                                logDiv.className = `log-entry log-${log.level}`;
                                logDiv.textContent = `[${log.timestamp}] ${log.level}: ${log.message}`;
                                logsContainer.appendChild(logDiv);
                            });
                        }
                        
                        // Auto-scroll to bottom
                        if (autoScroll) {
                            logsContainer.scrollTop = logsContainer.scrollHeight;
                        }
                    }
                })
                .catch(error => {
                    console.error('Failed to fetch logs:', error);
                });
        }
        
        function clearLogs() {
            logEntries = [];
            document.getElementById('logsContainer').innerHTML = '<div class="log-entry">Logs cleared.</div>';
        }
        
        function toggleAutoScroll() {
            autoScroll = !autoScroll;
            alert(`Auto-scroll ${autoScroll ? 'enabled' : 'disabled'}`);
        }
        
        function exportLogs() {
            const logs = logEntries.map(log => `[${log.timestamp}] ${log.level}: ${log.message}`).join('\\n');
            const blob = new Blob([logs], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `hardening-logs-${new Date().toISOString()}.txt`;
            a.click();
            URL.revokeObjectURL(url);
        }
        
        // Auto-refresh logs
        function startAutoRefresh() {
            const checkbox = document.getElementById('autoRefresh');
            if (checkbox.checked) {
                setTimeout(() => {
                    updateLogs();
                    startAutoRefresh();
                }, 2000);
            } else {
                setTimeout(startAutoRefresh, 1000);
            }
        }
        
        // Initial load and start auto-refresh
        updateLogs();
        startAutoRefresh();
    </script>
</body>
</html>
'''

REPORTS_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>System Hardening Tool - Reports</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 15px; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
        .nav a:hover { background: #0056b3; }
        .report-card { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 6px; }
        .report-header { display: flex; justify-content: space-between; align-items: center; }
        .report-status { padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .status-completed { background: #d4edda; color: #155724; }
        .status-failed { background: #f8d7da; color: #721c24; }
        .status-running { background: #fff3cd; color: #856404; }
        .btn { padding: 8px 16px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-primary { background: #007bff; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn:hover { opacity: 0.8; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Reports</h1>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/rules">Rules</a>
            <a href="/logs">Live Logs</a>
            <a href="/reports">Reports</a>
        </div>
        
        <div style="margin: 20px 0;">
            <p>Available compliance reports from recent hardening operations.</p>
        </div>
        
        {% if reports %}
            {% for report in reports %}
            <div class="report-card">
                <div class="report-header">
                    <div>
                        <h4>{{ report.operation.title() }} Operation</h4>
                        <p style="margin: 5px 0; color: #666; font-family: monospace;">ID: {{ report.run_id }}</p>
                        <p style="margin: 5px 0;">Started: {{ report.start_time }}</p>
                        {% if report.score %}
                        <p style="margin: 5px 0;">Compliance Score: <strong>{{ report.score }}%</strong></p>
                        {% endif %}
                    </div>
                    <div>
                        <span class="report-status status-{{ report.status }}">{{ report.status.upper() }}</span>
                    </div>
                </div>
                <div style="margin-top: 10px;">
                    <button class="btn btn-primary" onclick="generateReport('{{ report.run_id }}')">📄 Download PDF Report</button>
                    <button class="btn btn-success" onclick="viewRunDetails('{{ report.run_id }}')">📋 View Details</button>
                </div>
            </div>
            {% endfor %}
        {% else %}
        <div class="report-card">
            <h4>No Reports Available</h4>
            <p>Run an audit or apply operation to generate compliance reports.</p>
            <button class="btn btn-primary" onclick="window.location.href='/'">Go to Dashboard</button>
        </div>
        {% endif %}
    </div>

    <script>
        function generateReport(runId) {
            // Show loading message
            const button = event.target;
            const originalText = button.textContent;
            button.textContent = '⏳ Generating...';
            button.disabled = true;
            
            // Generate and download report
            fetch(`/api/generate-report/${runId}`)
                .then(response => {
                    if (response.ok) {
                        return response.blob();
                    } else {
                        throw new Error('Report generation failed');
                    }
                })
                .then(blob => {
                    // Create download link
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `hardening-report-${runId}.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                    
                    alert('Report downloaded successfully!');
                })
                .catch(error => {
                    alert('Failed to generate report: ' + error.message);
                })
                .finally(() => {
                    button.textContent = originalText;
                    button.disabled = false;
                });
        }
        
        function viewRunDetails(runId) {
            alert(`Run details for ${runId} - This would show detailed audit results and rule statuses.`);
            // In a full implementation, this would open a detailed view
        }
    </script>
</body>
</html>
'''


if __name__ == '__main__':
    print("🛡️ Multi-Platform System Hardening Tool - Web GUI")
    print("=" * 50)
    
    if ORCHESTRATOR_AVAILABLE:
        print("✅ Orchestrator available - Full functionality enabled")
    else:
        print("⚠️ Orchestrator not available - Using CLI fallback mode")
    
    try:
        system_info = detect_os() if ORCHESTRATOR_AVAILABLE else None
        if system_info:
            print(f"🖥️ System: {system_info.os_type.value} {system_info.os_version}")
    except Exception as e:
        print(f"⚠️ System detection failed: {e}")
    
    print("\n🚀 Starting Flask web server...")
    print("📱 Web interface will be available at: http://localhost:5000")
    print("🔒 Note: This is a development server - use proper WSGI server for production")
    print("\n" + "=" * 50)
    
    # Initialize with some sample logs
    log_capture.add_log('INFO', 'Flask GUI started successfully')
    log_capture.add_log('INFO', f'Orchestrator status: {"Available" if ORCHESTRATOR_AVAILABLE else "CLI only"}')
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)