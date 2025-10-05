#!/usr/bin/env python3
"""
Desktop GUI for Multi-Platform System Hardening Tool

A comprehensive desktop application built with tkinter for system security hardening.
Provides an intuitive interface for auditing, applying rules, and generating reports.
"""

import json
import os
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk, messagebox, filedialog, scrolledtext
from typing import Dict, List, Optional

# Add hardening_tool to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from hardening_tool.core.orchestrator import HardeningTool
    from hardening_tool.rules.loader import RuleLoader
    from hardening_tool.database.manager import DatabaseManager
    from hardening_tool.utils.os_detection import detect_os, is_admin
    HARDENING_TOOL_AVAILABLE = True
except ImportError:
    HARDENING_TOOL_AVAILABLE = False
    # Fallback function for demo mode
    def is_admin():
        """Check if running with admin privileges (fallback)."""
        import os
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    def detect_os():
        """Detect OS (fallback)."""
        import platform
        return platform.system().lower()


class HardeningToolGUI:
    """Main GUI application for the hardening tool."""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Multi-Platform System Hardening Tool")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Initialize variables
        self.current_os = None
        self.available_rules = []
        self.selected_rules = []
        self.audit_results = {}
        self.operation_running = False
        
        # Initialize hardening tool if available
        if HARDENING_TOOL_AVAILABLE:
            try:
                self.hardening_tool = HardeningTool()
                self.current_os = detect_os()
            except Exception as e:
                self.hardening_tool = None
                messagebox.showerror("Initialization Error", f"Failed to initialize hardening tool: {e}")
        else:
            self.hardening_tool = None
            
        # Setup GUI
        self.setup_styles()
        self.create_menu()
        self.create_main_interface()
        self.load_initial_data()
        
    def setup_styles(self):
        """Configure GUI styling."""
        style = ttk.Style()
        
        # Configure colors and fonts
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 10))
        
        # Configure button styles
        style.configure('Action.TButton', font=('Arial', 10, 'bold'))
        style.configure('Success.TButton', background='green', foreground='white')
        style.configure('Warning.TButton', background='orange', foreground='white')
        style.configure('Danger.TButton', background='red', foreground='white')
        
    def create_menu(self):
        """Create the application menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Audit Results", command=self.export_results)
        file_menu.add_command(label="Import Rules", command=self.import_rules)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Generate PDF Report", command=self.generate_pdf_report)
        tools_menu.add_command(label="View Rollback Points", command=self.view_rollback_points)
        tools_menu.add_command(label="System Information", command=self.show_system_info)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        
    def create_main_interface(self):
        """Create the main application interface."""
        # Create main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title and status
        self.create_header(main_frame)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create tabs
        self.create_overview_tab()
        self.create_audit_tab()
        self.create_rules_tab()
        self.create_apply_tab()
        self.create_reports_tab()
        self.create_logs_tab()
        
    def create_header(self, parent):
        """Create the header section with title and status."""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        title_label = ttk.Label(
            header_frame,
            text="🛡️ Multi-Platform System Hardening Tool",
            style='Title.TLabel'
        )
        title_label.pack(side=tk.LEFT)
        
        # Status frame
        status_frame = ttk.Frame(header_frame)
        status_frame.pack(side=tk.RIGHT)
        
        # OS detection
        if self.current_os:
            os_label = ttk.Label(status_frame, text=f"OS: {self.current_os.title()}")
            os_label.pack(side=tk.TOP, anchor=tk.E)
        
        # Admin status with helpful info
        if is_admin():
            admin_status = "Administrator ✅"
            admin_tooltip = "Full privileges available"
        else:
            admin_status = "Standard User ⚠️"
            admin_tooltip = "Limited to audit and dry-run mode"
        
        self.admin_label = ttk.Label(status_frame, text=f"Privileges: {admin_status}")
        self.admin_label.pack(side=tk.TOP, anchor=tk.E)
        
        # Tool status
        tool_status = "Available" if HARDENING_TOOL_AVAILABLE else "Not Available"
        self.status_label = ttk.Label(status_frame, text=f"Tool Status: {tool_status}")
        self.status_label.pack(side=tk.TOP, anchor=tk.E)
        
    def create_overview_tab(self):
        """Create the overview/dashboard tab."""
        overview_frame = ttk.Frame(self.notebook)
        self.notebook.add(overview_frame, text="📊 Overview")
        
        # System information section
        sys_frame = ttk.LabelFrame(overview_frame, text="System Information", padding=10)
        sys_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.system_info_text = scrolledtext.ScrolledText(sys_frame, height=8, width=50)
        self.system_info_text.pack(fill=tk.BOTH, expand=True)
        
        # Quick actions section
        actions_frame = ttk.LabelFrame(overview_frame, text="Quick Actions", padding=10)
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(
            actions_frame,
            text="🔍 Quick Audit",
            command=self.quick_audit,
            style='Action.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            actions_frame,
            text="📋 Load Rules",
            command=self.load_rules,
            style='Action.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            actions_frame,
            text="📊 Generate Report",
            command=self.generate_report,
            style='Action.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        # Recent activity section
        activity_frame = ttk.LabelFrame(overview_frame, text="Recent Activity", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.activity_text = scrolledtext.ScrolledText(activity_frame, height=10)
        self.activity_text.pack(fill=tk.BOTH, expand=True)
        
    def create_audit_tab(self):
        """Create the audit tab."""
        audit_frame = ttk.Frame(self.notebook)
        self.notebook.add(audit_frame, text="🔍 Audit")
        
        # Control panel
        control_frame = ttk.LabelFrame(audit_frame, text="Audit Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Audit options
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill=tk.X)
        
        ttk.Label(options_frame, text="Audit Scope:").pack(side=tk.LEFT)
        
        self.audit_scope = tk.StringVar(value="all")
        ttk.Radiobutton(options_frame, text="All Rules", variable=self.audit_scope, value="all").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(options_frame, text="Selected Rules", variable=self.audit_scope, value="selected").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(options_frame, text="Category", variable=self.audit_scope, value="category").pack(side=tk.LEFT, padx=10)
        
        # Category selection
        category_frame = ttk.Frame(control_frame)
        category_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(category_frame, text="Category:").pack(side=tk.LEFT)
        self.category_var = tk.StringVar()
        self.category_combo = ttk.Combobox(
            category_frame,
            textvariable=self.category_var,
            values=["ssh", "firewall", "pam", "system", "network"]
        )
        self.category_combo.pack(side=tk.LEFT, padx=10)
        
        # Audit button
        self.audit_button = ttk.Button(
            control_frame,
            text="🔍 Run Security Audit",
            command=self.run_audit,
            style='Action.TButton'
        )
        self.audit_button.pack(pady=10)
        
        # Progress bar
        self.audit_progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.audit_progress.pack(fill=tk.X, pady=5)
        
        # Results section
        results_frame = ttk.LabelFrame(audit_frame, text="Audit Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Results tree
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=("rule_id", "title", "status", "severity", "message"),
            show="tree headings"
        )
        
        # Configure columns
        self.results_tree.heading("#0", text="Rule")
        self.results_tree.heading("rule_id", text="ID")
        self.results_tree.heading("title", text="Title")
        self.results_tree.heading("status", text="Status")
        self.results_tree.heading("severity", text="Severity")
        self.results_tree.heading("message", text="Details")
        
        # Configure column widths
        self.results_tree.column("#0", width=50)
        self.results_tree.column("rule_id", width=150)
        self.results_tree.column("title", width=200)
        self.results_tree.column("status", width=80)
        self.results_tree.column("severity", width=80)
        self.results_tree.column("message", width=300)
        
        # Add scrollbars
        results_scrollbar_v = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        results_scrollbar_h = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=results_scrollbar_v.set, xscrollcommand=results_scrollbar_h.set)
        
        # Pack tree and scrollbars
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar_v.pack(side=tk.RIGHT, fill=tk.Y)
        results_scrollbar_h.pack(side=tk.BOTTOM, fill=tk.X)
        
    def create_rules_tab(self):
        """Create the rules management tab."""
        rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(rules_frame, text="📋 Rules")
        
        # Rules list frame
        list_frame = ttk.LabelFrame(rules_frame, text="Available Rules", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Filter frame
        filter_frame = ttk.Frame(list_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        self.rule_filter = tk.StringVar()
        self.rule_filter.trace('w', self.filter_rules)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.rule_filter)
        filter_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        ttk.Button(filter_frame, text="🔄 Refresh", command=self.load_rules).pack(side=tk.RIGHT)
        
        # Rules tree
        self.rules_tree = ttk.Treeview(
            list_frame,
            columns=("id", "title", "category", "severity", "platform"),
            show="tree headings"
        )
        
        # Configure columns
        self.rules_tree.heading("#0", text="Select")
        self.rules_tree.heading("id", text="Rule ID")
        self.rules_tree.heading("title", text="Title")
        self.rules_tree.heading("category", text="Category")
        self.rules_tree.heading("severity", text="Severity")
        self.rules_tree.heading("platform", text="Platform")
        
        # Configure column widths
        self.rules_tree.column("#0", width=60)
        self.rules_tree.column("id", width=150)
        self.rules_tree.column("title", width=250)
        self.rules_tree.column("category", width=100)
        self.rules_tree.column("severity", width=80)
        self.rules_tree.column("platform", width=100)
        
        # Add scrollbar
        rules_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=rules_scrollbar.set)
        
        # Pack tree and scrollbar
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rules_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Rule details frame
        details_frame = ttk.LabelFrame(rules_frame, text="Rule Details", padding=10)
        details_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.rule_details_text = scrolledtext.ScrolledText(details_frame, height=8)
        self.rule_details_text.pack(fill=tk.BOTH, expand=True)
        
        # Bind tree selection
        self.rules_tree.bind('<<TreeviewSelect>>', self.on_rule_select)
        
    def create_apply_tab(self):
        """Create the apply/hardening tab."""
        apply_frame = ttk.Frame(self.notebook)
        self.notebook.add(apply_frame, text="🔧 Apply")
        
        # Warning frame
        warning_frame = ttk.LabelFrame(apply_frame, text="⚠️ Security Warning", padding=10)
        warning_frame.pack(fill=tk.X, padx=10, pady=5)
        
        if is_admin():
            warning_text = (
                "⚠️ CAUTION: Applying hardening rules will modify system configurations. "
                "Always run audit first and use dry-run mode to preview changes. "
                "Create rollback points for safe recovery. You have administrative privileges."
            )
        else:
            warning_text = (
                "ℹ️ INFO: You are running as a standard user. You can use dry-run mode to "
                "safely preview changes, but administrative privileges are required to "
                "apply actual system modifications. See the help button below for guidance."
            )
        ttk.Label(warning_frame, text=warning_text, wraplength=800).pack()
        
        # Apply controls
        control_frame = ttk.LabelFrame(apply_frame, text="Apply Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Options
        self.dry_run_var = tk.BooleanVar(value=True)
        self.create_rollback_var = tk.BooleanVar(value=True)
        self.interactive_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(control_frame, text="Dry Run (Preview only)", variable=self.dry_run_var).pack(anchor=tk.W)
        ttk.Checkbutton(control_frame, text="Create Rollback Point", variable=self.create_rollback_var).pack(anchor=tk.W)
        ttk.Checkbutton(control_frame, text="Interactive Mode", variable=self.interactive_var).pack(anchor=tk.W)
        
        # Apply button
        self.apply_button = ttk.Button(
            control_frame,
            text="🔧 Apply Hardening Rules",
            command=self.apply_hardening,
            style='Warning.TButton'
        )
        self.apply_button.pack(pady=10)
        
        # Privilege help button for standard users
        if not is_admin():
            help_button = ttk.Button(
                control_frame,
                text="ℹ️ Need Admin Privileges?",
                command=self.show_privilege_help,
                style='Action.TButton'
            )
            help_button.pack(pady=5)
        
        # Progress
        self.apply_progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.apply_progress.pack(fill=tk.X, pady=5)
        
        # Results
        apply_results_frame = ttk.LabelFrame(apply_frame, text="Apply Results", padding=10)
        apply_results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.apply_results_text = scrolledtext.ScrolledText(apply_results_frame)
        self.apply_results_text.pack(fill=tk.BOTH, expand=True)
        
    def create_reports_tab(self):
        """Create the reports tab."""
        reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(reports_frame, text="📊 Reports")
        
        # Report generation controls
        gen_frame = ttk.LabelFrame(reports_frame, text="Generate Report", padding=10)
        gen_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Format selection
        format_frame = ttk.Frame(gen_frame)
        format_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(format_frame, text="Format:").pack(side=tk.LEFT)
        self.report_format = tk.StringVar(value="pdf")
        ttk.Radiobutton(format_frame, text="PDF", variable=self.report_format, value="pdf").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(format_frame, text="HTML", variable=self.report_format, value="html").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(format_frame, text="JSON", variable=self.report_format, value="json").pack(side=tk.LEFT, padx=10)
        
        # Include options
        options_frame = ttk.Frame(gen_frame)
        options_frame.pack(fill=tk.X, pady=5)
        
        self.include_details_var = tk.BooleanVar(value=True)
        self.include_remediation_var = tk.BooleanVar(value=True)
        self.include_charts_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Include Details", variable=self.include_details_var).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(options_frame, text="Include Remediation", variable=self.include_remediation_var).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(options_frame, text="Include Charts", variable=self.include_charts_var).pack(side=tk.LEFT, padx=10)
        
        # Generate button
        ttk.Button(
            gen_frame,
            text="📊 Generate Report",
            command=self.generate_report,
            style='Action.TButton'
        ).pack(pady=10)
        
        # Report history
        history_frame = ttk.LabelFrame(reports_frame, text="Report History", padding=10)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.report_history_tree = ttk.Treeview(
            history_frame,
            columns=("timestamp", "format", "size", "status"),
            show="tree headings"
        )
        
        self.report_history_tree.heading("#0", text="Report")
        self.report_history_tree.heading("timestamp", text="Generated")
        self.report_history_tree.heading("format", text="Format")
        self.report_history_tree.heading("size", text="Size")
        self.report_history_tree.heading("status", text="Status")
        
        self.report_history_tree.pack(fill=tk.BOTH, expand=True)
        
    def create_logs_tab(self):
        """Create the logs/console tab."""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📝 Logs")
        
        # Log controls
        control_frame = ttk.Frame(logs_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(control_frame, text="🔄 Refresh", command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🗑️ Clear", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="💾 Save", command=self.save_logs).pack(side=tk.LEFT, padx=5)
        
        # Log level filter
        ttk.Label(control_frame, text="Level:").pack(side=tk.RIGHT, padx=5)
        self.log_level = tk.StringVar(value="ALL")
        level_combo = ttk.Combobox(
            control_frame,
            textvariable=self.log_level,
            values=["ALL", "DEBUG", "INFO", "WARNING", "ERROR"],
            width=10
        )
        level_combo.pack(side=tk.RIGHT, padx=5)
        
        # Log display
        self.log_text = scrolledtext.ScrolledText(
            logs_frame,
            font=('Consolas', 9),
            bg='black',
            fg='white'
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
    def load_initial_data(self):
        """Load initial data when the application starts."""
        self.log_message("INFO", "Application started")
        self.update_system_info()
        self.load_rules()
        
    def update_system_info(self):
        """Update the system information display."""
        if not self.hardening_tool:
            info = "Hardening tool not available. Running in demo mode.\n"
            info += "Install required dependencies to enable full functionality."
        else:
            info = f"Operating System: {self.current_os or 'Unknown'}\n"
            info += f"Architecture: {os.uname().machine if hasattr(os, 'uname') else 'Unknown'}\n"
            info += f"Python Version: {sys.version}\n"
            info += f"Tool Status: {'Available' if HARDENING_TOOL_AVAILABLE else 'Not Available'}\n"
            info += f"Admin Rights: {'Yes' if is_admin() else 'No'}\n"
            info += f"Database: {'Connected' if self.hardening_tool else 'Not Connected'}\n"
        
        self.system_info_text.delete(1.0, tk.END)
        self.system_info_text.insert(tk.END, info)
        
    def load_rules(self):
        """Load available hardening rules."""
        try:
            self.log_message("INFO", "Loading hardening rules...")
            
            if not self.hardening_tool:
                # Demo mode - create sample rules
                self.available_rules = [
                    {
                        "id": "ssh_disable_root_login",
                        "title": "Disable SSH Root Login",
                        "category": "ssh",
                        "severity": "HIGH",
                        "platforms": ["linux"],
                        "description": "Prevents direct root login via SSH for enhanced security."
                    },
                    {
                        "id": "firewall_enable_ufw",
                        "title": "Enable UFW Firewall",
                        "category": "firewall", 
                        "severity": "HIGH",
                        "platforms": ["ubuntu"],
                        "description": "Enables and configures UFW firewall with secure defaults."
                    },
                    {
                        "id": "pam_password_complexity",
                        "title": "Enforce Password Complexity",
                        "category": "pam",
                        "severity": "MEDIUM",
                        "platforms": ["linux"],
                        "description": "Enforces strong password complexity requirements."
                    }
                ]
            else:
                # Load actual rules from the hardening tool
                rule_loader = RuleLoader("hardening_tool/rules/definitions")
                self.available_rules = rule_loader.load_rules()
            
            self.update_rules_tree()
            self.log_message("INFO", f"Loaded {len(self.available_rules)} rules")
            
        except Exception as e:
            self.log_message("ERROR", f"Failed to load rules: {e}")
            messagebox.showerror("Error", f"Failed to load rules: {e}")
            
    def update_rules_tree(self):
        """Update the rules tree view."""
        # Clear existing items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        # Add rules
        for rule in self.available_rules:
            platforms = ", ".join(rule.get("platforms", []))
            self.rules_tree.insert(
                "",
                tk.END,
                text="☐",
                values=(
                    rule.get("id", ""),
                    rule.get("title", ""),
                    rule.get("category", ""),
                    rule.get("severity", ""),
                    platforms
                )
            )
    
    def filter_rules(self, *args):
        """Filter rules based on search text."""
        filter_text = self.rule_filter.get().lower()
        
        # Clear tree
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        # Add filtered rules
        for rule in self.available_rules:
            if (not filter_text or 
                filter_text in rule.get("id", "").lower() or
                filter_text in rule.get("title", "").lower() or
                filter_text in rule.get("category", "").lower()):
                
                platforms = ", ".join(rule.get("platforms", []))
                self.rules_tree.insert(
                    "",
                    tk.END,
                    text="☐",
                    values=(
                        rule.get("id", ""),
                        rule.get("title", ""),
                        rule.get("category", ""),
                        rule.get("severity", ""),
                        platforms
                    )
                )
    
    def on_rule_select(self, event):
        """Handle rule selection in the tree."""
        selection = self.rules_tree.selection()
        if selection:
            item = self.rules_tree.item(selection[0])
            rule_id = item['values'][0]
            
            # Find rule details
            rule = next((r for r in self.available_rules if r.get("id") == rule_id), None)
            if rule:
                details = f"Rule ID: {rule.get('id', '')}\n"
                details += f"Title: {rule.get('title', '')}\n"
                details += f"Category: {rule.get('category', '')}\n"
                details += f"Severity: {rule.get('severity', '')}\n"
                details += f"Platforms: {', '.join(rule.get('platforms', []))}\n"
                details += f"CIS Reference: {rule.get('cis_benchmark', 'N/A')}\n\n"
                details += f"Description:\n{rule.get('description', 'No description available.')}"
                
                self.rule_details_text.delete(1.0, tk.END)
                self.rule_details_text.insert(tk.END, details)
    
    def quick_audit(self):
        """Run a quick security audit."""
        if self.operation_running:
            messagebox.showwarning("Operation Running", "An operation is already in progress.")
            return
            
        self.run_audit()
    
    def run_audit(self):
        """Run a comprehensive security audit."""
        if self.operation_running:
            messagebox.showwarning("Operation Running", "Please wait for current operation to complete.")
            return
        
        def audit_thread():
            try:
                self.operation_running = True
                self.audit_button.config(state='disabled')
                self.audit_progress.start()
                
                self.log_message("INFO", "Starting security audit...")
                
                if not self.hardening_tool:
                    # Demo mode
                    import time
                    time.sleep(2)  # Simulate work
                    results = {
                        "overall_score": 65.5,
                        "total_rules": 3,
                        "passed": 2,
                        "failed": 1,
                        "errors": 0,
                        "results": [
                            {
                                "rule_id": "ssh_disable_root_login",
                                "title": "Disable SSH Root Login",
                                "status": "PASS",
                                "severity": "HIGH",
                                "message": "SSH root login is properly disabled"
                            },
                            {
                                "rule_id": "firewall_enable_ufw",
                                "title": "Enable UFW Firewall", 
                                "status": "FAIL",
                                "severity": "HIGH",
                                "message": "UFW firewall is not enabled"
                            },
                            {
                                "rule_id": "pam_password_complexity",
                                "title": "Enforce Password Complexity",
                                "status": "PASS", 
                                "severity": "MEDIUM",
                                "message": "Password complexity is enforced"
                            }
                        ]
                    }
                else:
                    # Real audit
                    audit_results = self.hardening_tool.audit()
                    results = audit_results.dict() if hasattr(audit_results, 'dict') else audit_results
                
                self.root.after(0, self.display_audit_results, results)
                
            except Exception as e:
                self.root.after(0, lambda: self.log_message("ERROR", f"Audit failed: {e}"))
                self.root.after(0, lambda: messagebox.showerror("Audit Error", f"Audit failed: {e}"))
            finally:
                self.operation_running = False
                self.root.after(0, lambda: self.audit_button.config(state='normal'))
                self.root.after(0, self.audit_progress.stop)
        
        threading.Thread(target=audit_thread, daemon=True).start()
    
    def display_audit_results(self, results):
        """Display audit results in the tree."""
        # Clear existing results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Add results
        if isinstance(results, dict) and "results" in results:
            for result in results["results"]:
                status_icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(result["status"], "❓")
                
                self.results_tree.insert(
                    "",
                    tk.END,
                    text=status_icon,
                    values=(
                        result.get("rule_id", ""),
                        result.get("title", ""),
                        result.get("status", ""),
                        result.get("severity", ""),
                        result.get("message", "")
                    )
                )
        
        # Update activity log
        score = results.get("overall_score", 0) if isinstance(results, dict) else 0
        self.log_message("INFO", f"Audit completed. Overall score: {score}%")
        
        # Store results
        self.audit_results = results
    
    def apply_hardening(self):
        """Apply hardening rules to the system."""
        if not is_admin():
            result = messagebox.askyesnocancel(
                "Administrative Privileges Required", 
                "Administrative privileges are required to apply hardening rules.\n\n" +
                "Options:\n" +
                "• YES: Close GUI and restart with sudo/admin privileges\n" +
                "• NO: Continue in dry-run mode (safe preview only)\n" +
                "• CANCEL: Return to current screen\n\n" +
                "Would you like to enable dry-run mode for safe testing?"
            )
            if result is True:  # Yes - restart with sudo
                messagebox.showinfo(
                    "Restart Required",
                    "Please close this application and restart with:\n\n" +
                    "sudo python3 desktop_gui.py\n\n" +
                    "This will provide the necessary privileges for system modifications."
                )
                return
            elif result is False:  # No - force dry-run mode
                self.dry_run_var.set(True)
                messagebox.showinfo(
                    "Dry-Run Mode Enabled",
                    "Dry-run mode has been enabled. You can preview changes safely " +
                    "without modifying the system. To apply actual changes, restart " +
                    "with administrative privileges."
                )
                # Continue with dry-run
            else:  # Cancel
                return
        
        if not self.dry_run_var.get():
            result = messagebox.askyesno(
                "Confirm Apply", 
                "This will modify system configurations. Are you sure you want to proceed?"
            )
            if not result:
                return
        
        def apply_thread():
            try:
                self.operation_running = True
                self.apply_button.config(state='disabled')
                self.apply_progress.start()
                
                mode = "dry-run" if self.dry_run_var.get() else "apply"
                self.log_message("INFO", f"Starting hardening application ({mode} mode)...")
                
                if not self.hardening_tool:
                    # Demo mode
                    import time
                    time.sleep(3)
                    results = "Demo Mode: No actual changes were made.\n"
                    results += "In real mode, this would apply selected hardening rules.\n"
                    if self.dry_run_var.get():
                        results += "Dry run mode: Changes would be previewed without applying."
                else:
                    # Real application
                    apply_results = self.hardening_tool.apply(
                        dry_run=self.dry_run_var.get(),
                        create_rollback=self.create_rollback_var.get()
                    )
                    results = str(apply_results)
                
                self.root.after(0, self.display_apply_results, results)
                
            except Exception as e:
                error_msg = f"Apply operation failed: {e}"
                self.root.after(0, lambda: self.log_message("ERROR", error_msg))
                self.root.after(0, lambda: messagebox.showerror("Apply Error", error_msg))
            finally:
                self.operation_running = False
                self.root.after(0, lambda: self.apply_button.config(state='normal'))
                self.root.after(0, self.apply_progress.stop)
        
        threading.Thread(target=apply_thread, daemon=True).start()
    
    def display_apply_results(self, results):
        """Display apply operation results."""
        self.apply_results_text.delete(1.0, tk.END)
        self.apply_results_text.insert(tk.END, str(results))
        
        mode = "dry-run" if self.dry_run_var.get() else "live"
        self.log_message("INFO", f"Apply operation completed ({mode} mode)")
    
    def generate_report(self):
        """Generate a compliance report."""
        if not self.audit_results:
            messagebox.showwarning("No Data", "Please run an audit first to generate a report.")
            return
        
        # Get output file
        format_ext = {"pdf": ".pdf", "html": ".html", "json": ".json"}
        file_ext = format_ext.get(self.report_format.get(), ".txt")
        
        filename = filedialog.asksaveasfilename(
            title="Save Report",
            defaultextension=file_ext,
            filetypes=[
                ("PDF files", "*.pdf"),
                ("HTML files", "*.html"), 
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                self.log_message("INFO", f"Generating {self.report_format.get().upper()} report...")
                
                if self.report_format.get() == "json":
                    with open(filename, 'w') as f:
                        json.dump(self.audit_results, f, indent=2)
                elif self.report_format.get() == "html":
                    self.generate_html_report(filename)
                else:
                    self.generate_pdf_report_file(filename)
                
                self.log_message("INFO", f"Report saved to {filename}")
                messagebox.showinfo("Success", f"Report saved to {filename}")
                
            except Exception as e:
                error_msg = f"Failed to generate report: {e}"
                self.log_message("ERROR", error_msg)
                messagebox.showerror("Report Error", error_msg)
    
    def generate_html_report(self, filename):
        """Generate an HTML report."""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Hardening Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; }}
                .results {{ margin: 20px 0; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .pass {{ color: green; }}
                .fail {{ color: red; }}
                .error {{ color: orange; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Security Hardening Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>System: {self.current_os or 'Unknown'}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>Overall Score: <strong>{self.audit_results.get('overall_score', 0)}%</strong></p>
                <p>Total Rules: {self.audit_results.get('total_rules', 0)}</p>
                <p>Passed: {self.audit_results.get('passed', 0)}</p>
                <p>Failed: {self.audit_results.get('failed', 0)}</p>
                <p>Errors: {self.audit_results.get('errors', 0)}</p>
            </div>
            
            <div class="results">
                <h2>Detailed Results</h2>
                <table>
                    <tr>
                        <th>Rule ID</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Message</th>
                    </tr>
        """
        
        if "results" in self.audit_results:
            for result in self.audit_results["results"]:
                status_class = result["status"].lower()
                html_content += f"""
                    <tr>
                        <td>{result.get('rule_id', '')}</td>
                        <td>{result.get('title', '')}</td>
                        <td class="{status_class}">{result.get('status', '')}</td>
                        <td>{result.get('severity', '')}</td>
                        <td>{result.get('message', '')}</td>
                    </tr>
                """
        
        html_content += """
                </table>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
    
    def generate_pdf_report_file(self, filename):
        """Generate a PDF report (placeholder - would need additional libraries)."""
        # This is a placeholder implementation
        # In a real application, you would use libraries like reportlab or weasyprint
        messagebox.showinfo(
            "PDF Generation", 
            "PDF generation requires additional libraries (reportlab/weasyprint). "
            "Please use HTML format for now."
        )
    
    def log_message(self, level, message):
        """Add a message to the log."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {level}: {message}\n"
        
        # Add to log display
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # Add to activity log
        self.activity_text.insert(tk.END, log_entry)
        self.activity_text.see(tk.END)
        
        # Limit log size
        if float(self.log_text.index(tk.END)) > 1000:
            self.log_text.delete(1.0, 100.0)
    
    # Additional method implementations
    def export_results(self):
        """Export audit results to file."""
        if not self.audit_results:
            messagebox.showwarning("No Results", "No audit results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export Results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.audit_results, f, indent=2)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export results: {e}")
    
    def import_rules(self):
        """Import custom rules from file."""
        filename = filedialog.askopenfilename(
            title="Import Rules",
            filetypes=[("YAML files", "*.yaml"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            messagebox.showinfo("Import", f"Rule import from {filename} (Feature not yet implemented)")
    
    def generate_pdf_report(self):
        """Generate a PDF report from current results."""
        if not self.audit_results:
            messagebox.showwarning("No Data", "Please run an audit first.")
            return
        messagebox.showinfo("PDF Report", "PDF generation feature requires additional setup.")
    
    def view_rollback_points(self):
        """View available rollback points."""
        messagebox.showinfo("Rollback Points", "Rollback management feature (Feature placeholder)")
    
    def show_system_info(self):
        """Show detailed system information."""
        info_window = tk.Toplevel(self.root)
        info_window.title("System Information")
        info_window.geometry("600x400")
        
        info_text = scrolledtext.ScrolledText(info_window)
        info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        system_info = f"""
System Information:
==================

Operating System: {self.current_os or 'Unknown'}
Python Version: {sys.version}
Platform: {sys.platform}
Architecture: {os.uname().machine if hasattr(os, 'uname') else 'Unknown'}

Tool Status:
============
Hardening Tool Available: {HARDENING_TOOL_AVAILABLE}
Admin Privileges: {is_admin()}
Database Connection: {'Connected' if self.hardening_tool else 'Not Connected'}

Available Rules: {len(self.available_rules)}
Last Audit Results: {'Available' if self.audit_results else 'None'}
        """
        
        info_text.insert(tk.END, system_info)
    
    def show_about(self):
        """Show about dialog."""
        about_text = """
🛡️ Multi-Platform System Hardening Tool
Desktop GUI Application

Version: 1.0
Platform: Desktop (Tkinter)

A comprehensive security hardening tool for Windows, Ubuntu, and CentOS systems.
Built with Python and tkinter for maximum compatibility.

Features:
• Multi-platform security auditing
• CIS Benchmark compliance checking  
• Safe hardening rule application
• Professional reporting
• Rollback capability
• Intuitive desktop interface

© 2025 TeamNueralNode
Licensed under MIT License
        """
        messagebox.showinfo("About", about_text)
    
    def show_documentation(self):
        """Show documentation."""
        messagebox.showinfo(
            "Documentation", 
            "Documentation is available in the docs/ directory.\n"
            "Key files:\n"
            "• README.md - Main documentation\n"
            "• docs/PROJECT_STRUCTURE.md - Architecture guide\n" 
            "• docs/TESTING.md - Testing procedures"
        )
    
    def refresh_logs(self):
        """Refresh the log display."""
        self.log_message("INFO", "Logs refreshed")
    
    def clear_logs(self):
        """Clear the log display."""
        self.log_text.delete(1.0, tk.END)
        self.activity_text.delete(1.0, tk.END)
    
    def save_logs(self):
        """Save logs to file."""
        filename = filedialog.asksaveasfilename(
            title="Save Logs",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Logs saved to {filename}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save logs: {e}")
    
    def show_privilege_help(self):
        """Show help for getting administrative privileges."""
        help_window = tk.Toplevel(self.root)
        help_window.title("Administrative Privileges Help")
        help_window.geometry("600x400")
        help_window.transient(self.root)
        help_window.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(help_window, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="🔐 Getting Administrative Privileges",
            style='Title.TLabel'
        )
        title_label.pack(pady=(0, 20))
        
        # Help text
        help_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=15)
        help_text.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        help_content = """Why Administrative Privileges Are Needed:
========================================

The Multi-Platform System Hardening Tool modifies critical system configurations including:
• SSH daemon configuration (/etc/ssh/sshd_config)
• Firewall settings (UFW, iptables, firewalld)
• PAM authentication modules
• System service configurations
• File permissions and ownership
• Kernel parameters and security settings

These changes require administrative (root) privileges to ensure system security.

How to Run with Administrative Privileges:
=========================================

Linux/Ubuntu/CentOS:
-------------------
1. Close this application
2. Open a terminal
3. Navigate to the project directory:
   cd /path/to/Multi-Platform-System-Hardening-Tool
4. Run with sudo:
   sudo python3 desktop_gui.py

Windows:
--------
1. Close this application
2. Right-click on Command Prompt or PowerShell
3. Select "Run as Administrator"
4. Navigate to the project directory
5. Run: python desktop_gui.py

What You Can Do Without Admin Privileges:
========================================

• Run security audits (full functionality)
• Browse and search hardening rules
• Generate compliance reports (PDF, HTML, JSON)
• Use dry-run mode to preview changes
• View system information and logs
• Export audit results

Safe Testing Options:
===================

• Dry-Run Mode: Preview all changes without applying them
• Demo Mode: Test interface functionality safely
• Audit Only: Assess current security posture
• Report Generation: Create compliance documentation

Security Best Practices:
=======================

• Always run audits before applying changes
• Use dry-run mode to understand impact
• Test in non-production environments first
• Create system backups before modifications
• Review logs and results carefully
• Follow your organization's change management procedures

Remember: The privilege requirement is a security feature to protect your system from unauthorized modifications."""
        
        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(
            button_frame,
            text="Enable Dry-Run Mode",
            command=lambda: [self.enable_dry_run_from_help(), help_window.destroy()]
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame,
            text="Close",
            command=help_window.destroy
        ).pack(side=tk.RIGHT)
    
    def enable_dry_run_from_help(self):
        """Enable dry-run mode from the help dialog."""
        self.dry_run_var.set(True)
        self.notebook.select(3)  # Switch to Apply tab
        messagebox.showinfo(
            "Dry-Run Mode Enabled",
            "Dry-run mode has been enabled. You can now safely preview " +
            "what changes would be made without modifying your system."
        )


def main():
    """Main entry point for the GUI application."""
    root = tk.Tk()
    app = HardeningToolGUI(root)
    
    # Center window on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()


if __name__ == "__main__":
    main()