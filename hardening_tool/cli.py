"""
Command Line Interface for the Multi-Platform System Hardening Tool.

Provides comprehensive CLI commands for auditing, applying hardening rules,
managing rollbacks, and generating compliance reports.
"""

import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text

from .core.orchestrator import HardeningTool
from .core.models import OSType, RuleSeverity
from .utils.os_detection import detect_os, validate_supported_os, is_admin


console = Console()


def check_privileges():
    """Check if running with administrative privileges."""
    if not is_admin():
        console.print(
            "[red]Error: Administrative privileges required![/red]\n"
            "Please run as:\n"
            "- Windows: Run as Administrator\n" 
            "- Linux: sudo hardening-tool <command>"
        )
        sys.exit(1)


def validate_system():
    """Validate that the system is supported."""
    try:
        system_info = detect_os()
        if not validate_supported_os(system_info):
            console.print(
                f"[red]Error: Unsupported operating system: {system_info.os_type}[/red]\n"
                "Supported systems: Windows 10/11, Ubuntu 20.04+, CentOS 7+"
            )
            sys.exit(1)
        return system_info
    except Exception as e:
        console.print(f"[red]Error detecting system: {e}[/red]")
        sys.exit(1)


@click.group()
@click.version_option(version="1.0.0")
@click.option('--config', '-c', help="Path to configuration file")
@click.option('--verbose', '-v', is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, config: Optional[str], verbose: bool):
    """
    Multi-Platform System Hardening Tool
    
    Automated security compliance enforcer for Windows, Ubuntu, and CentOS
    based on CIS Benchmarks and NTRO requirements.
    """
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['verbose'] = verbose
    
    # Initialize the hardening tool
    try:
        ctx.obj['tool'] = HardeningTool(config_path=config)
    except Exception as e:
        console.print(f"[red]Failed to initialize hardening tool: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--categories', '-c', help="Comma-separated rule categories to audit")
@click.option('--rules', '-r', help="Comma-separated specific rule IDs to audit")
@click.option('--output', '-o', help="Output file for results (JSON format)")
@click.option('--format', type=click.Choice(['json', 'table', 'summary']), 
              default='table', help="Output format")
@click.pass_context
def audit(ctx, categories: Optional[str], rules: Optional[str], 
          output: Optional[str], format: str):
    """
    Audit current system compliance against hardening rules.
    
    Performs a read-only assessment of system configuration without making changes.
    """
    system_info = validate_system()
    tool: HardeningTool = ctx.obj['tool']
    
    console.print(Panel(
        f"[bold]System Audit - {system_info.os_type.value.title()}[/bold]\n"
        f"OS: {system_info.os_version}\n"
        f"Architecture: {system_info.architecture}\n"
        f"Hostname: {system_info.hostname}",
        title="System Information"
    ))
    
    # Parse input parameters
    category_list = categories.split(',') if categories else None
    rule_list = rules.split(',') if rules else None
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Running security audit...", total=None)
            
            result = tool.audit(categories=category_list, rule_ids=rule_list)
            
        # Display results based on format
        if format == 'summary':
            _display_summary(result)
        elif format == 'table':
            _display_table(result)
        elif format == 'json' and output:
            _save_json_results(result, output)
        else:
            _display_table(result)
            
        # Save to file if requested
        if output and format != 'json':
            _save_json_results(result, output)
            console.print(f"\n[green]Results saved to: {output}[/green]")
            
    except Exception as e:
        console.print(f"[red]Audit failed: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--categories', '-c', help="Comma-separated rule categories to apply")
@click.option('--rules', '-r', help="Comma-separated specific rule IDs to apply")
@click.option('--interactive', '-i', is_flag=True, help="Prompt for confirmation before each rule")
@click.option('--dry-run', '-n', is_flag=True, help="Show what would be done without applying")
@click.option('--rollback-point', '-b', help="Create rollback point with custom description")
@click.option('--force', is_flag=True, help="Skip safety confirmations")
@click.pass_context
def apply(ctx, categories: Optional[str], rules: Optional[str], 
          interactive: bool, dry_run: bool, rollback_point: Optional[str], force: bool):
    """
    Apply hardening rules to the system.
    
    Makes actual system changes to improve security posture.
    Creates automatic rollback points unless disabled.
    """
    if not force:
        check_privileges()
    
    system_info = validate_system()
    tool: HardeningTool = ctx.obj['tool']
    
    if not force and not dry_run:
        console.print(
            "[yellow]Warning: This will make changes to your system configuration![/yellow]\n"
            "Ensure you have recent backups and understand the impact.\n"
        )
        if not click.confirm("Do you want to continue?"):
            console.print("Operation cancelled.")
            return
    
    # Parse input parameters
    category_list = categories.split(',') if categories else None
    rule_list = rules.split(',') if rules else None
    
    try:
        console.print(Panel(
            f"[bold]Applying Hardening Rules - {system_info.os_type.value.title()}[/bold]\n"
            f"Mode: {'Dry Run' if dry_run else 'Live Application'}\n"
            f"Interactive: {interactive}\n"
            f"Rollback Point: {rollback_point or 'Auto-generated'}",
            title="Hardening Application"
        ))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Applying hardening rules...", total=None)
            
            result = tool.apply(
                categories=category_list,
                rule_ids=rule_list,
                interactive=interactive,
                dry_run=dry_run,
                rollback_description=rollback_point
            )
            
        _display_apply_results(result, dry_run)
        
    except Exception as e:
        console.print(f"[red]Application failed: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--run-id', help="Specific run ID to rollback to")
@click.option('--list-points', is_flag=True, help="List available rollback points")
@click.option('--force', is_flag=True, help="Skip confirmation prompts")
@click.pass_context
def rollback(ctx, run_id: Optional[str], list_points: bool, force: bool):
    """
    Rollback system changes to a previous state.
    
    Restores configuration from automatic or manual rollback points.
    """
    if not force:
        check_privileges()
        
    tool: HardeningTool = ctx.obj['tool']
    
    if list_points:
        _list_rollback_points(tool)
        return
    
    if not run_id:
        console.print("[red]Error: --run-id required (use --list-points to see available options)[/red]")
        return
    
    if not force:
        console.print(f"[yellow]Warning: This will rollback system changes from run {run_id}[/yellow]")
        if not click.confirm("Do you want to continue?"):
            console.print("Rollback cancelled.")
            return
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Rolling back run {run_id}...", total=None)
            
            result = tool.rollback(run_id)
            
        console.print(f"[green]Successfully rolled back run {run_id}[/green]")
        _display_summary(result)
        
    except Exception as e:
        console.print(f"[red]Rollback failed: {e}[/red]")
        sys.exit(1)


@cli.group()
def rules():
    """Manage and inspect hardening rules."""
    pass


@rules.command('list')
@click.option('--platform', type=click.Choice(['windows', 'ubuntu', 'centos']), 
              help="Filter by platform")
@click.option('--category', help="Filter by category")
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low']), 
              help="Filter by severity")
@click.pass_context
def list_rules(ctx, platform: Optional[str], category: Optional[str], 
               severity: Optional[str]):
    """List available hardening rules."""
    tool: HardeningTool = ctx.obj['tool']
    
    try:
        rules = tool.get_available_rules(
            platform=OSType(platform) if platform else None,
            category=category,
            severity=RuleSeverity(severity) if severity else None
        )
        
        _display_rules_table(rules)
        
    except Exception as e:
        console.print(f"[red]Failed to list rules: {e}[/red]")


@rules.command('show')
@click.argument('rule_id')
@click.pass_context
def show_rule(ctx, rule_id: str):
    """Show detailed information about a specific rule."""
    tool: HardeningTool = ctx.obj['tool']
    
    try:
        rule = tool.get_rule_details(rule_id)
        _display_rule_details(rule)
        
    except Exception as e:
        console.print(f"[red]Failed to show rule: {e}[/red]")


@cli.command()
@click.option('--run-id', help="Specific run to generate report for")
@click.option('--format', type=click.Choice(['pdf', 'html', 'json']), 
              default='pdf', help="Report format")
@click.option('--output', '-o', required=True, help="Output file path")
@click.option('--template', help="Custom report template")
@click.pass_context
def report(ctx, run_id: Optional[str], format: str, output: str, 
           template: Optional[str]):
    """Generate compliance reports."""
    tool: HardeningTool = ctx.obj['tool']
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Generating report...", total=None)
            
            report_path = tool.generate_report(
                run_id=run_id,
                format=format,
                output_path=output,
                template_path=template
            )
            
        console.print(f"[green]Report generated: {report_path}[/green]")
        
    except Exception as e:
        console.print(f"[red]Report generation failed: {e}[/red]")


def _display_summary(result):
    """Display a summary of hardening results."""
    run = result.run
    
    # Create summary table
    table = Table(title="Hardening Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    
    table.add_row("Overall Score", f"{run.overall_score:.1f}%")
    table.add_row("Total Rules", str(run.total_rules))
    table.add_row("Passed", f"[green]{run.passed_rules}[/green]")
    table.add_row("Failed", f"[red]{run.failed_rules}[/red]" if run.failed_rules else "0")
    table.add_row("Errors", f"[yellow]{run.error_rules}[/yellow]" if run.error_rules else "0")
    table.add_row("Skipped", str(run.skipped_rules))
    
    console.print(table)
    
    # Show critical failures if any
    critical_failures = result.critical_failures
    if critical_failures:
        console.print("\n[red bold]Critical Failures:[/red bold]")
        for failure in critical_failures:
            console.print(f"  • {failure.rule_title}")


def _display_table(result):
    """Display detailed results in table format."""
    table = Table(title="Hardening Results")
    table.add_column("Rule ID", style="dim")
    table.add_column("Title")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Message", max_width=40)
    
    for rule_result in result.run.rule_results:
        status_color = {
            "pass": "green",
            "fail": "red", 
            "error": "yellow",
            "skipped": "dim",
            "not_applicable": "dim"
        }.get(rule_result.status.value, "white")
        
        severity_color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow", 
            "low": "blue",
            "info": "dim"
        }.get(rule_result.severity.value, "white")
        
        table.add_row(
            rule_result.rule_id,
            rule_result.rule_title,
            f"[{status_color}]{rule_result.status.value.upper()}[/{status_color}]",
            f"[{severity_color}]{rule_result.severity.value.upper()}[/{severity_color}]",
            rule_result.message or ""
        )
    
    console.print(table)
    _display_summary(result)


def _display_apply_results(result, dry_run: bool):
    """Display results from hardening application."""
    mode_text = "DRY RUN - " if dry_run else ""
    console.print(f"\n[bold]{mode_text}Hardening Application Complete[/bold]")
    
    _display_table(result)
    
    if not dry_run and result.run.success:
        console.print(f"\n[green]✓ Hardening applied successfully![/green]")
        console.print(f"Run ID: {result.run.run_id}")
    elif not dry_run:
        console.print(f"\n[yellow]⚠ Hardening completed with issues[/yellow]")
        console.print(f"Run ID: {result.run.run_id}")


def _save_json_results(result, output_path: str):
    """Save results to JSON file."""
    import json
    from pathlib import Path
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(result.run.dict(), f, indent=2, default=str)


def _list_rollback_points(tool: HardeningTool):
    """List available rollback points."""
    try:
        points = tool.get_rollback_points()
        
        if not points:
            console.print("[yellow]No rollback points available[/yellow]")
            return
        
        table = Table(title="Available Rollback Points")
        table.add_column("Run ID", style="dim")
        table.add_column("Created", style="dim")
        table.add_column("Description")
        table.add_column("System")
        
        for point in points:
            table.add_row(
                point.run_id,
                point.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                point.description or "Auto-generated",
                f"{point.system_info.os_type.value} {point.system_info.os_version}"
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Failed to list rollback points: {e}[/red]")


def _display_rules_table(rules):
    """Display available rules in table format."""
    table = Table(title="Available Hardening Rules")
    table.add_column("ID", style="dim")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Platforms")
    table.add_column("Categories")
    
    for rule in rules:
        severity_color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue", 
            "info": "dim"
        }.get(rule.severity.value, "white")
        
        platforms = ", ".join([p.value for p in rule.platforms])
        categories = ", ".join(rule.categories)
        
        table.add_row(
            rule.id,
            rule.title,
            f"[{severity_color}]{rule.severity.value.upper()}[/{severity_color}]",
            platforms,
            categories
        )
    
    console.print(table)


def _display_rule_details(rule):
    """Display detailed information about a specific rule."""
    console.print(Panel(
        f"[bold]{rule.title}[/bold]\n\n"
        f"[dim]ID:[/dim] {rule.id}\n"
        f"[dim]Severity:[/dim] {rule.severity.value.upper()}\n"
        f"[dim]Platforms:[/dim] {', '.join([p.value for p in rule.platforms])}\n"
        f"[dim]Categories:[/dim] {', '.join(rule.categories)}\n\n"
        f"[dim]Description:[/dim]\n{rule.description}\n\n"
        + (f"[dim]CIS Benchmark:[/dim] {rule.cis_benchmark}\n" if rule.cis_benchmark else "")
        + (f"[dim]NTRO Reference:[/dim] {rule.ntro_reference}\n" if rule.ntro_reference else ""),
        title="Rule Details"
    ))
    
    if rule.remediation_steps:
        console.print("\n[bold]Remediation Steps:[/bold]")
        for i, step in enumerate(rule.remediation_steps, 1):
            console.print(f"{i}. {step}")


def main():
    """Main CLI entry point."""
    cli()


if __name__ == "__main__":
    main()