import typer
from rich.console import Console
from key_manager import APIKeyManager

__version__ = "2.0.0"

def version_callback(value: bool):
    if value:
        print(f"SentinelAI v{__version__}")
        raise typer.Exit()

app = typer.Typer(help="SentinelAI - AI-powered security auditing CLI")
console = Console()

@app.callback(invoke_without_command=True)
def main_callback(
    version: bool = typer.Option(False, "--version", "-v", callback=version_callback,
                                  is_eager=True, help="Show version and exit"),
):
    """SentinelAI - Enterprise Security Auditor"""
    pass

@app.command()
def audit(
    target: str = typer.Argument(..., help="Path to local folder or GitHub repo"),
    keys: str = typer.Option("", "--keys", help="Comma separated API keys"),
    export: str = typer.Option("", "--export", help="Export report format: html or pdf"),
    compliance: str = typer.Option("", "--compliance", help="Compliance framework: owasp, pci-dss, hipaa, soc2, gdpr, cwe25"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Drop into chat mode after audit"),
    fix: bool = typer.Option(False, "--fix", help="Generate patch files for fixable vulnerabilities"),
    ci: bool = typer.Option(False, "--ci", help="CI mode: output JSON report with severity-based exit code"),
    sbom: bool = typer.Option(False, "--sbom", help="Generate CycloneDX SBOM for the target")
):
    """
    Run a full security audit against the target path using Multi-Agent RAG.
    """
    console.print(f"[bold green]Starting SentinelAI Audit on:[/bold green] {target}")
    
    if compliance:
        from compliance_profiles import get_profile
        profile = get_profile(compliance)
        if profile:
            console.print(f"[bold magenta]\U0001f6e1\ufe0f Compliance Mode: {profile['name']}[/bold magenta]")
        else:
            console.print(f"[red]Unknown compliance framework: {compliance}[/red]")
            console.print(f"[dim]Available: owasp, pci-dss, hipaa, soc2, gdpr, cwe25[/dim]")
            return
    
    key_manager = APIKeyManager([k.strip() for k in keys.split(",") if k.strip()] if keys else None)
    
    # Phase 0: Resolve target
    console.print("\n[bold yellow]Phase 0:[/bold yellow] Resolving target...")
    from repo_resolver import resolve_target
    try:
        resolved_path = resolve_target(target, log_callback=lambda msg: console.print(msg, end=""))
        console.print(f" [green]Resolved to: {resolved_path}[/green]")
    except Exception as e:
        console.print(f" [bold red]Failed: {e}[/bold red]")
        return

    # Phase 1: Static Analysis
    console.print("\n[bold yellow]Phase 1:[/bold yellow] Running Gitleaks...")
    from scanners.gitleaks import GitleaksScanner
    try:
        scanner = GitleaksScanner(resolved_path)
        secrets = scanner.run()
    except Exception as e:
        console.print(f" [red]Gitleaks error: {e}[/red]")
        secrets = []
        
    if secrets:
        console.print(f" [red]Found {len(secrets)} potential secrets![/red]")
    else:
        console.print(" [green]No secrets found.[/green]")
        
    # Phase 2: RAG Context
    console.print("\n[bold yellow]Phase 2:[/bold yellow] Building Vector DB using Lite Agent...")
    
    from rag_builder import build_rag_system
    from context_builder import build_project_context
    from ai_analyzer import analyze_codebase_stream, generate_suggestions
    import json
    import sys
    
    def log_cb(msg):
        console.print(msg, end="")
        
    collection = build_rag_system(resolved_path, key_manager, log_callback=log_cb)
    findings_str = json.dumps(secrets, indent=2) if secrets else "No static analysis findings."
    
    console.print("\n[bold yellow]Phase 3:[/bold yellow] Ingesting full source code...")
    raw_code = build_project_context(resolved_path)
    console.print(f" [green]Ingested {len(raw_code)/1024:.1f} KB of source code.[/green]")
    
    console.print("\n[bold yellow]Phase 4:[/bold yellow] Running 6-Phase Deep Security Audit...")
    
    full_report = ""
    for chunk in analyze_codebase_stream(collection, findings_str, key_manager, raw_code=raw_code, compliance=compliance):
        sys.stdout.write(chunk)
        sys.stdout.flush()
        full_report += chunk
        
    console.print("\n\n[bold yellow]Phase 4:[/bold yellow] Generating Actionable Suggestions (Reviewer Agent)...")
    suggestions = generate_suggestions(full_report, key_manager)
    console.print(f"\n{suggestions}")
    
    console.print("\n\n[bold blue]Audit complete![/bold blue]")
    
    # Auto-save to history (Feature 5)
    from history_tracker import save_audit
    try:
        code_size_kb = len(raw_code) / 1024
        audit_id = save_audit(
            target=target, report=full_report, suggestions=suggestions,
            compliance=compliance, secrets_count=len(secrets), code_size_kb=code_size_kb
        )
        console.print(f"[dim]\U0001f4be Saved to history (ID: {audit_id})[/dim]")
    except Exception as e:
        console.print(f"[dim red]History save failed: {e}[/dim red]")
    
    # SBOM generation (Feature 7)
    if sbom:
        from sbom_generator import generate_sbom, save_sbom, format_sbom_summary
        console.print("\n[bold yellow]\U0001f4e6 Generating SBOM...[/bold yellow]")
        sbom_data = generate_sbom(resolved_path, log_callback=lambda msg: console.print(msg, end=""))
        sbom_path = save_sbom(sbom_data)
        console.print(format_sbom_summary(sbom_data))
        console.print(f"\n[bold green]SBOM saved:[/bold green] {sbom_path}")
    
    # CI mode (Feature 3): output JSON and exit with severity code
    if ci:
        from ci_reporter import format_json_report, write_json_report, determine_exit_code
        json_report = format_json_report(full_report, suggestions, target, secrets)
        json_path = write_json_report(json_report)
        console.print(f"\n[bold green]JSON report:[/bold green] {json_path}")
        
        exit_code = determine_exit_code(json_report)
        risk = json_report['overall_risk']
        counts = json_report['severity_counts']
        console.print(
            f"[bold]Risk: {risk}[/bold] | "
            f"🔴 {counts['critical']} Critical | 🟠 {counts['high']} High | "
            f"🟡 {counts['medium']} Medium | 🟢 {counts['low']} Low"
        )
        
        if exit_code == 1:
            console.print("[bold red]CI GATE: FAIL — Critical or High severity findings detected.[/bold red]")
        elif exit_code == 2:
            console.print("[bold yellow]CI GATE: WARNING — Medium severity findings detected.[/bold yellow]")
        else:
            console.print("[bold green]CI GATE: PASS — No significant findings.[/bold green]")
    
    # Generate patches (Feature 2)
    if fix:
        from patch_generator import generate_patches, save_patches
        console.print("\n[bold yellow]🔧 Generating security patches...[/bold yellow]")
        patches = generate_patches(
            full_report, raw_code, key_manager,
            log_callback=lambda msg: console.print(msg, end="")
        )
        if patches:
            output_dir = save_patches(patches)
            console.print(f"\n[bold green]{len(patches)} patches saved to {output_dir}[/bold green]")
            console.print(f"[dim]Apply with: git apply {output_dir}/all_fixes.patch[/dim]")
        else:
            console.print("[yellow]No patchable findings found.[/yellow]")
    
    # Export if requested
    if export:
        from report_exporter import export_to_html, export_to_pdf
        export_fmt = export.lower().strip()
        try:
            if export_fmt == "pdf":
                path = export_to_pdf(full_report, suggestions, target)
                console.print(f"\n[bold green]PDF report saved:[/bold green] {path}")
            elif export_fmt == "html":
                path = export_to_html(full_report, suggestions, target)
                console.print(f"\n[bold green]HTML report saved:[/bold green] {path}")
            else:
                console.print(f"[red]Unknown export format: {export_fmt}. Use 'html' or 'pdf'.[/red]")
        except Exception as e:
            console.print(f"[red]Export error: {e}[/red]")
            # Fallback to HTML
            try:
                path = export_to_html(full_report, suggestions, target)
                console.print(f"[yellow]Exported as HTML instead:[/yellow] {path}")
            except Exception:
                pass
    
    # Interactive chat mode (Feature 4)
    if interactive:
        from chat_engine import AuditChatEngine
        console.print("\n[bold green]\U0001f4ac Entering interactive chat mode. Type 'exit' or 'quit' to leave.[/bold green]")
        console.print("[dim]Ask questions about the audited codebase...[/dim]\n")
        
        chat_history = []
        while True:
            try:
                question = console.input("[bold cyan]SentinelAI>[/bold cyan] ")
            except (KeyboardInterrupt, EOFError):
                break
            
            question = question.strip()
            if not question:
                continue
            if question.lower() in ("exit", "quit", "q"):
                break
            
            engine = AuditChatEngine(
                collection=collection,
                raw_code=raw_code,
                report=full_report,
                key_manager=key_manager,
                history=chat_history
            )
            
            answer = ""
            for chunk in engine.ask(question):
                sys.stdout.write(chunk)
                sys.stdout.flush()
                answer += chunk
            print("\n")
            
            chat_history.append({"role": "user", "content": question})
            chat_history.append({"role": "assistant", "content": answer})
        
        console.print("[bold blue]Chat session ended.[/bold blue]")


@app.command()
def history(
    target: str = typer.Argument("", help="Filter by target (optional)"),
    trend: bool = typer.Option(False, "--trend", help="Show trend analysis for a target"),
    limit: int = typer.Option(20, "--limit", help="Max results to show"),
    detail: str = typer.Option("", "--detail", help="Show full details for a specific audit ID"),
):
    """
    View audit history and trend analysis.
    """
    from history_tracker import (
        get_audit_history, get_audit_detail, get_trend_data,
        get_most_common_vulnerabilities,
        format_history_table, format_trend_summary
    )
    
    if detail:
        audit = get_audit_detail(detail)
        if audit:
            console.print(f"\n[bold green]Audit {audit['id']}[/bold green]")
            console.print(f"Target: {audit['target']}")
            console.print(f"Date: {audit['timestamp']}")
            console.print(f"Risk: {audit['overall_risk']}")
            console.print(
                f"Findings: {audit['critical_count']}C "
                f"{audit['high_count']}H {audit['medium_count']}M {audit['low_count']}L"
            )
            if audit.get('findings'):
                console.print(f"\n[bold]Detailed Findings ({len(audit['findings'])}):[/bold]")
                for f in audit['findings']:
                    console.print(f"  [{f['severity']}] {f['file']}: {f['description']}")
        else:
            console.print(f"[red]Audit ID '{detail}' not found.[/red]")
        return
    
    if trend and target:
        trend_data = get_trend_data(target, limit=limit)
        console.print(f"\n[bold green]Trend Analysis: {target}[/bold green]\n")
        console.print(format_trend_summary(trend_data))
        return
    
    audits = get_audit_history(target=target if target else None, limit=limit)
    
    if not audits:
        console.print("[yellow]No audit history found. Run an audit first.[/yellow]")
        return
    
    console.print(f"\n[bold green]Audit History ({len(audits)} results)[/bold green]\n")
    console.print(format_history_table(audits))
    
    # Show most common vulns if no specific target filter
    if not target:
        common = get_most_common_vulnerabilities(limit=5)
        if common:
            console.print("\n[bold yellow]Most Common Vulnerabilities:[/bold yellow]")
            for vuln in common:
                console.print(
                    f"  [{vuln['severity']}] {vuln['description'][:60]} "
                    f"(seen {vuln['occurrence_count']}x)"
                )


if __name__ == "__main__":
    app()
