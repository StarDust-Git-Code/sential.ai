from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Button, RichLog, Label, Select
from textual.containers import Horizontal, Vertical
from textual import work
from textual.binding import Binding
import pyperclip

from scanners.gitleaks import GitleaksScanner
from key_manager import APIKeyManager
from rag_builder import build_rag_system
from context_builder import build_project_context
from repo_resolver import resolve_target
from report_exporter import export_to_html, export_to_pdf, get_export_capabilities
from compliance_profiles import get_available_profiles
from patch_generator import generate_patches, save_patches
from history_tracker import save_audit, get_audit_history, format_history_table
from sbom_generator import generate_sbom, save_sbom, format_sbom_summary
from ai_analyzer import analyze_codebase_stream, generate_suggestions
import json

class SentinelApp(App):
    """A Textual app to manage SentinelAI audits."""

    TITLE = "SentinelAI — Enterprise Security Auditor"

    BINDINGS = [
        Binding("ctrl+c", "request_quit", "Quit")
    ]

    CSS = """
    #input-container, #api-key-container {
        height: auto;
        margin: 1 2;
    }
    Input {
        width: 1fr;
    }
    Button {
        margin-left: 1;
    }
    #main-content {
        height: 1fr;
    }
    #left-pane {
        width: 2fr;
    }
    #right-pane {
        width: 1fr;
        border-left: solid green;
    }
    RichLog {
        margin: 0 1;
        border: solid green;
        height: 1fr;
    }
    #thought-log {
        height: 8;
        border: solid yellow;
    }
    #key-count-label {
        margin-left: 1;
        content-align: center middle;
    }
    .copy-btn {
        dock: right;
        margin: 0 1;
        min-width: 12;
    }
    .pane-header {
        height: 3;
        margin: 0 1;
    }
    .pane-title {
        width: 1fr;
    }
    #compliance-select {
        width: 24;
        margin-left: 1;
    }
    #chat-container {
        height: auto;
        margin: 0 2;
        display: none;
    }
    #chat-container.visible {
        display: block;
    }
    #chat-input {
        width: 1fr;
    }
    """

    def __init__(self):
        super().__init__()
        self.key_manager = APIKeyManager()
        self._quit_count = 0
        self._audit_report_text = ""
        self._suggestions_text = ""
        self._audit_target = ""
        self._resolved_path = ""
        self._secrets_count = 0
        self._code_size_kb = 0.0
        # Chat state (Feature 4)
        self._chat_collection = None
        self._chat_raw_code = ""
        self._chat_history = []

    def action_request_quit(self) -> None:
        self._quit_count += 1
        if self._quit_count >= 2:
            self.exit()
        else:
            self.notify("Press Ctrl+C again to exit the app.", severity="warning", timeout=3.0)
            def reset_count():
                self._quit_count = 0
            self.set_timer(3.0, reset_count)

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header(show_clock=True)
        with Vertical():
            with Horizontal(id="api-key-container"):
                yield Input(placeholder="Gemini API Key", password=True, id="api-key-input")
                yield Button("+", variant="primary", id="add-key-button")
                yield Label(f"Keys: {self.key_manager.count()}", id="key-count-label")
            with Horizontal(id="input-container"):
                yield Input(placeholder="Enter path to audit (e.g., . or /path/to/repo)", id="target-input")
                compliance_options = [("None (General)", "")] + [(name, key) for key, name in get_available_profiles().items()]
                yield Select(compliance_options, value="", id="compliance-select", allow_blank=False)
                yield Button("Start Audit", variant="success", id="start-button")
                
            with Horizontal(id="main-content"):
                with Vertical(id="left-pane"):
                    yield RichLog(id="thought-log", markup=True)
                    with Horizontal(classes="pane-header"):
                        yield Label("[bold]Audit Report[/bold]", classes="pane-title")
                        yield Button("📦 SBOM", variant="default", id="gen-sbom-btn", classes="copy-btn")
                        yield Button("🔧 Fixes", variant="error", id="gen-patches-btn", classes="copy-btn")
                        yield Button("📄 Export", variant="primary", id="export-btn", classes="copy-btn")
                        yield Button("📋 Copy Report", variant="warning", id="copy-report-btn", classes="copy-btn")
                    yield RichLog(id="audit-log", markup=True)
                with Vertical(id="right-pane"):
                    with Horizontal(classes="pane-header"):
                        yield Label("[bold]Suggestions[/bold]", classes="pane-title")
                        yield Button("📋 Copy", variant="warning", id="copy-suggestions-btn", classes="copy-btn")
                    yield RichLog(id="suggestions-log", markup=True)
            with Horizontal(id="chat-container"):
                yield Input(placeholder="Ask SentinelAI about this codebase...", id="chat-input")
                yield Button("Ask", variant="primary", id="chat-send-btn")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Event handler called when a button is pressed."""
        if event.button.id == "add-key-button":
            key_input = self.query_one("#api-key-input", Input)
            val = key_input.value.strip()
            if val:
                self.key_manager.add_key(val)
                key_input.value = ""
                self.query_one("#key-count-label", Label).update(f"Keys: {self.key_manager.count()}")
                self.notify(f"Key added! Total: {self.key_manager.count()}", severity="information")

        elif event.button.id == "copy-report-btn":
            if self._audit_report_text:
                try:
                    pyperclip.copy(self._audit_report_text)
                    self.notify("Audit report copied to clipboard!", severity="information")
                except Exception:
                    self.notify("Failed to copy. Install pyperclip.", severity="error")
            else:
                self.notify("No report to copy yet.", severity="warning")

        elif event.button.id == "copy-suggestions-btn":
            if self._suggestions_text:
                try:
                    pyperclip.copy(self._suggestions_text)
                    self.notify("Suggestions copied to clipboard!", severity="information")
                except Exception:
                    self.notify("Failed to copy. Install pyperclip.", severity="error")
            else:
                self.notify("No suggestions to copy yet.", severity="warning")

        elif event.button.id == "export-btn":
            if self._audit_report_text:
                self._export_report()
            else:
                self.notify("No report to export yet. Run an audit first.", severity="warning")

        elif event.button.id == "gen-patches-btn":
            if self._audit_report_text and self._chat_raw_code:
                self._generate_patches()
            else:
                self.notify("Run an audit first to generate patches.", severity="warning")

        elif event.button.id == "gen-sbom-btn":
            if self._resolved_path:
                self._generate_sbom()
            else:
                self.notify("Run an audit first to generate SBOM.", severity="warning")
                
        elif event.button.id == "start-button":
            target = self.query_one("#target-input", Input).value
            
            # If they didn't hit +, but there's text, add it
            key_input = self.query_one("#api-key-input", Input)
            val = key_input.value.strip()
            if val:
                self.key_manager.add_key(val)
                key_input.value = ""
                self.query_one("#key-count-label", Label).update(f"Keys: {self.key_manager.count()}")

            if not target:
                self.query_one("#target-input", Input).focus()
                return
            
            if self.key_manager.count() == 0:
                self.notify("Please add at least one API key first.", severity="error")
                return

            # Reset state
            self._audit_report_text = ""
            self._suggestions_text = ""
            self.query_one("#audit-log", RichLog).clear()
            self.query_one("#thought-log", RichLog).clear()
            self.query_one("#suggestions-log", RichLog).clear()
            
            self.run_audit(target)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key on chat input."""
        if event.input.id == "chat-input":
            question = event.input.value.strip()
            if question:
                event.input.value = ""
                self._run_chat(question)

    @work(exclusive=False, thread=True)
    def _export_report(self) -> None:
        """Export the audit report to HTML/PDF."""
        caps = get_export_capabilities()
        target_name = self._audit_target or "audit"
        
        try:
            if caps["pdf"]:
                path = export_to_pdf(self._audit_report_text, self._suggestions_text, target_name)
                self.notify(f"PDF report saved: {path}", severity="information", timeout=8)
            else:
                path = export_to_html(self._audit_report_text, self._suggestions_text, target_name)
                self.notify(f"HTML report saved: {path}", severity="information", timeout=8)
        except Exception as e:
            # If PDF fails, fall back to HTML
            try:
                path = export_to_html(self._audit_report_text, self._suggestions_text, target_name)
                self.notify(f"Exported as HTML (PDF unavailable): {path}", severity="warning", timeout=8)
            except Exception as e2:
                self.notify(f"Export failed: {e2}", severity="error")

    @work(exclusive=False, thread=True)
    def _generate_patches(self) -> None:
        """Generate security fix patches using AI."""
        thought_log = self.query_one("#thought-log", RichLog)
        
        def log_cb(msg):
            self.call_from_thread(thought_log.write, msg)
        
        self.call_from_thread(thought_log.write, "\n[bold yellow]🔧 Generating security patches...[/bold yellow]\n")
        
        try:
            patches = generate_patches(
                self._audit_report_text,
                self._chat_raw_code,
                self.key_manager,
                log_callback=log_cb
            )
            
            if patches:
                output_dir = save_patches(patches)
                self.notify(
                    f"Generated {len(patches)} patches in {output_dir}",
                    severity="information",
                    timeout=10
                )
                self.call_from_thread(
                    thought_log.write,
                    f"\n[bold green]✓ {len(patches)} patches saved to {output_dir}[/bold green]\n"
                    f"[dim]Apply with: git apply sentinel_patches/all_fixes.patch[/dim]\n"
                )
            else:
                self.notify("No patchable findings found.", severity="warning")
        except Exception as e:
            self.notify(f"Patch generation failed: {e}", severity="error")

    @work(exclusive=False, thread=True)
    def _generate_sbom(self) -> None:
        """Generate an SBOM (Software Bill of Materials)."""
        thought_log = self.query_one("#thought-log", RichLog)
        
        def log_cb(msg):
            self.call_from_thread(thought_log.write, msg)
        
        self.call_from_thread(thought_log.write, "\n[bold yellow]📦 Generating SBOM...[/bold yellow]\n")
        
        try:
            sbom = generate_sbom(self._resolved_path, log_callback=log_cb)
            path = save_sbom(sbom)
            summary = format_sbom_summary(sbom)
            self.call_from_thread(thought_log.write, summary + "\n")
            self.call_from_thread(thought_log.write, f"\n[bold green]\u2713 SBOM saved: {path}[/bold green]\n")
            self.notify(f"SBOM saved: {path}", severity="information", timeout=8)
        except Exception as e:
            self.notify(f"SBOM generation failed: {e}", severity="error")

    @work(exclusive=True, thread=True)
    def run_audit(self, target: str) -> None:
        """Run the full multi-phase enterprise audit."""
        audit_log = self.query_one("#audit-log", RichLog)
        thought_log = self.query_one("#thought-log", RichLog)
        suggestions_log = self.query_one("#suggestions-log", RichLog)
        
        def thought_callback(msg):
            self.call_from_thread(thought_log.write, msg)
            
        self.call_from_thread(audit_log.write, f"[bold green]━━━ SentinelAI Enterprise Security Audit ━━━[/bold green]")
        self.call_from_thread(audit_log.write, f"[bold green]Target:[/bold green] {target}\n")
        self._audit_target = target
        
        # Phase 0: Resolve target (clone if GitHub URL)
        self.call_from_thread(audit_log.write, "[bold yellow]▶ Resolving Target:[/bold yellow] Checking if target needs cloning...")
        try:
            resolved_path = resolve_target(target, log_callback=thought_callback)
            self.call_from_thread(audit_log.write, f" [green]✓ Resolved to: {resolved_path}[/green]\n")
            self._resolved_path = resolved_path
        except Exception as e:
            self.call_from_thread(audit_log.write, f" [bold red]Failed to resolve target: {e}[/bold red]")
            return

        # Phase 1: Static Analysis
        self.call_from_thread(audit_log.write, "[bold yellow]▶ Pre-Scan:[/bold yellow] Running Static Analysis (Gitleaks)...")
        try:
            scanner = GitleaksScanner(resolved_path)
            secrets = scanner.run()
        except Exception as e:
            self.call_from_thread(audit_log.write, f" [red]Gitleaks error: {e}[/red]\n")
            secrets = []
            
        if secrets:
            self.call_from_thread(audit_log.write, f" [red]⚠ Found {len(secrets)} potential secrets![/red]\n")
        else:
            self.call_from_thread(audit_log.write, " [green]✓ No secrets found.[/green]\n")
        self._secrets_count = len(secrets)
            
        # Phase 2: RAG Context Building
        self.call_from_thread(audit_log.write, "\n[bold yellow]▶ Indexing:[/bold yellow] Building codebase vector index...")
        try:
            collection = build_rag_system(resolved_path, self.key_manager, log_callback=thought_callback)
        except Exception as e:
            self.call_from_thread(audit_log.write, f"\n[bold red]Error building RAG context:[/bold red] {e}")
            return
            
        # Phase 3: Build raw code context
        self.call_from_thread(audit_log.write, "\n[bold yellow]▶ Code Ingestion:[/bold yellow] Reading full source code for deep analysis...")
        raw_code = build_project_context(resolved_path)
        code_size_kb = len(raw_code) / 1024
        self._code_size_kb = code_size_kb
        self.call_from_thread(audit_log.write, f" [green]✓ Ingested {code_size_kb:.1f} KB of source code.[/green]\n")

        # Phase 4: Multi-Phase Deep Audit
        self.call_from_thread(audit_log.write, "\n[bold yellow]▶ Deep Audit:[/bold yellow] Running 6-Phase Security Analysis...\n")
        findings_str = json.dumps(secrets, indent=2) if secrets else "No static analysis findings."
        
        full_report = ""
        buffer = ""
        # Get compliance selection
        compliance_select = self.query_one("#compliance-select", Select)
        compliance_key = compliance_select.value if compliance_select.value != Select.BLANK else ""
        
        for chunk in analyze_codebase_stream(collection, findings_str, self.key_manager, raw_code=raw_code, compliance=compliance_key):
            full_report += chunk
            buffer += chunk
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                self.call_from_thread(audit_log.write, line)
        
        if buffer:
            self.call_from_thread(audit_log.write, buffer)
        
        self._audit_report_text = full_report
            
        # Phase 4: Actionable Suggestions (Reviewer)
        self.call_from_thread(suggestions_log.write, "[bold yellow]Generating Prioritized Remediation Plan...[/bold yellow]\n\n")
        suggestions = generate_suggestions(full_report, self.key_manager)
        self.call_from_thread(suggestions_log.write, suggestions)
        self._suggestions_text = suggestions

        self.call_from_thread(audit_log.write, "\n\n[bold blue]━━━ Audit Complete ━━━[/bold blue]")
        self.notify("Audit complete! Use the 📋 buttons to copy results.", severity="information")
        
        # Save to history (Feature 5)
        try:
            compliance_val = compliance_key if compliance_key else ""
            audit_id = save_audit(
                target=target,
                report=full_report,
                suggestions=suggestions,
                compliance=compliance_val,
                secrets_count=self._secrets_count,
                code_size_kb=self._code_size_kb
            )
            self.call_from_thread(audit_log.write, f"[dim]💾 Saved to history (ID: {audit_id})[/dim]")
        except Exception as e:
            self.call_from_thread(audit_log.write, f"[dim red]History save failed: {e}[/dim red]")
        
        # Enable chat mode (Feature 4)
        self._chat_collection = collection
        self._chat_raw_code = raw_code
        self._chat_history = []
        # Show the chat input
        chat_container = self.query_one("#chat-container")
        self.call_from_thread(chat_container.add_class, "visible")
        self.call_from_thread(audit_log.write, "\n[bold green]💬 Chat mode enabled! Ask questions about this codebase below.[/bold green]")

    @work(exclusive=False, thread=True)
    def _run_chat(self, question: str) -> None:
        """Handle a chat question using the RAG index and report context."""
        suggestions_log = self.query_one("#suggestions-log", RichLog)
        
        if not self._chat_collection:
            self.notify("Run an audit first to enable chat.", severity="warning")
            return
        
        self.call_from_thread(suggestions_log.write, f"\n[bold cyan]You:[/bold cyan] {question}\n")
        
        from chat_engine import AuditChatEngine
        engine = AuditChatEngine(
            collection=self._chat_collection,
            raw_code=self._chat_raw_code,
            report=self._audit_report_text,
            key_manager=self.key_manager,
            history=self._chat_history
        )
        
        self.call_from_thread(suggestions_log.write, "[bold green]SentinelAI:[/bold green] ")
        full_answer = ""
        buffer = ""
        for chunk in engine.ask(question):
            full_answer += chunk
            buffer += chunk
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                self.call_from_thread(suggestions_log.write, line)
        if buffer:
            self.call_from_thread(suggestions_log.write, buffer)
        
        self._chat_history.append({"role": "user", "content": question})
        self._chat_history.append({"role": "assistant", "content": full_answer})
        self.call_from_thread(suggestions_log.write, "\n")

if __name__ == "__main__":
    app = SentinelApp()
    app.run()
