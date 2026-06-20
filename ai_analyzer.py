import os
import google.generativeai as genai
from google.api_core.exceptions import ResourceExhausted, InvalidArgument, NotFound
from typing import Iterator, Callable
from key_manager import APIKeyManager
from compliance_profiles import get_phase_suffix, get_summary_suffix, get_profile
import time

# Model configs: (model_id, supports_search_grounding)
AUDITOR_MODELS = [
    ("gemini-3.1-flash-lite",  False),  # 15 RPM, 500 RPD
    ("gemini-2.5-flash-lite",  True),   # 10 RPM,  20 RPD
    ("gemini-2.5-flash",       True),   #  5 RPM,  20 RPD
]

# ─── Multi-Pass Audit Phases ───────────────────────────────────────────
# Each phase is a focused security lens. The AI runs each one separately
# against the RAG context, producing a section of the final report.
AUDIT_PHASES = [
    {
        "id": "recon",
        "name": "Reconnaissance & Attack Surface Mapping",
        "prompt": """You are performing Phase 1 of a professional security audit.
Your task: MAP THE ATTACK SURFACE of this codebase.
- Identify all entry points (API routes, CLI args, form inputs, file uploads).
- List all external integrations (databases, APIs, cloud services, message queues).
- Identify authentication/session boundaries.
- Map data flow: where does user input enter, how is it processed, where does it exit?

Output a structured Markdown section titled "## Phase 1: Attack Surface & Reconnaissance".
Include a table of entry points with columns: Endpoint | Method | Auth Required | Risk Level.
"""
    },
    {
        "id": "auth",
        "name": "Authentication, Authorization & Session Management",
        "prompt": """You are performing Phase 2 of a professional security audit.
Your task: Deep-dive into AUTHENTICATION, AUTHORIZATION, and SESSION MANAGEMENT.
- Check for broken authentication (weak password policies, missing MFA).
- Look for IDOR (Insecure Direct Object References).
- Check for privilege escalation paths.
- Analyze JWT/token handling, session fixation, CSRF protections.
- Check for missing role-based access controls (RBAC).

Output a structured Markdown section titled "## Phase 2: Authentication & Authorization Audit".
For each finding, include: Severity (Critical/High/Medium/Low) | File | Line (if known) | Description | Remediation.
"""
    },
    {
        "id": "injection",
        "name": "Injection & Input Validation Analysis",
        "prompt": """You are performing Phase 3 of a professional security audit.
Your task: Analyze for ALL INJECTION VULNERABILITIES and INPUT VALIDATION issues.
- SQL Injection (including ORM misuse, raw queries).
- Cross-Site Scripting (XSS) - Stored, Reflected, DOM-based.
- Command Injection / OS Command Injection.
- Path Traversal / Local File Inclusion.
- Server-Side Request Forgery (SSRF).
- Template Injection (SSTI).
- LDAP Injection, XML External Entity (XXE).
- Deserialization attacks.

Output a structured Markdown section titled "## Phase 3: Injection & Input Validation".
For each finding, include: CWE ID | Severity | Attack Vector | Proof of Concept | Remediation.
"""
    },
    {
        "id": "secrets",
        "name": "Secrets, Configuration & Data Exposure",
        "prompt": """You are performing Phase 4 of a professional security audit.
Your task: Hunt for SECRETS, MISCONFIGURATIONS, and DATA EXPOSURE.
- Hardcoded API keys, passwords, tokens, connection strings.
- Sensitive data in logs (PII, credentials).
- Insecure default configurations.
- Missing encryption (data at rest, data in transit).
- Exposed debug endpoints or verbose error messages.
- .env files, config files with secrets, docker-compose secrets.
- CORS misconfigurations.

Output a structured Markdown section titled "## Phase 4: Secrets & Configuration Audit".
For each finding, include: Severity | File | Evidence | Risk | Remediation.
"""
    },
    {
        "id": "logic",
        "name": "Business Logic & Race Condition Analysis",
        "prompt": """You are performing Phase 5 of a professional security audit.
Your task: Analyze BUSINESS LOGIC FLAWS and RACE CONDITIONS.
- Look for TOCTOU (Time-of-Check Time-of-Use) vulnerabilities.
- Check for race conditions in financial transactions, inventory, or state changes.
- Analyze for business logic bypasses (e.g., skipping payment, manipulating quantities).
- Check for mass assignment vulnerabilities.
- Look for insecure randomness usage.
- Analyze error handling - are errors caught or do they leak state?

Output a structured Markdown section titled "## Phase 5: Business Logic & Race Conditions".
For each finding, include: Severity | Attack Scenario | Impact | Remediation.
"""
    },
    {
        "id": "deps",
        "name": "Dependency & Supply Chain Audit",
        "prompt": """You are performing Phase 6 of a professional security audit.
Your task: Analyze DEPENDENCY SECURITY and SUPPLY CHAIN risks.
- Check for known vulnerable dependencies (outdated packages).
- Look for typosquatting risks in package names.
- Check for pinned vs unpinned dependency versions.
- Analyze Dockerfile / container security if applicable.
- Check for use of deprecated APIs or libraries.

Output a structured Markdown section titled "## Phase 6: Dependency & Supply Chain Audit".
For each finding, include: Package | Current Version | Risk | Remediation.
"""
    },
]

EXECUTIVE_SUMMARY_PROMPT = """You are writing the EXECUTIVE SUMMARY for a professional security audit report.
Below are the detailed findings from 6 audit phases.

Your task:
1. Write a professional "# SentinelAI Security Audit Report" header.
2. Write a "## Executive Summary" with:
   - Overall risk rating (Critical / High / Medium / Low)
   - Total findings count broken down by severity
   - Top 3 most critical findings
   - Compliance considerations (OWASP Top 10, CWE Top 25)
3. Write a "## Remediation Priority Matrix" table with columns:
   Priority | Finding | Severity | Effort | Impact

Keep it concise and executive-friendly. This goes to the CISO.
{compliance_summary_instruction}

### Detailed Phase Findings:
{phase_results}
"""


def _retrieve_context(collection, query: str, key_manager: APIKeyManager, n_results: int = 5):
    """Retrieve relevant context from ChromaDB."""
    def retrieve_func():
        embed_resp = genai.embed_content(
            model="models/gemini-embedding-2",
            content=query,
            task_type="retrieval_query"
        )
        return collection.query(query_embeddings=[embed_resp['embedding']], n_results=n_results)
    
    results = key_manager.execute_with_retry(retrieve_func)
    if results and results['documents'] and results['documents'][0]:
        return "\n\n".join(results['documents'][0])
    return "No relevant context found."


def _run_model(prompt: str, key_manager: APIKeyManager, stream: bool = True):
    """Try running a prompt against the model fallback chain. Returns an iterator of text chunks."""
    last_error = None
    for model_id, has_search in AUDITOR_MODELS:
        attempts = 0
        max_attempts = max(key_manager.count() * 2, 2)
        
        while attempts < max_attempts:
            try:
                genai.configure(api_key=key_manager.get_current_key())
                
                if has_search:
                    model = genai.GenerativeModel(model_id, tools="google_search_retrieval")
                else:
                    model = genai.GenerativeModel(model_id)
                
                if stream:
                    response = model.generate_content(prompt, stream=True)
                    chunks = []
                    for chunk in response:
                        if chunk.text:
                            chunks.append(chunk.text)
                            yield chunk.text
                    return
                else:
                    response = model.generate_content(prompt)
                    if response.text:
                        yield response.text
                    return
                    
            except (ResourceExhausted, NotFound) as e:
                key_manager.rotate_key()
                attempts += 1
                time.sleep(2)
                last_error = e
            except InvalidArgument as e:
                last_error = e
                break
            except Exception as e:
                last_error = e
                break
    
    yield f"\n[bold red]Model call failed:[/bold red] {last_error}\n"


def analyze_codebase_stream(collection, findings: str, key_manager: APIKeyManager, raw_code: str = "", compliance: str = "") -> Iterator[str]:
    """Run the full multi-phase corporate audit pipeline.
    
    Args:
        compliance: Optional compliance framework key (e.g. 'owasp', 'hipaa', 'pci-dss').
                    If provided, each phase prompt is augmented with framework-specific instructions.
    """
    
    phase_results = {}
    compliance_suffix = get_phase_suffix(compliance) if compliance else ""
    compliance_profile = get_profile(compliance) if compliance else None
    
    if compliance_profile:
        yield f"\n[bold magenta]🛡️ Compliance Mode: {compliance_profile['name']}[/bold magenta]\n"
    
    for i, phase in enumerate(AUDIT_PHASES):
        phase_num = i + 1
        total = len(AUDIT_PHASES)
        
        yield f"\n{'='*60}\n"
        yield f"[bold cyan]PHASE {phase_num}/{total}: {phase['name']}[/bold cyan]\n"
        yield f"{'='*60}\n\n"
        
        # Retrieve phase-specific context from RAG
        rag_query = phase['id'] + " " + phase['name']
        if "No static analysis" not in findings:
            rag_query += " " + findings[:200]
        
        try:
            context = _retrieve_context(collection, rag_query, key_manager, n_results=8)
        except Exception as e:
            yield f"[red]RAG retrieval error for phase {phase_num}: {e}[/red]\n"
            context = "Context retrieval failed."
        
        full_prompt = f"""{phase['prompt']}
{compliance_suffix}

### Full Source Code (READ THIS CAREFULLY - cite specific files and line numbers):
{raw_code[:80000]}

### RAG-Retrieved Relevant Context:
{context}

### Static Analysis Findings:
{findings}
"""
        
        phase_text = ""
        for chunk in _run_model(full_prompt, key_manager):
            phase_text += chunk
            yield chunk
            
        phase_results[phase['id']] = phase_text
        
        # Cooldown between phases to respect rate limits
        yield f"\n\n[dim]Phase {phase_num} complete. Cooling down before next phase...[/dim]\n"
        time.sleep(3)
    
    # Final: Executive Summary
    yield f"\n{'='*60}\n"
    yield f"[bold magenta]GENERATING EXECUTIVE SUMMARY[/bold magenta]\n"
    yield f"{'='*60}\n\n"
    
    all_findings = "\n\n".join(f"### {p['name']}\n{phase_results.get(p['id'], 'N/A')}" for p in AUDIT_PHASES)
    
    compliance_summary_instruction = ""
    if compliance:
        summary_suffix = get_summary_suffix(compliance)
        if summary_suffix:
            compliance_summary_instruction = f"\nCOMPLIANCE FRAMEWORK: {compliance_profile['name']}\n{summary_suffix}\n"
    
    exec_prompt = EXECUTIVE_SUMMARY_PROMPT.format(
        phase_results=all_findings,
        compliance_summary_instruction=compliance_summary_instruction
    )
    
    for chunk in _run_model(exec_prompt, key_manager):
        yield chunk


def generate_suggestions(report: str, key_manager: APIKeyManager) -> str:
    """Use Gemma 4 31B to extract actionable suggestions from the full report."""
    reviewer_model = "models/gemma-4-31b-it"
    prompt = f"""You are reviewing a comprehensive security audit report for a CISO.
Extract exactly 5 prioritized, actionable remediation steps.
For each step, format as:
**Priority X (Severity):** One-line action item
- Impact: What risk does this mitigate?
- Effort: Low/Medium/High

Report:
{report[:8000]}"""
    
    def review_func():
        model = genai.GenerativeModel(reviewer_model)
        return model.generate_content(prompt).text
        
    try:
        return key_manager.execute_with_retry(review_func)
    except Exception as e:
        return f"Failed to generate suggestions: {e}"
