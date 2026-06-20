"""
SentinelAI — Automated Remediation Patch Generator
Generates unified diff patches for each fixable vulnerability found in the audit.
"""

import os
import re
import google.generativeai as genai
from google.api_core.exceptions import ResourceExhausted, InvalidArgument, NotFound
from key_manager import APIKeyManager
from datetime import datetime
import time


PATCH_MODEL = "gemini-3.1-flash-lite"  # 15 RPM, 500 RPD — fast + high quota

PATCH_PROMPT = """You are a senior security engineer generating a code fix.

Given a security vulnerability finding and the relevant source code, generate a unified diff patch that fixes the vulnerability.

RULES:
1. Output ONLY the unified diff in standard format. No explanation, no markdown fences.
2. Use the exact file path from the finding.
3. The diff must be applicable with `git apply`.
4. Be minimal — change only what's needed to fix the vulnerability.
5. Include 3 lines of context above and below the change.
6. If the fix requires adding a new file (e.g., middleware), output the full file content as an addition diff.

FORMAT:
--- a/{file_path}
+++ b/{file_path}
@@ -{old_start},{old_count} +{new_start},{new_count} @@
 context line
-removed line
+added line
 context line

VULNERABILITY:
{finding}

SOURCE CODE:
{source_code}
"""


def _extract_findings(report: str) -> list:
    """Extract individual findings with file references from the audit report."""
    findings = []
    
    # Pattern 1: Table rows with severity | file | line | description | remediation
    table_pattern = re.compile(
        r'\|\s*\*\*(?P<severity>Critical|High|Medium|Low)\*\*\s*\|'
        r'\s*`?(?P<file>[^|`]+?)`?\s*\|'
        r'\s*(?P<line>[^|]*?)\s*\|'
        r'\s*(?P<desc>[^|]+?)\s*\|'
        r'\s*(?P<fix>[^|]+?)\s*\|',
        re.IGNORECASE
    )
    
    for match in table_pattern.finditer(report):
        findings.append({
            "severity": match.group("severity").strip(),
            "file": match.group("file").strip(),
            "line": match.group("line").strip(),
            "description": match.group("desc").strip(),
            "remediation": match.group("fix").strip(),
        })
    
    # Pattern 2: Numbered findings with **File:** or **Severity:** format
    section_pattern = re.compile(
        r'###\s*\d+\.\s*(?P<title>[^\n]+)\n'
        r'(?P<body>(?:(?!###\s*\d+\.)[\s\S])*)',
        re.MULTILINE
    )
    
    for match in section_pattern.finditer(report):
        body = match.group("body")
        title = match.group("title").strip()
        
        # Extract file reference from body
        file_match = re.search(r'\*\*File:\*\*\s*`?([^`\n]+)`?', body)
        severity_match = re.search(r'\*\*Severity:\*\*\s*(\w+)', body)
        
        if file_match:
            findings.append({
                "severity": severity_match.group(1) if severity_match else "Medium",
                "file": file_match.group(1).strip(),
                "line": "",
                "description": title,
                "remediation": body[:300],
            })
    
    # Pattern 3: Inline severity markers like "| **Critical** | `src/store.ts` |"
    inline_pattern = re.compile(
        r'\*\*(?P<severity>Critical|High|Medium)\*\*.*?`(?P<file>[^`]+\.\w+)`',
        re.IGNORECASE
    )
    
    # Avoid duplicates
    seen_files = {f["file"] for f in findings}
    for match in inline_pattern.finditer(report):
        file_ref = match.group("file").strip()
        if file_ref not in seen_files:
            # Get surrounding text as description
            start = max(0, match.start() - 50)
            end = min(len(report), match.end() + 200)
            context = report[start:end]
            
            findings.append({
                "severity": match.group("severity").strip(),
                "file": file_ref,
                "line": "",
                "description": context.strip(),
                "remediation": "",
            })
            seen_files.add(file_ref)
    
    return findings


def _get_file_content(raw_code: str, target_file: str) -> str:
    """Extract a specific file's content from the raw code dump."""
    # The raw code format from context_builder is:
    # === FILE: path/to/file.py ===
    # <content>
    # === END FILE ===
    
    patterns = [
        rf'===\s*FILE:\s*{re.escape(target_file)}\s*===\n(.*?)(?====\s*(?:FILE|END))',
        rf'===\s*FILE:.*?{re.escape(os.path.basename(target_file))}\s*===\n(.*?)(?====\s*(?:FILE|END))',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, raw_code, re.DOTALL)
        if match:
            return match.group(1).strip()
    
    return ""


def generate_patches(
    report: str,
    raw_code: str,
    key_manager: APIKeyManager,
    log_callback=None
) -> list:
    """
    Generate unified diff patches for vulnerabilities found in the audit report.
    
    Returns a list of dicts: [{"file": str, "severity": str, "finding": str, "patch": str}]
    """
    findings = _extract_findings(report)
    
    if not findings:
        if log_callback:
            log_callback("[yellow]No specific file-referenced findings found to patch.[/yellow]\n")
        return []
    
    if log_callback:
        log_callback(f"[bold]Found {len(findings)} patchable findings. Generating fixes...[/bold]\n")
    
    patches = []
    
    for i, finding in enumerate(findings):
        if log_callback:
            log_callback(f"[dim]  [{i+1}/{len(findings)}] Patching {finding['file']} ({finding['severity']})...[/dim]\n")
        
        # Get the relevant source code
        source_code = _get_file_content(raw_code, finding["file"])
        if not source_code:
            source_code = f"(File content not available for: {finding['file']})"
        
        finding_text = (
            f"Severity: {finding['severity']}\n"
            f"File: {finding['file']}\n"
            f"Line: {finding['line']}\n"
            f"Description: {finding['description']}\n"
            f"Remediation: {finding['remediation']}"
        )
        
        prompt = PATCH_PROMPT.format(
            file_path=finding["file"],
            finding=finding_text,
            source_code=source_code[:8000]
        )
        
        # Generate the patch
        patch_text = ""
        attempts = 0
        max_attempts = max(key_manager.count() * 2, 2)
        
        while attempts < max_attempts:
            try:
                genai.configure(api_key=key_manager.get_current_key())
                model = genai.GenerativeModel(PATCH_MODEL)
                response = model.generate_content(prompt)
                if response.text:
                    patch_text = response.text.strip()
                    # Clean markdown fences if the model included them
                    patch_text = re.sub(r'^```(?:diff)?\n?', '', patch_text)
                    patch_text = re.sub(r'\n?```$', '', patch_text)
                break
            except (ResourceExhausted, NotFound):
                key_manager.rotate_key()
                attempts += 1
                time.sleep(2)
            except Exception as e:
                if log_callback:
                    log_callback(f"[red]  Error generating patch for {finding['file']}: {e}[/red]\n")
                break
        
        if patch_text and ('---' in patch_text or '+++' in patch_text or '+' in patch_text):
            patches.append({
                "file": finding["file"],
                "severity": finding["severity"],
                "finding": finding_text,
                "patch": patch_text,
            })
        
        # Rate limit cooldown
        time.sleep(1)
    
    if log_callback:
        log_callback(f"[bold green]Generated {len(patches)} patches.[/bold green]\n")
    
    return patches


def save_patches(patches: list, output_dir: str = "sentinel_patches") -> str:
    """
    Save generated patches to disk.
    Creates individual patch files and a combined all_fixes.patch.
    
    Returns the absolute path to the output directory.
    """
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    all_patches = []
    
    for i, patch in enumerate(patches):
        severity = patch["severity"].lower()
        file_slug = re.sub(r'[^a-zA-Z0-9]', '_', os.path.basename(patch["file"]))
        filename = f"{i+1:03d}_{severity}_{file_slug}.patch"
        
        patch_content = f"# SentinelAI Fix: {patch['severity']} — {patch['file']}\n"
        patch_content += f"# Finding: {patch['finding'].split(chr(10))[3] if len(patch['finding'].split(chr(10))) > 3 else patch['finding'][:80]}\n"
        patch_content += f"# Generated: {datetime.now().isoformat()}\n\n"
        patch_content += patch["patch"]
        
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(patch_content)
        
        all_patches.append(patch["patch"])
    
    # Write combined patch
    if all_patches:
        combined_path = os.path.join(output_dir, "all_fixes.patch")
        with open(combined_path, "w", encoding="utf-8") as f:
            f.write(f"# SentinelAI Combined Security Patches\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total fixes: {len(all_patches)}\n\n")
            f.write("\n\n".join(all_patches))
    
    # Write a summary README
    readme_path = os.path.join(output_dir, "README.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write("# SentinelAI Security Patches\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## How to Apply\n\n")
        f.write("Apply all fixes at once:\n")
        f.write("```bash\ngit apply sentinel_patches/all_fixes.patch\n```\n\n")
        f.write("Or apply individual patches:\n")
        f.write("```bash\ngit apply sentinel_patches/001_critical_*.patch\n```\n\n")
        f.write("## Patches\n\n")
        f.write("| # | Severity | File | Patch |\n")
        f.write("| --- | --- | --- | --- |\n")
        for i, patch in enumerate(patches):
            severity = patch["severity"].lower()
            file_slug = re.sub(r'[^a-zA-Z0-9]', '_', os.path.basename(patch["file"]))
            filename = f"{i+1:03d}_{severity}_{file_slug}.patch"
            f.write(f"| {i+1} | {patch['severity']} | `{patch['file']}` | `{filename}` |\n")
        f.write("\n> ⚠️ Review each patch before applying. AI-generated fixes should be validated.\n")
    
    return output_dir
