"""
SentinelAI — CI/CD Reporter
Formats audit results as structured JSON for CI pipelines.
Posts findings as GitHub PR review comments.
"""

import os
import re
import json
from datetime import datetime, timezone


def _parse_severity_counts(report: str) -> dict:
    """Extract severity counts from the Executive Summary."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    patterns = {
        "critical": r'\*\*Critical:\*\*\s*(\d+)',
        "high": r'\*\*High:\*\*\s*(\d+)',
        "medium": r'\*\*Medium:\*\*\s*(\d+)',
        "low": r'\*\*Low:\*\*\s*(\d+)',
    }
    
    for severity, pattern in patterns.items():
        match = re.search(pattern, report, re.IGNORECASE)
        if match:
            counts[severity] = int(match.group(1))
    
    return counts


def _parse_overall_risk(report: str) -> str:
    """Extract overall risk rating from the report."""
    match = re.search(r'Overall Risk Rating[:\s]*\*?\*?(\w+)\*?\*?', report, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return "UNKNOWN"


def _parse_findings(report: str) -> list:
    """Extract structured findings from the audit report."""
    findings = []
    
    # Parse table-format findings
    table_pattern = re.compile(
        r'\|\s*\*\*(?P<severity>Critical|High|Medium|Low)\*\*\s*\|'
        r'\s*`?(?P<file>[^|`]+?)`?\s*\|'
        r'\s*(?P<line>[^|]*?)\s*\|'
        r'\s*(?P<desc>[^|]+?)\s*\|'
        r'\s*(?P<fix>[^|]+?)\s*\|',
        re.IGNORECASE
    )
    
    # Determine which phase each finding belongs to
    phase_sections = re.split(r'PHASE\s+(\d+)/6', report)
    
    for match in table_pattern.finditer(report):
        # Find which phase this match is in
        pos = match.start()
        phase_num = 0
        for phase_match in re.finditer(r'PHASE\s+(\d+)/6', report):
            if phase_match.start() < pos:
                phase_num = int(phase_match.group(1))
        
        line_str = match.group("line").strip()
        line_num = None
        if line_str and line_str.isdigit():
            line_num = int(line_str)
        
        findings.append({
            "phase": phase_num,
            "severity": match.group("severity").strip(),
            "file": match.group("file").strip(),
            "line": line_num,
            "description": match.group("desc").strip().replace("**", ""),
            "remediation": match.group("fix").strip(),
        })
    
    return findings


def _parse_suggestions(suggestions_text: str) -> list:
    """Parse the 5 prioritized suggestions into structured format."""
    suggestions = []
    
    pattern = re.compile(
        r'\*\*Priority\s+(\d+)\s*\((\w+)\):\*\*\s*(.+?)(?:\n|$)'
        r'(?:.*?Impact:\s*(.+?)(?:\n|$))?'
        r'(?:.*?Effort:\s*(\w+))?',
        re.DOTALL
    )
    
    for match in pattern.finditer(suggestions_text):
        suggestions.append({
            "priority": int(match.group(1)),
            "severity": match.group(2).strip(),
            "action": match.group(3).strip(),
            "impact": match.group(4).strip() if match.group(4) else "",
            "effort": match.group(5).strip() if match.group(5) else "",
        })
    
    return suggestions


def format_json_report(
    report: str,
    suggestions: str,
    target: str,
    findings_raw: list = None
) -> dict:
    """
    Format the full audit output as a structured JSON report for CI consumption.
    """
    counts = _parse_severity_counts(report)
    overall_risk = _parse_overall_risk(report)
    parsed_findings = _parse_findings(report)
    parsed_suggestions = _parse_suggestions(suggestions)
    
    return {
        "tool": "SentinelAI",
        "version": "2.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "overall_risk": overall_risk,
        "severity_counts": counts,
        "total_findings": sum(counts.values()),
        "findings": parsed_findings,
        "suggestions": parsed_suggestions,
        "static_analysis": {
            "secrets_found": len(findings_raw) if findings_raw else 0,
            "secrets": findings_raw or [],
        },
        "report_markdown": report,
        "suggestions_markdown": suggestions,
    }


def determine_exit_code(json_report: dict) -> int:
    """
    Determine CI exit code based on severity.
    0 = pass, 1 = critical/high found (fail), 2 = medium only (warning)
    """
    counts = json_report["severity_counts"]
    if counts["critical"] > 0 or counts["high"] > 0:
        return 1
    if counts["medium"] > 0:
        return 2
    return 0


def write_json_report(json_report: dict, output_path: str = "sentinel_report.json") -> str:
    """Write the JSON report to a file."""
    output_path = os.path.abspath(output_path)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(json_report, f, indent=2, ensure_ascii=False)
    return output_path


def format_github_summary(json_report: dict) -> str:
    """
    Format the report as a GitHub Actions Job Summary markdown.
    Written to $GITHUB_STEP_SUMMARY.
    """
    counts = json_report["severity_counts"]
    risk = json_report["overall_risk"]
    
    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk, "⚪")
    
    md = f"# {risk_emoji} SentinelAI Security Audit\n\n"
    md += f"**Target:** `{json_report['target']}`\n"
    md += f"**Risk Rating:** **{risk}**\n"
    md += f"**Scanned:** {json_report['timestamp']}\n\n"
    
    md += "## Findings Summary\n\n"
    md += "| Severity | Count |\n| --- | --- |\n"
    md += f"| 🔴 Critical | {counts['critical']} |\n"
    md += f"| 🟠 High | {counts['high']} |\n"
    md += f"| 🟡 Medium | {counts['medium']} |\n"
    md += f"| 🟢 Low | {counts['low']} |\n"
    md += f"| **Total** | **{json_report['total_findings']}** |\n\n"
    
    if json_report["findings"]:
        md += "## Top Findings\n\n"
        md += "| Severity | File | Description |\n| --- | --- | --- |\n"
        # Show top 10 findings, prioritized by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(
            json_report["findings"],
            key=lambda f: severity_order.get(f["severity"], 4)
        )
        for finding in sorted_findings[:10]:
            desc = finding["description"][:80]
            md += f"| **{finding['severity']}** | `{finding['file']}` | {desc} |\n"
        md += "\n"
    
    if json_report["suggestions"]:
        md += "## Remediation Priorities\n\n"
        for sug in json_report["suggestions"]:
            md += f"**P{sug['priority']} ({sug['severity']}):** {sug['action']}\n\n"
    
    md += "\n---\n*Generated by SentinelAI — AI-Powered Security Auditing*\n"
    
    return md


def post_github_pr_comments(
    json_report: dict,
    repo: str,
    pr_number: int,
    token: str
) -> bool:
    """
    Post audit findings as a GitHub PR review with per-file comments.
    
    Args:
        json_report: The structured JSON report
        repo: GitHub repo in "owner/repo" format
        pr_number: Pull request number
        token: GitHub token with repo permissions
    
    Returns True if comments were posted successfully.
    """
    try:
        import requests
    except ImportError:
        print("Error: 'requests' package is required for GitHub integration.")
        return False
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    
    # Get the files changed in this PR
    pr_files_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    resp = requests.get(pr_files_url, headers=headers)
    if resp.status_code != 200:
        print(f"Failed to get PR files: {resp.status_code} {resp.text}")
        return False
    
    changed_files = {f["filename"] for f in resp.json()}
    
    # Build review comments for findings that match changed files
    comments = []
    for finding in json_report["findings"]:
        file_path = finding["file"]
        # Normalize path separators
        file_path_normalized = file_path.replace("\\", "/")
        
        # Check if this file was changed in the PR
        matched_file = None
        for cf in changed_files:
            if cf.endswith(file_path_normalized) or file_path_normalized.endswith(cf):
                matched_file = cf
                break
        
        if matched_file:
            severity_emoji = {
                "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"
            }.get(finding["severity"], "⚪")
            
            body = (
                f"{severity_emoji} **SentinelAI [{finding['severity']}]:** "
                f"{finding['description']}\n\n"
            )
            if finding.get("remediation"):
                body += f"**Fix:** {finding['remediation']}\n"
            
            comment = {
                "path": matched_file,
                "body": body,
            }
            
            if finding.get("line"):
                comment["line"] = finding["line"]
                comment["side"] = "RIGHT"
            else:
                comment["line"] = 1
                comment["side"] = "RIGHT"
            
            comments.append(comment)
    
    if not comments:
        # Post a summary comment instead
        summary = format_github_summary(json_report)
        comment_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        resp = requests.post(comment_url, headers=headers, json={"body": summary})
        return resp.status_code == 201
    
    # Create a PR review with all comments
    review_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    
    counts = json_report["severity_counts"]
    review_body = (
        f"## 🛡️ SentinelAI Security Audit\n\n"
        f"**Risk:** {json_report['overall_risk']} | "
        f"🔴 {counts['critical']} Critical | 🟠 {counts['high']} High | "
        f"🟡 {counts['medium']} Medium | 🟢 {counts['low']} Low\n\n"
        f"Found **{len(comments)}** security issues in files changed by this PR."
    )
    
    event = "REQUEST_CHANGES" if counts["critical"] > 0 else "COMMENT"
    
    review_payload = {
        "body": review_body,
        "event": event,
        "comments": comments,
    }
    
    resp = requests.post(review_url, headers=headers, json=review_payload)
    if resp.status_code == 200:
        print(f"Posted PR review with {len(comments)} comments.")
        return True
    else:
        print(f"Failed to post PR review: {resp.status_code} {resp.text}")
        return False
