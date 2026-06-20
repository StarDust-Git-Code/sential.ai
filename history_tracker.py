"""
SentinelAI — Historical Trend Tracking
Stores audit results in SQLite for trend analysis over time.
"""

import os
import re
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel_history.db")


def _get_connection(db_path: str = None) -> sqlite3.Connection:
    """Get a SQLite connection with WAL mode for concurrent reads."""
    path = db_path or DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str = None) -> None:
    """Initialize the database schema if it doesn't exist."""
    conn = _get_connection(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS audits (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            overall_risk TEXT,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            compliance_framework TEXT DEFAULT '',
            secrets_found INTEGER DEFAULT 0,
            code_size_kb REAL DEFAULT 0,
            report_md TEXT,
            suggestions_md TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id TEXT NOT NULL,
            phase INTEGER,
            severity TEXT NOT NULL,
            file TEXT,
            line INTEGER,
            description TEXT,
            remediation TEXT,
            FOREIGN KEY (audit_id) REFERENCES audits(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_audits_target ON audits(target);
        CREATE INDEX IF NOT EXISTS idx_audits_timestamp ON audits(timestamp);
        CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    """)
    conn.commit()
    conn.close()


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
    """Extract overall risk rating."""
    match = re.search(r'Overall Risk Rating[:\s]*\*?\*?(\w+)\*?\*?', report, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def _parse_findings(report: str) -> list:
    """Extract individual findings from the report."""
    findings = []
    table_pattern = re.compile(
        r'\|\s*\*\*(?P<severity>Critical|High|Medium|Low)\*\*\s*\|'
        r'\s*`?(?P<file>[^|`]+?)`?\s*\|'
        r'\s*(?P<line>[^|]*?)\s*\|'
        r'\s*(?P<desc>[^|]+?)\s*\|'
        r'\s*(?P<fix>[^|]+?)\s*\|',
        re.IGNORECASE
    )
    
    for match in table_pattern.finditer(report):
        pos = match.start()
        phase_num = 0
        for pm in re.finditer(r'PHASE\s+(\d+)/6', report):
            if pm.start() < pos:
                phase_num = int(pm.group(1))
        
        line_str = match.group("line").strip()
        findings.append({
            "phase": phase_num,
            "severity": match.group("severity").strip(),
            "file": match.group("file").strip(),
            "line": int(line_str) if line_str.isdigit() else None,
            "description": match.group("desc").strip().replace("**", ""),
            "remediation": match.group("fix").strip(),
        })
    return findings


def save_audit(
    target: str,
    report: str,
    suggestions: str,
    compliance: str = "",
    secrets_count: int = 0,
    code_size_kb: float = 0,
    db_path: str = None
) -> str:
    """
    Save a completed audit to the history database.
    Returns the audit ID.
    """
    init_db(db_path)
    
    audit_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    counts = _parse_severity_counts(report)
    risk = _parse_overall_risk(report)
    findings = _parse_findings(report)
    
    conn = _get_connection(db_path)
    
    conn.execute("""
        INSERT INTO audits (id, target, timestamp, overall_risk,
            critical_count, high_count, medium_count, low_count, total_findings,
            compliance_framework, secrets_found, code_size_kb, report_md, suggestions_md)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        audit_id, target, now, risk,
        counts["critical"], counts["high"], counts["medium"], counts["low"],
        sum(counts.values()),
        compliance, secrets_count, code_size_kb,
        report, suggestions
    ))
    
    for finding in findings:
        conn.execute("""
            INSERT INTO findings (audit_id, phase, severity, file, line, description, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            audit_id, finding["phase"], finding["severity"],
            finding["file"], finding["line"],
            finding["description"], finding["remediation"]
        ))
    
    conn.commit()
    conn.close()
    
    return audit_id


def get_audit_history(
    target: Optional[str] = None,
    limit: int = 20,
    db_path: str = None
) -> list:
    """
    Get audit history, optionally filtered by target.
    Returns a list of audit summary dicts, newest first.
    """
    init_db(db_path)
    conn = _get_connection(db_path)
    
    if target:
        rows = conn.execute("""
            SELECT id, target, timestamp, overall_risk,
                critical_count, high_count, medium_count, low_count,
                total_findings, compliance_framework, secrets_found
            FROM audits WHERE target = ? ORDER BY timestamp DESC LIMIT ?
        """, (target, limit)).fetchall()
    else:
        rows = conn.execute("""
            SELECT id, target, timestamp, overall_risk,
                critical_count, high_count, medium_count, low_count,
                total_findings, compliance_framework, secrets_found
            FROM audits ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
    
    conn.close()
    return [dict(row) for row in rows]


def get_audit_detail(audit_id: str, db_path: str = None) -> Optional[dict]:
    """Get full details of a specific audit including findings."""
    init_db(db_path)
    conn = _get_connection(db_path)
    
    audit = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if not audit:
        conn.close()
        return None
    
    findings = conn.execute(
        "SELECT * FROM findings WHERE audit_id = ? ORDER BY severity, phase",
        (audit_id,)
    ).fetchall()
    
    conn.close()
    
    result = dict(audit)
    result["findings"] = [dict(f) for f in findings]
    return result


def get_trend_data(target: str, limit: int = 10, db_path: str = None) -> dict:
    """
    Get trend data for a specific target across multiple audits.
    Returns data suitable for plotting severity counts over time.
    """
    init_db(db_path)
    conn = _get_connection(db_path)
    
    rows = conn.execute("""
        SELECT timestamp, overall_risk,
            critical_count, high_count, medium_count, low_count, total_findings
        FROM audits WHERE target = ? ORDER BY timestamp ASC LIMIT ?
    """, (target, limit)).fetchall()
    
    conn.close()
    
    if not rows:
        return {"target": target, "audits": [], "trend": "no_data"}
    
    data = [dict(r) for r in rows]
    
    # Calculate trend direction
    if len(data) >= 2:
        first_total = data[0]["total_findings"]
        last_total = data[-1]["total_findings"]
        if last_total < first_total:
            trend = "improving"
        elif last_total > first_total:
            trend = "degrading"
        else:
            trend = "stable"
    else:
        trend = "insufficient_data"
    
    return {
        "target": target,
        "audit_count": len(data),
        "trend": trend,
        "audits": data,
    }


def get_most_common_vulnerabilities(limit: int = 10, db_path: str = None) -> list:
    """Get the most frequently occurring vulnerability types across all audits."""
    init_db(db_path)
    conn = _get_connection(db_path)
    
    rows = conn.execute("""
        SELECT description, severity, COUNT(*) as occurrence_count,
            GROUP_CONCAT(DISTINCT file) as affected_files
        FROM findings
        GROUP BY description, severity
        ORDER BY occurrence_count DESC
        LIMIT ?
    """, (limit,)).fetchall()
    
    conn.close()
    return [dict(r) for r in rows]


def format_history_table(audits: list) -> str:
    """Format audit history as a rich-printable table string."""
    if not audits:
        return "No audit history found."
    
    lines = []
    lines.append(f"{'ID':>8} | {'Target':>30} | {'Date':>19} | {'Risk':>8} | {'C':>2} {'H':>2} {'M':>2} {'L':>2} | {'Total':>5}")
    lines.append("-" * 95)
    
    for audit in audits:
        ts = audit["timestamp"][:19].replace("T", " ")
        target = audit["target"][:30]
        lines.append(
            f"{audit['id']:>8} | {target:>30} | {ts:>19} | "
            f"{audit['overall_risk']:>8} | "
            f"{audit['critical_count']:>2} {audit['high_count']:>2} "
            f"{audit['medium_count']:>2} {audit['low_count']:>2} | "
            f"{audit['total_findings']:>5}"
        )
    
    return "\n".join(lines)


def format_trend_summary(trend_data: dict) -> str:
    """Format trend data as a human-readable summary."""
    if trend_data["trend"] == "no_data":
        return "No historical data for this target."
    
    trend_emoji = {
        "improving": "[v] IMPROVING",
        "degrading": "[^] DEGRADING",
        "stable": "[-] STABLE",
        "insufficient_data": "[?] NEEDS MORE DATA",
    }
    
    lines = []
    lines.append(f"Target: {trend_data['target']}")
    lines.append(f"Audits: {trend_data['audit_count']}")
    lines.append(f"Trend: {trend_emoji.get(trend_data['trend'], trend_data['trend'])}")
    lines.append("")
    lines.append(f"{'Date':>19} | {'Risk':>8} | {'C':>2} {'H':>2} {'M':>2} {'L':>2} | {'Total':>5}")
    lines.append("-" * 60)
    
    for audit in trend_data["audits"]:
        ts = audit["timestamp"][:19].replace("T", " ")
        lines.append(
            f"{ts:>19} | {audit['overall_risk']:>8} | "
            f"{audit['critical_count']:>2} {audit['high_count']:>2} "
            f"{audit['medium_count']:>2} {audit['low_count']:>2} | "
            f"{audit['total_findings']:>5}"
        )
    
    return "\n".join(lines)
