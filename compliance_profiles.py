"""
SentinelAI — Compliance Framework Profiles
Injects compliance-specific prompt suffixes into audit phases.
"""

COMPLIANCE_PROFILES = {
    "owasp": {
        "name": "OWASP Top 10 (2021)",
        "description": "Web application security standard by OWASP Foundation",
        "prompt_suffix": """
COMPLIANCE REQUIREMENT: Map EVERY finding to the OWASP Top 10 (2021) categories below.
Include the OWASP ID in your findings table as a column.

  A01:2021 - Broken Access Control
  A02:2021 - Cryptographic Failures
  A03:2021 - Injection
  A04:2021 - Insecure Design
  A05:2021 - Security Misconfiguration
  A06:2021 - Vulnerable and Outdated Components
  A07:2021 - Identification and Authentication Failures
  A08:2021 - Software and Data Integrity Failures
  A09:2021 - Security Logging and Monitoring Failures
  A10:2021 - Server-Side Request Forgery (SSRF)

For each OWASP category, state whether the codebase is COMPLIANT, NON-COMPLIANT, or NEEDS REVIEW.
If a category has ZERO findings, explicitly note it as compliant.
""",
        "summary_suffix": "Include an OWASP Top 10 Compliance Matrix table mapping each A01-A10 category to its status (Compliant/Non-Compliant/Needs Review) with the specific finding references."
    },

    "pci-dss": {
        "name": "PCI-DSS v4.0",
        "description": "Payment Card Industry Data Security Standard",
        "prompt_suffix": """
COMPLIANCE REQUIREMENT: Evaluate findings against PCI-DSS v4.0 requirements.
Focus specifically on:

  Req 1 & 2: Network Security Controls / Secure Configurations
  Req 3: Protect Stored Account Data (encryption at rest, key management)
  Req 4: Protect Cardholder Data in Transit (TLS, certificate validation)
  Req 5: Protect Against Malicious Software
  Req 6: Develop and Maintain Secure Systems (SDLC, code review, patching)
  Req 7: Restrict Access by Business Need to Know (RBAC, least privilege)
  Req 8: Identify Users and Authenticate Access (MFA, password policies)
  Req 9: Restrict Physical Access to Cardholder Data
  Req 10: Log and Monitor All Access (audit trails, log integrity)
  Req 11: Test Security Regularly (vulnerability scanning, penetration testing)
  Req 12: Support Information Security with Policies

For each finding, include the PCI-DSS requirement number it violates.
Flag any storage or transmission of card numbers (PAN), CVV, or expiration dates.
""",
        "summary_suffix": "Include a PCI-DSS Compliance Status table mapping each Requirement (1-12) to Compliant/Non-Compliant/Not Applicable with evidence references."
    },

    "hipaa": {
        "name": "HIPAA Security Rule",
        "description": "Health Insurance Portability and Accountability Act",
        "prompt_suffix": """
COMPLIANCE REQUIREMENT: Evaluate findings against the HIPAA Security Rule.
Focus specifically on:

  § 164.312(a) - Access Control (unique user IDs, emergency access, automatic logoff, encryption)
  § 164.312(b) - Audit Controls (audit logs, monitoring)
  § 164.312(c) - Integrity Controls (data integrity mechanisms, authentication of ePHI)
  § 164.312(d) - Person or Entity Authentication
  § 164.312(e) - Transmission Security (encryption in transit, integrity controls)
  § 164.308(a)(1) - Security Management Process (risk analysis, risk management)
  § 164.308(a)(5) - Security Awareness Training

Hunt specifically for:
- Any storage, transmission, or logging of Protected Health Information (PHI/ePHI)
- Patient names, dates of birth, SSNs, medical record numbers, health plan IDs
- Unencrypted PHI in databases, logs, localStorage, or API responses
- Missing audit trail for PHI access

For each finding, include the HIPAA section number it violates.
""",
        "summary_suffix": "Include a HIPAA Security Rule Compliance Matrix mapping each § section to its compliance status with specific code evidence."
    },

    "soc2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Control 2 Trust Services Criteria",
        "prompt_suffix": """
COMPLIANCE REQUIREMENT: Evaluate findings against SOC 2 Type II Trust Services Criteria.
Focus specifically on:

  CC6.1 - Logical and Physical Access Controls
  CC6.2 - User Authentication Mechanisms
  CC6.3 - Authorization and Access Restrictions
  CC6.6 - Protection Against Threats Outside System Boundaries
  CC6.7 - Restriction of Data Transmission/Movement/Removal
  CC6.8 - Prevention of Unauthorized Software
  CC7.1 - Detection and Monitoring of Security Events
  CC7.2 - Monitoring for Anomalies (Incident Response)
  CC8.1 - Change Management Controls
  CC9.1 - Risk Mitigation

Also evaluate:
  A1.1 - Availability: Processing capacity, environmental protections
  PI1.1 - Processing Integrity: Input validation, error handling
  C1.1 - Confidentiality: Classification, encryption, disposal
  P1.1 - Privacy: Consent, data minimization, retention

For each finding, include the Trust Services Criteria ID.
""",
        "summary_suffix": "Include a SOC 2 Trust Services Criteria matrix mapping CC6-CC9, A1, PI1, C1, P1 to compliance status."
    },

    "gdpr": {
        "name": "GDPR (EU General Data Protection Regulation)",
        "description": "European Union data protection and privacy regulation",
        "prompt_suffix": """
COMPLIANCE REQUIREMENT: Evaluate findings against GDPR requirements.
Focus specifically on:

  Art. 5  - Principles (lawfulness, purpose limitation, data minimization, accuracy, storage limitation, integrity, accountability)
  Art. 6  - Lawfulness of Processing (legal basis for data processing)
  Art. 7  - Conditions for Consent (explicit, informed, withdrawable)
  Art. 13 - Information to Data Subject (privacy notices)
  Art. 15 - Right of Access
  Art. 17 - Right to Erasure ("Right to be Forgotten")
  Art. 20 - Right to Data Portability
  Art. 25 - Data Protection by Design and by Default
  Art. 32 - Security of Processing (encryption, pseudonymization, resilience, regular testing)
  Art. 33 - Breach Notification (72-hour notification obligation)
  Art. 35 - Data Protection Impact Assessment (DPIA)
  Art. 44 - Cross-Border Data Transfers

Hunt specifically for:
- Personal data (names, emails, phone numbers, IP addresses, device IDs)
- Missing consent mechanisms before data collection
- Missing data deletion/export functionality
- Data sent to third-party services without DPA (Data Processing Agreement)
- Cross-border transfers without adequate safeguards (SCCs, adequacy decisions)

For each finding, include the GDPR Article number it violates.
""",
        "summary_suffix": "Include a GDPR Compliance Matrix mapping key Articles (5, 6, 7, 13, 17, 25, 32, 33, 35) to compliance status."
    },

    "cwe25": {
        "name": "CWE Top 25 (2024)",
        "description": "MITRE Common Weakness Enumeration Top 25 Most Dangerous Software Weaknesses",
        "prompt_suffix": """
COMPLIANCE REQUIREMENT: Map EVERY finding to the CWE Top 25 (2024) list below.
Include the CWE ID in your findings.

  CWE-787: Out-of-bounds Write
  CWE-79:  Cross-site Scripting (XSS)
  CWE-89:  SQL Injection
  CWE-416: Use After Free
  CWE-78:  OS Command Injection
  CWE-20:  Improper Input Validation
  CWE-125: Out-of-bounds Read
  CWE-22:  Path Traversal
  CWE-352: Cross-Site Request Forgery (CSRF)
  CWE-434: Unrestricted Upload of File with Dangerous Type
  CWE-862: Missing Authorization
  CWE-476: NULL Pointer Dereference
  CWE-287: Improper Authentication
  CWE-190: Integer Overflow
  CWE-502: Deserialization of Untrusted Data
  CWE-77:  Command Injection
  CWE-119: Buffer Overflow
  CWE-798: Hardcoded Credentials
  CWE-918: SSRF
  CWE-306: Missing Authentication for Critical Function
  CWE-362: Race Condition
  CWE-269: Improper Privilege Management
  CWE-94:  Code Injection
  CWE-863: Incorrect Authorization
  CWE-276: Incorrect Default Permissions

For each CWE in the top 25, state whether the codebase is VULNERABLE, SAFE, or NEEDS REVIEW.
""",
        "summary_suffix": "Include a CWE Top 25 Coverage Matrix showing each CWE ID, its status, and the specific code reference if vulnerable."
    },
}


def get_available_profiles() -> dict:
    """Returns a dict of {key: name} for all available compliance profiles."""
    return {k: v["name"] for k, v in COMPLIANCE_PROFILES.items()}


def get_profile(key: str) -> dict:
    """Get a specific compliance profile by key. Returns None if not found."""
    return COMPLIANCE_PROFILES.get(key.lower().strip())


def get_phase_suffix(key: str) -> str:
    """Get the prompt suffix to inject into each audit phase."""
    profile = get_profile(key)
    if profile:
        return profile["prompt_suffix"]
    return ""


def get_summary_suffix(key: str) -> str:
    """Get the extra instruction to inject into the executive summary prompt."""
    profile = get_profile(key)
    if profile:
        return profile.get("summary_suffix", "")
    return ""
