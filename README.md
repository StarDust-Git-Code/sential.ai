# SentinelAI

**Enterprise-Grade AI Security Auditing for Modern Codebases**

SentinelAI is a revolutionary security auditing tool that bridges the gap between traditional Static Application Security Testing (SAST) and human-level security reviews. By leveraging Large Language Models (LLMs) and Retrieval-Augmented Generation (RAG), SentinelAI builds a deep, semantic understanding of your entire repository to find complex business-logic flaws, authorization bypasses, and security vulnerabilities that legacy scanners completely miss.

## 🏆 Built for MLH Gemini.exe 2.0 Hackathon

**SentinelAI is our proud submission for the Google x MLH Gemini.exe 2.0 Hackathon!** 

This project was built from the ground up to showcase the power of the Gemini API in complex reasoning tasks. Here is exactly how Gemini powers SentinelAI:
1. **Semantic Code Search**: We use Gemini's powerful embedding models to tokenize and vectorize entire repositories, allowing our local ChromaDB instance to understand the *meaning* of your code, not just the syntax.
2. **Deep Security Reasoning**: We leverage Gemini's massive context window and advanced logic capabilities to power our Multi-Agent security engine. Gemini doesn't just read code—it cross-references multiple files to find chained vulnerabilities, authorization bypasses, and business-logic flaws that regular pattern-matching scanners miss.
3. **Automated Remediation**: Gemini doesn't just point out errors; it generates highly accurate, standard `.patch` files to automatically fix the vulnerabilities it finds.

---

## 📑 Table of Contents

- [The Problem with Legacy Scanners](#-the-problem-with-legacy-scanners)
- [The SentinelAI Solution](#-the-sentinelai-solution)
- [Core Features](#-core-features)
- [Deep Dive: Technical Architecture](#-deep-dive-technical-architecture)
- [Supported Compliance Frameworks](#-supported-compliance-frameworks)
- [Installation Guide](#-installation-guide)
- [Comprehensive Usage Guide](#-comprehensive-usage-guide)
- [Data Privacy & Security](#-data-privacy--security)

---

## 🛑 The Problem with Legacy Scanners

Modern software development moves at lightning speed, but security tooling has lagged behind. Traditional SAST tools rely heavily on rigid regular expressions, Abstract Syntax Tree (AST) matching, and static pattern recognition. This creates massive friction for engineering teams:

1. **Context Blindness**: Legacy scanners check files independently. They cannot understand that a variable instantiated in `middleware.ts` is insecurely passed into a database query in `routes.py`. 
2. **Business Logic Ignorance**: Traditional tools cannot understand the *intent* of your code. They cannot detect if an API endpoint allows users to escalate their privileges or access another user's tenant data (BOLA/IDOR).
3. **Alert Fatigue**: Developers are bombarded with hundreds of false positives (e.g., flagging a test-suite variable named `password` as a critical vulnerability).

Hiring dedicated security engineers to manually review every Pull Request is too slow and too expensive for startups and hackathon teams.

---

## 💡 The SentinelAI Solution

SentinelAI flips the paradigm. Instead of searching for known bad strings, it **reads and comprehends your codebase like a Senior Security Engineer**.

Using a local **ChromaDB** vector database and Google's **Gemini LLM**, SentinelAI maps out your repository's architecture. It understands your authentication flows, database schemas, and API routing. When evaluating a specific function, the AI is provided with the full semantic context of how that function interacts with the rest of the application. It then simulates real-world attack paths to find complex, multi-step vulnerabilities.

---

## ✨ Core Features

### 1. 🧠 Multi-Agent RAG Analysis
SentinelAI chunks your codebase, generates intelligent summaries, and builds a searchable semantic index. It utilizes specialized AI prompts to hunt for architectural weaknesses, injection flaws, and dependency risks with deep context.

### 2. 🖥️ Dual Interfaces
- **Terminal UI (TUI)**: A beautifully styled, hacker-friendly, interactive terminal dashboard for developers who never want to leave their command line.
- **Web UI (Mission Control)**: A full-featured browser dashboard with real-time WebSocket streaming, visual analytics, and interactive chat.

### 3. 📜 Native Compliance Engine
Ensure your code meets legal and enterprise standards. SentinelAI natively scans against compliance profiles and highlights exact lines of code that violate regulations.

### 4. 🛠️ Auto-Remediation Patch Generation
Don't just find bugs—fix them. SentinelAI can automatically generate standard `.patch` files containing exact code changes to mitigate discovered vulnerabilities.

### 5. 📦 Automated SBOM Generation
Instantly generate standard **CycloneDX Software Bill of Materials (SBOM) in JSON format**. Essential for enterprise vendor compliance and tracking supply chain risks.

### 6. 💬 Interactive Code Chat
Drop into a chat interface *after* an audit finishes. Ask questions like *"How do I implement the suggested fix for the JWT vulnerability in line 45?"* and get contextual answers instantly.

### 7. 🤖 Headless CI/CD Mode
Designed for pipelines. In CI mode, SentinelAI outputs a structured JSON report and automatically fails the build (exit code `1`) if vulnerabilities exceeding a specified severity are found.

### 8. 📊 Historical Trending & Analytics
A local SQLite database (`sentinel_history.db`) tracks every audit you run, letting you visualize your project's security posture improving (or degrading) over time.

---

## 🏗️ Deep Dive: Technical Architecture

SentinelAI operates through an intensive **6-Phase Security Pipeline**:

1. **Target Resolution**: Validates the local folder or securely clones a remote GitHub repository.
2. **Phase 1: Pre-Scan (Gitleaks)**: Executes a high-speed traditional scan using Gitleaks to instantly detect hardcoded API keys, passwords, and sensitive tokens.
3. **Phase 2: RAG Vectorization**: Your codebase is tokenized and chunked. Gemini Embedding models convert the code into mathematical vectors, which are stored in an ephemeral **ChromaDB** instance.
4. **Phase 3: Context Building**: SentinelAI creates a master architectural overview, mapping out how different files and directories relate to one another.
5. **Phase 4: Multi-Agent Analysis**: The core engine. It executes specialized prompts against the LLM, feeding it highly relevant codebase chunks retrieved from the vector database to hunt for logic flaws.
6. **Phase 5 & 6: Reporting & Remediation**: Findings are synthesized, severity scores are standardized, and the final output is routed to the CLI, TUI, Web Server, HTML Exporter, or JSON/SBOM builder.

---

## 📋 Supported Compliance Frameworks

Pass the `--compliance <framework>` flag to audit your code against specific industry standards:

- `owasp`: Checks against the OWASP Top 10 Web Application Security Risks.
- `gdpr`: EU General Data Protection Regulation (focuses on Data Minimization, Right to Erasure, Encryption).
- `hipaa`: Health Insurance Portability and Accountability Act (focuses on ePHI protection, audit controls).
- `pci-dss`: Payment Card Industry Data Security Standard (focuses on secure transmission, cardholder data protection).
- `soc2`: System and Organization Controls 2 (focuses on Security, Availability, and Confidentiality principles).
- `cwe25`: Top 25 Most Dangerous Software Weaknesses.

---

## 🚀 Installation Guide

We've built a frictionless, idempotent installation script for Windows environments.

**What the installer does automatically:**
- Verifies and installs Python 3.10+ (via winget if missing).
- Verifies Git (via winget if missing).
- Downloads and configures the `gitleaks` binary for Phase 1 scanning.
- Creates an isolated Python virtual environment (`.venv`).
- Installs all heavily pinned dependencies from `requirements.txt`.
- Registers the `sentinelai` command globally in your Windows System PATH.

### Steps:
1. Clone or download the repository:
   ```bash
   git clone https://github.com/StarDust-Git-Code/sential.ai.git
   cd sential.ai
   ```
2. Open **PowerShell** (Run as Administrator is recommended for PATH changes) and execute:
   ```powershell
   powershell -ExecutionPolicy Bypass -File install.ps1
   ```
3. Open a **brand new** terminal window to apply the PATH changes. You are now ready to run `sentinelai`.

---

## 💻 Comprehensive Usage Guide

SentinelAI is incredibly versatile. It functions as a global CLI tool that can spin up local servers, run interactive dashboards, or execute headless scans.

### Interface Launchers

```bash
# Launch the Terminal UI (TUI)
sentinelai

# Launch the Web Dashboard (Starts FastAPI backend and opens browser to localhost:8765)
sentinelai --web
```

### CLI Auditing Power Commands

```bash
# Run a standard AI security audit on the current directory
sentinelai audit .

# Run an audit on a specific remote GitHub repository
sentinelai audit https://github.com/expressjs/express

# Run an audit and verify against HIPAA compliance
sentinelai audit . --compliance hipaa

# Run an audit and automatically generate a CycloneDX SBOM
sentinelai audit . --sbom

# Run an audit and auto-generate .patch files for all fixable vulnerabilities
sentinelai audit . --fix

# CI/CD Pipeline Mode: Outputs JSON and throws exit codes on critical failures
sentinelai audit . --ci

# Interactive Chat Mode: After the audit finishes, drop into a terminal prompt to ask questions about your code
sentinelai audit . --interactive

# Combine flags for a massive enterprise scan!
sentinelai audit . --compliance owasp --sbom --fix --export html --interactive
```

### History & Tracking

```bash
# View a summary of all past audits, including timestamps and total vulnerabilities found
sentinelai history
```

---

## 🔒 Data Privacy & Security

We understand that source code is your most valuable asset.

- **Local Processing**: All file parsing, chunking, and database operations (ChromaDB, SQLite) happen strictly on your local machine.
- **LLM Transmission**: Code chunks are sent *only* to the Google Gemini API for semantic analysis. 
- **No Telemetry**: SentinelAI does not track you, does not phone home, and does not store your code on our servers.
- **Key Security**: Your Gemini API Key is stored locally in `.sentinel_keys.json`. Our `.gitignore` ensures this file is never accidentally pushed to version control. 

*(Note: Ensure you read the data processing agreements of your LLM provider regarding API data retention).*
