# 🛡️ SentinelAI

<div align="center">
  <br />
  <h3>AI-powered security auditing for modern codebases</h3>
  <p>Identify vulnerabilities, logic flaws, and compliance risks using Multi-Agent RAG.</p>
</div>

---

## 📖 Overview

SentinelAI is a next-generation security auditing CLI and Web Dashboard. Unlike traditional static scanners that rely purely on regex or pattern matching, SentinelAI uses **Large Language Models (LLMs) and Retrieval-Augmented Generation (RAG)** to build contextual understanding of your entire repository.

It understands how your files interact, simulates attack paths, and detects deep business-logic flaws that regular scanners miss.

## ✨ Features

* 🧠 **AI-Powered Analysis**: Context-aware vulnerability detection using Gemini and RAG (ChromaDB).
* 🖥️ **Mission Control UIs**: Includes both a beautiful Terminal UI (TUI) and a full-featured Web UI.
* 📜 **Compliance Frameworks**: Native scanning for **OWASP, HIPAA, GDPR, PCI-DSS**, and more.
* 📦 **SBOM Generation**: Automatically generate CycloneDX Software Bill of Materials.
* 🛠️ **Auto-Remediation**: Generates `.patch` files to instantly fix discovered vulnerabilities.
* 💬 **Interactive Chat**: Chat directly with your codebase's security context after an audit.
* 📊 **History & Trends**: Local SQLite database tracks audit history and vulnerability trends over time.
* 🤖 **CI/CD Mode**: Headless JSON output with severity-based exit codes for pipelines.
* 📑 **Rich Exports**: Export your full security reports to styled HTML or PDF.

## 🚀 Installation (Windows)

We provide a one-click installer for fresh Windows environments. It will automatically install Python, Git, Gitleaks, create a virtual environment, install dependencies, and register `sentinelai` in your System PATH.

1. Clone or download the repository.
2. Open **PowerShell** as Administrator and run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File install.ps1
   ```
3. Open a **new** terminal window and type `sentinelai`!

## 💻 Usage

SentinelAI can be used via its interactive interfaces or strictly through the CLI.

### Launching the Interfaces

```bash
# Launch the Terminal UI (TUI)
sentinelai

# Launch the Web UI Dashboard in your browser
sentinelai --web
```

### CLI Commands

```bash
# Basic audit of the current directory
sentinelai audit .

# Audit with Compliance checks and SBOM generation
sentinelai audit . --compliance owasp --sbom

# Auto-generate fix patches for vulnerabilities
sentinelai audit . --fix

# CI/CD Mode (outputs JSON and exits with error code if critical vulns found)
sentinelai audit . --ci

# Interactive mode (drop into chat after audit)
sentinelai audit . --interactive

# Export report to HTML
sentinelai audit . --export html

# View Audit History
sentinelai history
```

## 🏗️ Architecture

1. **Target Resolution**: Clones GitHub repos or resolves local folders.
2. **Pre-Scan (Gitleaks)**: Scans for hardcoded secrets and API keys.
3. **RAG Ingestion**: Chunks, vectorizes, and stores your codebase in a local ChromaDB instance.
4. **Security Multi-Agent**:
   * Analyzes dependencies and configurations.
   * Hunts for logic flaws and architecture weaknesses.
   * Maps findings against requested compliance frameworks.
5. **Reporting Engine**: Synthesizes findings, builds mitigation steps, and generates UI/CLI reports.

## 🔑 API Keys

SentinelAI requires a Gemini API Key to function. Keys are stored **locally** and never sent anywhere except directly to the LLM provider.

* **In the Web UI**: Click the "Settings" icon to add your key.
* **In the TUI**: Enter your key in the prompt.
* **Via CLI**: Pass the `--keys` flag or configure your `.env`.

---
*Built for developers who need enterprise-grade security insights without the enterprise price tag.*
