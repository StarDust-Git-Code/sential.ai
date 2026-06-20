@echo off
REM ══════════════════════════════════════════════
REM  SentinelAI Launcher
REM  Usage:
REM    sentinelai              → Launch TUI
REM    sentinelai audit . ...  → CLI mode
REM    sentinelai history      → CLI history
REM    sentinelai --version    → Show version
REM ══════════════════════════════════════════════
SET SCRIPT_DIR=%~dp0
call "%SCRIPT_DIR%.venv\Scripts\activate.bat" >nul 2>&1

IF "%1"=="" (
    python "%SCRIPT_DIR%tui.py"
) ELSE (
    python "%SCRIPT_DIR%main.py" %*
)
