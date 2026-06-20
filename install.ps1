# ══════════════════════════════════════════════════════════════
#  SentinelAI Installer for Windows
#  Run: powershell -ExecutionPolicy Bypass -File install.ps1
# ══════════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"
$SENTINEL_DIR = $PSScriptRoot
if (-not $SENTINEL_DIR) { $SENTINEL_DIR = (Get-Location).Path }

Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   SentinelAI Installer v2.0          ║" -ForegroundColor Cyan
Write-Host "  ║   AI-Powered Security Auditing       ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Phase 0: Clean previous data ──────────────────────────

Write-Host "[0/5] Cleaning previous data..." -ForegroundColor Yellow

$cleanNames = @("sentinel_history.db", "sentinel_history.db-wal", "sentinel_history.db-shm", ".sentinel_keys.json")
foreach ($name in $cleanNames) {
    $fp = Join-Path $SENTINEL_DIR $name
    if (Test-Path $fp) {
        Remove-Item $fp -Force
        Write-Host "  Removed: $name" -ForegroundColor Gray
    }
}

# Also clean temp files
Get-ChildItem -Path $SENTINEL_DIR -Filter "temp-*.md" -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem -Path $SENTINEL_DIR -Filter "sentinel_report_*.html" -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem -Path $SENTINEL_DIR -Filter "sentinel_sbom_*.json" -ErrorAction SilentlyContinue | Remove-Item -Force

# Clean cloned repos cache
$reposDir = Join-Path $SENTINEL_DIR ".sentinel_repos"
if (Test-Path $reposDir) { Remove-Item $reposDir -Recurse -Force }

Write-Host "  Clean slate ready." -ForegroundColor Green


# ── Phase 1: Check Python ──────────────────────────────────

Write-Host "[1/5] Checking Python..." -ForegroundColor Yellow

$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match 'Python (\d+)\.(\d+)') {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 10) {
                $pythonCmd = $cmd
                Write-Host "  Found: $ver" -ForegroundColor Green
                break
            } else {
                Write-Host ('  Found ' + $ver + ' but need 3.10 or higher') -ForegroundColor Red
            }
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host '  Python 3.10+ not found. Attempting install via winget...' -ForegroundColor Red
    try {
        winget install Python.Python.3.12 --accept-package-agreements --accept-source-agreements
        $pythonCmd = "python"
        Write-Host "  Python installed. You may need to restart this terminal." -ForegroundColor Yellow
    } catch {
        Write-Host "  ERROR: Could not install Python automatically." -ForegroundColor Red
        Write-Host '  Please install Python 3.10+ from https://python.org and re-run this script.' -ForegroundColor Red
        exit 1
    }
}

# ── Phase 2: Check Git ─────────────────────────────────────

Write-Host "[2/5] Checking Git..." -ForegroundColor Yellow
try {
    $gitVer = & git --version 2>&1
    Write-Host "  Found: $gitVer" -ForegroundColor Green
} catch {
    Write-Host "  Git not found. Attempting install via winget..." -ForegroundColor Red
    try {
        winget install Git.Git --accept-package-agreements --accept-source-agreements
        Write-Host "  Git installed. You may need to restart this terminal." -ForegroundColor Yellow
    } catch {
        Write-Host "  WARNING: Git not available. Repo cloning will not work." -ForegroundColor Yellow
        Write-Host "  Install from https://git-scm.com" -ForegroundColor Yellow
    }
}

# ── Phase 3: Install Gitleaks ──────────────────────────────

Write-Host "[3/5] Checking Gitleaks..." -ForegroundColor Yellow

$gitleaksInstalled = $false
try {
    $glVer = & gitleaks version 2>&1
    Write-Host "  Found: gitleaks $glVer" -ForegroundColor Green
    $gitleaksInstalled = $true
} catch {}

if (-not $gitleaksInstalled) {
    Write-Host "  Gitleaks not found. Downloading..." -ForegroundColor Yellow
    $gitleaksDir = Join-Path $SENTINEL_DIR "tools"
    $gitleaksExe = Join-Path $gitleaksDir "gitleaks.exe"

    if (-not (Test-Path $gitleaksDir)) { New-Item -ItemType Directory -Path $gitleaksDir -Force | Out-Null }

    # Detect architecture
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x32" }
    $gitleaksVersion = "8.24.3"
    $downloadUrl = "https://github.com/gitleaks/gitleaks/releases/download/v${gitleaksVersion}/gitleaks_${gitleaksVersion}_windows_${arch}.zip"
    $zipPath = Join-Path $gitleaksDir "gitleaks.zip"

    try {
        Write-Host "  Downloading from: $downloadUrl" -ForegroundColor Gray
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing

        Write-Host "  Extracting..." -ForegroundColor Gray
        Expand-Archive -Path $zipPath -DestinationPath $gitleaksDir -Force
        Remove-Item $zipPath -Force

        if (Test-Path $gitleaksExe) {
            Write-Host "  Gitleaks installed to: $gitleaksExe" -ForegroundColor Green

            # Add tools dir to User PATH if not already there
            $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
            if ($userPath -notlike "*$gitleaksDir*") {
                [Environment]::SetEnvironmentVariable("PATH", "$userPath;$gitleaksDir", "User")
                $env:PATH = "$env:PATH;$gitleaksDir"
                Write-Host "  Added tools/ to PATH" -ForegroundColor Green
            }
        } else {
            Write-Host "  WARNING: Extraction succeeded but gitleaks.exe not found." -ForegroundColor Yellow
            Write-Host "  Static analysis (secrets scan) will be skipped." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  WARNING: Could not download Gitleaks: $_" -ForegroundColor Yellow
        Write-Host "  Static analysis (secrets scan) will be skipped." -ForegroundColor Yellow
        Write-Host "  You can install it manually from: https://github.com/gitleaks/gitleaks/releases" -ForegroundColor Yellow
    }
}

# ── Phase 4: Create venv + Install Dependencies ───────────

Write-Host "[4/5] Setting up Python environment..." -ForegroundColor Yellow

$venvPath = Join-Path $SENTINEL_DIR ".venv"

if (-not (Test-Path (Join-Path $venvPath "Scripts\activate.bat"))) {
    Write-Host "  Creating virtual environment..." -ForegroundColor Gray
    & $pythonCmd -m venv $venvPath
    Write-Host "  Virtual environment created." -ForegroundColor Green
} else {
    Write-Host "  Virtual environment already exists." -ForegroundColor Green
}

# Activate and install
$pipExe = Join-Path $venvPath "Scripts\pip.exe"
$pythonExe = Join-Path $venvPath "Scripts\python.exe"

$reqFile = Join-Path $SENTINEL_DIR "requirements.txt"
if (Test-Path $reqFile) {
    Write-Host "  Installing dependencies (this may take a few minutes)..." -ForegroundColor Gray
    & $pipExe install -r $reqFile --quiet 2>&1 | Out-Null
    Write-Host "  Dependencies installed." -ForegroundColor Green
} else {
    Write-Host "  WARNING: requirements.txt not found. Skipping dependency install." -ForegroundColor Yellow
}

# Install the package itself (editable mode)
$pyprojectFile = Join-Path $SENTINEL_DIR "pyproject.toml"
if (Test-Path $pyprojectFile) {
    Write-Host "  Installing SentinelAI package..." -ForegroundColor Gray
    & $pipExe install -e $SENTINEL_DIR --quiet 2>&1 | Out-Null
    Write-Host "  Package installed." -ForegroundColor Green
}

# ── Phase 5: Add to PATH ──────────────────────────────────

Write-Host "[5/5] Registering 'sentinelai' command..." -ForegroundColor Yellow

$batFile = Join-Path $SENTINEL_DIR "sentinelai.bat"
if (-not (Test-Path $batFile)) {
    Write-Host "  ERROR: sentinelai.bat not found in $SENTINEL_DIR" -ForegroundColor Red
    exit 1
}

$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")

if ($userPath -like "*$SENTINEL_DIR*") {
    Write-Host "  Already in PATH." -ForegroundColor Green
} else {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$SENTINEL_DIR", "User")
    $env:PATH = "$env:PATH;$SENTINEL_DIR"
    Write-Host "  Added to User PATH." -ForegroundColor Green

    # Broadcast WM_SETTINGCHANGE so other windows pick up the change
    try {
        Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
            [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern IntPtr SendMessageTimeout(
                IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
                uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x001A
        $result = [UIntPtr]::Zero
        [Win32.NativeMethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "Environment", 2, 5000, [ref]$result) | Out-Null
        Write-Host "  Environment refreshed." -ForegroundColor Green
    } catch {
        Write-Host "  Note: Open a new terminal for PATH changes to take effect." -ForegroundColor Yellow
    }
}

# ── Done ───────────────────────────────────────────────────

Write-Host ""
Write-Host "  ══════════════════════════════════════" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "  ══════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  Open a NEW terminal and try:" -ForegroundColor White
Write-Host ""
Write-Host "    sentinelai                          → Launch TUI" -ForegroundColor Cyan
Write-Host "    sentinelai audit . --sbom           → CLI audit with SBOM" -ForegroundColor Cyan
Write-Host "    sentinelai audit . --compliance owasp → Compliance audit" -ForegroundColor Cyan
Write-Host "    sentinelai history                  → View past audits" -ForegroundColor Cyan
Write-Host "    sentinelai --help                   → All options" -ForegroundColor Cyan
Write-Host ""
