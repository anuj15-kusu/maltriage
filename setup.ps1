<#
.SYNOPSIS
    One-command setup for maltriage on Windows.

.DESCRIPTION
    Creates .venv with a supported Python (3.11 or 3.12), installs the project with
    its dev dependencies, enables the pre-commit secret guard and copies .env.example
    to .env when it is missing. Safe to re-run: an existing venv and .env are reused.

.PARAMETER Python
    Interpreter to use, for example -Python "C:\Python312\python.exe".
    Default: the first working py -3.12, py -3.11, python3.12, python3.11 or python.

.PARAMETER Recreate
    Delete and rebuild .venv before installing.

.PARAMETER SkipDoctor
    Do not run the final "maltriage doctor" check.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\setup.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\setup.ps1 -Recreate
#>
[CmdletBinding()]
param(
    [string]$Python,
    [switch]$Recreate,
    [switch]$SkipDoctor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$supported = @('3.11', '3.12')
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $Root

try {
    Write-Host "maltriage setup: $Root" -ForegroundColor Cyan

    function Get-PythonVersion {
        param([string[]]$Command)
        $exe = $Command[0]
        $prefix = @()
        if ($Command.Count -gt 1) { $prefix = $Command[1..($Command.Count - 1)] }
        $probe = @($prefix) + @('-c', "import sys; print('%d.%d' % sys.version_info[:2])")
        $output = & $exe @probe 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $output) { return $null }
        return ($output | Select-Object -Last 1).Trim()
    }

    # Prefer an explicit interpreter, then the newest supported one on PATH. A
    # candidate only counts if it actually runs: on Windows python and python3 can
    # be the Store alias stub, which exists but fails when invoked.
    $candidates = @()
    if ($Python) {
        # An explicit interpreter is the answer, not a hint: if it is missing or
        # unsupported this fails instead of quietly using a different one.
        $candidates += , ($Python -split '\s+')
    }
    else {
        foreach ($version in $supported) { $candidates += , @('py', "-$version") }
        foreach ($version in $supported) { $candidates += , @("python$version") }
        $candidates += , @('python')
    }

    $chosen = $null
    $rejected = @()
    foreach ($candidate in $candidates) {
        $label = ($candidate -join ' ')
        $version = $null
        try { $version = Get-PythonVersion -Command $candidate } catch { $version = $null }
        if ($null -eq $version) { continue }
        if ($supported -contains $version) {
            $chosen = @{ Command = $candidate; Version = $version }
            break
        }
        $rejected += "$label -> Python $version"
    }

    if ($null -eq $chosen) {
        Write-Host 'No supported Python found; this project needs 3.11 or 3.12.' -ForegroundColor Red
        foreach ($line in $rejected) { Write-Host "  found: $line" }
        Write-Host 'Install Python 3.12 (winget install Python.Python.3.12) and run this script again.' -ForegroundColor Red
        exit 1
    }
    Write-Host ('Using {0} (Python {1})' -f ($chosen.Command -join ' '), $chosen.Version)

    $venv = Join-Path $Root '.venv'
    $venvPython = Join-Path $venv 'Scripts\python.exe'
    if ($Recreate -and (Test-Path $venv)) {
        Write-Host 'Removing the existing .venv'
        Remove-Item -LiteralPath $venv -Recurse -Force
    }
    if (-not (Test-Path $venvPython)) {
        $createArgs = @()
        if ($chosen.Command.Count -gt 1) {
            $createArgs = $chosen.Command[1..($chosen.Command.Count - 1)]
        }
        Write-Host 'Creating .venv'
        & $chosen.Command[0] @createArgs -m venv $venv
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the virtual environment.' }
    }
    else {
        Write-Host '.venv already exists - reusing it'
    }

    Write-Host 'Installing dependencies'
    & $venvPython -m pip install --upgrade pip --quiet
    & $venvPython -m pip install -e '.[dev]'
    if ($LASTEXITCODE -ne 0) { throw 'Dependency install failed.' }

    if (Test-Path (Join-Path $Root '.git')) {
        if (Get-Command git -ErrorAction SilentlyContinue) {
            & git -C $Root config core.hooksPath .githooks
            if ($LASTEXITCODE -eq 0) {
                Write-Host 'Enabled the pre-commit secret guard (.githooks)'
            }
            else {
                Write-Warning 'Could not set core.hooksPath; enable it by hand.'
            }
        }
    }
    else {
        Write-Host 'Not a git checkout - skipped the pre-commit hook'
    }

    $envFile = Join-Path $Root '.env'
    if (-not (Test-Path $envFile)) {
        Copy-Item -LiteralPath (Join-Path $Root '.env.example') -Destination $envFile
        Write-Host 'Created .env from .env.example - add your keys; .env stays gitignored'
    }
    else {
        Write-Host '.env already exists - left untouched'
    }

    $maltriage = Join-Path $venv 'Scripts\maltriage.exe'
    & $maltriage version
    if (-not $SkipDoctor) {
        & $maltriage doctor
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'doctor reported a failing check; see the table above.'
            exit 1
        }
    }

    Write-Host ''
    Write-Host 'Ready. Next steps:' -ForegroundColor Green
    Write-Host '  .\.venv\Scripts\Activate.ps1'
    Write-Host '  edit .env, then: maltriage doctor --check-api'
    Write-Host '  maltriage scan <file>'
}
finally {
    Pop-Location
}
