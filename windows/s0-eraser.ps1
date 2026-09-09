<#
.SYNOPSIS
    s0 Windows Secure File & Folder Eraser PowerShell Runner (Root Delegation)
.DESCRIPTION
    Delegates execution directly to windows/cli/s0-eraser.ps1.
#>

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$cliRunner = Join-Path $scriptDir "cli\s0-eraser.ps1"
& $cliRunner @args
exit $LASTEXITCODE
