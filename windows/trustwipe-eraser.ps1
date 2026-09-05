<#
.SYNOPSIS
    TrustWipe Windows Secure File & Folder Eraser PowerShell Runner
.DESCRIPTION
    Executes forensic-grade sanitization compliant with NIST SP 800-88 Rev. 1 on Microsoft Windows.
.PARAMETER Targets
    One or more files or directories to sanitize.
.PARAMETER Passes
    Number of overwrite passes (default 1 per NIST Clear).
.PARAMETER Pattern
    Pattern: 'zero' or 'random'.
#>

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string[]]$Targets,

    [Parameter(Mandatory=$false, Position=1)]
    [int]$Passes = 1,

    [Parameter(Mandatory=$false, Position=2)]
    [ValidateSet("zero", "random")]
    [string]$Pattern = "zero",

    [Parameter(Mandatory=$false)]
    [string]$OutDir = ".\sanitization_reports"
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$eraserScript = Join-Path $scriptDir "trustwipe_eraser.py"

python $eraserScript --targets $Targets --passes $Passes --pattern $Pattern --out-dir $OutDir
