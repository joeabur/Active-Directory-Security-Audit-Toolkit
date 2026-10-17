<#
.SYNOPSIS
    Runs PSScriptAnalyzer over the toolkit with the repository settings. Exits non-zero on any finding.
.EXAMPLE
    ./scripts/Invoke-Lint.ps1
#>
[CmdletBinding()]
param([switch] $PassThru)
Set-StrictMode -Version 2.0
$root = Split-Path -Path $PSScriptRoot -Parent
Import-Module PSScriptAnalyzer -ErrorAction Stop
$findings = @()
foreach ($p in 'src', 'scripts', 'examples') {
    $path = Join-Path $root $p
    if (Test-Path -LiteralPath $path) { $findings += Invoke-ScriptAnalyzer -Path $path -Recurse -Settings (Join-Path $root 'PSScriptAnalyzerSettings.psd1') }
}
$findings += Invoke-ScriptAnalyzer -Path (Join-Path $root 'tests') -Recurse -Settings (Join-Path $root 'tests/PSScriptAnalyzerSettings.psd1')
foreach ($f in $findings) { Write-Output ('{0}:{1} [{2}] {3} - {4}' -f $f.ScriptName, $f.Line, $f.Severity, $f.RuleName, $f.Message) }
Write-Information "PSScriptAnalyzer findings: $(@($findings).Count)" -InformationAction Continue
if ($PassThru) { return $findings }
if (@($findings).Count -gt 0) { exit 1 }
