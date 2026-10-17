<#
.SYNOPSIS
    Runs the Pester suites. Unit tests are portable and need no domain.
.PARAMETER Suite
    Unit (default), Integration (offline end-to-end; the Windows-domain suite stays skipped unless explicitly enabled), or All.
.PARAMETER CI
    Writes NUnit XML to TestResults/ and fails the process on any test failure.
.EXAMPLE
    ./scripts/Invoke-Tests.ps1 -Suite All
#>
[CmdletBinding()]
param(
    [ValidateSet('Unit', 'Integration', 'All')] [string] $Suite = 'Unit',
    [switch] $CI,
    [ValidateSet('None', 'Normal', 'Detailed')] [string] $Verbosity = 'Normal'
)
Set-StrictMode -Version 2.0
$root = Split-Path -Path $PSScriptRoot -Parent
$pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [version]'5.0.0' } | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) { throw 'Pester 5 is required. Run ./scripts/Install-DevDependencies.ps1' }
Import-Module $pester.Path -Force

$paths = switch ($Suite) {
    'Unit' { @((Join-Path $root 'tests/Unit')) }
    'Integration' { @((Join-Path $root 'tests/Integration')) }
    default { @((Join-Path $root 'tests/Unit'), (Join-Path $root 'tests/Integration')) }
}
$config = New-PesterConfiguration
$config.Run.Path = $paths
$config.Run.PassThru = $true
$config.Output.Verbosity = $Verbosity
if ($CI) {
    $out = Join-Path $root 'TestResults'
    if (-not (Test-Path -LiteralPath $out)) { New-Item -ItemType Directory -Path $out | Out-Null }
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path $out "pester-$($Suite.ToLowerInvariant()).xml"
    $config.TestResult.OutputFormat = 'NUnitXml'
}
$result = Invoke-Pester -Configuration $config
Write-Information ("Passed: {0}  Failed: {1}  Skipped: {2}  NotRun: {3}" -f $result.PassedCount, $result.FailedCount, $result.SkippedCount, $result.NotRunCount) -InformationAction Continue
if ($result.FailedCount -gt 0 -or $result.Result -eq 'Failed') { exit 1 }
