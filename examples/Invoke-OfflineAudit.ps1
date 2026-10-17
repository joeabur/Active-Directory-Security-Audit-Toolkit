<#
.SYNOPSIS
    Example: offline audit of the synthetic sample with a custom configuration. No domain access.
.EXAMPLE
    ./examples/Invoke-OfflineAudit.ps1
#>
[CmdletBinding()]
param([string] $OutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'output/example-offline'))
Set-StrictMode -Version 2.0
$root = Split-Path -Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'src/ADSecurityAudit.psd1') -Force

$configPath = Join-Path $root 'examples/custom-config.json'
$check = Test-ADSAConfig -Path $configPath
if (-not $check.IsValid) { throw "Configuration is invalid: $($check.Errors -join '; ')" }

$report = Invoke-ADSecurityAudit -SnapshotPath (Join-Path $root 'sample-data/contoso-sim.snapshot.json') -ConfigPath $configPath -OutputPath $OutputPath
Write-Information $report.Metadata.Notice -InformationAction Continue
Write-Information $report.Summary.Headline -InformationAction Continue
$report.OutputFiles
