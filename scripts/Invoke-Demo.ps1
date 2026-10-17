<#
.SYNOPSIS
    Repeatable offline demo: audits the SYNTHETIC sample snapshot and writes JSON, CSV and HTML reports. No domain access.
.DESCRIPTION
    The sample data is invented (domain contoso-sim.test). Results demonstrate the toolkit; they say nothing about any real domain.
    The script self-checks the run (valid report, simulated label, all five statuses, expected planted findings) and exits non-zero if a check fails.
.PARAMETER OutputPath
    Where reports are written. Defaults to ./output/demo (untracked).
.PARAMETER UpdateSampleReports
    Maintainers only: regenerates the committed examples/sample-reports files.
.EXAMPLE
    ./scripts/Invoke-Demo.ps1
#>
[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'output/demo'),
    [switch] $UpdateSampleReports
)
Set-StrictMode -Version 2.0
$root = Split-Path -Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'src/ADSecurityAudit.psd1') -Force
$snapshot = Join-Path $root 'sample-data/contoso-sim.snapshot.json'
$info = @{ InformationAction = 'Continue' }

Write-Information 'DEMO: offline audit of SYNTHETIC data (no domain access, no network).' @info
$target = $OutputPath
$extra = @{}
if ($UpdateSampleReports) { $target = Join-Path $root 'examples/sample-reports'; $extra.AllowRepositoryOutput = $true }

$ErrorActionPreference = 'Stop'
$report = Invoke-ADSecurityAudit -SnapshotPath $snapshot -OutputPath $target -BaseName 'sample-report' @extra
$redacted = Invoke-ADSecurityAudit -SnapshotPath $snapshot -OutputPath $target -Format Json, Html -Redact -RedactionSalt 'sample' -BaseName 'sample-report-redacted' @extra

Write-Information '' @info
Write-Information $report.Metadata.Notice @info
Write-Information $report.Summary.Headline @info
Write-Output ($report.Summary.ActiveFindingsBySeverity | Format-List | Out-String)
Write-Output ($report.Findings | Where-Object { $_.Status -eq 'FAIL' } | Select-Object -First 8 |
        Format-Table Severity, RuleId, AffectedObject, Confidence -AutoSize | Out-String)
Write-Information 'Reports written:' @info
foreach ($f in @($report.OutputFiles) + @($redacted.OutputFiles)) { Write-Information "  $f" @info }

# Self-checks
$problems = New-Object System.Collections.Generic.List[string]
if (-not (Test-ADSAReport -Report $report).IsValid) { $problems.Add('report failed schema validation') }
if ($report.Metadata.DataSource -ne 'Simulated') { $problems.Add('report is not labelled Simulated') }
foreach ($s in 'PASS', 'FAIL', 'ERROR', 'NOT_APPLICABLE', 'NOT_ASSESSED') {
    if (-not ($report.Findings | Where-Object { $_.Status -eq $s })) { $problems.Add("no $s result produced") }
}
foreach ($expect in 'ADSA-ACL-002', 'ADSA-GPO-003', 'ADSA-KRB-001', 'ADSA-PRV-007') {
    if (-not ($report.Findings | Where-Object { $_.RuleId -eq $expect -and $_.Status -eq 'FAIL' })) { $problems.Add("expected planted finding $expect missing") }
}
foreach ($f in @($report.OutputFiles)) { if (-not (Test-Path -LiteralPath $f)) { $problems.Add("missing output $f") } }
if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Error "Demo self-check failed: $_" -ErrorAction Continue }
    exit 1
}
Write-Information 'Demo self-checks passed.' @info
