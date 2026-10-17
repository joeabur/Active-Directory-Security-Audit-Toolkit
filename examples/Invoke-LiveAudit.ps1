<#
.SYNOPSIS
    OPTIONAL example: read-only audit of an explicitly authorized TEST domain. Not used by tests or the demo.
.DESCRIPTION
    Requires Windows, the ActiveDirectory module (RSAT) and written authorization to assess the target domain.
    Credentials are requested interactively and never stored. Output goes to an untracked folder and should be
    handled as sensitive. Start with -SkipDcHostChecks; add DC host checks only when you have the rights documented
    in docs/security-and-limitations.md.
.EXAMPLE
    ./examples/Invoke-LiveAudit.ps1 -Server dc01.lab.example -SkipDcHostChecks
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Server,
    [string] $OutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'output/live'),
    [switch] $SkipDcHostChecks,
    [switch] $Redact
)
Set-StrictMode -Version 2.0
$root = Split-Path -Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'src/ADSecurityAudit.psd1') -Force

$prereq = Test-ADSAPrerequisite
if (-not $prereq.LiveReady) { throw 'This host cannot run live collection (needs Windows and the ActiveDirectory module). Use offline analysis instead.' }

$credential = Get-Credential -Message "Read-only audit account for $Server"
$report = Invoke-ADSecurityAudit -AuthorizedAssessment -Server $Server -Credential $credential -SkipDcHostChecks:$SkipDcHostChecks -Redact:$Redact -OutputPath $OutputPath
Write-Information $report.Summary.Headline -InformationAction Continue
$report.OutputFiles
