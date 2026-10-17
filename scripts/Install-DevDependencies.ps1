<#
.SYNOPSIS
    Installs the pinned development dependencies (Pester, PSScriptAnalyzer) for the current user.
.DESCRIPTION
    Only needed to run tests and lint. Running an audit needs no extra modules for offline analysis, and only the
    ActiveDirectory module (RSAT) for live collection. Versions are pinned for repeatable results.
.EXAMPLE
    ./scripts/Install-DevDependencies.ps1
#>
[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
if ($PSVersionTable.PSVersion.Major -lt 6) {
    # Windows PowerShell 5.1: make sure the NuGet provider exists and TLS 1.2 is used for the gallery.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) { $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser }
}
$required = @(
    @{ Name = 'Pester'; Version = '5.7.1' }
    @{ Name = 'PSScriptAnalyzer'; Version = '1.23.0' }
)
foreach ($m in $required) {
    $have = Get-Module -ListAvailable -Name $m.Name | Where-Object { $_.Version -eq [version]$m.Version }
    if ($have) {
        Write-Information "$($m.Name) $($m.Version) already installed." -InformationAction Continue
        continue
    }
    Write-Information "Installing $($m.Name) $($m.Version) for the current user from the PowerShell Gallery..." -InformationAction Continue
    Install-Module -Name $m.Name -RequiredVersion $m.Version -Scope CurrentUser -Force -SkipPublisherCheck -AllowClobber
}
Write-Information 'Development dependencies are ready.' -InformationAction Continue
