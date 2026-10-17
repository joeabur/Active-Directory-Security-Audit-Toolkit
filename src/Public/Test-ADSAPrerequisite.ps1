function Test-ADSAPrerequisite {
    <#
    .SYNOPSIS
        Reports whether this host can run offline analysis and live collection. Changes nothing.
    #>
    [CmdletBinding()]
    param()
    $isWindows = Test-ADSAWindowsPlatform
    $adModule = [bool](Get-Module -ListAvailable -Name 'ActiveDirectory' -ErrorAction SilentlyContinue)
    $edition = if ($PSVersionTable.ContainsKey('PSEdition')) { $PSVersionTable.PSEdition } else { 'Desktop' }
    $checks = @(
        [pscustomobject]@{ Check = 'PowerShellVersion'; Ok = ($PSVersionTable.PSVersion -ge [version]'5.1'); Detail = "PowerShell $($PSVersionTable.PSVersion) ($edition). Required: 5.1 or later." }
        [pscustomobject]@{ Check = 'Windows'; Ok = $isWindows; Detail = $(if ($isWindows) { 'Windows detected.' } else { 'Not Windows: offline analysis of snapshots only.' }) }
        [pscustomobject]@{ Check = 'ActiveDirectoryModule'; Ok = $adModule; Detail = $(if ($adModule) { 'ActiveDirectory module found.' } else { 'ActiveDirectory module (RSAT) not found: live collection unavailable.' }) }
    )
    $domainJoined = $false
    if ($isWindows) { try { $domainJoined = [bool](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { $domainJoined = $false } }
    $checks += [pscustomobject]@{ Check = 'DomainJoined'; Ok = $domainJoined; Detail = $(if ($domainJoined) { 'Host is domain joined.' } else { 'Host is not domain joined (live collection needs -Server and credentials with network access).' }) }
    return [pscustomobject]@{
        OfflineReady = ($PSVersionTable.PSVersion -ge [version]'5.1')
        LiveReady    = ($isWindows -and $adModule)
        Checks       = $checks
    }
}
