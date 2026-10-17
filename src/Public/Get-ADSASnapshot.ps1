function Get-ADSASnapshot {
    <#
    .SYNOPSIS
        Collects a read-only snapshot from a live domain using the ActiveDirectory module.
    .DESCRIPTION
        Only Get-AD* cmdlets, a fixed read-only remote script block (per DC) and SYSVOL file reads are used.
        Credentials are accepted only as a [pscredential] at run time and are never stored.
    .EXAMPLE
        $snap = Get-ADSASnapshot -Server dc01.lab.example -Credential (Get-Credential) -SkipDcHostChecks
    #>
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [string] $Server,
        [pscredential] $Credential,
        [switch] $SkipDcHostChecks,
        [switch] $SkipSysvol,
        [switch] $SkipAcls
    )
    $config = Get-ADSAConfig -Path $ConfigPath
    $snapshot = Get-ADSASnapshotData -Config $config -Server $Server -Credential $Credential -SkipDcHostChecks:$SkipDcHostChecks -SkipSysvol:$SkipSysvol -SkipAcls:$SkipAcls
    return ConvertTo-ADSAObject -InputObject $snapshot
}
