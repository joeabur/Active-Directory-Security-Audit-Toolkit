function Get-ADSASnapshot {
    <#
    .SYNOPSIS
        Collects a read-only snapshot from a live domain using the ActiveDirectory module.
    .DESCRIPTION
        Only Get-AD* cmdlets, a fixed read-only remote script block (per DC) and SYSVOL file reads are used.
        Credentials are accepted only as a [pscredential] at run time and are never stored.
    .EXAMPLE
        $snap = Get-ADSASnapshot -AuthorizedAssessment -Server dc01.lab.example -Credential (Get-Credential) -SkipDcHostChecks
    #>
    [CmdletBinding()]
    param(
        [switch] $AuthorizedAssessment,
        [string] $ConfigPath,
        [string] $Server,
        [pscredential] $Credential,
        [switch] $SkipDcHostChecks,
        [switch] $SkipSysvol,
        [switch] $SkipAcls
    )
    if (-not $AuthorizedAssessment) { throw 'Live collection reads directory data from a real domain. Re-run with -AuthorizedAssessment to confirm you are authorized to assess it.' }
    $config = Get-ADSAConfig -Path $ConfigPath
    $snapshot = Get-ADSASnapshotData -Config $config -Server $Server -Credential $Credential -SkipDcHostChecks:$SkipDcHostChecks -SkipSysvol:$SkipSysvol -SkipAcls:$SkipAcls
    return ConvertTo-ADSAObject -InputObject $snapshot
}
