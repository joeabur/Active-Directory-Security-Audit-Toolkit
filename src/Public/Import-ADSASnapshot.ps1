function Import-ADSASnapshot {
    <#
    .SYNOPSIS
        Loads and validates a snapshot JSON file for offline analysis.
    .DESCRIPTION
        Snapshots from real domains are sensitive. Synthetic snapshots carry dataSource = 'Simulated'.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)
    $snapshot = Read-ADSAJsonFile -Path $Path -Description 'Snapshot file'
    $check = Test-ADSASnapshotData -Snapshot $snapshot
    if (-not $check.IsValid) { throw ("Snapshot '$Path' is invalid:`n - " + ($check.Errors -join "`n - ")) }
    return $snapshot
}
