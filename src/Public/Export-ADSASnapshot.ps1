function Export-ADSASnapshot {
    <#
    .SYNOPSIS
        Writes a collected snapshot to JSON for later offline analysis. The file contains directory data: protect it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Snapshot,
        [Parameter(Mandatory)] [string] $OutputPath,
        [string] $FileName,
        [switch] $AllowUncOutput,
        [switch] $AllowRepositoryOutput
    )
    $dir = Resolve-ADSAOutputPath -Path $OutputPath -AllowUnc:$AllowUncOutput -AllowRepositoryPath:$AllowRepositoryOutput
    if (-not $FileName) { $FileName = 'ADSA-snapshot-{0}.snapshot.json' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ') }
    if ($FileName -match '[\\/]' -or $FileName.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw "FileName '$FileName' must be a plain file name." }
    $check = Test-ADSASnapshotData -Snapshot $Snapshot
    if (-not $check.IsValid) { throw ("Snapshot is invalid:`n - " + ($check.Errors -join "`n - ")) }
    Write-ADSALog -Level Warning -Message 'Snapshot files contain directory data. Store them encrypted and delete them when no longer needed.'
    return Write-ADSAFile -Path (Join-Path $dir $FileName) -Content ($Snapshot | ConvertTo-Json -Depth 12)
}
