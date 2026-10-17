function Get-ADSAConfig {
    <#
    .SYNOPSIS
        Loads the effective configuration (defaults overlaid with an optional file). Throws if it is invalid.
    #>
    [CmdletBinding()]
    param([string] $Path)
    $loaded = Import-ADSAConfigData -Path $Path
    foreach ($w in $loaded.Warnings) { Write-Warning $w }
    return $loaded.Config
}
