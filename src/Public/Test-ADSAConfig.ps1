function Test-ADSAConfig {
    <#
    .SYNOPSIS
        Validates a configuration file without throwing. Returns IsValid, Errors and Warnings.
    .EXAMPLE
        Test-ADSAConfig -Path .\examples\custom-config.json
    #>
    [CmdletBinding()]
    param([string] $Path)
    try {
        $loaded = Import-ADSAConfigData -Path $Path
        return [pscustomobject]@{ IsValid = $true; Errors = @(); Warnings = @($loaded.Warnings) }
    } catch {
        $lines = @("$($_.Exception.Message)" -split "`r?`n" | ForEach-Object { $_.Trim(' ', '-') } | Where-Object { $_ -and $_ -ne 'Configuration is invalid:' })
        return [pscustomobject]@{ IsValid = $false; Errors = $lines; Warnings = @() }
    }
}
