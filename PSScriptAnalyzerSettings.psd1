@{
    Severity     = @('Error', 'Warning')
    IncludeRules = @('*')
    ExcludeRules = @(
        # Output is written to files and the information stream, never Write-Host, so no exclusion needed for that.
        # Report content is ASCII-only; BOM rule stays enabled.
    )
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
