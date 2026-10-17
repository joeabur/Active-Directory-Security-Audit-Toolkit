function Get-ADSARuleCatalog {
    <#
    .SYNOPSIS
        Lists the audit rules implemented by the toolkit.
    .EXAMPLE
        Get-ADSARuleCatalog -Module Acl | Format-Table Id, Severity, Title
    #>
    [CmdletBinding()]
    param(
        [string] $Id,
        [string] $Module
    )
    $rules = (Get-ADSARuleCatalogData).Rules
    if ($Id) { $rules = $rules | Where-Object { $_.Id -like $Id } }
    if ($Module) { $rules = $rules | Where-Object { $_.Module -eq $Module } }
    return $rules
}
