# ADSecurityAudit root module. Dot-sources Private, Modules and Public in a fixed order.
# The toolkit is read-only: no function in this module changes directory, ACL, GPO or DC state.
Set-StrictMode -Version 2.0

$script:ADSAModuleRoot = $PSScriptRoot
$script:ADSARoot = Split-Path -Path $PSScriptRoot -Parent
$script:ADSAVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'ADSecurityAudit.psd1')).ModuleVersion
$script:ADSARuleCatalogCache = $null

foreach ($folder in 'Private', 'Modules', 'Public') {
    $files = Get-ChildItem -Path (Join-Path $PSScriptRoot $folder) -Filter '*.ps1' -File | Sort-Object Name
    foreach ($file in $files) {
        . $file.FullName
    }
}

$publicFunctions = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File |
    ForEach-Object { $_.BaseName }
Export-ModuleMember -Function $publicFunctions
