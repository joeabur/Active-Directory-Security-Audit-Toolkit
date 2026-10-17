@{
    RootModule            = 'ADSecurityAudit.psm1'
    ModuleVersion         = '1.0.0'
    GUID                  = '6f0f6a3e-5d1b-4c7e-9a52-3b1d8c4e7a10'
    Author                = 'Active Directory Security Audit Toolkit contributors'
    CompanyName           = 'Community'
    Copyright             = '(c) Active Directory Security Audit Toolkit contributors. All rights reserved.'
    Description           = 'Read-only Active Directory security auditing toolkit for authorized assessments. Produces evidence-backed findings (JSON, CSV, HTML). Does not exploit, attack credentials or change directory state.'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FunctionsToExport     = @(
        'Export-ADSAReport'
        'Export-ADSASnapshot'
        'Get-ADSAConfig'
        'Get-ADSARuleCatalog'
        'Get-ADSASnapshot'
        'Import-ADSASnapshot'
        'Invoke-ADSecurityAudit'
        'Test-ADSAConfig'
        'Test-ADSAPrerequisite'
        'Test-ADSAReport'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
    PrivateData           = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Security', 'Audit', 'ReadOnly', 'Assessment')
            ProjectUri = 'https://github.com/joeabur/Active-Directory-Security-Audit-Toolkit'
        }
    }
}
