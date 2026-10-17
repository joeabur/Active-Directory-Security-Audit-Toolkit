# Synthetic builders for unit tests. Nothing here is a real directory observation.
$script:TestDomainSid = 'S-1-5-21-111111111-222222222-333333333'
$script:TestDomainDn = 'DC=test,DC=local'
$script:TestNow = '2026-10-01T00:00:00Z'

function New-TestUser {
    param(
        [Parameter(Mandatory)] [string] $Sam,
        [int] $Rid = 1100,
        [int] $Uac = 512,
        [AllowNull()] $LastLogon = '2026-09-25T00:00:00Z',
        [AllowNull()] $PwdSet = '2026-08-01T00:00:00Z',
        $Created = '2024-01-01T00:00:00Z',
        [string[]] $Spn = @(),
        [AllowNull()] [string] $Manager = $null,
        $AdminCount = 0,
        [string[]] $Delegate = @(),
        [string[]] $Omit = @()
    )
    $u = [ordered]@{
        SamAccountName = $Sam; DistinguishedName = "CN=$Sam,CN=Users,$script:TestDomainDn"; Sid = "$script:TestDomainSid-$Rid"
        UserAccountControl = $Uac; Enabled = (($Uac -band 2) -eq 0); LastLogonTimestamp = $LastLogon; PasswordLastSet = $PwdSet; WhenCreated = $Created
        ServicePrincipalNames = $Spn; Manager = $Manager; AdminCount = $AdminCount; PrimaryGroupId = 513; AllowedToDelegateTo = $Delegate
    }
    foreach ($o in $Omit) { $u.Remove($o) }
    return [pscustomobject]$u
}

function Get-TestUserDn([string] $Sam) { "CN=$Sam,CN=Users,$script:TestDomainDn" }
function Get-TestGroupDn([string] $Name) { "CN=$Name,CN=Users,$script:TestDomainDn" }

function New-TestGroup {
    param([Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] [string] $Sid, [string[]] $Members = @())
    return [pscustomobject][ordered]@{ SamAccountName = $Name; Name = $Name; DistinguishedName = (Get-TestGroupDn $Name); Sid = $Sid; Members = $Members; AdminCount = 0 }
}

function New-TestComputer {
    param([Parameter(Mandatory)] [string] $Sam, [int] $Uac = 4096, $LastLogon = '2026-09-25T00:00:00Z', $PwdSet = '2026-09-01T00:00:00Z', $Created = '2024-01-01T00:00:00Z', [string] $Os = 'Windows 11 Enterprise', [string[]] $Rbcd = @(), [string[]] $Delegate = @(), [string[]] $Omit = @())
    $c = [ordered]@{ SamAccountName = $Sam; DistinguishedName = "CN=$($Sam.TrimEnd('$')),CN=Computers,$script:TestDomainDn"; Sid = "$script:TestDomainSid-3000"; UserAccountControl = $Uac; Enabled = (($Uac -band 2) -eq 0)
        LastLogonTimestamp = $LastLogon; PasswordLastSet = $PwdSet; WhenCreated = $Created; OperatingSystem = $Os; AllowedToDelegateTo = $Delegate; AllowedToActOnBehalf = $Rbcd }
    foreach ($o in $Omit) { $c.Remove($o) }
    return [pscustomobject]$c
}

function New-TestSection {
    param([string] $Status = 'Collected', $Data = @(), [string] $Error = '', [string] $Category = '')
    return [pscustomobject][ordered]@{ status = $Status; data = $Data; error = $Error; errorCategory = $Category }
}

function New-TestSnapshot {
    param([hashtable] $Sections = @{}, [string] $DataSource = 'Simulated', [string] $DomainMode = 'Windows2016Domain', [string] $ForestMode = 'Windows2016Forest')
    $sec = [ordered]@{}
    foreach ($k in $Sections.Keys) { $sec[$k] = $Sections[$k] }
    return [pscustomobject][ordered]@{
        schemaVersion = '1.0'; dataSource = $DataSource; collectionTime = $script:TestNow
        domain = [pscustomobject][ordered]@{ name = 'test.local'; distinguishedName = $script:TestDomainDn; netBiosName = 'TEST'; sid = $script:TestDomainSid; domainMode = $DomainMode; forestMode = $ForestMode; forestName = 'test.local'; domainControllersContainer = "OU=Domain Controllers,$script:TestDomainDn" }
        sections = [pscustomobject]$sec
    }
}

function New-TestConfigFile {
    # Writes a (partial) configuration overlay to $TestDrive and returns its path.
    param([Parameter(Mandatory)] [string] $Json, [string] $Name = 'config.json')
    $path = Join-Path $TestDrive $Name
    [System.IO.File]::WriteAllText($path, $Json)
    return $path
}

function New-TestAce {
    param([string] $Sid, [string[]] $Rights, [string] $ObjectType = '00000000-0000-0000-0000-000000000000', [string] $Type = 'Allow', [string] $Inheritance = 'None', [bool] $Inherited = $false, [string] $Name = '')
    return [pscustomobject][ordered]@{ IdentitySid = $Sid; IdentityName = $Name; Rights = $Rights; AccessControlType = $Type; ObjectType = $ObjectType; InheritedObjectType = '00000000-0000-0000-0000-000000000000'; IsInherited = $Inherited; InheritanceType = $Inheritance }
}

function Invoke-TestAudit {
    # Runs selected modules over a snapshot through the public API and returns the report.
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [string[]] $Module, [string] $ConfigPath)
    $p = @{ Snapshot = $Snapshot; Module = $Module }
    if ($ConfigPath) { $p.ConfigPath = $ConfigPath }
    return Invoke-ADSecurityAudit @p
}

function Get-TestResult {
    param([Parameter(Mandatory)] $Report, [Parameter(Mandatory)] [string] $RuleId)
    return @($Report.Findings | Where-Object { $_.RuleId -eq $RuleId })
}
