<#
.SYNOPSIS
    Generates the SYNTHETIC sample snapshot used by the demo, tests and documentation.
.DESCRIPTION
    Every object, name and SID here is invented. The domain 'contoso-sim.test' does not exist.
    The output is labelled dataSource = 'Simulated' and must never be mistaken for observations of a real domain.
    The data deliberately contains one example of most rule violations so the reports show every status.
.EXAMPLE
    ./scripts/New-SampleSnapshot.ps1
#>
[CmdletBinding()]
param([string] $OutputFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'sample-data/contoso-sim.snapshot.json'))

Set-StrictMode -Version 2.0
$domainDn = 'DC=contoso-sim,DC=test'
$domainSid = 'S-1-5-21-1004336348-1177238915-682003330'
$dcOu = "OU=Domain Controllers,$domainDn"

$users = New-Object System.Collections.Generic.List[object]
function Add-SimUser {
    param([string]$Sam, [int]$Rid, [int]$Uac = 512, $LastLogon = '2026-09-25T08:00:00Z', $PwdSet = '2026-08-01T08:00:00Z', $Created = '2024-01-10T08:00:00Z',
        [string[]]$Spn = @(), [string]$Manager = $null, $AdminCount = 0, [string[]]$Delegate = @())
    $users.Add([ordered]@{
            SamAccountName = $Sam; DistinguishedName = "CN=$Sam,CN=Users,$domainDn"; Sid = "$domainSid-$Rid"
            UserAccountControl = $Uac; Enabled = (($Uac -band 2) -eq 0)
            LastLogonTimestamp = $LastLogon; PasswordLastSet = $PwdSet; WhenCreated = $Created
            ServicePrincipalNames = $Spn; Manager = $Manager; AdminCount = $AdminCount; PrimaryGroupId = 513; AllowedToDelegateTo = $Delegate
        })
}
function Get-SimDn([string]$Sam) { "CN=$Sam,CN=Users,$domainDn" }

Add-SimUser 'Administrator' 500 -Uac 66048 -PwdSet '2025-11-02T08:00:00Z' -AdminCount 1
Add-SimUser 'Guest' 501 -Uac 66082 -LastLogon $null -PwdSet $null
Add-SimUser 'krbtgt' 502 -Uac 514 -LastLogon $null -PwdSet '2023-01-15T08:00:00Z' -AdminCount 1
Add-SimUser 'alice.admin' 1101 -AdminCount 1
Add-SimUser 'bob.helpdesk' 1102 -AdminCount 1
Add-SimUser 'svc_sql' 1103 -Uac 66048 -PwdSet '2023-03-01T08:00:00Z' -Spn @('MSSQLSvc/sql01.contoso-sim.test:1433')
Add-SimUser 'svc_backup' 1104 -Uac 66048 -PwdSet '2024-02-01T08:00:00Z' -Spn @('backupsvc/bk01.contoso-sim.test') -AdminCount 1
Add-SimUser 'carol.stale' 1105 -LastLogon '2025-02-01T08:00:00Z'
Add-SimUser 'dave.recent' 1106
Add-SimUser 'erin.nologon' 1107 -LastLogon $null -Created '2025-06-01T08:00:00Z'
Add-SimUser 'frank.preauth' 1108 -Uac (512 -bor 0x400000)
Add-SimUser 'grace.nopwd' 1109 -Uac (512 -bor 0x20)
Add-SimUser 'henry.des' 1110 -Uac (512 -bor 0x200000)
Add-SimUser 'jack.left' 1111 -Uac 514 -LastLogon '2025-05-01T08:00:00Z'
Add-SimUser 'ivan.orphan' 1112 -Manager (Get-SimDn 'jack.left')
Add-SimUser 'kate.oldadmin' 1113 -AdminCount 1
Add-SimUser 'leo.disabledadmin' 1114 -Uac 514 -LastLogon '2025-06-01T08:00:00Z' -AdminCount 1
Add-SimUser 'mike.staleadmin' 1115 -LastLogon '2025-01-10T08:00:00Z' -AdminCount 1
Add-SimUser 'sam.schema' 1116 -AdminCount 1
Add-SimUser 'nina.ops' 1117 -AdminCount 1
Add-SimUser 'svc_web' 1118 -Uac (512 -bor 0x80000) -Spn @('HTTP/web01.contoso-sim.test')
Add-SimUser 'svc_proto' 1119 -Uac (512 -bor 0x1000000) -Spn @('proto/app01.contoso-sim.test') -Delegate @('cifs/dc01.contoso-sim.test')
Add-SimUser 'svc_sync' 1150

$computers = @(
    [ordered]@{ SamAccountName = 'DC01$'; DistinguishedName = "CN=DC01,$dcOu"; Sid = "$domainSid-1001"; UserAccountControl = 532480; Enabled = $true; LastLogonTimestamp = '2026-09-30T02:00:00Z'; PasswordLastSet = '2026-09-10T02:00:00Z'; WhenCreated = '2020-01-01T00:00:00Z'; OperatingSystem = 'Windows Server 2022 Standard'; AllowedToDelegateTo = @(); AllowedToActOnBehalf = @() }
    [ordered]@{ SamAccountName = 'DC02$'; DistinguishedName = "CN=DC02,$dcOu"; Sid = "$domainSid-1002"; UserAccountControl = 532480; Enabled = $true; LastLogonTimestamp = '2026-09-30T02:00:00Z'; PasswordLastSet = '2026-09-10T02:00:00Z'; WhenCreated = '2020-01-01T00:00:00Z'; OperatingSystem = 'Windows Server 2012 R2 Standard'; AllowedToDelegateTo = @(); AllowedToActOnBehalf = @((Get-SimDn 'svc_web')) }
    [ordered]@{ SamAccountName = 'DC03$'; DistinguishedName = "CN=DC03,$dcOu"; Sid = "$domainSid-1003"; UserAccountControl = 532480; Enabled = $true; LastLogonTimestamp = '2026-09-30T02:00:00Z'; PasswordLastSet = '2026-09-10T02:00:00Z'; WhenCreated = '2025-06-01T00:00:00Z'; OperatingSystem = 'Windows Server 2025 Datacenter'; AllowedToDelegateTo = @(); AllowedToActOnBehalf = @() }
    [ordered]@{ SamAccountName = 'WS-OK01$'; DistinguishedName = "CN=WS-OK01,CN=Computers,$domainDn"; Sid = "$domainSid-2001"; UserAccountControl = 4096; Enabled = $true; LastLogonTimestamp = '2026-09-28T08:00:00Z'; PasswordLastSet = '2026-09-05T08:00:00Z'; WhenCreated = '2024-03-01T00:00:00Z'; OperatingSystem = 'Windows 11 Enterprise'; AllowedToDelegateTo = @(); AllowedToActOnBehalf = @() }
    [ordered]@{ SamAccountName = 'WS-OLD01$'; DistinguishedName = "CN=WS-OLD01,CN=Computers,$domainDn"; Sid = "$domainSid-2002"; UserAccountControl = 4096; Enabled = $true; LastLogonTimestamp = '2025-03-01T08:00:00Z'; PasswordLastSet = '2025-03-01T08:00:00Z'; WhenCreated = '2022-03-01T00:00:00Z'; OperatingSystem = 'Windows 10 Enterprise'; AllowedToDelegateTo = @(); AllowedToActOnBehalf = @() }
    [ordered]@{ SamAccountName = 'APP01$'; DistinguishedName = "CN=APP01,CN=Computers,$domainDn"; Sid = "$domainSid-2003"; UserAccountControl = (4096 -bor 0x80000); Enabled = $true; LastLogonTimestamp = '2026-09-29T08:00:00Z'; PasswordLastSet = '2026-09-02T08:00:00Z'; WhenCreated = '2023-03-01T00:00:00Z'; OperatingSystem = 'Windows Server 2019 Standard'; AllowedToDelegateTo = @(); AllowedToActOnBehalf = @() }
)

function Add-SimGroup {
    param([string]$Name, [string]$Sid, [string[]]$Members = @(), $AdminCount = 0, [string]$Container = 'CN=Users')
    [ordered]@{ SamAccountName = $Name; Name = $Name; DistinguishedName = "CN=$Name,$Container,$domainDn"; Sid = $Sid; Members = $Members; AdminCount = $AdminCount }
}
$gDn = { param($n, $c = 'CN=Users') "CN=$n,$c,$domainDn" }
$groups = @(
    (Add-SimGroup 'Domain Admins' "$domainSid-512" @((Get-SimDn 'Administrator'), (Get-SimDn 'alice.admin'), (Get-SimDn 'mike.staleadmin'), (Get-SimDn 'svc_backup'), (& $gDn 'IT-Admins')) 1)
    (Add-SimGroup 'Enterprise Admins' "$domainSid-519" @((Get-SimDn 'Administrator')) 1)
    (Add-SimGroup 'Schema Admins' "$domainSid-518" @((Get-SimDn 'sam.schema')) 1)
    (Add-SimGroup 'Group Policy Creator Owners' "$domainSid-520" @())
    (Add-SimGroup 'Administrators' 'S-1-5-32-544' @((& $gDn 'Domain Admins'), (& $gDn 'Enterprise Admins'), (Get-SimDn 'Administrator'), (Get-SimDn 'leo.disabledadmin')) 1 'CN=Builtin')
    (Add-SimGroup 'Account Operators' 'S-1-5-32-548' @() 1 'CN=Builtin')
    (Add-SimGroup 'Server Operators' 'S-1-5-32-549' @() 1 'CN=Builtin')
    (Add-SimGroup 'Print Operators' 'S-1-5-32-550' @() 1 'CN=Builtin')
    (Add-SimGroup 'Backup Operators' 'S-1-5-32-551' @() 1 'CN=Builtin')
    (Add-SimGroup 'Replicator' 'S-1-5-32-552' @() 1 'CN=Builtin')
    (Add-SimGroup 'Domain Users' "$domainSid-513" @())
    (Add-SimGroup 'IT-Admins' "$domainSid-1201" @((Get-SimDn 'bob.helpdesk'), (& $gDn 'Server-Ops-Team')))
    (Add-SimGroup 'Server-Ops-Team' "$domainSid-1202" @((Get-SimDn 'nina.ops'), (& $gDn 'IT-Admins')))
    (Add-SimGroup 'Helpdesk-Ops' "$domainSid-1203" @())
)

$allow = { param($Sid, $Rights, $ObjType = '00000000-0000-0000-0000-000000000000', $Inh = 'None') [ordered]@{ IdentitySid = $Sid; IdentityName = ''; Rights = $Rights; AccessControlType = 'Allow'; ObjectType = $ObjType; InheritedObjectType = '00000000-0000-0000-0000-000000000000'; IsInherited = $false; InheritanceType = $Inh } }
$baseAces = { @((& $allow 'S-1-5-18' @('GenericAll')), (& $allow "$domainSid-512" @('GenericAll')), (& $allow 'S-1-5-32-544' @('GenericAll'))) }
$acls = @(
    [ordered]@{ DistinguishedName = $domainDn; ObjectClass = 'domainDNS'; Role = 'DomainRoot'; OwnerSid = 'S-1-5-32-544'
        Aces = @((& $baseAces) + @(
                (& $allow "$domainSid-1150" @('ExtendedRight') '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'),
                (& $allow "$domainSid-1150" @('ExtendedRight') '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'),
                (& $allow 'S-1-5-11' @('ReadProperty', 'GenericExecute'))
            )) }
    [ordered]@{ DistinguishedName = "CN=AdminSDHolder,CN=System,$domainDn"; ObjectClass = 'container'; Role = 'AdminSDHolder'; OwnerSid = "$domainSid-512"
        Aces = @((& $baseAces) + @((& $allow "$domainSid-1203" @('WriteDacl')))) }
    [ordered]@{ DistinguishedName = (& $gDn 'Domain Admins'); ObjectClass = 'group'; Role = 'PrivilegedGroup'; OwnerSid = "$domainSid-1102"
        Aces = @(& $baseAces) }
    [ordered]@{ DistinguishedName = $dcOu; ObjectClass = 'organizationalUnit'; Role = 'DomainControllersOu'; OwnerSid = "$domainSid-512"
        Aces = @(& $baseAces) }
)

$gpoAcl = { param($extra) @((& $allow 'S-1-5-18' @('GenericAll')), (& $allow "$domainSid-512" @('GenericAll')), (& $allow 'S-1-5-11' @('ReadProperty', 'ExtendedRight') 'edacfd8f-ffb3-11d1-b41d-00a0c968f939')) + $extra }
$gpos = @(
    [ordered]@{ Id = '31b2f340-016d-11d2-945f-00c04fb984f9'; DisplayName = 'Default Domain Policy'; DistinguishedName = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$domainDn"
        LinkedTo = @([ordered]@{ Target = $domainDn; Enabled = $true; Enforced = $false }); OwnerSid = "$domainSid-512"; Aces = @(& $gpoAcl @()); SysvolStatus = 'Read'; Settings = @{}; CpasswordFiles = @() }
    [ordered]@{ Id = '6ac1786c-016f-11d2-945f-00c04fb984f9'; DisplayName = 'Default Domain Controllers Policy'; DistinguishedName = "CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$domainDn"
        LinkedTo = @([ordered]@{ Target = $dcOu; Enabled = $true; Enforced = $false }); OwnerSid = "$domainSid-512"; Aces = @(& $gpoAcl @()); SysvolStatus = 'Read'
        Settings = @{ 'machine\system\currentcontrolset\control\lsa\lmcompatibilitylevel' = '3'; 'machine\system\currentcontrolset\services\lanmanserver\parameters\requiresecuritysignature' = '1' }; CpasswordFiles = @() }
    [ordered]@{ Id = '9d3f0c1a-5b6e-4a7d-8f21-0a1b2c3d4e5f'; DisplayName = 'Legacy Drive Mapping'; DistinguishedName = "CN={9D3F0C1A-5B6E-4A7D-8F21-0A1B2C3D4E5F},CN=Policies,CN=System,$domainDn"
        LinkedTo = @([ordered]@{ Target = "OU=Workstations,$domainDn"; Enabled = $true; Enforced = $false }); OwnerSid = "$domainSid-512"; Aces = @(& $gpoAcl @((& $allow "$domainSid-1102" @('GenericAll')))); SysvolStatus = 'Read'; Settings = @{}
        CpasswordFiles = @('Machine\Preferences\Groups\Groups.xml') }
)

$auditSetting = { param($guid, $name, $setting) [ordered]@{ Guid = "{$guid}"; Subcategory = $name; Setting = $setting } }
$entries = @(
    (& $auditSetting '0CCE923F-69AE-11D9-BED3-505054503030' 'Credential Validation' 'Success and Failure')
    (& $auditSetting '0CCE9242-69AE-11D9-BED3-505054503030' 'Kerberos Authentication Service' 'No Auditing')
    (& $auditSetting '0CCE9240-69AE-11D9-BED3-505054503030' 'Kerberos Service Ticket Operations' 'Success and Failure')
    (& $auditSetting '0CCE9235-69AE-11D9-BED3-505054503030' 'User Account Management' 'Success and Failure')
    (& $auditSetting '0CCE9236-69AE-11D9-BED3-505054503030' 'Computer Account Management' 'Success')
    (& $auditSetting '0CCE9237-69AE-11D9-BED3-505054503030' 'Security Group Management' 'Success')
    (& $auditSetting '0CCE923C-69AE-11D9-BED3-505054503030' 'Directory Service Changes' 'Success')
    (& $auditSetting '0CCE9215-69AE-11D9-BED3-505054503030' 'Logon' 'Success and Failure')
    (& $auditSetting '0CCE921B-69AE-11D9-BED3-505054503030' 'Special Logon' 'Success')
    (& $auditSetting '0CCE922F-69AE-11D9-BED3-505054503030' 'Audit Policy Change' 'Success')
)
$dcHosts = @(
    [ordered]@{ Name = 'DC01'; HostName = 'dc01.contoso-sim.test'; OperatingSystem = 'Windows Server 2022 Standard'; Reachable = $true; Error = ''; ErrorCategory = ''
        Ldap = [ordered]@{ Status = 'Collected'; ServerIntegrity = 2; ChannelBinding = 1 }
        Spooler = [ordered]@{ Status = 'Collected'; State = 'Running' }
        AuditPolicy = [ordered]@{ Status = 'Collected'; Entries = $entries }
        SecurityLog = [ordered]@{ Status = 'Collected'; MaximumSizeInBytes = 4294967296; LogMode = 'Circular' } }
    [ordered]@{ Name = 'DC02'; HostName = 'dc02.contoso-sim.test'; OperatingSystem = 'Windows Server 2012 R2 Standard'; Reachable = $false
        Error = 'Simulated: WinRM cannot process the request because the server dc02.contoso-sim.test is unreachable.'; ErrorCategory = 'Unreachable' }
    [ordered]@{ Name = 'DC03'; HostName = 'dc03.contoso-sim.test'; OperatingSystem = 'Windows Server 2025 Datacenter'; Reachable = $true; Error = ''; ErrorCategory = ''
        Ldap = [ordered]@{ Status = 'Collected'; ServerIntegrity = $null; ChannelBinding = 2 }
        Spooler = [ordered]@{ Status = 'Collected'; State = 'Stopped' }
        AuditPolicy = [ordered]@{ Status = 'Collected'; Entries = @($entries | ForEach-Object { [ordered]@{ Guid = $_.Guid; Subcategory = $_.Subcategory; Setting = 'Success and Failure' } }) }
        SecurityLog = [ordered]@{ Status = 'Collected'; MaximumSizeInBytes = 4294967296; LogMode = 'Circular' } }
)

$snapshot = [ordered]@{
    schemaVersion    = '1.0'
    dataSource       = 'Simulated'
    simulationNotice = 'SYNTHETIC DATA. Every object in this file is invented. It demonstrates the toolkit and says nothing about any real domain.'
    collectionTime   = '2026-10-01T00:00:00Z'
    domain           = [ordered]@{ name = 'contoso-sim.test'; distinguishedName = $domainDn; netBiosName = 'CONTOSOSIM'; sid = $domainSid; domainMode = 'Windows2012R2Domain'; forestMode = 'Windows2008R2Forest'; forestName = 'contoso-sim.test'; domainControllersContainer = $dcOu; pdcEmulator = 'dc01.contoso-sim.test' }
    sections         = [ordered]@{
        Users               = [ordered]@{ status = 'Collected'; data = $users.ToArray(); error = ''; errorCategory = '' }
        Computers           = [ordered]@{ status = 'Collected'; data = $computers; error = ''; errorCategory = '' }
        Groups              = [ordered]@{ status = 'Collected'; data = $groups; error = ''; errorCategory = '' }
        DomainControllers   = [ordered]@{ status = 'Collected'; error = ''; errorCategory = ''; data = @(
                [ordered]@{ Name = 'DC01'; HostName = 'dc01.contoso-sim.test'; OperatingSystem = 'Windows Server 2022 Standard'; OperatingSystemVersion = '10.0 (20348)'; Site = 'Default-First-Site-Name'; IsGlobalCatalog = $true; IsReadOnly = $false; ComputerObjectDN = "CN=DC01,$dcOu" }
                [ordered]@{ Name = 'DC02'; HostName = 'dc02.contoso-sim.test'; OperatingSystem = 'Windows Server 2012 R2 Standard'; OperatingSystemVersion = '6.3 (9600)'; Site = 'Branch-Site'; IsGlobalCatalog = $false; IsReadOnly = $false; ComputerObjectDN = "CN=DC02,$dcOu" }
                [ordered]@{ Name = 'DC03'; HostName = 'dc03.contoso-sim.test'; OperatingSystem = 'Windows Server 2025 Datacenter'; OperatingSystemVersion = '10.0 (26100)'; Site = 'Default-First-Site-Name'; IsGlobalCatalog = $true; IsReadOnly = $false; ComputerObjectDN = "CN=DC03,$dcOu" }
            ) }
        PasswordPolicy      = [ordered]@{ status = 'Collected'; error = ''; errorCategory = ''; data = [ordered]@{ MinPasswordLength = 8; PasswordHistoryCount = 24; ComplexityEnabled = $true; LockoutThreshold = 0; LockoutDurationMinutes = 30; LockoutObservationWindowMinutes = 30; ReversibleEncryptionEnabled = $false; MaxPasswordAgeDays = 90; MinPasswordAgeDays = 1 } }
        FineGrainedPolicies = [ordered]@{ status = 'Error'; data = @(); error = 'Simulated: Access is denied. Fine-grained password policy objects are readable only by Domain Admins by default.'; errorCategory = 'AccessDenied' }
        Trusts              = [ordered]@{ status = 'Collected'; error = ''; errorCategory = ''; data = @(
                [ordered]@{ Name = 'partner.example.test'; FlatName = 'PARTNER'; TrustAttributes = 0; TrustDirection = 3; TrustType = 2 }
                [ordered]@{ Name = 'fabrikam-sim.test'; FlatName = 'FABRIKAM'; TrustAttributes = 20; TrustDirection = 3; TrustType = 2 }
            ) }
        Acls                = [ordered]@{ status = 'Collected'; data = $acls; error = ''; errorCategory = '' }
        Gpos                = [ordered]@{ status = 'Collected'; data = $gpos; error = ''; errorCategory = '' }
        DcHosts             = [ordered]@{ status = 'Collected'; data = $dcHosts; error = ''; errorCategory = '' }
    }
    collector        = [ordered]@{ tool = 'New-SampleSnapshot.ps1'; note = 'hand-authored synthetic fixture' }
}
$dir = Split-Path -Path $OutputFile -Parent
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
[System.IO.File]::WriteAllText($OutputFile, ($snapshot | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding($false)))
Write-Information "Wrote synthetic snapshot: $OutputFile" -InformationAction Continue
