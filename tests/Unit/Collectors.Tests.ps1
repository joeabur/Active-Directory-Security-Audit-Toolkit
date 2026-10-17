# Mocked ActiveDirectory cmdlets: portable, no domain access. Results here prove the collector code paths only.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')

    # Stubs so Pester can mock commands that do not exist off-domain
    foreach ($n in 'Get-ADDomain', 'Get-ADForest', 'Get-ADUser', 'Get-ADComputer', 'Get-ADGroup', 'Get-ADDomainController', 'Get-ADDefaultDomainPasswordPolicy', 'Get-ADFineGrainedPasswordPolicy') {
        Set-Item -Path "function:global:$n" -Value ([scriptblock]::Create('[CmdletBinding()] param($Filter, $Properties, $Server, $Credential, $ResultPageSize) '))
    }
    Set-Item -Path 'function:global:Get-ADObject' -Value ([scriptblock]::Create('[CmdletBinding()] param($Filter, $LDAPFilter, $SearchBase, $Identity, $Properties, $Server, $Credential) '))
    # Write cmdlets exist only so the tests can prove they are never called
    foreach ($n in 'Set-ADUser', 'Set-ADObject', 'Set-ADAccountPassword', 'Add-ADGroupMember', 'Remove-ADGroupMember', 'Remove-ADObject', 'New-ADUser', 'Unlock-ADAccount', 'Disable-ADAccount', 'Set-ADDefaultDomainPasswordPolicy') {
        Set-Item -Path "function:global:$n" -Value ([scriptblock]::Create('[CmdletBinding()] param() '))
    }

    $script:sidObj = { param($v) [pscustomobject]@{ Value = $v } }
    function New-FakeSd($ownerSid, $rules) {
        $sd = [pscustomobject]@{ Marker = 'sd' }
        $sd | Add-Member -MemberType ScriptMethod -Name GetOwner -Value ({ param($t) [pscustomobject]@{ Value = $ownerSid } }.GetNewClosure())
        $sd | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value ({ param($a, $b, $t) $rules }.GetNewClosure())
        return $sd
    }
    $script:rule = [pscustomobject]@{ IdentityReference = [pscustomobject]@{ Value = "$script:TestDomainSid-1500" }; ActiveDirectoryRights = 'WriteDacl'; AccessControlType = 'Allow'; ObjectType = [guid]::Empty; InheritedObjectType = [guid]::Empty; IsInherited = $false; InheritanceType = 'None' }

    function Set-HappyMocks {
        Mock -ModuleName ADSecurityAudit Get-ADDomain { [pscustomobject]@{ DNSRoot = 'test.local'; DistinguishedName = 'DC=test,DC=local'; NetBIOSName = 'TEST'; DomainSID = [pscustomobject]@{ Value = $script:TestDomainSid }; DomainMode = 'Windows2016Domain'; DomainControllersContainer = 'OU=Domain Controllers,DC=test,DC=local'; PDCEmulator = 'dc1.test.local' } }
        Mock -ModuleName ADSecurityAudit Get-ADForest { [pscustomobject]@{ Name = 'test.local'; ForestMode = 'Windows2016Forest' } }
        Mock -ModuleName ADSecurityAudit Get-ADUser {
            @(
                [pscustomobject]@{ SamAccountName = 'alice'; DistinguishedName = 'CN=alice,CN=Users,DC=test,DC=local'; SID = [pscustomobject]@{ Value = "$script:TestDomainSid-1100" }; Enabled = $true; userAccountControl = 66048; LastLogonTimestamp = ([datetime]'2026-09-01T00:00:00Z').ToFileTimeUtc(); PasswordLastSet = [datetime]'2026-01-01T00:00:00Z'; WhenCreated = [datetime]'2024-01-01T00:00:00Z'; ServicePrincipalNames = @('HTTP/a'); PrimaryGroupID = 513; adminCount = 1 },
                [pscustomobject]@{ SamAccountName = 'bob'; DistinguishedName = 'CN=bob,CN=Users,DC=test,DC=local'; SID = [pscustomobject]@{ Value = "$script:TestDomainSid-1101" }; Enabled = $false; userAccountControl = 514 }
            )
        }
        Mock -ModuleName ADSecurityAudit Get-ADComputer { @([pscustomobject]@{ SamAccountName = 'WS1$'; DistinguishedName = 'CN=WS1,CN=Computers,DC=test,DC=local'; SID = [pscustomobject]@{ Value = "$script:TestDomainSid-2000" }; Enabled = $true; userAccountControl = 4096; OperatingSystem = 'Windows 11'; PrincipalsAllowedToDelegateToAccount = @('CN=x,DC=test') }) }
        Mock -ModuleName ADSecurityAudit Get-ADGroup { @([pscustomobject]@{ SamAccountName = 'Domain Admins'; Name = 'Domain Admins'; DistinguishedName = 'CN=Domain Admins,CN=Users,DC=test,DC=local'; SID = [pscustomobject]@{ Value = "$script:TestDomainSid-512" }; Member = @('CN=alice,CN=Users,DC=test,DC=local') }) }
        Mock -ModuleName ADSecurityAudit Get-ADDomainController { @([pscustomobject]@{ Name = 'DC1'; HostName = 'dc1.test.local'; OperatingSystem = 'Windows Server 2022'; OperatingSystemVersion = '10.0'; Site = 'Default'; IsGlobalCatalog = $true; IsReadOnly = $false; ComputerObjectDN = 'CN=DC1,OU=Domain Controllers,DC=test,DC=local' }) }
        Mock -ModuleName ADSecurityAudit Get-ADDefaultDomainPasswordPolicy { [pscustomobject]@{ MinPasswordLength = 12; PasswordHistoryCount = 24; ComplexityEnabled = $true; LockoutThreshold = 5; LockoutDuration = [timespan]::FromMinutes(30); LockoutObservationWindow = [timespan]::FromMinutes(30); ReversibleEncryptionEnabled = $false; MaxPasswordAge = [timespan]::FromDays(60); MinPasswordAge = [timespan]::FromDays(1) } }
        Mock -ModuleName ADSecurityAudit Get-ADFineGrainedPasswordPolicy { @() }
        foreach ($n in 'Set-ADUser', 'Set-ADObject', 'Set-ADAccountPassword', 'Add-ADGroupMember', 'Remove-ADGroupMember', 'Remove-ADObject', 'New-ADUser', 'Unlock-ADAccount', 'Disable-ADAccount', 'Set-ADDefaultDomainPasswordPolicy') { Mock -ModuleName ADSecurityAudit $n { } }
        Mock -ModuleName ADSecurityAudit Get-ADObject { @() }
        Mock -ModuleName ADSecurityAudit Get-ADObject { @([pscustomobject]@{ Name = 'partner.test'; trustAttributes = 0; trustDirection = 3; trustType = 2; flatName = 'PARTNER' }) } -ParameterFilter { $Filter -like '*trustedDomain*' }
        Mock -ModuleName ADSecurityAudit Get-ADObject { @([pscustomobject]@{ DistinguishedName = 'DC=test,DC=local'; gPLink = '[LDAP://cn={AAAAAAAA-0000-0000-0000-000000000001},cn=policies,cn=system,DC=test,DC=local;0]' }) } -ParameterFilter { $LDAPFilter }
        Mock -ModuleName ADSecurityAudit Get-ADObject { @([pscustomobject]@{ Name = '{AAAAAAAA-0000-0000-0000-000000000001}'; DistinguishedName = 'CN={AAAAAAAA-0000-0000-0000-000000000001},CN=Policies,CN=System,DC=test,DC=local'; displayName = 'Test GPO'; gPCFileSysPath = (Join-Path $TestDrive 'does-not-exist'); ObjectClass = 'groupPolicyContainer'; nTSecurityDescriptor = (New-FakeSd 'S-1-5-32-544' @($script:rule)) }) } -ParameterFilter { $Filter -like '*groupPolicyContainer*' }
        Mock -ModuleName ADSecurityAudit Get-ADObject { [pscustomobject]@{ DistinguishedName = $Identity; ObjectClass = 'container'; nTSecurityDescriptor = (New-FakeSd 'S-1-5-32-544' @($script:rule)) } } -ParameterFilter { $Identity }
    }
}

AfterAll {
    foreach ($n in 'Get-ADDomain', 'Get-ADForest', 'Get-ADUser', 'Get-ADComputer', 'Get-ADGroup', 'Get-ADDomainController', 'Get-ADDefaultDomainPasswordPolicy', 'Get-ADFineGrainedPasswordPolicy', 'Get-ADObject', 'Set-ADUser', 'Set-ADObject', 'Set-ADAccountPassword', 'Add-ADGroupMember', 'Remove-ADGroupMember', 'Remove-ADObject', 'New-ADUser', 'Unlock-ADAccount', 'Disable-ADAccount', 'Set-ADDefaultDomainPasswordPolicy') {
        Get-ChildItem -Path function: | Where-Object { $_.Name -eq $n } | Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Error classification' {
    It 'maps exceptions to categories' {
        InModuleScope ADSecurityAudit {
            function Get-Cat($ex) { try { throw $ex } catch { Get-ADSAErrorCategory -ErrorRecord $_ } }
            Get-Cat ([System.UnauthorizedAccessException]::new('Access is denied.')) | Should -Be 'AccessDenied'
            Get-Cat ([System.Exception]::new('Insufficient access rights to perform the operation')) | Should -Be 'AccessDenied'
            Get-Cat ([System.Exception]::new('Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running.')) | Should -Be 'Unreachable'
            Get-Cat ([System.Exception]::new('The server is not operational.')) | Should -Be 'Unreachable'
            Get-Cat ([System.Exception]::new("One or more properties are invalid.`r`nParameter name: msDS-Fake")) | Should -Be 'UnsupportedAttribute'
            Get-Cat ([System.Exception]::new('A referral was returned from the server (LDAP).')) | Should -Be 'LdapError'
            Get-Cat ([System.Management.Automation.CommandNotFoundException]::new("The term 'Get-ADUser' is not recognized as a name of a cmdlet")) | Should -Be 'ModuleUnavailable'
            Get-Cat ([System.Exception]::new('something odd')) | Should -Be 'Error'
        }
    }
}

Describe 'Live collection with mocked ActiveDirectory cmdlets' {
    BeforeEach { Set-HappyMocks }

    It 'collects a valid snapshot labelled Live and normalises values' {
        $s = Get-ADSASnapshot -SkipDcHostChecks -SkipSysvol
        $s.dataSource | Should -Be 'Live'
        $s.domain.name | Should -Be 'test.local'
        $s.domain.sid | Should -Be $script:TestDomainSid
        $u = $s.sections.Users.data | Where-Object SamAccountName -eq 'alice'
        $u.Sid | Should -Be "$script:TestDomainSid-1100"
        $u.LastLogonTimestamp | Should -Be '2026-09-01T00:00:00Z'
        $u.PasswordLastSet | Should -Be '2026-01-01T00:00:00Z'
        $u.ServicePrincipalNames | Should -Be @('HTTP/a')
        $bob = $s.sections.Users.data | Where-Object SamAccountName -eq 'bob'
        $bob.Manager | Should -BeNullOrEmpty
        $bob.PSObject.Properties.Name | Should -Contain 'Manager'   # present-but-empty, so rules can tell "not set" from "not retrieved"
        $s.sections.PasswordPolicy.data.LockoutDurationMinutes | Should -Be 30
        $s.sections.Computers.data[0].AllowedToActOnBehalf | Should -Be @('CN=x,DC=test')
        $s.sections.Trusts.data[0].TrustDirection | Should -Be 3
        $s.sections.Gpos.data[0].LinkedTo[0].Target | Should -Be 'DC=test,DC=local'
        $s.sections.Gpos.data[0].SysvolStatus | Should -Be 'Skipped'
        $s.sections.DcHosts.status | Should -Be 'NotAssessed'
    }
    It 'reads ACLs through nTSecurityDescriptor and records owner and ACEs' {
        $s = Get-ADSASnapshot -SkipDcHostChecks -SkipSysvol
        $s.sections.Acls.status | Should -Be 'Collected'
        $root = $s.sections.Acls.data | Where-Object Role -eq 'DomainRoot'
        $root.OwnerSid | Should -Be 'S-1-5-32-544'
        $root.Aces[0].Rights | Should -Be @('WriteDacl')
        $roles = @($s.sections.Acls.data | ForEach-Object { $_.Role })
        $roles | Should -Contain 'AdminSDHolder'
        $roles | Should -Contain 'DomainControllersOu'
        $roles | Should -Contain 'PrivilegedGroup'
        $roles | Should -Contain 'DomainController'
    }
    It 'runs a full audit over a collected snapshot' {
        $s = Get-ADSASnapshot -SkipDcHostChecks -SkipSysvol
        $r = Invoke-ADSecurityAudit -Snapshot $s -Module AccountLifecycle, AuthenticationPolicy, Acl
        $r.Metadata.DataSource | Should -Be 'Live'
        (Get-TestResult $r 'ADSA-ACC-003' | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be 'alice'
        (Get-TestResult $r 'ADSA-POL-001').Status | Should -Be 'FAIL'
        @(Get-TestResult $r 'ADSA-ACL-001' | Where-Object Status -eq 'FAIL').Count | Should -BeGreaterThan 0
        (Test-ADSAReport -Report $r).IsValid | Should -BeTrue
    }
    It 'never calls any state-changing ActiveDirectory cmdlet' {
        $null = Get-ADSASnapshot -SkipDcHostChecks -SkipSysvol
        foreach ($n in 'Set-ADUser', 'Set-ADObject', 'Set-ADAccountPassword', 'Add-ADGroupMember', 'Remove-ADGroupMember', 'Remove-ADObject', 'New-ADUser', 'Unlock-ADAccount', 'Disable-ADAccount', 'Set-ADDefaultDomainPasswordPolicy') {
            Should -Invoke -CommandName $n -ModuleName ADSecurityAudit -Times 0 -Exactly
        }
    }
    It 'passes -Server and -Credential through without persisting them' {
        $cred = [pscredential]::new('TEST\auditor', (ConvertTo-SecureString 'not-a-real-password' -AsPlainText -Force))
        $s = Get-ADSASnapshot -Server 'dc1.test.local' -Credential $cred -SkipDcHostChecks -SkipSysvol
        Should -Invoke -CommandName Get-ADUser -ModuleName ADSecurityAudit -ParameterFilter { $Server -eq 'dc1.test.local' -and $Credential.UserName -eq 'TEST\auditor' }
        ($s | ConvertTo-Json -Depth 12) | Should -Not -Match 'not-a-real-password|auditor'
    }
}

Describe 'Collection failures' {
    BeforeEach { Set-HappyMocks }

    It 'records an access-denied section as Error/AccessDenied while other sections still collect' {
        Mock -ModuleName ADSecurityAudit Get-ADUser { throw [System.UnauthorizedAccessException]::new('Access is denied.') }
        $s = Get-ADSASnapshot -SkipDcHostChecks -SkipSysvol
        $s.sections.Users.status | Should -Be 'Error'
        $s.sections.Users.errorCategory | Should -Be 'AccessDenied'
        $s.sections.Groups.status | Should -Be 'Collected'
        $r = Invoke-ADSecurityAudit -Snapshot $s -Module AccountLifecycle
        (Get-TestResult $r 'ADSA-ACC-003').Status | Should -Be 'ERROR'
        @($r.CollectionErrors | Where-Object { $_.Source -eq 'Users' -and $_.Category -eq 'AccessDenied' }).Count | Should -Be 1
    }
    It 'records an unsupported attribute error distinctly' {
        Mock -ModuleName ADSecurityAudit Get-ADComputer { throw [System.Exception]::new('One or more properties are invalid.') }
        $s = Get-ADSASnapshot -SkipDcHostChecks -SkipSysvol
        $s.sections.Computers.errorCategory | Should -Be 'UnsupportedAttribute'
    }
    It 'handles an LDAP failure on one section' {
        Mock -ModuleName ADSecurityAudit Get-ADGroup { throw [System.Exception]::new('A referral was returned from the server (LDAP).') }
        $s = Get-ADSASnapshot -SkipDcHostChecks -SkipSysvol
        $s.sections.Groups.errorCategory | Should -Be 'LdapError'
        $s.sections.Users.status | Should -Be 'Collected'
    }
    It 'marks every section Error/Unreachable when the domain cannot be contacted' {
        Mock -ModuleName ADSecurityAudit Get-ADDomain { throw [System.Exception]::new('Unable to contact the server.') }
        $s = Get-ADSASnapshot -Server 'down.test.local'
        foreach ($sec in $s.sections.PSObject.Properties) { $sec.Value.status | Should -Be 'Error'; $sec.Value.errorCategory | Should -Be 'Unreachable' }
        $r = Invoke-ADSecurityAudit -Snapshot $s
        @($r.Findings | Where-Object Status -in 'PASS', 'FAIL').Count | Should -Be 0
    }
    It 'marks every section NotAssessed/ModuleUnavailable when the ActiveDirectory module is missing' {
        Mock -ModuleName ADSecurityAudit Get-Command { $null } -ParameterFilter { $Name -eq 'Get-ADDomain' }
        $s = Get-ADSASnapshot
        foreach ($sec in $s.sections.PSObject.Properties) { $sec.Value.status | Should -Be 'NotAssessed'; $sec.Value.errorCategory | Should -Be 'ModuleUnavailable' }
        $r = Invoke-ADSecurityAudit -Snapshot $s
        @($r.Findings | Where-Object Status -in 'PASS', 'FAIL').Count | Should -Be 0
        @($r.Findings | Where-Object Status -eq 'NOT_ASSESSED').Count | Should -BeGreaterThan 30
    }
    It 'keeps collecting ACLs when one target is unreadable and reports it' {
        Mock -ModuleName ADSecurityAudit Get-ADObject { if ($Identity -like 'CN=AdminSDHolder*') { throw [System.UnauthorizedAccessException]::new('Access is denied.') }; [pscustomobject]@{ DistinguishedName = $Identity; ObjectClass = 'container'; nTSecurityDescriptor = (New-FakeSd 'S-1-5-32-544' @($script:rule)) } } -ParameterFilter { $Identity }
        $s = Get-ADSASnapshot -SkipDcHostChecks -SkipSysvol
        $s.sections.Acls.status | Should -Be 'Collected'
        @($s.sections.Acls.warnings | Where-Object category -eq 'AccessDenied').Count | Should -Be 1
    }
    It 'fails the ACL section when no descriptor can be read at all' {
        Mock -ModuleName ADSecurityAudit Get-ADObject { throw [System.UnauthorizedAccessException]::new('Access is denied.') } -ParameterFilter { $Identity }
        $s = Get-ADSASnapshot -SkipDcHostChecks -SkipSysvol
        $s.sections.Acls.status | Should -Be 'Error'
        $s.sections.Acls.errorCategory | Should -Be 'AccessDenied'
    }
}

Describe 'Domain controller host collection (mocked remoting)' {
    BeforeEach { Set-HappyMocks }

    It 'stores per-DC results from the fixed read-only remote script block' {
        Mock -ModuleName ADSecurityAudit Invoke-Command {
            @{ Ldap = @{ Status = 'Collected'; ServerIntegrity = 2; ChannelBinding = 2 }; Spooler = @{ Status = 'Collected'; State = 'Stopped' }; AuditPolicy = @{ Status = 'Collected'; Entries = @() }; SecurityLog = @{ Status = 'Collected'; MaximumSizeInBytes = 1GB; LogMode = 'Circular' } }
        }
        $s = Get-ADSASnapshot -SkipSysvol
        $dc = $s.sections.DcHosts.data[0]
        $dc.Reachable | Should -BeTrue
        $dc.Ldap.ServerIntegrity | Should -Be 2
        Should -Invoke -CommandName Invoke-Command -ModuleName ADSecurityAudit -Times 1 -Exactly
    }
    It 'records an unreachable DC without failing the whole run' {
        Mock -ModuleName ADSecurityAudit Invoke-Command { throw [System.Exception]::new('WinRM cannot process the request. Unable to contact the server.') }
        $s = Get-ADSASnapshot -SkipSysvol
        $dc = $s.sections.DcHosts.data[0]
        $dc.Reachable | Should -BeFalse
        $dc.ErrorCategory | Should -Be 'Unreachable'
        $s.sections.DcHosts.status | Should -Be 'Collected'
    }
    It 'defines a remote script block that only reads' {
        $src = (Get-Content -Raw (Join-Path $PSScriptRoot '../../src/Private/Collectors.ps1'))
        $src | Should -Match "auditpol\.exe /get /category:\* /r"
        $src | Should -Not -Match '(?i)auditpol[^\r\n]*/set'
    }
}
