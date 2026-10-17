BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')
    $script:da = "$script:TestDomainSid-512"
    $script:attacker = "$script:TestDomainSid-1500"
    function Invoke-Acl($Targets = @(), $Gpos, $Config, $Extra = @{}) {
        $sections = @{ Acls = (New-TestSection -Data $Targets); Gpos = $(if ($null -ne $Gpos) { New-TestSection -Data $Gpos } else { New-TestSection -Data @() }) }
        foreach ($k in $Extra.Keys) { $sections[$k] = $Extra[$k] }
        Invoke-TestAudit -Snapshot (New-TestSnapshot -Sections $sections) -Module Acl -ConfigPath $Config
    }
    function New-Target($Role, $Class, $Aces, $Owner = "$script:TestDomainSid-512", $Dn = 'CN=T,DC=test,DC=local') {
        [pscustomobject]@{ DistinguishedName = $Dn; ObjectClass = $Class; Role = $Role; OwnerSid = $Owner; Aces = $Aces }
    }
}

Describe 'ACL interpretation' {
    It 'classifies high-risk rights and ignores read-only and deny ACEs' {
        InModuleScope ADSecurityAudit {
            function ace($r, $t = '00000000-0000-0000-0000-000000000000', $type = 'Allow', $inh = 'None') { [pscustomobject]@{ Rights = $r; AccessControlType = $type; ObjectType = $t; InheritanceType = $inh } }
            (Get-ADSAAceRisk -Ace (ace @('GenericAll'))) | Should -Contain 'GenericAll'
            (Get-ADSAAceRisk -Ace (ace @('WriteDacl', 'WriteOwner'))) | Should -Be @('WriteDacl', 'WriteOwner')
            (Get-ADSAAceRisk -Ace (ace @('WriteProperty'))) | Should -Contain 'WriteAllProperties'
            (Get-ADSAAceRisk -Ace (ace @('WriteProperty') 'bf967a0e-0de6-11d0-a285-00c04fc2dcd2')).Count | Should -Be 0   # a single specific property
            (Get-ADSAAceRisk -Ace (ace @('ExtendedRight'))) | Should -Contain 'AllExtendedRights'
            (Get-ADSAAceRisk -Ace (ace @('ExtendedRight') '00299570-246d-11d0-a768-00c04fc2dcd2') -TargetClass 'user') | Should -Contain 'ResetPassword'
            (Get-ADSAAceRisk -Ace (ace @('ExtendedRight') '00299570-246d-11d0-a768-00c04fc2dcd2') -TargetClass 'group').Count | Should -Be 0
            (Get-ADSAAceRisk -Ace (ace @('WriteProperty') 'bf9679c0-0de6-11d0-a285-00c04fc2dcd2') -TargetClass 'group') | Should -Contain 'WriteGroupMembership'
            (Get-ADSAAceRisk -Ace (ace @('Self') 'bf9679c0-0de6-11d0-a285-00c04fc2dcd2') -TargetClass 'group') | Should -Contain 'WriteGroupMembership'
            (Get-ADSAAceRisk -Ace (ace @('WriteProperty') 'f30e3bbe-9ff0-11d1-b603-0000f80367c1') -TargetClass 'organizationalUnit') | Should -Contain 'WriteGPLink'
            (Get-ADSAAceRisk -Ace (ace @('ReadProperty', 'GenericExecute'))).Count | Should -Be 0
            (Get-ADSAAceRisk -Ace (ace @('GenericAll') -type 'Deny')).Count | Should -Be 0
        }
    }
    It 'ignores inherit-only ACEs because they do not apply to the object itself' {
        InModuleScope ADSecurityAudit {
            $a = [pscustomobject]@{ Rights = @('GenericAll'); AccessControlType = 'Allow'; ObjectType = '00000000-0000-0000-0000-000000000000'; InheritanceType = 'Descendents' }
            (Get-ADSAAceRisk -Ace $a).Count | Should -Be 0
            $b = [pscustomobject]@{ Rights = @('GenericAll'); AccessControlType = 'Allow'; ObjectType = '00000000-0000-0000-0000-000000000000'; InheritanceType = 'All' }
            (Get-ADSAAceRisk -Ace $b).Count | Should -Be 1
        }
    }
    It 'normalises an ActiveDirectoryAccessRule-shaped object' {
        InModuleScope ADSecurityAudit {
            $rule = [pscustomobject]@{ IdentityReference = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1500' }; ActiveDirectoryRights = 'WriteDacl, WriteOwner'; AccessControlType = 'Allow'; ObjectType = [guid]::Empty; InheritedObjectType = [guid]::Empty; IsInherited = $true; InheritanceType = 'All' }
            $ace = ConvertTo-ADSAAce -AccessRule $rule
            $ace.IdentitySid | Should -Be 'S-1-5-21-1-2-3-1500'
            $ace.Rights | Should -Be @('WriteDacl', 'WriteOwner')
            $ace.IsInherited | Should -BeTrue
            $named = ConvertTo-ADSAAce -AccessRule ([pscustomobject]@{ IdentityReference = 'CONTOSO\helpdesk'; ActiveDirectoryRights = 'GenericAll'; AccessControlType = 'Allow' })
            $named.IdentityName | Should -Be 'CONTOSO\helpdesk'
            $named.IdentitySid | Should -BeNullOrEmpty
        }
    }
    It 'requires both replication rights for DCSync capability and honours GenericAll / all-extended-rights' {
        InModuleScope ADSecurityAudit {
            function ace($r, $t = '00000000-0000-0000-0000-000000000000') { [pscustomobject]@{ Rights = $r; AccessControlType = 'Allow'; ObjectType = $t; InheritanceType = 'None' } }
            (Get-ADSAReplicationGrant -Aces @((ace @('ExtendedRight') '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'))).HasBoth | Should -BeFalse
            (Get-ADSAReplicationGrant -Aces @((ace @('ExtendedRight') '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'), (ace @('ExtendedRight') '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))).HasBoth | Should -BeTrue
            (Get-ADSAReplicationGrant -Aces @((ace @('ExtendedRight')))).HasBoth | Should -BeTrue
            (Get-ADSAReplicationGrant -Aces @((ace @('GenericAll')))).HasBoth | Should -BeTrue
        }
    }
}

Describe 'ACL audit rules' {
    It 'ADSA-ACL-001 flags an untrusted principal and not default administrators' {
        $aces = @((New-TestAce -Sid 'S-1-5-18' -Rights 'GenericAll'), (New-TestAce -Sid $script:da -Rights 'GenericAll'), (New-TestAce -Sid $script:attacker -Rights 'WriteDacl'))
        $r = Invoke-Acl -Targets @((New-Target 'AdminSDHolder' 'container' $aces))
        $f = Get-TestResult $r 'ADSA-ACL-001' | Where-Object Status -eq 'FAIL'
        $f.Count | Should -Be 1
        $f.Evidence.Principal | Should -Match '1500'
        $f.Evidence.HighRiskRights | Should -Contain 'WriteDacl'
        $f.Severity | Should -Be 'High'
    }
    It 'escalates to Critical when the principal is broad (Authenticated Users)' {
        $r = Invoke-Acl -Targets @((New-Target 'DomainRoot' 'domainDNS' @((New-TestAce -Sid 'S-1-5-11' -Rights 'GenericWrite'))))
        (Get-TestResult $r 'ADSA-ACL-001' | Where-Object Status -eq 'FAIL').Severity | Should -Be 'Critical'
    }
    It 'treats configured trusted principals (by SID and by name) as expected' {
        $cfg = New-TestConfigFile ('{ "trustedPrincipals": { "sids": ["' + $script:attacker + '"], "names": ["CONTOSO\\sync"] } }')
        $aces = @((New-TestAce -Sid $script:attacker -Rights 'GenericAll'), (New-TestAce -Sid '' -Name 'CONTOSO\sync' -Rights 'GenericAll'))
        $r = Invoke-Acl -Targets @((New-Target 'DomainRoot' 'domainDNS' $aces)) -Config $cfg
        (Get-TestResult $r 'ADSA-ACL-001').Status | Should -Be 'PASS'
    }
    It 'passes when only default principals hold powerful rights' {
        $r = Invoke-Acl -Targets @((New-Target 'DomainRoot' 'domainDNS' @((New-TestAce -Sid $script:da -Rights 'GenericAll'), (New-TestAce -Sid 'S-1-5-11' -Rights 'ReadProperty'))))
        (Get-TestResult $r 'ADSA-ACL-001').Status | Should -Be 'PASS'
    }
    It 'ADSA-ACL-002 flags only principals holding both replication rights' {
        $both = @((New-TestAce -Sid $script:attacker -Rights 'ExtendedRight' -ObjectType '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'), (New-TestAce -Sid $script:attacker -Rights 'ExtendedRight' -ObjectType '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))
        $one = @((New-TestAce -Sid "$script:TestDomainSid-1501" -Rights 'ExtendedRight' -ObjectType '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'))
        $r = Invoke-Acl -Targets @((New-Target 'DomainRoot' 'domainDNS' ($both + $one)))
        $f = Get-TestResult $r 'ADSA-ACL-002' | Where-Object Status -eq 'FAIL'
        $f.Count | Should -Be 1
        $f.Severity | Should -Be 'Critical'
        $f.Evidence.Principal | Should -Match '1500'
    }
    It 'ADSA-ACL-002 is NOT_ASSESSED if the domain root ACL was not collected' {
        $r = Invoke-Acl -Targets @((New-Target 'AdminSDHolder' 'container' @()))
        (Get-TestResult $r 'ADSA-ACL-002').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'ADSA-ACL-003 flags a non-privileged owner and is NOT_ASSESSED without an owner' {
        $r = Invoke-Acl -Targets @((New-Target 'PrivilegedGroup' 'group' @() -Owner $script:attacker))
        (Get-TestResult $r 'ADSA-ACL-003').Status | Should -Be 'FAIL'
        $r2 = Invoke-Acl -Targets @((New-Target 'PrivilegedGroup' 'group' @() -Owner $null))
        (Get-TestResult $r2 'ADSA-ACL-003').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'ADSA-ACL-004 flags write rights on a GPO and ignores apply-only rights' {
        $gpo = [pscustomobject]@{ Id = 'g1'; DisplayName = 'Risky GPO'; LinkedTo = @(); Aces = @((New-TestAce -Sid $script:attacker -Rights 'GenericWrite'), (New-TestAce -Sid 'S-1-5-11' -Rights 'ExtendedRight' -ObjectType 'edacfd8f-ffb3-11d1-b41d-00a0c968f939')) }
        $r = Invoke-Acl -Targets @((New-Target 'DomainRoot' 'domainDNS' @())) -Gpos @($gpo)
        $f = Get-TestResult $r 'ADSA-ACL-004' | Where-Object Status -eq 'FAIL'
        $f.Count | Should -Be 1
        $f.AffectedObject | Should -Be 'Risky GPO'
    }
    It 'ADSA-ACL-004 is NOT_ASSESSED when the GPO ACL was not collected' {
        $gpo = [pscustomobject]@{ Id = 'g1'; DisplayName = 'No ACL'; LinkedTo = @() }
        $r = Invoke-Acl -Targets @() -Gpos @($gpo)
        (Get-TestResult $r 'ADSA-ACL-004').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'reports ERROR for all ACL rules when ACL collection was denied' {
        $snap = New-TestSnapshot -Sections @{ Acls = (New-TestSection -Status 'Error' -Error 'Access is denied' -Category 'AccessDenied'); Gpos = (New-TestSection -Status 'Error' -Error 'Access is denied' -Category 'AccessDenied') }
        $r = Invoke-TestAudit -Snapshot $snap -Module Acl
        @($r.Findings | Where-Object Status -eq 'ERROR').Count | Should -Be 4
        @($r.Findings | Where-Object Status -eq 'PASS').Count | Should -Be 0
    }
    It 'surfaces unread ACL targets in limitations' {
        $sec = [pscustomobject]@{ status = 'Collected'; data = @((New-Target 'DomainRoot' 'domainDNS' @())); error = ''; errorCategory = ''; warnings = @([pscustomobject]@{ target = 'CN=X'; category = 'AccessDenied'; message = 'denied' }) }
        $snap = New-TestSnapshot -Sections @{ Acls = $sec; Gpos = (New-TestSection -Data @()) }
        $r = Invoke-TestAudit -Snapshot $snap -Module Acl
        (Get-TestResult $r 'ADSA-ACL-001').Limitations | Should -Match '1 ACL target\(s\) could not be read'
        @($r.CollectionErrors | Where-Object Target -eq 'CN=X').Count | Should -Be 1
    }
}
