BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')
    function Invoke-Prv($Users, $Groups, $Config) {
        $snap = New-TestSnapshot -Sections @{ Users = (New-TestSection -Data $Users); Groups = (New-TestSection -Data $Groups); Computers = (New-TestSection -Data @()) }
        Invoke-TestAudit -Snapshot $snap -Module PrivilegedAccess -ConfigPath $Config
    }
    $script:da = "$script:TestDomainSid-512"
}

Describe 'Privileged access' {
    It 'counts nested members toward the group maximum' {
        $users = 1..7 | ForEach-Object { New-TestUser -Sam "u$_" -Rid (1200 + $_) }
        $inner = New-TestGroup -Name 'Inner' -Sid "$script:TestDomainSid-2001" -Members @(1..7 | ForEach-Object { Get-TestUserDn "u$_" })
        $da = New-TestGroup -Name 'Domain Admins' -Sid $script:da -Members @((Get-TestGroupDn 'Inner'))
        $r = Invoke-Prv -Users $users -Groups @($da, $inner)
        $f = Get-TestResult $r 'ADSA-PRV-001' | Where-Object Status -eq 'FAIL'
        $f.AffectedObject | Should -Be 'Domain Admins'
        $f.Evidence.EffectiveMemberCount | Should -Be 7
        $f.Evidence.Maximum | Should -Be 5
        $f.Evidence.NestedGroupCount | Should -Be 1
    }
    It 'reports disabled and stale privileged accounts with different severities' {
        $users = @((New-TestUser -Sam 'dis' -Uac 514), (New-TestUser -Sam 'stale' -LastLogon '2025-01-01T00:00:00Z'), (New-TestUser -Sam 'ok'))
        $da = New-TestGroup -Name 'Domain Admins' -Sid $script:da -Members @($users | ForEach-Object { $_.DistinguishedName })
        $r = Invoke-Prv -Users $users -Groups @($da)
        $f = Get-TestResult $r 'ADSA-PRV-002' | Where-Object Status -eq 'FAIL'
        ($f | Where-Object AffectedObject -eq 'dis').Severity | Should -Be 'Low'
        ($f | Where-Object AffectedObject -eq 'stale').Severity | Should -Be 'High'
        ($f | Where-Object AffectedObject -eq 'ok') | Should -BeNullOrEmpty
    }
    It 'reports never-expiring passwords, SPNs, and non-sensitive privileged accounts' {
        $u = New-TestUser -Sam 'svcadm' -Uac 66048 -Spn @('MSSQLSvc/x')
        $safe = New-TestUser -Sam 'safe' -Uac (512 -bor 0x100000)
        $da = New-TestGroup -Name 'Domain Admins' -Sid $script:da -Members @($u.DistinguishedName, $safe.DistinguishedName)
        $r = Invoke-Prv -Users @($u, $safe) -Groups @($da)
        (Get-TestResult $r 'ADSA-PRV-003' | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be 'svcadm'
        (Get-TestResult $r 'ADSA-PRV-004' | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be 'svcadm'
        (Get-TestResult $r 'ADSA-PRV-006' | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be 'svcadm'
    }
    It 'names the nested path in the evidence' {
        $u = New-TestUser -Sam 'deep' -Uac 66048
        $inner = New-TestGroup -Name 'Inner' -Sid "$script:TestDomainSid-2001" -Members @($u.DistinguishedName)
        $da = New-TestGroup -Name 'Domain Admins' -Sid $script:da -Members @((Get-TestGroupDn 'Inner'))
        $r = Invoke-Prv -Users @($u) -Groups @($da, $inner)
        (Get-TestResult $r 'ADSA-PRV-003' | Where-Object Status -eq 'FAIL').Evidence.Groups | Should -Match 'nested via Inner'
    }
    It 'detects a cycle among privileged groups' {
        $a = New-TestGroup -Name 'Domain Admins' -Sid $script:da -Members @((Get-TestGroupDn 'B'))
        $b = New-TestGroup -Name 'B' -Sid "$script:TestDomainSid-2002" -Members @((Get-TestGroupDn 'Domain Admins'))
        $r = Invoke-Prv -Users @() -Groups @($a, $b)
        $f = Get-TestResult $r 'ADSA-PRV-007' | Where-Object Status -eq 'FAIL'
        $f.Count | Should -Be 1
        $f.Evidence.Cycle.Count | Should -Be 3
    }
    It 'flags a populated Schema Admins group' {
        $u = New-TestUser -Sam 'schema'
        $sa = New-TestGroup -Name 'Schema Admins' -Sid "$script:TestDomainSid-518" -Members @($u.DistinguishedName)
        $r = Invoke-Prv -Users @($u) -Groups @($sa)
        (Get-TestResult $r 'ADSA-PRV-005').Status | Should -Be 'FAIL'
    }
    It 'flags adminCount=1 accounts that are no longer privileged but not krbtgt' {
        $orph = New-TestUser -Sam 'orph' -AdminCount 1
        $krb = New-TestUser -Sam 'krbtgt' -Rid 502 -AdminCount 1 -Uac 514
        $inGroup = New-TestUser -Sam 'inGroup' -AdminCount 1
        $da = New-TestGroup -Name 'Domain Admins' -Sid $script:da -Members @($inGroup.DistinguishedName)
        $r = Invoke-Prv -Users @($orph, $krb, $inGroup) -Groups @($da)
        @((Get-TestResult $r 'ADSA-PRV-008') | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be @('orph')
    }
    It 'is NOT_ASSESSED when adminCount was not retrieved' {
        $u = New-TestUser -Sam 'x' -Omit 'AdminCount'
        $da = New-TestGroup -Name 'Domain Admins' -Sid $script:da -Members @()
        $r = Invoke-Prv -Users @($u) -Groups @($da)
        (Get-TestResult $r 'ADSA-PRV-008').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'is NOT_ASSESSED when none of the configured groups exist in the data' {
        $r = Invoke-Prv -Users @() -Groups @((New-TestGroup -Name 'Other' -Sid "$script:TestDomainSid-4000"))
        @($r.Findings | Where-Object Status -eq 'NOT_ASSESSED').Count | Should -Be 8
        @($r.Findings | Where-Object Status -eq 'PASS').Count | Should -Be 0
    }
    It 'is ERROR for every rule when the Groups section failed (permission failure)' {
        $snap = New-TestSnapshot -Sections @{ Users = (New-TestSection -Data @()); Groups = (New-TestSection -Status 'Error' -ErrorText 'Insufficient access rights' -Category 'AccessDenied') }
        $r = Invoke-TestAudit -Snapshot $snap -Module PrivilegedAccess
        @($r.Findings | Where-Object Status -eq 'ERROR').Count | Should -Be 8
    }
    It 'supports a documented exception for a privileged service account' {
        $u = New-TestUser -Sam 'svc_priv' -Spn @('x/y')
        $da = New-TestGroup -Name 'Domain Admins' -Sid $script:da -Members @($u.DistinguishedName)
        $cfg = New-TestConfigFile '{ "exceptions": [ { "id": "PRIV-1", "ruleId": "ADSA-PRV-004", "objectPattern": "svc_priv", "reason": "backup agent requires it", "owner": "backup-team", "approvedBy": "CISO", "expires": "2099-12-31" } ] }'
        $r = Invoke-Prv -Users @($u) -Groups @($da) -Config $cfg
        $f = Get-TestResult $r 'ADSA-PRV-004' | Where-Object Status -eq 'FAIL'
        $f.Excepted | Should -BeTrue
        $f.Exception.ApprovedBy | Should -Be 'CISO'
    }
    It 'ADSA-PRV-006 treats Protected Users members (direct or nested) as compliant' {
        $direct = New-TestUser -Sam 'protectedDirect' -Rid 1301
        $nested = New-TestUser -Sam 'protectedNested' -Rid 1302
        $exposed = New-TestUser -Sam 'exposed' -Rid 1303
        $inner = New-TestGroup -Name 'InnerPU' -Sid "$script:TestDomainSid-2101" -Members @($nested.DistinguishedName)
        $pu = New-TestGroup -Name 'Protected Users' -Sid "$script:TestDomainSid-525" -Members @($direct.DistinguishedName, (Get-TestGroupDn 'InnerPU'))
        $da = New-TestGroup -Name 'Domain Admins' -Sid $script:da -Members @($direct.DistinguishedName, $nested.DistinguishedName, $exposed.DistinguishedName)
        $r = Invoke-Prv -Users @($direct, $nested, $exposed) -Groups @($da, $pu, $inner)
        @((Get-TestResult $r 'ADSA-PRV-006') | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be @('exposed')
    }
    It 'ADSA-PRV-001 is NOT_ASSESSED for a privileged group whose member list was not collected' {
        $da = New-TestGroup -Name 'Domain Admins' -Sid $script:da -Members @()
        $da | Add-Member -NotePropertyName MembersCollected -NotePropertyValue $false
        $r = Invoke-Prv -Users @() -Groups @($da)
        (Get-TestResult $r 'ADSA-PRV-001').Status | Should -Be 'NOT_ASSESSED'
    }
}
