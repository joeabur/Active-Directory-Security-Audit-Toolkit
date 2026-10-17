BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')
    function Invoke-Acc($Users, $Computers = @(), $Config) {
        $snap = New-TestSnapshot -Sections @{ Users = (New-TestSection -Data $Users); Computers = (New-TestSection -Data $Computers) }
        Invoke-TestAudit -Snapshot $snap -Module AccountLifecycle -ConfigPath $Config
    }
}

Describe 'ADSA-ACC-001 stale users (inactivity thresholds)' {
    It 'flags an account just beyond the threshold and passes one exactly at it' {
        # reference time is 2026-10-01; 90 days before is 2026-07-03
        $over = New-TestUser -Sam 'over' -LastLogon '2026-07-02T00:00:00Z'
        $at = New-TestUser -Sam 'at' -LastLogon '2026-07-03T00:00:00Z'
        $r = Invoke-Acc -Users @($over, $at)
        $f = Get-TestResult $r 'ADSA-ACC-001'
        ($f | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be 'over'
        ($f | Where-Object Status -eq 'FAIL').Evidence.DaysSinceLastLogon | Should -Be 91
        ($f | Where-Object AffectedObject -eq 'at') | Should -BeNullOrEmpty
    }
    It 'honours a configured threshold' {
        $cfg = New-TestConfigFile '{ "thresholds": { "staleUserDays": 600 } }'
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'old' -LastLogon '2025-06-01T00:00:00Z')) -Config $cfg
        (Get-TestResult $r 'ADSA-ACC-001').Status | Should -Be 'PASS'
    }
    It 'does not flag disabled accounts and treats them as out of scope' {
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'dis' -Uac 514 -LastLogon '2020-01-01T00:00:00Z'))
        (Get-TestResult $r 'ADSA-ACC-001').Status | Should -Be 'NOT_APPLICABLE'
    }
    It 'is NOT_ASSESSED, never PASS, when lastLogonTimestamp was not retrieved' {
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'x' -Omit 'LastLogonTimestamp'))
        $f = Get-TestResult $r 'ADSA-ACC-001'
        $f.Status | Should -Be 'NOT_ASSESSED'
        $f.Explanation | Should -Match 'lastLogonTimestamp was not retrieved'
    }
    It 'reports a PASS with a limitation when only some objects lacked data' {
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'good'), (New-TestUser -Sam 'nodata' -Omit 'LastLogonTimestamp'))
        $f = Get-TestResult $r 'ADSA-ACC-001'
        $f.Status | Should -Be 'PASS'
        $f.Limitations | Should -Match '1 enabled user accounts could not be evaluated'
    }
    It 'classifies stale accounts as hygiene, not a confirmed vulnerability' {
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'old' -LastLogon '2020-01-01T00:00:00Z'))
        $f = Get-TestResult $r 'ADSA-ACC-001'
        $f.FindingType | Should -Be 'Hygiene'
        $f.Explanation | Should -Match 'not a confirmed vulnerability'
    }
}

Describe 'Other account lifecycle rules' {
    It 'ADSA-ACC-008 flags enabled accounts that never logged on beyond the grace period only' {
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'never' -LastLogon $null -Created '2026-01-01T00:00:00Z'), (New-TestUser -Sam 'fresh' -LastLogon $null -Created '2026-09-20T00:00:00Z'))
        $f = Get-TestResult $r 'ADSA-ACC-008'
        @($f | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be 'never'
    }
    It 'ADSA-ACC-003/005/006/007 detect their userAccountControl flags on enabled accounts only' {
        $users = @(
            (New-TestUser -Sam 'noexpire' -Uac 66048), (New-TestUser -Sam 'nopwd' -Uac 544), (New-TestUser -Sam 'nopreauth' -Uac (512 -bor 0x400000)),
            (New-TestUser -Sam 'des' -Uac (512 -bor 0x200000)), (New-TestUser -Sam 'rev' -Uac (512 -bor 0x80)), (New-TestUser -Sam 'disabled' -Uac (514 -bor 0x10000 -bor 0x20))
        )
        $r = Invoke-Acc -Users $users
        @((Get-TestResult $r 'ADSA-ACC-003') | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be @('noexpire')
        @((Get-TestResult $r 'ADSA-ACC-005') | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be @('nopwd')
        @((Get-TestResult $r 'ADSA-ACC-006') | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be @('nopreauth')
        @((Get-TestResult $r 'ADSA-ACC-007') | Where-Object Status -eq 'FAIL').AffectedObject | Should -Contain 'des'
        @((Get-TestResult $r 'ADSA-ACC-007') | Where-Object Status -eq 'FAIL').AffectedObject | Should -Contain 'rev'
    }
    It 'ADSA-ACC-004 flags an account whose manager is disabled and skips unresolvable managers' {
        $mgr = New-TestUser -Sam 'mgr' -Uac 514
        $r = Invoke-Acc -Users @($mgr, (New-TestUser -Sam 'orphan' -Manager (Get-TestUserDn 'mgr')), (New-TestUser -Sam 'ext' -Manager 'CN=Someone,DC=other'))
        $f = Get-TestResult $r 'ADSA-ACC-004'
        @($f | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be @('orphan')
        $f[0].Confidence | Should -Be 'Low'
    }
    It 'ADSA-SVC-001 flags old service-account passwords and ignores accounts without SPNs' {
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'svc_old' -Spn @('HTTP/a') -PwdSet '2023-01-01T00:00:00Z'), (New-TestUser -Sam 'svc_new' -Spn @('HTTP/b') -PwdSet '2026-08-01T00:00:00Z'), (New-TestUser -Sam 'plain' -PwdSet '2020-01-01T00:00:00Z'))
        @((Get-TestResult $r 'ADSA-SVC-001') | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be @('svc_old')
    }
    It 'ADSA-ACC-002 uses the later of logon and password change and excludes domain controllers' {
        $comps = @(
            (New-TestComputer -Sam 'OLD$' -LastLogon '2025-01-01T00:00:00Z' -PwdSet '2025-01-01T00:00:00Z'),
            (New-TestComputer -Sam 'RECENTPWD$' -LastLogon '2025-01-01T00:00:00Z' -PwdSet '2026-09-01T00:00:00Z'),
            (New-TestComputer -Sam 'DC$' -Uac 532480 -LastLogon '2020-01-01T00:00:00Z' -PwdSet '2020-01-01T00:00:00Z')
        )
        $r = Invoke-Acc -Users @() -Computers $comps
        @((Get-TestResult $r 'ADSA-ACC-002') | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be @('OLD$')
    }
    It 'ADSA-ACC-002 is NOT_ASSESSED when neither timestamp was retrieved' {
        $r = Invoke-Acc -Users @() -Computers @((New-TestComputer -Sam 'X$' -Omit 'LastLogonTimestamp', 'PasswordLastSet'))
        (Get-TestResult $r 'ADSA-ACC-002').Status | Should -Be 'NOT_ASSESSED'
    }
}

Describe 'Exclusions and exceptions' {
    It 'excludes matching objects, counts them, and documents the exclusion in limitations' {
        $cfg = New-TestConfigFile '{ "exclusions": [ { "pattern": "svc_*", "appliesTo": ["user"], "ruleIds": ["ADSA-ACC-003"], "reason": "gMSA migration tracked in CHG-1" } ] }'
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'svc_a' -Uac 66048), (New-TestUser -Sam 'human' -Uac 66048)) -Config $cfg
        $f = Get-TestResult $r 'ADSA-ACC-003'
        @($f | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be @('human')
        ($f | Where-Object Status -eq 'FAIL').Limitations | Should -Match '1 .* excluded'
    }
    It 'marks excepted findings without hiding or removing them' {
        $cfg = New-TestConfigFile '{ "exceptions": [ { "id": "EXC-1", "ruleId": "ADSA-ACC-003", "objectPattern": "svc_*", "reason": "vendor requirement", "owner": "app-team", "expires": "2099-01-01" } ] }'
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'svc_a' -Uac 66048)) -Config $cfg
        $f = Get-TestResult $r 'ADSA-ACC-003'
        $f.Status | Should -Be 'FAIL'
        $f.Excepted | Should -BeTrue
        $f.Exception.Id | Should -Be 'EXC-1'
        $r.Summary.ActiveFindings | Should -Be 0
        $r.Summary.ExceptedFindings | Should -Be 1
    }
    It 'does not apply an expired exception' {
        $cfg = New-TestConfigFile '{ "exceptions": [ { "id": "EXC-2", "ruleId": "ADSA-ACC-003", "objectPattern": "svc_*", "reason": "r", "owner": "o", "expires": "2026-09-30" } ] }'
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'svc_a' -Uac 66048)) -Config $cfg
        (Get-TestResult $r 'ADSA-ACC-003').Excepted | Should -BeFalse
        $r.Summary.ActiveFindings | Should -BeGreaterThan 0
    }
    It 'warns about exceptions that match nothing' {
        $cfg = New-TestConfigFile '{ "exceptions": [ { "id": "EXC-3", "ruleId": "ADSA-ACC-003", "objectPattern": "ghost*", "reason": "r", "owner": "o", "expires": "2099-01-01" } ] }'
        $r = Invoke-Acc -Users @((New-TestUser -Sam 'svc_a' -Uac 66048)) -Config $cfg
        ($r.Metadata.Warnings -join ' ') | Should -Match "EXC-3.*matched no finding"
    }
}

Describe 'Collection failures are never passes' {
    It 'turns an access-denied Users section into ERROR for every user rule' {
        $snap = New-TestSnapshot -Sections @{ Users = (New-TestSection -Status 'Error' -Error 'Access is denied.' -Category 'AccessDenied'); Computers = (New-TestSection -Data @()) }
        $r = Invoke-TestAudit -Snapshot $snap -Module AccountLifecycle
        foreach ($id in 'ADSA-ACC-001', 'ADSA-ACC-003', 'ADSA-ACC-005', 'ADSA-SVC-001') {
            $f = Get-TestResult $r $id
            $f.Status | Should -Be 'ERROR'
            $f.Evidence.ErrorCategory | Should -Be 'AccessDenied'
        }
        (Get-TestResult $r 'ADSA-ACC-002').Status | Should -Not -Be 'ERROR'
        @($r.Findings | Where-Object Status -eq 'PASS' | Where-Object RuleId -ne 'ADSA-ACC-002').Count | Should -Be 0
    }
    It 'turns a NotAssessed or missing section into NOT_ASSESSED' {
        $snap = New-TestSnapshot -Sections @{ Computers = (New-TestSection -Status 'NotAssessed' -Error 'skipped' -Category 'Skipped') }
        $r = Invoke-TestAudit -Snapshot $snap -Module AccountLifecycle
        (Get-TestResult $r 'ADSA-ACC-001').Status | Should -Be 'NOT_ASSESSED'
        (Get-TestResult $r 'ADSA-ACC-002').Status | Should -Be 'NOT_ASSESSED'
    }
}
