BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')
    $script:goodPolicy = [pscustomobject]@{ MinPasswordLength = 14; PasswordHistoryCount = 24; ComplexityEnabled = $true; LockoutThreshold = 5; LockoutDurationMinutes = 30; LockoutObservationWindowMinutes = 30; ReversibleEncryptionEnabled = $false }
    function Invoke-Pol($Policy, $Users = @(), $DcHosts, $Config) {
        $sections = @{ PasswordPolicy = $(if ($null -ne $Policy) { New-TestSection -Data $Policy } else { New-TestSection -Data $null }); Users = (New-TestSection -Data $Users) }
        if ($null -ne $DcHosts) { $sections.DcHosts = $DcHosts }
        Invoke-TestAudit -Snapshot (New-TestSnapshot -Sections $sections) -Module AuthenticationPolicy -ConfigPath $Config
    }
    function Copy-Policy($Changes) { $p = [ordered]@{}; $script:goodPolicy.PSObject.Properties | ForEach-Object { $p[$_.Name] = $_.Value }; foreach ($k in $Changes.Keys) { $p[$k] = $Changes[$k] }; [pscustomobject]$p }
}

Describe 'Domain password and lockout policy' {
    It 'passes a compliant policy' {
        $r = Invoke-Pol -Policy $script:goodPolicy
        foreach ($i in 1..4 + 6) { (Get-TestResult $r ('ADSA-POL-00{0}' -f $i)).Status | Should -Be 'PASS' }
        (Get-TestResult $r 'ADSA-POL-005').Status | Should -Be 'PASS'
    }
    It 'fails weak settings with evidence' {
        $r = Invoke-Pol -Policy (Copy-Policy @{ MinPasswordLength = 8; ComplexityEnabled = $false; PasswordHistoryCount = 3; LockoutThreshold = 0; ReversibleEncryptionEnabled = $true })
        (Get-TestResult $r 'ADSA-POL-001').Evidence.MinPasswordLength | Should -Be 8
        foreach ($id in 'ADSA-POL-001', 'ADSA-POL-002', 'ADSA-POL-003', 'ADSA-POL-004', 'ADSA-POL-006') { (Get-TestResult $r $id).Status | Should -Be 'FAIL' }
        (Get-TestResult $r 'ADSA-POL-005').Status | Should -Be 'NOT_APPLICABLE'
    }
    It 'fails a lockout threshold above the configured maximum and a short lockout duration' {
        $r = Invoke-Pol -Policy (Copy-Policy @{ LockoutThreshold = 50; LockoutDurationMinutes = 5 })
        (Get-TestResult $r 'ADSA-POL-004').Status | Should -Be 'FAIL'
        (Get-TestResult $r 'ADSA-POL-005').Status | Should -Be 'FAIL'
    }
    It 'treats an administrator-unlock duration of 0 as compliant' {
        (Get-TestResult (Invoke-Pol -Policy (Copy-Policy @{ LockoutDurationMinutes = 0 })) 'ADSA-POL-005').Status | Should -Be 'PASS'
    }
    It 'honours configured baselines and a disabled complexity requirement' {
        $cfg = New-TestConfigFile '{ "passwordPolicy": { "minLength": 20, "complexityRequired": false } }'
        $r = Invoke-Pol -Policy (Copy-Policy @{ ComplexityEnabled = $false }) -Config $cfg
        (Get-TestResult $r 'ADSA-POL-001').Status | Should -Be 'FAIL'
        (Get-TestResult $r 'ADSA-POL-002').Status | Should -Be 'NOT_APPLICABLE'
    }
    It 'is NOT_ASSESSED when a policy property is missing' {
        $p = [pscustomobject]@{ MinPasswordLength = 14 }
        $r = Invoke-Pol -Policy $p
        (Get-TestResult $r 'ADSA-POL-001').Status | Should -Be 'PASS'
        (Get-TestResult $r 'ADSA-POL-003').Status | Should -Be 'NOT_ASSESSED'
        (Get-TestResult $r 'ADSA-POL-004').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'is ERROR when the policy cannot be read' {
        $snap = New-TestSnapshot -Sections @{ PasswordPolicy = (New-TestSection -Status 'Error' -ErrorText 'Insufficient access' -Category 'AccessDenied'); Users = (New-TestSection -Data @()) }
        $r = Invoke-TestAudit -Snapshot $snap -Module AuthenticationPolicy
        foreach ($i in 1..6) { (Get-TestResult $r ('ADSA-POL-00{0}' -f $i)).Status | Should -Be 'ERROR' }
    }
}

Describe 'krbtgt' {
    It 'fails an old krbtgt password and passes a recent one' {
        $old = New-TestUser -Sam 'krbtgt' -Rid 502 -Uac 514 -PwdSet '2022-01-01T00:00:00Z'
        (Get-TestResult (Invoke-Pol -Policy $script:goodPolicy -Users @($old)) 'ADSA-KRB-001').Status | Should -Be 'FAIL'
        $new = New-TestUser -Sam 'krbtgt' -Rid 502 -Uac 514 -PwdSet '2026-08-01T00:00:00Z'
        (Get-TestResult (Invoke-Pol -Policy $script:goodPolicy -Users @($new)) 'ADSA-KRB-001').Status | Should -Be 'PASS'
    }
    It 'is NOT_ASSESSED when krbtgt is not in the data' {
        (Get-TestResult (Invoke-Pol -Policy $script:goodPolicy -Users @()) 'ADSA-KRB-001').Status | Should -Be 'NOT_ASSESSED'
    }
}

Describe 'Per-DC settings' {
    BeforeAll {
        function New-Dc($Name, $Ldap, $Spooler = 'Stopped', $Entries, $Size = 4GB, [bool] $Reachable = $true, $Os = 'Windows Server 2022') {
            $dc = [ordered]@{ Name = $Name; HostName = "$Name.test.local"; OperatingSystem = $Os; Reachable = $Reachable; Error = ''; ErrorCategory = '' }
            if (-not $Reachable) { $dc.Error = 'WinRM cannot process the request'; $dc.ErrorCategory = 'Unreachable'; return [pscustomobject]$dc }
            $dc.Ldap = $Ldap
            $dc.Spooler = [pscustomobject]@{ Status = 'Collected'; State = $Spooler }
            $dc.AuditPolicy = [pscustomobject]@{ Status = 'Collected'; Entries = $Entries }
            $dc.SecurityLog = [pscustomobject]@{ Status = 'Collected'; MaximumSizeInBytes = [int64]$Size; LogMode = 'Circular' }
            [pscustomobject]$dc
        }
        function New-LdapSection($Integrity, $Binding) { [pscustomobject]@{ Status = 'Collected'; ServerIntegrity = $Integrity; ChannelBinding = $Binding } }
        function New-AuditEntries($Setting = 'Success and Failure') {
            @('0CCE923F-69AE-11D9-BED3-505054503030', '0CCE9242-69AE-11D9-BED3-505054503030', '0CCE9240-69AE-11D9-BED3-505054503030', '0CCE9235-69AE-11D9-BED3-505054503030', '0CCE9236-69AE-11D9-BED3-505054503030', '0CCE9237-69AE-11D9-BED3-505054503030', '0CCE923C-69AE-11D9-BED3-505054503030', '0CCE9215-69AE-11D9-BED3-505054503030', '0CCE921B-69AE-11D9-BED3-505054503030', '0CCE922F-69AE-11D9-BED3-505054503030') |
                ForEach-Object { [pscustomobject]@{ Guid = "{$_}"; Subcategory = 'x'; Setting = $Setting } }
        }
        function Invoke-Dc($Dcs) { Invoke-Pol -Policy $script:goodPolicy -DcHosts (New-TestSection -Data $Dcs) }
    }
    It 'passes a hardened DC' {
        $r = Invoke-Dc @((New-Dc 'dc1' (New-LdapSection 2 2) -Entries (New-AuditEntries)))
        foreach ($id in 'ADSA-LDAP-001', 'ADSA-LDAP-002', 'ADSA-DC-001', 'ADSA-AUD-001', 'ADSA-AUD-002') { (Get-TestResult $r $id).Status | Should -Be 'PASS' }
    }
    It 'fails weak LDAP signing, channel binding, spooler, audit and log size' {
        $r = Invoke-Dc @((New-Dc 'dc1' (New-LdapSection 1 0) 'Running' (New-AuditEntries 'No Auditing') -Size 20MB))
        foreach ($id in 'ADSA-LDAP-001', 'ADSA-LDAP-002', 'ADSA-DC-001', 'ADSA-AUD-001', 'ADSA-AUD-002') { (Get-TestResult $r $id).Status | Should -Be 'FAIL' }
        (Get-TestResult $r 'ADSA-AUD-001').Evidence.MissingCoverage.Count | Should -Be 10
    }
    It 'rates an unset LDAP signing value as lower confidence, and does not assert the 2025 default' {
        $r = Invoke-Dc @((New-Dc 'dc1' (New-LdapSection $null $null) -Entries (New-AuditEntries)))
        (Get-TestResult $r 'ADSA-LDAP-001').Confidence | Should -Be 'Medium'
        $r25 = Invoke-Dc @((New-Dc 'dc25' (New-LdapSection $null $null) -Entries (New-AuditEntries) -Os 'Windows Server 2025 Datacenter'))
        (Get-TestResult $r25 'ADSA-LDAP-001').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'treats channel binding "when supported" as a low-severity finding' {
        $r = Invoke-Dc @((New-Dc 'dc1' (New-LdapSection 2 1) -Entries (New-AuditEntries)))
        $f = Get-TestResult $r 'ADSA-LDAP-002'
        $f.Status | Should -Be 'FAIL'
        $f.Severity | Should -Be 'Low'
    }
    It 'evaluates reachable DCs and reports ERROR (not PASS) for unreachable ones' {
        $r = Invoke-Dc @((New-Dc 'dc1' (New-LdapSection 2 2) -Entries (New-AuditEntries)), (New-Dc 'dc2' $null -Reachable $false))
        $f = Get-TestResult $r 'ADSA-LDAP-001'
        ($f | Where-Object AffectedObject -eq 'dc2').Status | Should -Be 'ERROR'
        ($f | Where-Object AffectedObject -eq 'dc2').Evidence.ErrorCategory | Should -Be 'Unreachable'
        ($f | Where-Object Status -eq 'PASS').Limitations | Should -Match 'could not be queried'
        $cov = @($r.Coverage.Rules | Where-Object { $_.RuleId -eq 'ADSA-LDAP-001' })
        $cov[0].Partial | Should -BeTrue
        $cov[0].Status | Should -Be 'ERROR'
        @($r.CollectionErrors | Where-Object { $_.Source -eq 'DcHosts' -and $_.Target -eq 'dc2' }).Count | Should -Be 1
    }
    It 'reports NOT_ASSESSED when auditpol output is not understood (non-English)' {
        $r = Invoke-Dc @((New-Dc 'dc1' (New-LdapSection 2 2) -Entries (New-AuditEntries 'Erfolg und Fehler')))
        (Get-TestResult $r 'ADSA-AUD-001').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'reports ERROR when a DC sub-collection was denied but others succeeded' {
        $dc = New-Dc 'dc1' (New-LdapSection 2 2) -Entries (New-AuditEntries)
        $dc.AuditPolicy = [pscustomobject]@{ Status = 'Error'; Error = 'Access is denied'; ErrorCategory = 'AccessDenied' }
        $r = Invoke-Dc @($dc)
        (Get-TestResult $r 'ADSA-AUD-001').Status | Should -Be 'ERROR'
        (Get-TestResult $r 'ADSA-LDAP-001').Status | Should -Be 'PASS'
    }
    It 'is NOT_ASSESSED for all per-DC rules when host checks were skipped' {
        $r = Invoke-Pol -Policy $script:goodPolicy -DcHosts (New-TestSection -Status 'NotAssessed' -ErrorText 'skipped' -Category 'Skipped')
        foreach ($id in 'ADSA-LDAP-001', 'ADSA-LDAP-002', 'ADSA-DC-001', 'ADSA-AUD-001', 'ADSA-AUD-002') { (Get-TestResult $r $id).Status | Should -Be 'NOT_ASSESSED' }
    }
}
