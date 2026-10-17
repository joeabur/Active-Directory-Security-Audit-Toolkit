BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')
    $script:sample = Join-Path $PSScriptRoot '../../sample-data/contoso-sim.snapshot.json'
}

Describe 'Engine over the synthetic sample snapshot (simulated, offline)' {
    BeforeAll { $script:r = Invoke-ADSecurityAudit -SnapshotPath $script:sample }
    It 'labels the run as simulated offline analysis' {
        $r.Metadata.DataSource | Should -Be 'Simulated'
        $r.Metadata.AnalysisMode | Should -Be 'OfflineSnapshot'
        $r.Metadata.Notice | Should -Match 'SIMULATED'
        foreach ($f in $r.Findings) { $f.DataSource | Should -Be 'Simulated' }
    }
    It 'evaluates every catalog rule and produces a valid report' {
        $r.Coverage.Rules.Count | Should -Be (Get-ADSARuleCatalog).Count
        (Test-ADSAReport -Report $r).IsValid | Should -BeTrue
    }
    It 'produces all five result statuses' {
        foreach ($s in 'PASS', 'FAIL', 'ERROR', 'NOT_APPLICABLE', 'NOT_ASSESSED') { @($r.Findings | Where-Object Status -eq $s).Count | Should -BeGreaterThan 0 -Because "the sample should demonstrate $s" }
    }
    It 'finds the planted issues' {
        $expected = @{
            'ADSA-ACC-001' = 'carol.stale'; 'ADSA-ACC-002' = 'WS-OLD01$'; 'ADSA-ACC-003' = 'svc_sql'; 'ADSA-ACC-005' = 'grace.nopwd'; 'ADSA-ACC-006' = 'frank.preauth'
            'ADSA-ACC-007' = 'henry.des'; 'ADSA-ACC-008' = 'erin.nologon'; 'ADSA-ACC-004' = 'ivan.orphan'; 'ADSA-SVC-001' = 'svc_sql'
            'ADSA-PRV-002' = 'mike.staleadmin'; 'ADSA-PRV-004' = 'svc_backup'; 'ADSA-PRV-007' = 'IT-Admins'; 'ADSA-PRV-008' = 'kate.oldadmin'
            'ADSA-DEL-001' = 'svc_web'; 'ADSA-DEL-002' = 'svc_proto'; 'ADSA-DEL-003' = 'svc_proto'; 'ADSA-DEL-004' = 'DC02$'
            'ADSA-KRB-001' = 'krbtgt'; 'ADSA-INF-001' = 'DC02'; 'ADSA-INF-003' = 'partner.example.test'; 'ADSA-GPO-003' = 'Legacy Drive Mapping'
        }
        foreach ($id in $expected.Keys) { @($r.Findings | Where-Object { $_.RuleId -eq $id -and $_.Status -eq 'FAIL' }).AffectedObject | Should -Contain $expected[$id] -Because $id }
        (Get-TestResult $r 'ADSA-ACL-002' | Where-Object Status -eq 'FAIL').Evidence.Principal | Should -Match '1150'
    }
    It 'treats the unreachable DC as ERROR everywhere and as a collection error' {
        @($r.Findings | Where-Object { $_.AffectedObject -eq 'DC02' -and $_.Status -eq 'ERROR' }).Count | Should -Be 5
        @($r.CollectionErrors | Where-Object Target -eq 'DC02').Count | Should -Be 1
        @($r.CollectionErrors | Where-Object { $_.Source -eq 'FineGrainedPolicies' -and $_.Category -eq 'AccessDenied' }).Count | Should -Be 1
    }
    It 'counts only non-excepted FAIL results in the severity summary' {
        $r.Summary.ActiveFindings | Should -Be @($r.Findings | Where-Object { $_.Status -eq 'FAIL' -and -not $_.Excepted }).Count
        ($r.Summary.ActiveFindingsBySeverity.PSObject.Properties.Value | Measure-Object -Sum).Sum | Should -Be $r.Summary.ActiveFindings
    }
    It 'sorts FAIL results before everything else, most severe first' {
        $r.Findings[0].Status | Should -Be 'FAIL'
        $r.Findings[0].Severity | Should -Be 'Critical'
    }
    It 'includes inventories' {
        @($r.Inventories.PrivilegedGroups).Count | Should -BeGreaterThan 3
        @($r.Inventories.ServiceAccounts | Where-Object SamAccountName -eq 'svc_backup').Privileged | Should -BeTrue
        @($r.Inventories.DomainControllers).Count | Should -Be 3
    }
}

Describe 'Engine safeguards' {
    It 'reports ERROR for every rule of a module that crashes and keeps other modules running' {
        Mock -ModuleName ADSecurityAudit Invoke-ADSAAclAudit { throw 'boom' }
        $r = Invoke-ADSecurityAudit -SnapshotPath $script:sample -Module Acl, Delegation
        @($r.Findings | Where-Object { $_.Module -eq 'Acl' -and $_.Status -ne 'ERROR' }).Count | Should -Be 0
        (Get-TestResult $r 'ADSA-ACL-001').Explanation | Should -Match 'boom'
        @($r.Findings | Where-Object { $_.Module -eq 'Delegation' -and $_.Status -eq 'FAIL' }).Count | Should -BeGreaterThan 0
    }
    It 'reports ERROR when a module silently returns no result for a rule' {
        Mock -ModuleName ADSecurityAudit Invoke-ADSAInfrastructureAudit { }
        $r = Invoke-ADSecurityAudit -SnapshotPath $script:sample -Module Infrastructure
        @($r.Findings | Where-Object Status -eq 'ERROR').Count | Should -Be 4
        @($r.Findings | Where-Object Status -eq 'PASS').Count | Should -Be 0
    }
    It 'marks rules from unselected modules NOT_ASSESSED in coverage' {
        $r = Invoke-ADSecurityAudit -SnapshotPath $script:sample -Module Infrastructure
        ($r.Coverage.Rules | Where-Object RuleId -eq 'ADSA-ACC-001').Status | Should -Be 'NOT_ASSESSED'
        ($r.Coverage.Rules | Where-Object RuleId -eq 'ADSA-ACC-001').Note | Should -Match 'not selected'
        @($r.Findings | Where-Object Module -eq 'AccountLifecycle').Count | Should -Be 0
    }
    It 'rejects a malformed or incomplete snapshot' {
        $bad = Join-Path $TestDrive 'bad.json'
        Set-Content -LiteralPath $bad -Value '{ not json'
        { Invoke-ADSecurityAudit -SnapshotPath $bad } | Should -Throw '*not valid JSON*'
        Set-Content -LiteralPath $bad -Value '{ "schemaVersion": "9.0", "dataSource": "Maybe" }'
        { Invoke-ADSecurityAudit -SnapshotPath $bad } | Should -Throw '*invalid*'
        { Invoke-ADSecurityAudit -SnapshotPath (Join-Path $TestDrive 'missing.json') } | Should -Throw '*not found*'
    }
    It 'validates the output path before doing any work' {
        { Invoke-ADSecurityAudit -SnapshotPath $script:sample -OutputPath (Join-Path $PSScriptRoot '../../src') } | Should -Throw '*tracked repository folder*'
    }
    It 'throws on an invalid configuration file' {
        $cfg = New-TestConfigFile '{ "thresholds": { "staleUserDays": -5 } }'
        { Invoke-ADSecurityAudit -SnapshotPath $script:sample -ConfigPath $cfg } | Should -Throw '*Configuration is invalid*'
    }
    It 'writes all three report formats when OutputPath is given' {
        $r = Invoke-ADSecurityAudit -SnapshotPath $script:sample -OutputPath (Join-Path $TestDrive 'engine-out')
        $r.OutputFiles.Count | Should -Be 3
        foreach ($f in $r.OutputFiles) { Test-Path -LiteralPath $f | Should -BeTrue }
        (Test-ADSAReport -Path ($r.OutputFiles | Where-Object { $_ -like '*.json' })).IsValid | Should -BeTrue
    }
    It 'degrades gracefully when the ActiveDirectory module is absent (live mode on a non-domain host)' {
        Mock -ModuleName ADSecurityAudit Get-Command { $null } -ParameterFilter { $Name -eq 'Get-ADDomain' }
        $r = Invoke-ADSecurityAudit -Server 'dc.invalid.test' -Module AccountLifecycle, Acl
        @($r.Findings | Where-Object Status -in 'PASS', 'FAIL').Count | Should -Be 0
        @($r.CollectionErrors | Where-Object Category -eq 'ModuleUnavailable').Count | Should -BeGreaterThan 0
        $r.Metadata.AnalysisMode | Should -Be 'LiveCollection'
    }
}

Describe 'Snapshot import and export' {
    It 'round-trips a snapshot through Export-ADSASnapshot / Import-ADSASnapshot' {
        $s = Import-ADSASnapshot -Path $script:sample
        $file = Export-ADSASnapshot -Snapshot $s -OutputPath (Join-Path $TestDrive 'snap') -FileName 'x.snapshot.json'
        $back = Import-ADSASnapshot -Path $file.FullName
        $back.domain.name | Should -Be $s.domain.name
        $back.dataSource | Should -Be 'Simulated'
    }
    It 'refuses file names with path separators' {
        $s = Import-ADSASnapshot -Path $script:sample
        { Export-ADSASnapshot -Snapshot $s -OutputPath $TestDrive -FileName '../x.json' } | Should -Throw '*plain file name*'
    }
}

Describe 'Prerequisite check' {
    It 'reports offline readiness without changing anything' {
        $p = Test-ADSAPrerequisite
        $p.OfflineReady | Should -BeTrue
        @($p.Checks).Count | Should -BeGreaterThan 3
    }
}
