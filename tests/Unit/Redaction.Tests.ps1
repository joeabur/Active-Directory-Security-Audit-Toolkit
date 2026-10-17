BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')
    $script:sample = Join-Path $PSScriptRoot '../../sample-data/contoso-sim.snapshot.json'
    $script:report = Invoke-ADSecurityAudit -SnapshotPath $script:sample
}

Describe 'Report redaction' {
    It 'removes account, host, GPO and domain names from the serialised report but keeps rule content' {
        $red = Invoke-ADSecurityAudit -SnapshotPath $script:sample -Redact -RedactionSalt 'unit-test'
        $json = $red | ConvertTo-Json -Depth 12
        foreach ($name in 'carol.stale', 'svc_sql', 'svc_backup', 'mike.staleadmin', 'contoso-sim', 'Legacy Drive Mapping', 'IT-Admins', 'dc01', 'DC02', 'WS-OLD01', 'partner.example.test') {
            $json | Should -Not -Match ([regex]::Escape($name)) -Because "$name must be pseudonymised"
        }
        $json | Should -Match 'redacted-[0-9a-f]{8}'
        $json | Should -Not -Match 'S-1-5-21-1004336348'
        $red.Metadata.Redacted | Should -BeTrue
        $red.Metadata.Notice | Should -Match 'pseudonymised'
    }
    It 'keeps the structure, counts, well-known names and rule metadata intact' {
        $red = Invoke-ADSecurityAudit -SnapshotPath $script:sample -Redact -RedactionSalt 'unit-test'
        $red.Findings.Count | Should -Be $script:report.Findings.Count
        $red.Summary.ActiveFindings | Should -Be $script:report.Summary.ActiveFindings
        ($red.Findings | Where-Object RuleId -eq 'ADSA-PRV-005').AffectedObject | Should -Be 'Schema Admins'
        ($red.Findings | Where-Object RuleId -eq 'ADSA-KRB-001' | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be 'krbtgt'
        ($red.Findings | Where-Object RuleId -eq 'ADSA-ACC-001')[0].Remediation | Should -Be ($script:report.Findings | Where-Object RuleId -eq 'ADSA-ACC-001')[0].Remediation
        (Test-ADSAReport -Report $red).IsValid | Should -BeTrue
    }
    It 'is deterministic for the same salt and different for another salt' {
        $a = Invoke-ADSecurityAudit -SnapshotPath $script:sample -Redact -RedactionSalt 's1'
        $b = Invoke-ADSecurityAudit -SnapshotPath $script:sample -Redact -RedactionSalt 's1'
        $c = Invoke-ADSecurityAudit -SnapshotPath $script:sample -Redact -RedactionSalt 's2'
        ($a.Findings | Where-Object RuleId -eq 'ADSA-ACC-001')[0].AffectedObject | Should -Be ($b.Findings | Where-Object RuleId -eq 'ADSA-ACC-001')[0].AffectedObject
        ($a.Findings | Where-Object RuleId -eq 'ADSA-ACC-001')[0].AffectedObject | Should -Not -Be ($c.Findings | Where-Object RuleId -eq 'ADSA-ACC-001')[0].AffectedObject
    }
    It 'uses the same token for the same name everywhere' {
        $red = Invoke-ADSecurityAudit -SnapshotPath $script:sample -Redact -RedactionSalt 'x'
        $f = $red.Findings | Where-Object { $_.RuleId -eq 'ADSA-SVC-001' -and $_.Status -eq 'FAIL' } | Select-Object -First 1
        $f.Evidence.DistinguishedName | Should -Match ([regex]::Escape($f.AffectedObject))
    }
    It 'does not alter the original report object' {
        $null = Invoke-ADSecurityAudit -SnapshotPath $script:sample -Redact -RedactionSalt 'x'
        ($script:report | ConvertTo-Json -Depth 12) | Should -Match 'carol.stale'
    }
    It 'writes redacted files through Export-ADSAReport -Redact' {
        $files = Export-ADSAReport -Report $script:report -OutputPath (Join-Path $TestDrive 'red') -Redact -RedactionSalt 'x'
        foreach ($f in $files) { (Get-Content -Raw $f.FullName) | Should -Not -Match 'carol\.stale' }
        (Get-Content -Raw ($files | Where-Object Extension -eq '.html').FullName) | Should -Match 'redacted-'
    }
}
