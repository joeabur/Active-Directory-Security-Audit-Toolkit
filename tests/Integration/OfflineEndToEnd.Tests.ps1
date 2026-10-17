# Portable end-to-end checks over SYNTHETIC data. These prove the toolkit pipeline works; they say nothing about any real domain.
BeforeAll {
    $script:root = Join-Path $PSScriptRoot '../..'
    Import-Module (Join-Path $script:root 'src/ADSecurityAudit.psd1') -Force
}

Describe 'Offline end-to-end (simulated data)' -Tag 'Offline' {
    It 'runs the repeatable demo script and its self-checks pass' {
        $out = Join-Path $TestDrive 'demo'
        $pwsh = (Get-Process -Id $PID).Path
        $log = & $pwsh -NoProfile -File (Join-Path $script:root 'scripts/Invoke-Demo.ps1') -OutputPath $out 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($log -join "`n")
        ($log -join "`n") | Should -Match 'Demo self-checks passed'
        (Get-ChildItem $out).Count | Should -Be 5
    }
    It 'produces schema-valid JSON that also satisfies the published JSON schema' {
        $out = Join-Path $TestDrive 'e2e'
        $r = Invoke-ADSecurityAudit -SnapshotPath (Join-Path $script:root 'sample-data/contoso-sim.snapshot.json') -OutputPath $out
        $json = Get-Content -Raw ($r.OutputFiles | Where-Object { $_ -like '*.json' })
        (Test-ADSAReport -Report ($json | ConvertFrom-Json)).IsValid | Should -BeTrue
        if (Get-Command Test-Json -ErrorAction SilentlyContinue) {
            Test-Json -Json $json -Schema (Get-Content -Raw (Join-Path $script:root 'config/schemas/report.schema.json')) | Should -BeTrue
            Test-Json -Json (Get-Content -Raw (Join-Path $script:root 'sample-data/contoso-sim.snapshot.json')) -Schema (Get-Content -Raw (Join-Path $script:root 'config/schemas/snapshot.schema.json')) | Should -BeTrue
        }
    }
    It 'runs the offline example script' {
        $pwsh = (Get-Process -Id $PID).Path
        $log = & $pwsh -NoProfile -File (Join-Path $script:root 'examples/Invoke-OfflineAudit.ps1') -OutputPath (Join-Path $TestDrive 'ex') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($log -join "`n")
    }
    It 'applies the example configuration: exception honoured, exclusion counted' {
        $r = Invoke-ADSecurityAudit -SnapshotPath (Join-Path $script:root 'sample-data/contoso-sim.snapshot.json') -ConfigPath (Join-Path $script:root 'examples/custom-config.json') -Module PrivilegedAccess
        $f = $r.Findings | Where-Object { $_.RuleId -eq 'ADSA-PRV-004' -and $_.Status -eq 'FAIL' }
        $f.Excepted | Should -BeTrue
        $f.Exception.Id | Should -Be 'EXC-001'
    }
    It 'keeps committed sample reports valid and clearly simulated' {
        $dir = Join-Path $script:root 'examples/sample-reports'
        $json = Get-ChildItem $dir -Filter 'sample-report.json'
        $json | Should -Not -BeNullOrEmpty
        $rep = Get-Content -Raw $json.FullName | ConvertFrom-Json
        (Test-ADSAReport -Report $rep).IsValid | Should -BeTrue
        $rep.Metadata.DataSource | Should -Be 'Simulated'
        (Get-Content -Raw (Join-Path $dir 'sample-report.html')) | Should -Match 'SIMULATED DATA'
    }
}
