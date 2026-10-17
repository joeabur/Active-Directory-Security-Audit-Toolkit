BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    $script:catalog = Get-ADSARuleCatalog
    $script:moduleText = (Get-ChildItem (Join-Path $PSScriptRoot '../../src/Modules') -Filter '*.ps1' | ForEach-Object { Get-Content -Raw $_.FullName }) -join "`n"
}

Describe 'Rule catalog integrity (no placeholder rules)' {
    It 'has unique, well-formed, stable rule IDs' {
        $ids = $script:catalog.Id
        $ids.Count | Should -Be (@($ids | Sort-Object -Unique).Count)
        foreach ($id in $ids) { $id | Should -Match '^ADSA-(ACC|SVC|PRV|DEL|ACL|POL|KRB|LDAP|DC|AUD|INF|GPO)-\d{3}$' }
    }
    It 'defines every required metadata field with real content' {
        foreach ($r in $script:catalog) {
            foreach ($f in 'Title', 'Category', 'Module', 'Severity', 'Confidence', 'FindingType', 'Description', 'Remediation', 'Limitations', 'RequiredData', 'Permissions') {
                "$($r.$f)".Trim().Length | Should -BeGreaterOrEqual 3 -Because "$($r.Id).$f"
            }
            $r.Severity | Should -BeIn 'Critical', 'High', 'Medium', 'Low', 'Informational'
            $r.Confidence | Should -BeIn 'High', 'Medium', 'Low'
            $r.FindingType | Should -BeIn 'Hygiene', 'Misconfiguration', 'PotentialRisk', 'Informational'
            $r.Description | Should -Not -Match '(?i)\b(todo|tbd|placeholder|lorem)\b' -Because $r.Id
        }
    }
    It 'implements every catalog rule in module code' {
        foreach ($r in $script:catalog) { $script:moduleText | Should -Match ([regex]::Escape("'$($r.Id)'")) -Because "$($r.Id) must be referenced by an audit module" }
    }
    It 'catalogs every rule ID referenced by module code' {
        $referenced = [regex]::Matches($script:moduleText, "'(ADSA-[A-Z]+-\d{3})'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        foreach ($id in $referenced) { $script:catalog.Id | Should -Contain $id }
    }
    It 'assigns each rule to a registered module' {
        $modules = InModuleScope ADSecurityAudit { Get-ADSAModuleName }
        foreach ($r in $script:catalog) { $r.Module | Should -BeIn $modules }
    }
    It 'documents stale-account rules as hygiene, not vulnerabilities' {
        foreach ($id in 'ADSA-ACC-001', 'ADSA-ACC-002', 'ADSA-ACC-008') {
            $r = $script:catalog | Where-Object Id -eq $id
            $r.FindingType | Should -Be 'Hygiene'
            $r.Description | Should -Match 'not a confirmed vulnerability'
        }
    }
    It 'filters by module and id' {
        (Get-ADSARuleCatalog -Module Acl).Count | Should -Be 4
        (Get-ADSARuleCatalog -Id 'ADSA-DEL-*').Count | Should -Be 4
    }
}
