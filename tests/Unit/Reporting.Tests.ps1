BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')
    $script:xss = '<script>alert(1)</script>'
    $script:payloads = @($script:xss, '"><img src=x onerror=alert(2)>', "'; DROP TABLE x;--", '</td><td onclick="evil()">', '&lt;already&gt;', '{{7*7}}', '<svg/onload=alert(3)>')

    function New-HostileReport {
        $users = @(
            (New-TestUser -Sam $script:xss -Uac 66048),
            (New-TestUser -Sam '=HYPERLINK("http://evil","click")' -Uac 66048 -Rid 1101),
            (New-TestUser -Sam '"><img src=x onerror=alert(2)>' -Uac 66048 -Rid 1102),
            (New-TestUser -Sam '+cmd|calc' -Uac 66048 -Rid 1103),
            (New-TestUser -Sam '@SUM(1)' -Uac 66048 -Rid 1104)
        )
        $snap = New-TestSnapshot -Sections @{ Users = (New-TestSection -Data $users); Computers = (New-TestSection -Data @()) }
        $snap.domain.name = '<svg/onload=alert(3)>'
        Invoke-TestAudit -Snapshot $snap -Module AccountLifecycle
    }
}

Describe 'HTML report escaping' {
    BeforeAll {
        $script:report = New-HostileReport
        $script:html = InModuleScope ADSecurityAudit -Parameters @{ R = $script:report } { param($R) ConvertTo-ADSAHtmlReport -Report $R }
    }
    It 'contains no executable markup from data' {
        $script:html | Should -Not -Match '<script'
        $allowed = 'html', 'head', 'meta', 'title', 'style', 'body', 'h1', 'h2', 'h3', 'div', 'p', 'strong', 'em', 'span', 'details', 'summary', 'table', 'tr', 'th', 'td', 'dl', 'dt', 'dd', 'ul', 'li', 'b'
        $tags = [regex]::Matches($script:html, '<\s*([A-Za-z][A-Za-z0-9]*)') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } | Sort-Object -Unique
        foreach ($t in $tags) { $t | Should -BeIn $allowed -Because "tag <$t> is not part of the report template" }
        # no real tag carries an event-handler attribute
        $script:html | Should -Not -Match '<[^>]*\son[a-z]+\s*='
    }
    It 'contains the encoded form of hostile values so they remain visible to the analyst' {
        $script:html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $script:html | Should -Match '&quot;&gt;&lt;img src=x onerror=alert\(2\)&gt;'
    }
    It 'sets a restrictive Content-Security-Policy and uses no external resources or scripts' {
        $script:html | Should -Match "Content-Security-Policy"
        $script:html | Should -Match "default-src 'none'"
        $script:html | Should -Not -Match '(?i)(src|href)\s*=\s*"https?:'
        $script:html | Should -Not -Match '(?i)<link '
    }
    It 'labels simulated data prominently' {
        $script:html | Should -Match 'SIMULATED DATA'
        $script:html | Should -Match 'Data source: Simulated'
    }
    It 'only emits whitelisted css class tokens' {
        $classes = [regex]::Matches($script:html, 'class="((?:sev|st)-[^"]*)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        foreach ($c in $classes) { $c | Should -Match '^(sev-(critical|high|medium|low|informational|unknown)|st-(fail|pass|error|not-assessed|not-applicable|unknown))$' }
    }
    It 'escapes a hostile severity token rather than using it as a class' {
        InModuleScope ADSecurityAudit {
            Get-ADSASafeToken -Value '"><script>' -Allowed @('High', 'Low') | Should -Be 'unknown'
            Get-ADSASafeToken -Value 'High' -Allowed @('High', 'Low') | Should -Be 'high'
        }
    }
}

Describe 'CSV report' {
    BeforeAll {
        $script:csv = InModuleScope ADSecurityAudit -Parameters @{ R = (New-HostileReport) } { param($R) ConvertTo-ADSACsvReport -Report $R }
        $script:rows = $script:csv | ConvertFrom-Csv
    }
    It 'neutralises formula injection in every cell' {
        foreach ($row in $script:rows) { foreach ($p in $row.PSObject.Properties) { if ($p.Value) { $p.Value | Should -Not -Match '^[=+\-@]' } } }
        ($script:rows | Where-Object AffectedObject -like "*HYPERLINK*").AffectedObject | Should -Match '^''='
    }
    It 'contains one row per finding with all required columns' {
        $script:rows.Count | Should -BeGreaterThan 5
        foreach ($c in 'RuleId', 'Status', 'Severity', 'AffectedObject', 'Evidence', 'Explanation', 'Confidence', 'Remediation', 'CollectionTime', 'Limitations') { $script:rows[0].PSObject.Properties.Name | Should -Contain $c }
    }
    It 'emits a header for an empty report' {
        InModuleScope ADSecurityAudit {
            (ConvertTo-ADSACsvReport -Report ([pscustomobject]@{ Findings = @() })) | Should -Match '^RuleId,Status'
        }
    }
}

Describe 'JSON report and schema' {
    BeforeAll { $script:rep = New-HostileReport }
    It 'round-trips as valid JSON and passes structural validation' {
        $json = InModuleScope ADSecurityAudit -Parameters @{ R = $script:rep } { param($R) ConvertTo-ADSAJsonReport -Report $R }
        $back = $json | ConvertFrom-Json
        $back.Findings.Count | Should -Be $script:rep.Findings.Count
        (Test-ADSAReport -Report $back).IsValid | Should -BeTrue
        $back.Findings[0].PSObject.Properties.Name | Should -Contain 'Evidence'
    }
    It 'validates against the published JSON schema when Test-Json is available' -Skip:(-not (Get-Command Test-Json -ErrorAction SilentlyContinue)) {
        $json = InModuleScope ADSecurityAudit -Parameters @{ R = $script:rep } { param($R) ConvertTo-ADSAJsonReport -Report $R }
        $schema = Get-Content -Raw (Join-Path $PSScriptRoot '../../config/schemas/report.schema.json')
        Test-Json -Json $json -Schema $schema | Should -BeTrue
    }
    It 'rejects a report with a missing or invalid field' {
        $bad = $script:rep | ConvertTo-Json -Depth 12 | ConvertFrom-Json
        $bad.Findings[0].Status = 'MAYBE'
        $bad.Findings[1].PSObject.Properties.Remove('Remediation')
        $r = Test-ADSAReport -Report $bad
        $r.IsValid | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match "Status 'MAYBE'"
        ($r.Errors -join ' ') | Should -Match "missing 'Remediation'"
    }
    It 'every finding carries the mandatory fields' {
        foreach ($f in $script:rep.Findings) {
            foreach ($k in 'RuleId', 'Severity', 'AffectedObject', 'Evidence', 'Explanation', 'Confidence', 'Remediation', 'CollectionTime', 'Limitations') {
                $f.PSObject.Properties.Name | Should -Contain $k
                if ($k -ne 'Evidence' -and $f.Status -ne 'PASS') { "$($f.$k)" | Should -Not -BeNullOrEmpty -Because "$($f.RuleId) must provide $k" }
            }
        }
    }
}

Describe 'Export-ADSAReport' {
    It 'writes json, csv and html files to a validated directory and labels simulated output' {
        $rep = New-HostileReport
        $files = Export-ADSAReport -Report $rep -OutputPath (Join-Path $TestDrive 'out')
        $files.Count | Should -Be 3
        $files.Name | Should -Match '^SIMULATED-ADSA-report-'
        ($files.Extension | Sort-Object) | Should -Be @('.csv', '.html', '.json')
        foreach ($f in $files) { $f.Length | Should -BeGreaterThan 100 }
        if ($IsLinux -or $IsMacOS) { [System.IO.File]::GetUnixFileMode($files[0].FullName) | Should -Be ([System.IO.UnixFileMode]'UserRead, UserWrite') }
    }
    It 'rejects path-like base names and tracked repository folders' {
        $rep = New-HostileReport
        { Export-ADSAReport -Report $rep -OutputPath $TestDrive -BaseName '../escape' } | Should -Throw '*plain file name*'
        { Export-ADSAReport -Report $rep -OutputPath (Join-Path $PSScriptRoot '../../docs') } | Should -Throw '*tracked repository folder*'
    }
    It 'refuses to export a report that fails schema validation' {
        $bad = New-HostileReport
        $bad.Findings[0].Status = 'MAYBE'
        { Export-ADSAReport -Report $bad -OutputPath (Join-Path $TestDrive 'bad') } | Should -Throw '*schema validation*'
    }
    It 'exports only the requested formats' {
        $files = Export-ADSAReport -Report (New-HostileReport) -OutputPath (Join-Path $TestDrive 'one') -Format Json
        $files.Count | Should -Be 1
    }
}

Describe 'HTML report structure' {
    It 'groups findings by rule and shows a top-priorities table' {
        $users = 1..30 | ForEach-Object { New-TestUser -Sam "svc$_" -Rid (2000 + $_) -Uac 66048 }
        $snap = New-TestSnapshot -Sections @{ Users = (New-TestSection -Data $users); Computers = (New-TestSection -Data @()) }
        $rep = Invoke-TestAudit -Snapshot $snap -Module AccountLifecycle
        $html = InModuleScope ADSecurityAudit -Parameters @{ R = $rep } { param($R) ConvertTo-ADSAHtmlReport -Report $R }
        $html | Should -Match 'Top priorities'
        ([regex]::Matches($html, '<details open>')).Count | Should -Be 1
        $html | Should -Match '30 affected'
        $html | Should -Match 'Showing 10 of 30 active findings'
        $rep.Summary.TopFindings.Count | Should -Be 10
    }
}
