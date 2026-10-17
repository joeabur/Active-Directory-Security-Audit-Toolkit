BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')
}

Describe 'Configuration' {
    It 'loads the shipped default configuration' {
        $c = Get-ADSAConfig
        $c['configVersion'] | Should -Be '1.0'
        $c['thresholds']['staleUserDays'] | Should -Be 90
    }
    It 'overlays a partial user file on the defaults' {
        $p = New-TestConfigFile '{ "configVersion": "1.0", "thresholds": { "staleUserDays": 120 } }'
        $c = Get-ADSAConfig -Path $p
        $c['thresholds']['staleUserDays'] | Should -Be 120
        $c['thresholds']['staleComputerDays'] | Should -Be 90
    }
    It 'reports malformed JSON without throwing from Test-ADSAConfig' {
        $p = New-TestConfigFile '{ "configVersion": "1.0", '
        $r = Test-ADSAConfig -Path $p
        $r.IsValid | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match 'not valid JSON'
    }
    It 'throws a clear error for malformed JSON when loading' {
        $p = New-TestConfigFile 'this is not json'
        { Get-ADSAConfig -Path $p } | Should -Throw '*not valid JSON*'
    }
    It 'rejects a missing file' {
        (Test-ADSAConfig -Path (Join-Path $TestDrive 'nope.json')).IsValid | Should -BeFalse
    }
    It 'rejects unknown keys so typos cannot silently disable a check' {
        $r = Test-ADSAConfig -Path (New-TestConfigFile '{ "thresholds": { "staleUserDay": 10 } }')
        $r.IsValid | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match "Unknown configuration key 'thresholds.staleUserDay'"
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "bogus": 1 }')).IsValid | Should -BeFalse
    }
    It 'rejects out-of-range and wrongly typed values' {
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "thresholds": { "staleUserDays": 1 } }')).IsValid | Should -BeFalse
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "thresholds": { "staleUserDays": "ninety" } }')).IsValid | Should -BeFalse
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "passwordPolicy": { "complexityRequired": "yes" } }')).IsValid | Should -BeFalse
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "logging": { "level": "Verbose" } }')).IsValid | Should -BeFalse
    }
    It 'rejects unsupported config versions' {
        $r = Test-ADSAConfig -Path (New-TestConfigFile '{ "configVersion": "2.0" }')
        $r.IsValid | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match 'not supported'
    }
    It 'rejects invalid regular expressions and SIDs' {
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "domainControllers": { "unsupportedOsPattern": "(" } }')).IsValid | Should -BeFalse
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "trustedPrincipals": { "sids": ["nonsense"] } }')).IsValid | Should -BeFalse
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "privilegedGroups": [ { "name": "X" } ] }')).IsValid | Should -BeFalse
    }
    It 'requires a reason on every exclusion' {
        $r = Test-ADSAConfig -Path (New-TestConfigFile '{ "exclusions": [ { "pattern": "svc_*" } ] }')
        $r.IsValid | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match "documented 'reason'"
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "exclusions": [ { "pattern": "svc_*", "reason": "managed elsewhere" } ] }')).IsValid | Should -BeTrue
    }
    It 'requires owner, reason and expiry on exceptions and warns about expired ones' {
        $bad = Test-ADSAConfig -Path (New-TestConfigFile '{ "exceptions": [ { "id": "E1", "ruleId": "ADSA-ACC-003", "objectPattern": "svc_*" } ] }')
        $bad.IsValid | Should -BeFalse
        $expired = Test-ADSAConfig -Path (New-TestConfigFile '{ "exceptions": [ { "id": "E1", "ruleId": "ADSA-ACC-003", "objectPattern": "svc_*", "reason": "r", "owner": "o", "expires": "2001-01-01" } ] }')
        $expired.IsValid | Should -BeTrue
        ($expired.Warnings -join ' ') | Should -Match 'expired'
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "exceptions": [ { "id": "E1", "ruleId": "bad", "objectPattern": "x", "reason": "r", "owner": "o", "expires": "2099-01-01" } ] }')).IsValid | Should -BeFalse
        (Test-ADSAConfig -Path (New-TestConfigFile '{ "exceptions": [ { "id": "E1", "ruleId": "ADSA-ACC-003", "objectPattern": "x", "reason": "r", "owner": "o", "expires": "not-a-date" } ] }')).IsValid | Should -BeFalse
    }
    It 'ships a default config and examples that contain no credential-like keys' {
        $text = Get-Content -Raw (Join-Path $PSScriptRoot '../../config/default.config.json')
        $text | Should -Not -Match '(?i)password"\s*:|secret|token|apikey'
    }
}
