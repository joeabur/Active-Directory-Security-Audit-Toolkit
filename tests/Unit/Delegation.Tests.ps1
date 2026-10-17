BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')
    function Invoke-Del($Users = @(), $Computers = @(), $Dcs = @()) {
        $snap = New-TestSnapshot -Sections @{ Users = (New-TestSection -Data $Users); Computers = (New-TestSection -Data $Computers); DomainControllers = (New-TestSection -Data $Dcs) }
        Invoke-TestAudit -Snapshot $snap -Module Delegation
    }
    $script:dcs = @([pscustomobject]@{ Name = 'DC01'; HostName = 'dc01.test.local' })
}

Describe 'Delegation analysis (independent module)' {
    It 'DEL-001 flags unconstrained delegation on users and member computers but not DCs or disabled accounts' {
        $r = Invoke-Del -Users @((New-TestUser -Sam 'svc' -Uac (512 -bor 0x80000)), (New-TestUser -Sam 'dis' -Uac (514 -bor 0x80000))) `
            -Computers @((New-TestComputer -Sam 'APP$' -Uac (4096 -bor 0x80000)), (New-TestComputer -Sam 'DC01$' -Uac (0x2000 -bor 0x80000)))
        $f = Get-TestResult $r 'ADSA-DEL-001' | Where-Object Status -eq 'FAIL'
        @($f.AffectedObject | Sort-Object) | Should -Be @('APP$', 'svc')
    }
    It 'DEL-002 flags protocol transition' {
        $r = Invoke-Del -Users @((New-TestUser -Sam 'pt' -Uac (512 -bor 0x1000000) -Delegate @('cifs/files.test.local')))
        (Get-TestResult $r 'ADSA-DEL-002' | Where-Object Status -eq 'FAIL').AffectedObject | Should -Be 'pt'
    }
    It 'DEL-003 matches DC hosts by short and fully qualified name and ignores other services' {
        $r = Invoke-Del -Dcs $script:dcs -Users @(
            (New-TestUser -Sam 'a' -Delegate @('ldap/dc01.test.local')), (New-TestUser -Sam 'b' -Delegate @('cifs/DC01')),
            (New-TestUser -Sam 'c' -Delegate @('MSSQLSvc/dc01.test.local:1433')), (New-TestUser -Sam 'd' -Delegate @('cifs/files.test.local')))
        @((Get-TestResult $r 'ADSA-DEL-003' | Where-Object Status -eq 'FAIL').AffectedObject | Sort-Object) | Should -Be @('a', 'b')
    }
    It 'DEL-004 flags RBCD on a domain controller object only' {
        $r = Invoke-Del -Computers @((New-TestComputer -Sam 'DC01$' -Uac 0x2000 -Rbcd @('CN=x,DC=test')), (New-TestComputer -Sam 'WS$' -Rbcd @('CN=x,DC=test'))) -Dcs $script:dcs
        @((Get-TestResult $r 'ADSA-DEL-004' | Where-Object Status -eq 'FAIL').AffectedObject) | Should -Be @('DC01$')
    }
    It 'is NOT_ASSESSED when delegation properties were not collected' {
        $r = Invoke-Del -Users @((New-TestUser -Sam 'u' -Omit 'UserAccountControl', 'AllowedToDelegateTo')) -Dcs $script:dcs
        (Get-TestResult $r 'ADSA-DEL-001').Status | Should -Be 'NOT_ASSESSED'
        (Get-TestResult $r 'ADSA-DEL-003').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'reports ERROR, not PASS, when both account sections failed' {
        $snap = New-TestSnapshot -Sections @{ Users = (New-TestSection -Status 'Error' -ErrorText 'denied' -Category 'AccessDenied'); Computers = (New-TestSection -Status 'Error' -ErrorText 'denied' -Category 'AccessDenied'); DomainControllers = (New-TestSection -Data @()) }
        $r = Invoke-TestAudit -Snapshot $snap -Module Delegation
        @($r.Findings | Where-Object Status -eq 'ERROR').Count | Should -Be 4
        @($r.Findings | Where-Object Status -eq 'PASS').Count | Should -Be 0
    }
    It 'warns in limitations when only one account section was available' {
        $snap = New-TestSnapshot -Sections @{ Users = (New-TestSection -Status 'Error' -ErrorText 'denied' -Category 'AccessDenied'); Computers = (New-TestSection -Data @((New-TestComputer -Sam 'W$'))); DomainControllers = (New-TestSection -Data @()) }
        $r = Invoke-TestAudit -Snapshot $snap -Module Delegation
        (Get-TestResult $r 'ADSA-DEL-001').Limitations | Should -Match 'Users section Error'
    }
    It 'parses SPNs defensively' {
        InModuleScope ADSecurityAudit {
            (Get-ADSASpnPart -Spn 'ldap/dc01.t.local:389/DomainDnsZones.t.local').Host | Should -Be 'dc01.t.local'
            Get-ADSASpnPart -Spn 'garbage' | Should -BeNullOrEmpty
            Get-ADSASpnPart -Spn '' | Should -BeNullOrEmpty
        }
    }
}
