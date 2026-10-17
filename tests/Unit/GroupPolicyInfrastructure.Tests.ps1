BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    . (Join-Path $PSScriptRoot '../Fixtures/TestData.ps1')
    $script:dcOu = "OU=Domain Controllers,$script:TestDomainDn"
    function New-Gpo($Name, $Settings = @{}, $Status = 'Read', $Link = $script:dcOu, $Cpw = @()) {
        [pscustomobject]@{ Id = $Name.ToLower(); DisplayName = $Name; LinkedTo = @([pscustomobject]@{ Target = $Link; Enabled = $true }); SysvolStatus = $Status; Settings = $Settings; CpasswordFiles = $Cpw }
    }
    function Invoke-Gpo($Gpos) { Invoke-TestAudit -Snapshot (New-TestSnapshot -Sections @{ Gpos = (New-TestSection -Data $Gpos) }) -Module GroupPolicy }
    $script:lm = 'machine\system\currentcontrolset\control\lsa\lmcompatibilitylevel'
    $script:smb = 'machine\system\currentcontrolset\services\lanmanserver\parameters\requiresecuritysignature'
}

Describe 'GptTmpl.inf parsing' {
    It 'extracts registry values and ignores other sections' {
        InModuleScope ADSecurityAudit {
            $text = "[Unicode]`r`nUnicode=yes`r`n[System Access]`r`nMinimumPasswordLength = 7`r`n[Registry Values]`r`nMACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5`r`n; comment`r`nMACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1`r`n[Version]`r`nsignature=x"
            $s = ConvertFrom-ADSAGptTmplText -Text $text
            $s['machine\system\currentcontrolset\control\lsa\lmcompatibilitylevel'] | Should -Be '5'
            $s['machine\system\currentcontrolset\services\lanmanserver\parameters\requiresecuritysignature'] | Should -Be '1'
            $s.Keys.Count | Should -Be 2
        }
    }
    It 'handles empty and malformed input' {
        InModuleScope ADSecurityAudit {
            (ConvertFrom-ADSAGptTmplText -Text '').Count | Should -Be 0
            (ConvertFrom-ADSAGptTmplText -Text "[Registry Values]`r`nnot a setting line").Count | Should -Be 0
        }
    }
    It 'parses gPLink values including disabled and enforced links' {
        InModuleScope ADSecurityAudit {
            $l = ConvertFrom-ADSAGpLink -GpLink '[LDAP://cn={AAAAAAAA-0000-0000-0000-000000000001},cn=policies,cn=system,DC=t;1][LDAP://cn={AAAAAAAA-0000-0000-0000-000000000002},cn=policies,cn=system,DC=t;2]'
            $l.Count | Should -Be 2
            $l[0].Enabled | Should -BeFalse
            $l[1].Enforced | Should -BeTrue
        }
    }
}

Describe 'Group Policy rules' {
    It 'GPO-001/002 fail weak values and pass strong values for linked GPOs' {
        $r = Invoke-Gpo @((New-Gpo 'DCPolicy' @{ $script:lm = '3'; $script:smb = '1' }))
        (Get-TestResult $r 'ADSA-GPO-001').Status | Should -Be 'FAIL'
        (Get-TestResult $r 'ADSA-GPO-002').Status | Should -Be 'PASS'
    }
    It 'lowers confidence when another GPO defines a compliant value (precedence not modelled)' {
        $r = Invoke-Gpo @((New-Gpo 'Weak' @{ $script:lm = '1' }), (New-Gpo 'Strong' @{ $script:lm = '5' }))
        $f = Get-TestResult $r 'ADSA-GPO-001' | Where-Object Status -eq 'FAIL'
        $f.Confidence | Should -Be 'Low'
        $f.Limitations | Should -Match 'precedence'
    }
    It 'is NOT_ASSESSED, not PASS, when no assessed GPO defines the setting' {
        $r = Invoke-Gpo @((New-Gpo 'Empty' @{}))
        (Get-TestResult $r 'ADSA-GPO-001').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'ignores GPOs not linked to the domain root or Domain Controllers OU' {
        $r = Invoke-Gpo @((New-Gpo 'OtherOu' @{ $script:lm = '1' } -Link "OU=Workstations,$script:TestDomainDn"))
        (Get-TestResult $r 'ADSA-GPO-001').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'reports ERROR when SYSVOL could not be read' {
        $r = Invoke-Gpo @((New-Gpo 'Locked' -Status 'AccessDenied'))
        (Get-TestResult $r 'ADSA-GPO-001').Status | Should -Be 'ERROR'
        (Get-TestResult $r 'ADSA-GPO-003').Status | Should -Be 'ERROR'
        @($r.CollectionErrors | Where-Object { $_.Source -eq 'Gpos' }).Count | Should -Be 1
    }
    It 'GPO-003 reports cpassword file paths and never a secret value' {
        $r = Invoke-Gpo @((New-Gpo 'Legacy' -Cpw @('Machine\Preferences\Groups\Groups.xml')))
        $f = Get-TestResult $r 'ADSA-GPO-003' | Where-Object Status -eq 'FAIL'
        $f.Severity | Should -Be 'Critical'
        $f.Evidence.Files | Should -Contain 'Machine\Preferences\Groups\Groups.xml'
        ($f | ConvertTo-Json -Depth 6) | Should -Not -Match 'cpassword="'
    }
    It 'reads a real folder structure from SYSVOL without storing the secret' {
        $root = Join-Path $TestDrive 'gpo1'
        $sec = Join-Path $root 'Machine/Microsoft/Windows NT/SecEdit'
        $grp = Join-Path $root 'Machine/Preferences/Groups'
        New-Item -ItemType Directory -Path $sec, $grp -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $sec 'GptTmpl.inf') -Value "[Registry Values]`r`nMACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,3"
        Set-Content -LiteralPath (Join-Path $grp 'Groups.xml') -Value '<Groups><User><Properties cpassword="SECRETVALUE123" userName="x"/></User></Groups>'
        InModuleScope ADSecurityAudit -Parameters @{ Root = $root } {
            param($Root)
            $r = Get-ADSAGpoSysvolSetting -Path $Root
            $r.SysvolStatus | Should -Be 'Read'
            $r.Settings['machine\system\currentcontrolset\control\lsa\lmcompatibilitylevel'] | Should -Be '3'
            $r.CpasswordFiles.Count | Should -Be 1
            ($r | ConvertTo-Json -Depth 5) | Should -Not -Match 'SECRETVALUE123'
            (Get-ADSAGpoSysvolSetting -Path (Join-Path $Root 'missing')).SysvolStatus | Should -Be 'NotFound'
            (Get-ADSAGpoSysvolSetting -Path '').SysvolStatus | Should -Be 'NotFound'
        }
    }
}

Describe 'Infrastructure rules' {
    BeforeAll {
        function Invoke-Inf($Dcs = @(), $Trusts = @(), $Domain = 'Windows2016Domain', $Forest = 'Windows2016Forest', $Config) {
            $snap = New-TestSnapshot -Sections @{ DomainControllers = (New-TestSection -Data $Dcs); Trusts = (New-TestSection -Data $Trusts) } -DomainMode $Domain -ForestMode $Forest
            Invoke-TestAudit -Snapshot $snap -Module Infrastructure -ConfigPath $Config
        }
    }
    It 'INF-001 flags unsupported operating systems' {
        $r = Invoke-Inf -Dcs @([pscustomobject]@{ Name = 'old'; HostName = 'old.t'; OperatingSystem = 'Windows Server 2012 R2 Standard' }, [pscustomobject]@{ Name = 'new'; HostName = 'new.t'; OperatingSystem = 'Windows Server 2022 Datacenter' }, [pscustomobject]@{ Name = 'x'; HostName = 'x.t'; OperatingSystem = 'Windows Server 2008 R2' })
        @((Get-TestResult $r 'ADSA-INF-001' | Where-Object Status -eq 'FAIL').AffectedObject | Sort-Object) | Should -Be @('old', 'x')
    }
    It 'INF-001 bounds a pathological operator regex instead of hanging' {
        $cfg = New-TestConfigFile '{ "domainControllers": { "unsupportedOsPattern": "(a+)+$" } }'
        $os = ('a' * 45) + '!'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-Inf -Dcs @([pscustomobject]@{ Name = 'x'; HostName = 'x.t'; OperatingSystem = $os }) -Config $cfg
        $sw.Stop()
        (Get-TestResult $r 'ADSA-INF-001').Status | Should -Be 'NOT_ASSESSED'
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 20
    }
    It 'INF-001 is NOT_ASSESSED when the OS attribute is missing' {
        (Get-TestResult (Invoke-Inf -Dcs @([pscustomobject]@{ Name = 'a'; HostName = 'a.t' })) 'ADSA-INF-001').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'INF-002 compares functional levels with the baseline and skips unknown names' {
        $r = Invoke-Inf -Domain 'Windows2008R2Domain' -Forest 'Windows2008R2Forest'
        @(Get-TestResult $r 'ADSA-INF-002' | Where-Object Status -eq 'FAIL').Count | Should -Be 2
        (Get-TestResult (Invoke-Inf -Domain 'WindowsFuture' -Forest 'WindowsFuture') 'ADSA-INF-002').Status | Should -Be 'NOT_ASSESSED'
        (Get-TestResult (Invoke-Inf) 'ADSA-INF-002').Status | Should -Be 'PASS'
    }
    It 'INF-003/004 interpret trust attributes and direction' {
        $trusts = @(
            [pscustomobject]@{ Name = 'external-nofilter'; TrustAttributes = 0; TrustDirection = 3 },
            [pscustomobject]@{ Name = 'external-filtered'; TrustAttributes = 4; TrustDirection = 2 },
            [pscustomobject]@{ Name = 'forest-ok'; TrustAttributes = 8; TrustDirection = 3 },
            [pscustomobject]@{ Name = 'forest-asexternal'; TrustAttributes = (8 -bor 0x40 -bor 0x10); TrustDirection = 3 },
            [pscustomobject]@{ Name = 'inbound-only'; TrustAttributes = 0; TrustDirection = 1 },
            [pscustomobject]@{ Name = 'child'; TrustAttributes = 0x20; TrustDirection = 3 }
        )
        $r = Invoke-Inf -Trusts $trusts
        @((Get-TestResult $r 'ADSA-INF-003' | Where-Object Status -eq 'FAIL').AffectedObject | Sort-Object) | Should -Be @('external-nofilter', 'forest-asexternal')
        @((Get-TestResult $r 'ADSA-INF-004' | Where-Object Status -eq 'FAIL').AffectedObject | Sort-Object) | Should -Be @('external-filtered', 'external-nofilter', 'forest-ok')
    }
    It 'INF-003 is NOT_ASSESSED when a trust has no attributes' {
        (Get-TestResult (Invoke-Inf -Trusts @([pscustomobject]@{ Name = 'x' })) 'ADSA-INF-003').Status | Should -Be 'NOT_ASSESSED'
    }
    It 'INF-003/004 are NOT_APPLICABLE when there are no trusts' {
        (Get-TestResult (Invoke-Inf -Trusts @()) 'ADSA-INF-003').Status | Should -Be 'NOT_APPLICABLE'
    }
    It 'reports ERROR when trusts could not be read' {
        $snap = New-TestSnapshot -Sections @{ DomainControllers = (New-TestSection -Data @()); Trusts = (New-TestSection -Status 'Error' -ErrorText 'LDAP referral' -Category 'LdapError') }
        $r = Invoke-TestAudit -Snapshot $snap -Module Infrastructure
        (Get-TestResult $r 'ADSA-INF-003').Status | Should -Be 'ERROR'
    }
}
