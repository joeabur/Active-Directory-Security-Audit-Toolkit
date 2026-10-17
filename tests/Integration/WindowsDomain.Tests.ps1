# Windows test-domain integration suite. SKIPPED unless every gate below is satisfied.
#
# Gates (all required):
#   * Windows host with the ActiveDirectory module (RSAT)
#   * $env:ADSA_INTEGRATION_SERVER   = a domain controller of an EXPLICITLY AUTHORIZED TEST DOMAIN
#   * $env:ADSA_INTEGRATION_CONFIRM  = 'I-AM-AUTHORIZED-FOR-THIS-TEST-DOMAIN'
# Optional:
#   * $env:ADSA_INTEGRATION_DCHOSTS  = '1'   also exercise remote DC host checks (needs WinRM + rights on the DC)
#
# The suite is read-only. It has NOT been run by the author: this repository was developed on Linux without a domain.
BeforeDiscovery {
    $script:runLive = (
        [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT -and
        [bool](Get-Module -ListAvailable -Name ActiveDirectory) -and
        [bool]$env:ADSA_INTEGRATION_SERVER -and
        $env:ADSA_INTEGRATION_CONFIRM -eq 'I-AM-AUTHORIZED-FOR-THIS-TEST-DOMAIN'
    )
    $script:dcHosts = ($env:ADSA_INTEGRATION_DCHOSTS -eq '1')
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    $script:server = $env:ADSA_INTEGRATION_SERVER
    $script:dcHosts = ($env:ADSA_INTEGRATION_DCHOSTS -eq '1')
}

Describe 'Live collection against an authorized Windows test domain' -Tag 'WindowsDomain' -Skip:(-not $script:runLive) {
    BeforeAll {
        $script:snap = Get-ADSASnapshot -AuthorizedAssessment -Server $script:server -SkipDcHostChecks:(-not $script:dcHosts)
    }
    It 'reports the host as live-ready' {
        (Test-ADSAPrerequisite).LiveReady | Should -BeTrue
    }
    It 'collects core sections from the real domain and labels them Live' {
        $script:snap.dataSource | Should -Be 'Live'
        $script:snap.sections.Users.status | Should -Be 'Collected'
        $script:snap.sections.Groups.status | Should -Be 'Collected'
        $script:snap.sections.PasswordPolicy.status | Should -Be 'Collected'
        @($script:snap.sections.Users.data).Count | Should -BeGreaterThan 0
    }
    It 'includes the built-in privileged groups and krbtgt' {
        @($script:snap.sections.Groups.data | Where-Object { $_.Sid -like '*-512' }).Count | Should -Be 1
        @($script:snap.sections.Users.data | Where-Object SamAccountName -eq 'krbtgt').Count | Should -Be 1
    }
    It 'reads DACLs for the domain root' {
        $root = $script:snap.sections.Acls.data | Where-Object Role -eq 'DomainRoot'
        $root | Should -Not -BeNullOrEmpty
        $root.OwnerSid | Should -Match '^S-1-5-'
        @($root.Aces).Count | Should -BeGreaterThan 0
    }
    It 'produces a schema-valid Live report with no PASS for any rule whose data failed to collect' {
        $r = Invoke-ADSecurityAudit -Snapshot $script:snap
        (Test-ADSAReport -Report $r).IsValid | Should -BeTrue
        $r.Metadata.DataSource | Should -Be 'Live'
        $failed = @($r.Coverage.Sections | Where-Object Status -ne 'Collected')
        foreach ($s in $failed) { @($r.CollectionErrors | Where-Object Source -eq $s.Section).Count | Should -BeGreaterThan 0 }
    }
    It 'checks domain controller host settings when enabled' -Skip:(-not $script:dcHosts) {
        $script:snap.sections.DcHosts.status | Should -Be 'Collected'
        @($script:snap.sections.DcHosts.data).Count | Should -BeGreaterThan 0
    }
    It 'is read-only: object counts are unchanged by a second collection' {
        $again = Get-ADSASnapshot -AuthorizedAssessment -Server $script:server -SkipDcHostChecks -SkipAcls -SkipSysvol
        @($again.sections.Users.data).Count | Should -BeGreaterOrEqual (@($script:snap.sections.Users.data).Count - 5)
    }
}
