BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
}

Describe 'Helpers' {
    It 'parses dates from ISO strings, DateTime and FILETIME and rejects junk' {
        InModuleScope ADSecurityAudit {
            (ConvertTo-ADSADateTime -Value '2026-10-01T00:00:00Z').ToString('o') | Should -Be '2026-10-01T00:00:00.0000000Z'
            (ConvertTo-ADSADateTime -Value ([datetime]::SpecifyKind([datetime]'2026-01-02', 'Utc'))).Kind | Should -Be 'Utc'
            (ConvertTo-ADSADateTime -Value ([datetime]'2026-01-02T00:00:00Z').ToFileTimeUtc()).Year | Should -Be 2026
            ConvertTo-ADSADateTime -Value 0 | Should -BeNullOrEmpty
            ConvertTo-ADSADateTime -Value '9223372036854775807' | Should -BeNullOrEmpty
            ConvertTo-ADSADateTime -Value 'not a date' | Should -BeNullOrEmpty
            ConvertTo-ADSADateTime -Value $null | Should -BeNullOrEmpty
            ConvertTo-ADSADateTime -Value '' | Should -BeNullOrEmpty
        }
    }
    It 'distinguishes missing properties from null values' {
        InModuleScope ADSecurityAudit {
            $o = [pscustomobject]@{ A = $null }
            Test-ADSAHasProp -InputObject $o -Name 'A' | Should -BeTrue
            Test-ADSAHasProp -InputObject $o -Name 'B' | Should -BeFalse
            Get-ADSAProp -InputObject $o -Name 'B' -Default 'x' | Should -Be 'x'
            Test-ADSAHasProp -InputObject @{ K = 1 } -Name 'K' | Should -BeTrue
            Get-ADSAProp -InputObject $null -Name 'K' -Default 5 | Should -Be 5
        }
    }
    It 'returns lists without nulls and keeps single items as arrays' {
        InModuleScope ADSecurityAudit {
            $one = Get-ADSAList -InputObject ([pscustomobject]@{ L = 'a' }) -Name 'L'
            $one.Count | Should -Be 1
            $none = Get-ADSAList -InputObject ([pscustomobject]@{ L = $null }) -Name 'L'
            $none.Count | Should -Be 0
            $missing = Get-ADSAList -InputObject ([pscustomobject]@{}) -Name 'L'
            $missing.Count | Should -Be 0
        }
    }
    It 'evaluates userAccountControl flags' {
        InModuleScope ADSecurityAudit {
            Test-ADSAUacFlag -Uac 66048 -Flag 'DONT_EXPIRE_PASSWORD' | Should -BeTrue
            Test-ADSAUacFlag -Uac 512 -Flag 'DONT_EXPIRE_PASSWORD' | Should -BeFalse
            Get-ADSAEnabled -InputObject ([pscustomobject]@{ UserAccountControl = 514 }) | Should -BeFalse
            Get-ADSAEnabled -InputObject ([pscustomobject]@{ Foo = 1 }) | Should -BeNullOrEmpty
            { Test-ADSAUacFlag -Uac 1 -Flag 'NOPE' } | Should -Throw
        }
    }
}

Describe 'Structured logging' {
    It 'redacts secret-looking keys' {
        InModuleScope ADSecurityAudit {
            $safe = Protect-ADSALogData -Data @{ server = 'dc1'; Password = 'hunter2'; apiToken = 'abc'; cpassword = 'zzz' }
            $safe['server'] | Should -Be 'dc1'
            $safe['Password'] | Should -Be '[REDACTED]'
            $safe['apiToken'] | Should -Be '[REDACTED]'
            $safe['cpassword'] | Should -Be '[REDACTED]'
        }
    }
    It 'writes JSON lines to the configured log file' {
        $log = Join-Path $TestDrive 'logs/run.log'
        InModuleScope ADSecurityAudit -Parameters @{ Log = $log } {
            param($Log)
            Initialize-ADSALog -Level Information -Path $Log
            Write-ADSALog -Message 'hello' -Data @{ secret = 'x'; n = 1 }
            $line = Get-Content -LiteralPath $Log | Select-Object -First 1 | ConvertFrom-Json
            $line.message | Should -Be 'hello'
            $line.data.secret | Should -Be '[REDACTED]'
            $line.level | Should -Be 'Information'
            Initialize-ADSALog -Level Information -Path $null
        }
    }
}

Describe 'Output path validation' {
    It 'rejects empty paths' {
        InModuleScope ADSecurityAudit { { Resolve-ADSAOutputPath -Path '' } | Should -Throw '*must not be empty*' }
    }
    It 'rejects tracked repository folders' {
        InModuleScope ADSecurityAudit {
            { Resolve-ADSAOutputPath -Path (Join-Path $script:ADSARoot 'docs') } | Should -Throw '*tracked repository folder*'
            { Resolve-ADSAOutputPath -Path (Join-Path $script:ADSARoot 'src/Private') } | Should -Throw '*tracked repository folder*'
        }
    }
    It 'rejects UNC paths unless explicitly allowed' {
        InModuleScope ADSecurityAudit { { Resolve-ADSAOutputPath -Path '\\server\share\out' } | Should -Throw '*UNC*' }
    }
    It 'rejects an existing file and creates a new directory otherwise' {
        $file = Join-Path $TestDrive 'afile.txt'
        Set-Content -LiteralPath $file -Value 'x'
        $new = Join-Path $TestDrive 'nested/out'
        InModuleScope ADSecurityAudit -Parameters @{ File = $file; New = $new } {
            param($File, $New)
            { Resolve-ADSAOutputPath -Path $File } | Should -Throw '*existing file*'
            $full = Resolve-ADSAOutputPath -Path $New
            Test-Path -LiteralPath $full -PathType Container | Should -BeTrue
        }
    }
}
