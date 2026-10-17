BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
    $script:srcRoot = Join-Path $PSScriptRoot '../../src'
    $script:files = Get-ChildItem -Path $script:srcRoot -Filter '*.ps1' -Recurse
    function Get-CommandNames($file) {
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errs)
        $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
    }
}

Describe 'Read-only guarantee (static analysis of every command used)' {
    It 'parses without syntax errors' {
        foreach ($f in $script:files) {
            $errs = $null; $tokens = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
            $errs | Should -BeNullOrEmpty -Because $f.Name
        }
    }
    It 'never calls a state-changing Active Directory, Group Policy or DC cmdlet' {
        $forbidden = '^(Set|New|Remove|Add|Clear|Move|Rename|Restore|Unlock|Disable|Enable|Reset|Grant|Revoke|Install|Uninstall|Sync|Import|Invoke)-(AD(?!SA)|GP|Dfs|Dns|Cluster)\w*$'
        $allowedInvoke = '^Invoke-(ADSA\w+|ADSecurityAudit)$'
        foreach ($f in $script:files) {
            foreach ($n in (Get-CommandNames $f)) {
                if ($n -match $allowedInvoke) { continue }
                $n | Should -Not -Match $forbidden -Because "$($f.Name) uses $n"
            }
        }
    }
    It 'never uses cmdlets that change services, registry, computers, accounts or arbitrary code' {
        $forbidden = @('Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Service', 'Start-Service', 'Stop-Service', 'Restart-Service', 'Restart-Computer', 'Stop-Computer',
            'Invoke-Expression', 'Invoke-WebRequest', 'Invoke-RestMethod', 'Start-Process', 'Set-LocalUser', 'New-LocalUser', 'Add-LocalGroupMember', 'Set-GPO', 'Set-GPPermission', 'Remove-Item', 'Set-ExecutionPolicy',
            'Add-Type', 'Register-ScheduledTask', 'Send-MailMessage', 'New-NetFirewallRule', 'Disable-NetAdapter', 'netsh', 'net', 'reg', 'sc', 'schtasks', 'dsacls', 'ldifde', 'csvde', 'repadmin', 'ntdsutil')
        foreach ($f in $script:files) {
            $names = Get-CommandNames $f
            foreach ($bad in $forbidden) { $names | Should -Not -Contain $bad -Because "$($f.Name) must not call $bad" }
        }
    }
    It 'restricts Set-Acl to protecting the toolkit''s own output files' {
        foreach ($f in $script:files) {
            $uses = Get-CommandNames $f | Where-Object { $_ -in 'Set-Acl' }
            if ($f.Name -ne 'Paths.ps1') { $uses | Should -BeNullOrEmpty -Because $f.Name } 
        }
        (Get-Content -Raw (Join-Path $script:srcRoot 'Private/Paths.ps1')) | Should -Match 'Set-Acl -LiteralPath \$Path -AclObject \$acl'
    }
    It 'limits native executables to a read-only auditpol query' {
        $text = Get-Content -Raw (Join-Path $script:srcRoot 'Private/Collectors.ps1')
        ([regex]::Matches($text, '(?i)&\s+\w+\.exe[^\r\n]*') | ForEach-Object { $_.Value.Trim() }) | Should -Be @('& auditpol.exe /get /category:* /r 2>&1')
    }
    It 'writes files only through the validated output helper' {
        foreach ($f in $script:files) {
            $names = Get-CommandNames $f
            if ($f.Name -notin 'Paths.ps1', 'Logging.ps1') {
                foreach ($w in 'Out-File', 'Set-Content', 'Add-Content', 'Export-Csv', 'Export-Clixml', 'New-Item') { $names | Should -Not -Contain $w -Because "$($f.Name) uses $w" }
            }
        }
    }
}

Describe 'Credential handling' {
    It 'accepts credentials only as PSCredential parameters and never as plain text' {
        foreach ($f in $script:files) {
            $tokens = $null; $errs = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
            foreach ($p in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true)) {
                $name = $p.Name.VariablePath.UserPath
                if ($name -match '(?i)pass|secret|token|apikey|credential|pwd') {
                    $name -in 'Credential' | Should -BeTrue -Because "$($f.Name): parameter $name"
                    $p.StaticType.FullName | Should -Be 'System.Management.Automation.PSCredential'
                }
            }
        }
    }
    It 'never converts secrets to or from plain text' {
        foreach ($f in $script:files) {
            $text = Get-Content -Raw $f.FullName
            $text | Should -Not -Match '(?i)ConvertTo-SecureString|AsPlainText|GetNetworkCredential|\.Password\b' -Because $f.Name
        }
    }
    It 'ships no credential-like keys in configuration, examples or sample data' {
        $root = Join-Path $PSScriptRoot '../..'
        $json = @(Get-ChildItem (Join-Path $root 'config') -Filter '*.json' -Recurse) + @(Get-ChildItem (Join-Path $root 'examples') -Filter '*.json' -Recurse -ErrorAction SilentlyContinue) + @(Get-ChildItem (Join-Path $root 'sample-data') -Filter '*.json' -ErrorAction SilentlyContinue)
        foreach ($j in $json) {
            $keys = [regex]::Matches((Get-Content -Raw $j.FullName), '"([^"]+)"\s*:') | ForEach-Object { $_.Groups[1].Value }
            foreach ($k in $keys) { $k | Should -Not -Match '(?i)^(password|passwd|pwd|secret|token|apikey|credential|cpassword)$' -Because "$($j.Name) key $k" }
        }
    }
}

Describe 'Module surface' {
    It 'exports exactly the functions listed in the manifest' {
        $manifest = Import-PowerShellDataFile (Join-Path $script:srcRoot 'ADSecurityAudit.psd1')
        $exported = (Get-Module ADSecurityAudit).ExportedFunctions.Keys | Sort-Object
        $exported | Should -Be ($manifest.FunctionsToExport | Sort-Object)
    }
    It 'gives every public function help with a synopsis' {
        foreach ($name in (Get-Module ADSecurityAudit).ExportedFunctions.Keys) { (Get-Help $name).Synopsis | Should -Not -BeNullOrEmpty -Because $name }
    }
    It 'passes manifest validation' {
        { Test-ModuleManifest (Join-Path $script:srcRoot 'ADSecurityAudit.psd1') -ErrorAction Stop } | Should -Not -Throw
    }
    It 'keeps source files ASCII so Windows PowerShell 5.1 reads them without a BOM' {
        foreach ($f in (Get-ChildItem (Join-Path $PSScriptRoot '../..') -Include '*.ps1', '*.psm1', '*.psd1' -Recurse | Where-Object FullName -notmatch '/\.git/')) {
            [System.IO.File]::ReadAllText($f.FullName) | Should -Not -Match '[^\x00-\x7F]' -Because $f.Name
        }
    }
}
