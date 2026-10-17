# Delegation analysis module. Independent of the other audit modules: consumes only the 'Users', 'Computers'
# and 'DomainControllers' snapshot sections. Reports selected risky Kerberos delegation configurations.

function Get-ADSASpnPart {
    # 'service/host[:port][/name]' -> @{ Service; Host }. Returns $null for unparsable values.
    [CmdletBinding()]
    param([AllowNull()] [string] $Spn)
    if ([string]::IsNullOrWhiteSpace($Spn)) { return $null }
    $slash = $Spn.IndexOf('/')
    if ($slash -lt 1) { return $null }
    $svc = $Spn.Substring(0, $slash).ToLowerInvariant()
    $rest = $Spn.Substring($slash + 1)
    $hostPart = ($rest -split '[:/]')[0].ToLowerInvariant()
    if (-not $hostPart) { return $null }
    return [pscustomobject]@{ Service = $svc; Host = $hostPart }
}

function Test-ADSAHostMatchesDc {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $HostName, [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $DomainControllers)
    foreach ($dc in $DomainControllers) {
        $names = @(
            "$(Get-ADSAProp -InputObject $dc -Name 'HostName' -Default '')"
            "$(Get-ADSAProp -InputObject $dc -Name 'Name' -Default '')"
        ) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() }
        foreach ($n in $names) {
            if ($HostName -eq $n) { return $true }
            if ($HostName -notlike '*.*' -and $n -like "$HostName.*") { return $true }
            if ($n -notlike '*.*' -and $HostName -like "$n.*") { return $true }
        }
    }
    return $false
}

function Invoke-ADSADelegationAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config)
    $ctx = New-ADSAContext -Snapshot $Snapshot -Config $Config
    $users = Get-ADSASectionState -Context $ctx -Name 'Users'
    $computers = Get-ADSASectionState -Context $ctx -Name 'Computers'
    $dcs = Get-ADSASectionState -Context $ctx -Name 'DomainControllers'

    # Accounts considered: users and computers (both can be delegation-configured)
    $accountSections = @()
    if ($users.State -eq 'Ok') { $accountSections += , @{ Kind = 'user'; Data = @($users.Data) } }
    if ($computers.State -eq 'Ok') { $accountSections += , @{ Kind = 'computer'; Data = @($computers.Data) } }
    $unavailable = ($users.State -ne 'Ok' -and $computers.State -ne 'Ok')

    $dcList = @(if ($dcs.State -eq 'Ok') { $dcs.Data })
    $unusableNote = New-Object System.Collections.Generic.List[string]
    if ($users.State -ne 'Ok') { $unusableNote.Add("Users section $($users.State)") }
    if ($computers.State -ne 'Ok') { $unusableNote.Add("Computers section $($computers.State)") }

    $ruleIds = 'ADSA-DEL-001', 'ADSA-DEL-002', 'ADSA-DEL-003', 'ADSA-DEL-004'
    if ($unavailable) {
        foreach ($r in 'ADSA-DEL-001', 'ADSA-DEL-002') { New-ADSASectionResult -Context $ctx -RuleId $r -Section $(if ($users.State -eq 'Error' -or $computers.State -eq 'Error') { [pscustomobject]@{ State = 'Error'; Error = ($unusableNote -join '; '); Category = $users.Category } } else { $users }) -SectionName 'Users/Computers' }
        New-ADSASectionResult -Context $ctx -RuleId 'ADSA-DEL-003' -Section $users -SectionName 'Users/Computers'
        New-ADSASectionResult -Context $ctx -RuleId 'ADSA-DEL-004' -Section $computers -SectionName 'Computers'
        return
    }
    $partial = if ($unusableNote.Count -gt 0) { "Partial data: $($unusableNote -join '; ')." } else { '' }

    # --- DEL-001 / DEL-002 / DEL-003 over users + computers
    $eval = @{}; $skip = @{}; $fails = @{}
    foreach ($id in $ruleIds) { $eval[$id] = 0; $skip[$id] = 0; $fails[$id] = New-Object System.Collections.Generic.List[object] }

    foreach ($sec in $accountSections) {
        foreach ($acct in $sec.Data) {
            $sam = "$(Get-ADSAProp -InputObject $acct -Name 'SamAccountName' -Default (Get-ADSAProp -InputObject $acct -Name 'Name' -Default ''))"
            $dn = "$(Get-ADSAProp -InputObject $acct -Name 'DistinguishedName' -Default '')"
            $uac = Get-ADSAUac -InputObject $acct
            $enabled = Get-ADSAEnabled -InputObject $acct
            $otype = if ($sec.Kind -eq 'user') { 'User' } else { 'Computer' }

            if ($null -eq $uac -or $null -eq $enabled) {
                foreach ($id in 'ADSA-DEL-001', 'ADSA-DEL-002') { if (-not (Test-ADSAExcluded -Context $ctx -RuleId $id -Name $sam -DistinguishedName $dn -Kind $sec.Kind)) { $skip[$id]++ } }
            } elseif ($enabled) {
                $isDc = Test-ADSAUacFlag -Uac $uac -Flag 'SERVER_TRUST_ACCOUNT'
                # DEL-001 unconstrained (domain controllers are expected to be trusted for delegation)
                if (-not $isDc -and -not (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-DEL-001' -Name $sam -DistinguishedName $dn -Kind $sec.Kind)) {
                    $eval['ADSA-DEL-001']++
                    if (Test-ADSAUacFlag -Uac $uac -Flag 'TRUSTED_FOR_DELEGATION') {
                        $fails['ADSA-DEL-001'].Add(@{ Object = $sam; ObjectType = $otype; Evidence = [ordered]@{ DistinguishedName = $dn; Flag = 'TRUSTED_FOR_DELEGATION'; UserAccountControl = $uac } })
                    }
                }
                # DEL-002 protocol transition
                if (-not (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-DEL-002' -Name $sam -DistinguishedName $dn -Kind $sec.Kind)) {
                    $eval['ADSA-DEL-002']++
                    if (Test-ADSAUacFlag -Uac $uac -Flag 'TRUSTED_TO_AUTH_FOR_DELEGATION') {
                        $targets = Get-ADSAList -InputObject $acct -Name 'AllowedToDelegateTo'
                        $fails['ADSA-DEL-002'].Add(@{ Object = $sam; ObjectType = $otype; Evidence = [ordered]@{ DistinguishedName = $dn; Flag = 'TRUSTED_TO_AUTH_FOR_DELEGATION'; AllowedToDelegateTo = $targets } })
                    }
                }
            }

            # DEL-003 constrained delegation reaching DC services
            if ($dcs.State -eq 'Ok' -and (Test-ADSAHasProp -InputObject $acct -Name 'AllowedToDelegateTo')) {
                if (-not (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-DEL-003' -Name $sam -DistinguishedName $dn -Kind $sec.Kind)) {
                    $eval['ADSA-DEL-003']++
                    $hits = New-Object System.Collections.Generic.List[string]
                    foreach ($spn in (Get-ADSAList -InputObject $acct -Name 'AllowedToDelegateTo')) {
                        $parts = Get-ADSASpnPart -Spn "$spn"
                        if ($null -ne $parts -and $parts.Service -in 'ldap', 'cifs', 'host', 'gc', 'rpcss', 'wsman' -and (Test-ADSAHostMatchesDc -HostName $parts.Host -DomainControllers $dcList)) { $hits.Add("$spn") }
                    }
                    if ($hits.Count -gt 0) {
                        $fails['ADSA-DEL-003'].Add(@{ Object = $sam; ObjectType = $otype; Evidence = [ordered]@{ DistinguishedName = $dn; DomainControllerTargets = $hits.ToArray() } })
                    }
                }
            }
            elseif ($dcs.State -eq 'Ok') {
                if (-not (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-DEL-003' -Name $sam -DistinguishedName $dn -Kind $sec.Kind)) { $skip['ADSA-DEL-003']++ }
            }
        }
    }

    Complete-ADSARule -Context $ctx -RuleId 'ADSA-DEL-001' -Fail $fails['ADSA-DEL-001'].ToArray() -Evaluated $eval['ADSA-DEL-001'] -Skipped $skip['ADSA-DEL-001'] -SkipReason 'userAccountControl unavailable' -ObjectType 'Account' -Scope 'enabled non-DC accounts' -ExtraLimitation $partial
    Complete-ADSARule -Context $ctx -RuleId 'ADSA-DEL-002' -Fail $fails['ADSA-DEL-002'].ToArray() -Evaluated $eval['ADSA-DEL-002'] -Skipped $skip['ADSA-DEL-002'] -SkipReason 'userAccountControl unavailable' -ObjectType 'Account' -Scope 'enabled accounts' -ExtraLimitation $partial
    if ($dcs.State -ne 'Ok') {
        New-ADSASectionResult -Context $ctx -RuleId 'ADSA-DEL-003' -Section $dcs -SectionName 'DomainControllers'
    } else {
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-DEL-003' -Fail $fails['ADSA-DEL-003'].ToArray() -Evaluated $eval['ADSA-DEL-003'] -Skipped $skip['ADSA-DEL-003'] -SkipReason 'delegation targets unavailable' -ObjectType 'Account' -Scope 'accounts with constrained delegation targets' -ExtraLimitation $partial
    }

    # --- DEL-004 RBCD on domain controller computer objects
    if ($computers.State -ne 'Ok') {
        New-ADSASectionResult -Context $ctx -RuleId 'ADSA-DEL-004' -Section $computers -SectionName 'Computers'
    } else {
        $fail4 = New-Object System.Collections.Generic.List[object]; $eval4 = 0; $skip4 = 0
        foreach ($c in @($computers.Data)) {
            $sam = "$(Get-ADSAProp -InputObject $c -Name 'SamAccountName' -Default (Get-ADSAProp -InputObject $c -Name 'Name' -Default ''))"
            $dn = "$(Get-ADSAProp -InputObject $c -Name 'DistinguishedName' -Default '')"
            $uac = Get-ADSAUac -InputObject $c
            if ($null -eq $uac -or -not (Test-ADSAUacFlag -Uac $uac -Flag 'SERVER_TRUST_ACCOUNT')) {
                if ($null -eq $uac) { $skip4++ }
                continue
            }
            if (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-DEL-004' -Name $sam -DistinguishedName $dn -Kind 'computer') { continue }
            if (-not (Test-ADSAHasProp -InputObject $c -Name 'AllowedToActOnBehalf')) { $skip4++; continue }
            $eval4++
            $principals = Get-ADSAList -InputObject $c -Name 'AllowedToActOnBehalf'
            if ($principals.Count -gt 0) {
                $fail4.Add(@{ Object = $sam; ObjectType = 'DomainController'; Evidence = [ordered]@{ DistinguishedName = $dn; AllowedToActOnBehalf = $principals } })
            }
        }
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-DEL-004' -Fail $fail4.ToArray() -Evaluated $eval4 -Skipped $skip4 -SkipReason 'RBCD attribute or userAccountControl not collected' -ObjectType 'DomainController' -Scope 'domain controllers'
    }
}
