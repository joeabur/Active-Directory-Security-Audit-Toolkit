# Authentication and policy audit module: domain password/lockout policy, krbtgt age, and per-DC settings
# (LDAP signing, channel binding, Print Spooler, advanced audit policy, Security log capacity).

function ConvertFrom-ADSAAuditSetting {
    # Parses an auditpol 'Inclusion Setting' string. Only English output is understood; anything else returns Understood = $false.
    [CmdletBinding()]
    param([AllowNull()] [string] $Setting)
    $text = "$Setting".Trim()
    if ($text -match '^(?i)No Auditing$') { return [pscustomobject]@{ Understood = $true; Success = $false; Failure = $false } }
    if ($text -match '^(?i)Success and Failure$') { return [pscustomobject]@{ Understood = $true; Success = $true; Failure = $true } }
    if ($text -match '^(?i)Success$') { return [pscustomobject]@{ Understood = $true; Success = $true; Failure = $false } }
    if ($text -match '^(?i)Failure$') { return [pscustomobject]@{ Understood = $true; Success = $false; Failure = $true } }
    return [pscustomobject]@{ Understood = $false; Success = $false; Failure = $false }
}

function Get-ADSADcSubsection {
    # Returns @{ Ok; Error; Category; Data } for a per-DC sub-collection (Ldap, Spooler, AuditPolicy, SecurityLog).
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Dc, [Parameter(Mandatory)] [string] $Name)
    $reachable = Get-ADSAProp -InputObject $Dc -Name 'Reachable' -Default $true
    if ($reachable -eq $false) {
        return [pscustomobject]@{ Ok = $false; Error = "$(Get-ADSAProp -InputObject $Dc -Name 'Error' -Default 'Domain controller was not reachable.')"; Category = "$(Get-ADSAProp -InputObject $Dc -Name 'ErrorCategory' -Default 'Unreachable')"; Data = $null }
    }
    $sub = Get-ADSAProp -InputObject $Dc -Name $Name
    if ($null -eq $sub) { return [pscustomobject]@{ Ok = $false; Error = "$Name data was not collected."; Category = 'NotCollected'; Data = $null } }
    if ("$(Get-ADSAProp -InputObject $sub -Name 'Status')" -ne 'Collected') {
        return [pscustomobject]@{ Ok = $false; Error = "$(Get-ADSAProp -InputObject $sub -Name 'Error' -Default "$Name was not collected.")"; Category = "$(Get-ADSAProp -InputObject $sub -Name 'ErrorCategory' -Default 'Error')"; Data = $null }
    }
    return [pscustomobject]@{ Ok = $true; Error = ''; Category = ''; Data = $sub }
}

function Invoke-ADSAPerDcRule {
    <#
    .SYNOPSIS
        Runs an evaluator for each domain controller and completes the rule.
    .DESCRIPTION
        Evaluator receives ($dc, $sub) and returns @{ Outcome = Pass|Fail|NotAssessed; Evidence; Severity; Confidence; Message }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] [string] $RuleId, [Parameter(Mandatory)] [string] $Subsection, [Parameter(Mandatory)] [scriptblock] $Evaluator)
    $dcSection = Get-ADSASectionState -Context $Context -Name 'DcHosts'
    if ($dcSection.State -ne 'Ok') { New-ADSASectionResult -Context $Context -RuleId $RuleId -Section $dcSection -SectionName 'DcHosts'; return }
    $fails = New-Object System.Collections.Generic.List[object]; $errs = New-Object System.Collections.Generic.List[object]; $na = New-Object System.Collections.Generic.List[object]
    $eval = 0
    foreach ($dc in @($dcSection.Data)) {
        $name = "$(Get-ADSAProp -InputObject $dc -Name 'Name' -Default (Get-ADSAProp -InputObject $dc -Name 'HostName' -Default ''))"
        if (Test-ADSAExcluded -Context $Context -RuleId $RuleId -Name $name -DistinguishedName '' -Kind computer) { continue }
        $sub = Get-ADSADcSubsection -Dc $dc -Name $Subsection
        if (-not $sub.Ok) { $errs.Add(@{ Object = $name; ObjectType = 'DomainController'; Category = $sub.Category; Message = $sub.Error }); continue }
        $r = & $Evaluator $dc $sub.Data
        switch ($r.Outcome) {
            'Pass' { $eval++ }
            'Fail' { $eval++; $fails.Add(@{ Object = $name; ObjectType = 'DomainController'; Evidence = (Get-ADSAProp -InputObject $r -Name 'Evidence'); Severity = (Get-ADSAProp -InputObject $r -Name 'Severity'); Confidence = (Get-ADSAProp -InputObject $r -Name 'Confidence'); Explanation = (Get-ADSAProp -InputObject $r -Name 'Explanation') }) }
            'NotAssessed' { $na.Add(@{ Object = $name; ObjectType = 'DomainController'; Message = (Get-ADSAProp -InputObject $r -Name 'Message') }) }
        }
    }
    Complete-ADSARule -Context $Context -RuleId $RuleId -Fail $fails.ToArray() -Errors $errs.ToArray() -NotAssessed $na.ToArray() -Evaluated $eval -ObjectType 'DomainController' -Scope 'domain controllers'
}

function Invoke-ADSAAuthenticationPolicyAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config)
    $ctx = New-ADSAContext -Snapshot $Snapshot -Config $Config
    $pp = $Config['passwordPolicy']
    $domainName = "$(Get-ADSAProp -InputObject (Get-ADSAProp -InputObject $Snapshot -Name 'domain') -Name 'name' -Default '')"

    # ---- domain password policy (POL-001..006)
    $polRules = 'ADSA-POL-001', 'ADSA-POL-002', 'ADSA-POL-003', 'ADSA-POL-004', 'ADSA-POL-005', 'ADSA-POL-006'
    $policy = Get-ADSASectionState -Context $ctx -Name 'PasswordPolicy'
    if ($policy.State -ne 'Ok' -or $null -eq $policy.Data) {
        $sec = if ($policy.State -eq 'Ok') { [pscustomobject]@{ State = 'NotAssessed'; Error = 'Password policy section contained no data.'; Category = '' } } else { $policy }
        foreach ($r in $polRules) { New-ADSASectionResult -Context $ctx -RuleId $r -Section $sec -SectionName 'PasswordPolicy' }
    } else {
        $p = $policy.Data
        $checks = @(
            @{ Id = 'ADSA-POL-001'; Prop = 'MinPasswordLength'; Test = { param($v) [int]$v -lt [int]$pp['minLength'] }; Ev = { param($v) [ordered]@{ MinPasswordLength = [int]$v; Required = [int]$pp['minLength'] } } }
            @{ Id = 'ADSA-POL-002'; Prop = 'ComplexityEnabled'; Applicable = [bool]$pp['complexityRequired']; Test = { param($v) $v -eq $false }; Ev = { param($v) [ordered]@{ ComplexityEnabled = $false } } }
            @{ Id = 'ADSA-POL-003'; Prop = 'PasswordHistoryCount'; Test = { param($v) [int]$v -lt [int]$pp['minHistory'] }; Ev = { param($v) [ordered]@{ PasswordHistoryCount = [int]$v; Required = [int]$pp['minHistory'] } } }
            @{ Id = 'ADSA-POL-004'; Prop = 'LockoutThreshold'; Test = { param($v) ([int]$v -eq 0) -or ([int]$v -gt [int]$pp['lockoutThresholdMax']) }; Ev = { param($v) [ordered]@{ LockoutThreshold = [int]$v; Maximum = [int]$pp['lockoutThresholdMax']; Note = $(if ([int]$v -eq 0) { 'Account lockout is disabled' } else { 'Threshold exceeds the configured maximum' }) } } }
            @{ Id = 'ADSA-POL-006'; Prop = 'ReversibleEncryptionEnabled'; Test = { param($v) $v -eq $true }; Ev = { param($v) [ordered]@{ ReversibleEncryptionEnabled = $true } } }
        )
        foreach ($c in $checks) {
            if ($c.ContainsKey('Applicable') -and -not $c.Applicable) {
                New-ADSAResult -Context $ctx -RuleId $c.Id -Status 'NOT_APPLICABLE' -Explanation 'Complexity is not required by the configured baseline (passwordPolicy.complexityRequired = false).'
                continue
            }
            if (-not (Test-ADSAHasProp -InputObject $p -Name $c.Prop) -or $null -eq (Get-ADSAProp -InputObject $p -Name $c.Prop)) {
                Complete-ADSARule -Context $ctx -RuleId $c.Id -Fail @() -Evaluated 0 -Skipped 1 -SkipReason "$($c.Prop) is missing from the collected policy" -Scope 'policy settings'
                continue
            }
            $v = Get-ADSAProp -InputObject $p -Name $c.Prop
            $bad = & $c.Test $v
            $fail = @()
            if ($bad) { $fail = @(@{ Object = $domainName; ObjectType = 'Domain'; Evidence = (& $c.Ev $v) }) }
            Complete-ADSARule -Context $ctx -RuleId $c.Id -Fail $fail -Evaluated 1 -ObjectType 'Domain' -Scope 'policy settings'
        }
        # POL-005 lockout duration (only meaningful when lockout is enabled)
        $thr = Get-ADSAProp -InputObject $p -Name 'LockoutThreshold'
        $dur = Get-ADSAProp -InputObject $p -Name 'LockoutDurationMinutes'
        if ($null -eq $thr) {
            Complete-ADSARule -Context $ctx -RuleId 'ADSA-POL-005' -Fail @() -Evaluated 0 -Skipped 1 -SkipReason 'LockoutThreshold is missing from the collected policy' -Scope 'policy settings'
        } elseif ([int]$thr -eq 0) {
            New-ADSAResult -Context $ctx -RuleId 'ADSA-POL-005' -Status 'NOT_APPLICABLE' -Explanation 'Account lockout is disabled, so duration is not applicable (see ADSA-POL-004).'
        } elseif ($null -eq $dur) {
            Complete-ADSARule -Context $ctx -RuleId 'ADSA-POL-005' -Fail @() -Evaluated 0 -Skipped 1 -SkipReason 'LockoutDurationMinutes is missing from the collected policy' -Scope 'policy settings'
        } else {
            $fail = @()
            # 0 minutes = locked until an administrator unlocks the account (strongest setting)
            if ([int]$dur -ne 0 -and [int]$dur -lt [int]$pp['lockoutDurationMinMinutes']) {
                $fail = @(@{ Object = $domainName; ObjectType = 'Domain'; Evidence = [ordered]@{ LockoutDurationMinutes = [int]$dur; Required = [int]$pp['lockoutDurationMinMinutes'] } })
            }
            Complete-ADSARule -Context $ctx -RuleId 'ADSA-POL-005' -Fail $fail -Evaluated 1 -ObjectType 'Domain' -Scope 'policy settings'
        }
    }

    # ---- KRB-001 krbtgt password age
    $users = Get-ADSASectionState -Context $ctx -Name 'Users'
    if ($users.State -ne 'Ok') {
        New-ADSASectionResult -Context $ctx -RuleId 'ADSA-KRB-001' -Section $users -SectionName 'Users'
    } else {
        $krb = @($users.Data | Where-Object { "$(Get-ADSAProp -InputObject $_ -Name 'SamAccountName' -Default '')" -ieq 'krbtgt' })
        if ($krb.Count -eq 0) {
            New-ADSAResult -Context $ctx -RuleId 'ADSA-KRB-001' -Status 'NOT_ASSESSED' -Explanation 'The krbtgt account was not present in the collected Users data.'
        } else {
            Invoke-ADSAObjectRule -Context $ctx -RuleId 'ADSA-KRB-001' -Objects $krb -Kind user -ObjectType 'User' -Scope 'krbtgt accounts' -Evaluator {
                param($u)
                if (-not (Test-ADSAHasProp -InputObject $u -Name 'PasswordLastSet')) { return @{ Outcome = 'Skip'; SkipReason = 'pwdLastSet was not retrieved' } }
                $set = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $u -Name 'PasswordLastSet')
                if ($null -eq $set) { return @{ Outcome = 'Skip'; SkipReason = 'pwdLastSet is empty or malformed' } }
                $age = Get-ADSADaysBetween -From $set -To $ctx.ReferenceTime
                $max = [int]$Config['thresholds']['krbtgtMaxAgeDays']
                if ($age -gt $max) { return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = "$(Get-ADSAProp -InputObject $u -Name 'DistinguishedName')"; PasswordLastSet = (Format-ADSAIsoTime -Value $set); PasswordAgeDays = $age; ThresholdDays = $max } } }
                return @{ Outcome = 'Pass' }
            }
        }
    }

    # ---- per-DC rules
    Invoke-ADSAPerDcRule -Context $ctx -RuleId 'ADSA-LDAP-001' -Subsection 'Ldap' -Evaluator {
        param($dc, $ldap)
        $v = Get-ADSAProp -InputObject $ldap -Name 'ServerIntegrity'
        $os = "$(Get-ADSAProp -InputObject $dc -Name 'OperatingSystem' -Default '')"
        if ($null -eq $v) {
            if ($os -match '2025') { return @{ Outcome = 'NotAssessed'; Message = 'LDAPServerIntegrity is not set and the default on this OS version is not asserted by this toolkit; verify the effective value.' } }
            return @{ Outcome = 'Fail'; Confidence = 'Medium'; Evidence = [ordered]@{ LDAPServerIntegrity = 'NotSet'; OperatingSystem = $os; Note = 'Signing is not explicitly required; the OS default (negotiate) applies unless a GPO or newer OS default says otherwise.' } }
        }
        if ([int]$v -ge 2) { return @{ Outcome = 'Pass' } }
        return @{ Outcome = 'Fail'; Evidence = [ordered]@{ LDAPServerIntegrity = [int]$v; Required = 2 } }
    }
    Invoke-ADSAPerDcRule -Context $ctx -RuleId 'ADSA-LDAP-002' -Subsection 'Ldap' -Evaluator {
        param($dc, $ldap)
        $v = Get-ADSAProp -InputObject $ldap -Name 'ChannelBinding'
        if ($null -ne $v -and [int]$v -ge 2) { return @{ Outcome = 'Pass' } }
        if ($null -ne $v -and [int]$v -eq 1) { return @{ Outcome = 'Fail'; Severity = 'Low'; Evidence = [ordered]@{ LdapEnforceChannelBinding = 1; Note = 'Enforced only for clients that support channel binding' } } }
        $shown = if ($null -eq $v) { 'NotSet' } else { [int]$v }
        return @{ Outcome = 'Fail'; Confidence = $(if ($null -eq $v) { 'Medium' } else { 'High' }); Evidence = [ordered]@{ LdapEnforceChannelBinding = $shown; Required = 2 } }
    }
    Invoke-ADSAPerDcRule -Context $ctx -RuleId 'ADSA-DC-001' -Subsection 'Spooler' -Evaluator {
        param($dc, $svc)
        $state = "$(Get-ADSAProp -InputObject $svc -Name 'State' -Default '')"
        if (-not $state) { return @{ Outcome = 'NotAssessed'; Message = 'Print Spooler state was not returned.' } }
        if ($state -ieq 'Running') { return @{ Outcome = 'Fail'; Evidence = [ordered]@{ Service = 'Spooler'; State = $state } } }
        return @{ Outcome = 'Pass' }
    }
    Invoke-ADSAPerDcRule -Context $ctx -RuleId 'ADSA-AUD-001' -Subsection 'AuditPolicy' -Evaluator {
        param($dc, $audit)
        $entries = @(Get-ADSAProp -InputObject $audit -Name 'Entries' -Default @())
        $missing = New-Object System.Collections.Generic.List[object]
        foreach ($req in @($Config['auditPolicy']['required'])) {
            $guid = ("$($req['guid'])").Trim('{', '}')
            $entry = $entries | Where-Object { ("$(Get-ADSAProp -InputObject $_ -Name 'Guid' -Default '')").Trim('{', '}') -ieq $guid } | Select-Object -First 1
            if ($null -eq $entry) { return @{ Outcome = 'NotAssessed'; Message = "Subcategory '$($req['name'])' was not reported by auditpol." } }
            $parsed = ConvertFrom-ADSAAuditSetting -Setting (Get-ADSAProp -InputObject $entry -Name 'Setting')
            if (-not $parsed.Understood) { return @{ Outcome = 'NotAssessed'; Message = "Audit setting text '$(Get-ADSAProp -InputObject $entry -Name 'Setting')' was not understood (non-English auditpol output?)." } }
            $needS = ($req['success'] -eq $true); $needF = ($req['failure'] -eq $true)
            if (($needS -and -not $parsed.Success) -or ($needF -and -not $parsed.Failure)) {
                $missing.Add([ordered]@{ Subcategory = "$($req['name'])"; Configured = "$(Get-ADSAProp -InputObject $entry -Name 'Setting')"; RequiredSuccess = $needS; RequiredFailure = $needF })
            }
        }
        if ($missing.Count -gt 0) { return @{ Outcome = 'Fail'; Evidence = [ordered]@{ MissingCoverage = $missing.ToArray() } } }
        return @{ Outcome = 'Pass' }
    }
    Invoke-ADSAPerDcRule -Context $ctx -RuleId 'ADSA-AUD-002' -Subsection 'SecurityLog' -Evaluator {
        param($dc, $log)
        $size = Get-ADSAProp -InputObject $log -Name 'MaximumSizeInBytes'
        if ($null -eq $size) { return @{ Outcome = 'NotAssessed'; Message = 'Security log maximum size was not returned.' } }
        $minBytes = [int64]$Config['securityLog']['minSizeMB'] * 1MB
        if ([int64]$size -lt $minBytes) {
            return @{ Outcome = 'Fail'; Evidence = [ordered]@{ MaximumSizeMB = [math]::Round([int64]$size / 1MB, 1); RequiredMB = [int64]$Config['securityLog']['minSizeMB']; LogMode = "$(Get-ADSAProp -InputObject $log -Name 'LogMode' -Default '')" } }
        }
        return @{ Outcome = 'Pass' }
    }
}
