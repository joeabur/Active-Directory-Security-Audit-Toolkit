# Account lifecycle audit module: stale/inactive accounts, password settings, authentication-affecting flags, SPN accounts.
# A stale account is hygiene evidence, not a confirmed vulnerability; rule metadata carries that distinction.

function Invoke-ADSAAccountLifecycleAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config)
    $ctx = New-ADSAContext -Snapshot $Snapshot -Config $Config
    $now = $ctx.ReferenceTime
    $th = $Config['thresholds']
    $users = Get-ADSASectionState -Context $ctx -Name 'Users'
    $computers = Get-ADSASectionState -Context $ctx -Name 'Computers'

    $userRules = 'ADSA-ACC-001', 'ADSA-ACC-003', 'ADSA-ACC-004', 'ADSA-ACC-005', 'ADSA-ACC-006', 'ADSA-ACC-007', 'ADSA-ACC-008', 'ADSA-SVC-001'
    if ($users.State -ne 'Ok') {
        foreach ($r in $userRules) { New-ADSASectionResult -Context $ctx -RuleId $r -Section $users -SectionName 'Users' }
    } else {
        $all = @($users.Data)
        $userIndex = New-ADSADnIndex -Objects $all

        # ACC-001 stale enabled users (has logged on at some point, but not within the threshold)
        Invoke-ADSAObjectRule -Context $ctx -RuleId 'ADSA-ACC-001' -Objects $all -Kind user -ObjectType 'User' -Scope 'enabled user accounts' -Evaluator {
            param($u)
            $enabled = Get-ADSAEnabled -InputObject $u
            if ($null -eq $enabled) { return @{ Outcome = 'Skip'; SkipReason = 'Enabled state / userAccountControl unavailable' } }
            if (-not $enabled) { return @{ Outcome = 'NotInScope' } }
            if (-not (Test-ADSAHasProp -InputObject $u -Name 'LastLogonTimestamp')) { return @{ Outcome = 'Skip'; SkipReason = 'lastLogonTimestamp was not retrieved' } }
            $last = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $u -Name 'LastLogonTimestamp')
            if ($null -eq $last) { return @{ Outcome = 'NotInScope' } }   # never logged on: see ADSA-ACC-008
            $days = Get-ADSADaysBetween -From $last -To $now
            if ($days -gt [int]$th['staleUserDays']) {
                return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = "$(Get-ADSAProp -InputObject $u -Name 'DistinguishedName')"; LastLogonTimestamp = (Format-ADSAIsoTime -Value $last); DaysSinceLastLogon = $days; ThresholdDays = [int]$th['staleUserDays']; Note = 'lastLogonTimestamp replicates with up to ~14 days of lag' } }
            }
            return @{ Outcome = 'Pass' }
        }

        # ACC-008 enabled accounts that have never logged on, older than the grace period
        Invoke-ADSAObjectRule -Context $ctx -RuleId 'ADSA-ACC-008' -Objects $all -Kind user -ObjectType 'User' -Scope 'enabled user accounts' -Evaluator {
            param($u)
            $enabled = Get-ADSAEnabled -InputObject $u
            if ($null -eq $enabled) { return @{ Outcome = 'Skip'; SkipReason = 'Enabled state / userAccountControl unavailable' } }
            if (-not $enabled) { return @{ Outcome = 'NotInScope' } }
            if (-not (Test-ADSAHasProp -InputObject $u -Name 'LastLogonTimestamp') -or -not (Test-ADSAHasProp -InputObject $u -Name 'WhenCreated')) { return @{ Outcome = 'Skip'; SkipReason = 'lastLogonTimestamp or whenCreated was not retrieved' } }
            $last = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $u -Name 'LastLogonTimestamp')
            if ($null -ne $last) { return @{ Outcome = 'NotInScope' } }
            $created = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $u -Name 'WhenCreated')
            if ($null -eq $created) { return @{ Outcome = 'Skip'; SkipReason = 'whenCreated is missing or malformed' } }
            $age = Get-ADSADaysBetween -From $created -To $now
            if ($age -gt [int]$th['neverLoggedOnGraceDays']) {
                return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = "$(Get-ADSAProp -InputObject $u -Name 'DistinguishedName')"; WhenCreated = (Format-ADSAIsoTime -Value $created); AccountAgeDays = $age; GraceDays = [int]$th['neverLoggedOnGraceDays'] } }
            }
            return @{ Outcome = 'Pass' }
        }

        # Flag-based rules share one evaluator shape
        $flagRules = @(
            @{ Id = 'ADSA-ACC-003'; Flags = @('DONT_EXPIRE_PASSWORD') }
            @{ Id = 'ADSA-ACC-005'; Flags = @('PASSWD_NOTREQD') }
            @{ Id = 'ADSA-ACC-006'; Flags = @('DONT_REQ_PREAUTH') }
            @{ Id = 'ADSA-ACC-007'; Flags = @('USE_DES_KEY_ONLY', 'ENCRYPTED_TEXT_PWD_ALLOWED') }
        )
        foreach ($fr in $flagRules) {
            $flags = $fr.Flags
            Invoke-ADSAObjectRule -Context $ctx -RuleId $fr.Id -Objects $all -Kind user -ObjectType 'User' -Scope 'enabled user accounts' -Evaluator {
                param($u)
                $uac = Get-ADSAUac -InputObject $u
                $enabled = Get-ADSAEnabled -InputObject $u
                if ($null -eq $uac -or $null -eq $enabled) { return @{ Outcome = 'Skip'; SkipReason = 'userAccountControl unavailable' } }
                if (-not $enabled) { return @{ Outcome = 'NotInScope' } }
                $set = @($flags | Where-Object { Test-ADSAUacFlag -Uac $uac -Flag $_ })
                if ($set.Count -gt 0) {
                    return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = "$(Get-ADSAProp -InputObject $u -Name 'DistinguishedName')"; FlagsSet = $set; UserAccountControl = $uac } }
                }
                return @{ Outcome = 'Pass' }
            }
        }

        # ACC-004 potentially orphaned: enabled account whose manager resolves to a disabled account
        Invoke-ADSAObjectRule -Context $ctx -RuleId 'ADSA-ACC-004' -Objects $all -Kind user -ObjectType 'User' -Scope 'enabled user accounts with a manager' -Evaluator {
            param($u)
            $enabled = Get-ADSAEnabled -InputObject $u
            if ($null -eq $enabled) { return @{ Outcome = 'Skip'; SkipReason = 'Enabled state / userAccountControl unavailable' } }
            $managerDn = "$(Get-ADSAProp -InputObject $u -Name 'Manager' -Default '')"
            if (-not $enabled -or -not $managerDn) { return @{ Outcome = 'NotInScope' } }
            if (-not $userIndex.ContainsKey($managerDn)) { return @{ Outcome = 'Skip'; SkipReason = 'manager object is outside the collected user set (contact, other domain or unreadable)' } }
            $manager = $userIndex[$managerDn]
            $mEnabled = Get-ADSAEnabled -InputObject $manager
            if ($null -eq $mEnabled) { return @{ Outcome = 'Skip'; SkipReason = 'manager state unavailable' } }
            if (-not $mEnabled) {
                return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = "$(Get-ADSAProp -InputObject $u -Name 'DistinguishedName')"; Manager = $managerDn; ManagerEnabled = $false } }
            }
            return @{ Outcome = 'Pass' }
        }

        # SVC-001 service accounts (users with SPNs) with old passwords
        Invoke-ADSAObjectRule -Context $ctx -RuleId 'ADSA-SVC-001' -Objects $all -Kind user -ObjectType 'ServiceAccount' -Scope 'enabled user accounts with SPNs' -Evaluator {
            param($u)
            $enabled = Get-ADSAEnabled -InputObject $u
            if ($null -eq $enabled) { return @{ Outcome = 'Skip'; SkipReason = 'Enabled state / userAccountControl unavailable' } }
            $spns = Get-ADSAList -InputObject $u -Name 'ServicePrincipalNames'
            if (-not $enabled -or $spns.Count -eq 0 -or "$(Get-ADSAProp -InputObject $u -Name 'SamAccountName')" -like 'krbtgt*') { return @{ Outcome = 'NotInScope' } }
            if (-not (Test-ADSAHasProp -InputObject $u -Name 'PasswordLastSet')) { return @{ Outcome = 'Skip'; SkipReason = 'pwdLastSet was not retrieved' } }
            $set = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $u -Name 'PasswordLastSet')
            if ($null -eq $set) { return @{ Outcome = 'Skip'; SkipReason = 'password last set is empty (must change at next logon) or malformed' } }
            $age = Get-ADSADaysBetween -From $set -To $now
            if ($age -gt [int]$th['servicePasswordMaxAgeDays']) {
                return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = "$(Get-ADSAProp -InputObject $u -Name 'DistinguishedName')"; PasswordLastSet = (Format-ADSAIsoTime -Value $set); PasswordAgeDays = $age; ThresholdDays = [int]$th['servicePasswordMaxAgeDays']; ServicePrincipalNames = $spns } }
            }
            return @{ Outcome = 'Pass' }
        }
    }

    # ACC-002 inactive computers
    if ($computers.State -ne 'Ok') {
        New-ADSASectionResult -Context $ctx -RuleId 'ADSA-ACC-002' -Section $computers -SectionName 'Computers'
    } else {
        Invoke-ADSAObjectRule -Context $ctx -RuleId 'ADSA-ACC-002' -Objects @($computers.Data) -Kind computer -ObjectType 'Computer' -Scope 'enabled non-DC computer accounts' -Evaluator {
            param($c)
            $uac = Get-ADSAUac -InputObject $c
            $enabled = Get-ADSAEnabled -InputObject $c
            if ($null -eq $enabled -or $null -eq $uac) { return @{ Outcome = 'Skip'; SkipReason = 'Enabled state / userAccountControl unavailable' } }
            if (-not $enabled -or (Test-ADSAUacFlag -Uac $uac -Flag 'SERVER_TRUST_ACCOUNT')) { return @{ Outcome = 'NotInScope' } }
            $hasLogon = Test-ADSAHasProp -InputObject $c -Name 'LastLogonTimestamp'
            $hasPwd = Test-ADSAHasProp -InputObject $c -Name 'PasswordLastSet'
            if (-not $hasLogon -and -not $hasPwd) { return @{ Outcome = 'Skip'; SkipReason = 'neither lastLogonTimestamp nor pwdLastSet was retrieved' } }
            $logon = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $c -Name 'LastLogonTimestamp')
            $pwdSet = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $c -Name 'PasswordLastSet')
            $latest = @($logon, $pwdSet | Where-Object { $null -ne $_ } | Sort-Object -Descending | Select-Object -First 1)
            $limit = [int]$th['staleComputerDays']
            if ($latest.Count -eq 0) {
                $created = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $c -Name 'WhenCreated')
                if ($null -eq $created) { return @{ Outcome = 'Skip'; SkipReason = 'no activity timestamps and whenCreated missing' } }
                if ((Get-ADSADaysBetween -From $created -To $now) -gt $limit) {
                    return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = "$(Get-ADSAProp -InputObject $c -Name 'DistinguishedName')"; LastActivity = $null; WhenCreated = (Format-ADSAIsoTime -Value $created); ThresholdDays = $limit; OperatingSystem = "$(Get-ADSAProp -InputObject $c -Name 'OperatingSystem' -Default '')" } }
                }
                return @{ Outcome = 'Pass' }
            }
            $days = Get-ADSADaysBetween -From $latest[0] -To $now
            if ($days -gt $limit) {
                return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = "$(Get-ADSAProp -InputObject $c -Name 'DistinguishedName')"; LastActivity = (Format-ADSAIsoTime -Value $latest[0]); DaysInactive = $days; ThresholdDays = $limit; OperatingSystem = "$(Get-ADSAProp -InputObject $c -Name 'OperatingSystem' -Default '')" } }
            }
            return @{ Outcome = 'Pass' }
        }
    }
}
