# Privileged access audit module: administrative group membership (with nesting and cycle detection),
# privileged account hygiene, and orphaned AdminSDHolder protection (adminCount).

function Invoke-ADSAPrivilegedAccessAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config)
    $ctx = New-ADSAContext -Snapshot $Snapshot -Config $Config
    $now = $ctx.ReferenceTime
    $th = $Config['thresholds']
    $rules = 'ADSA-PRV-001', 'ADSA-PRV-002', 'ADSA-PRV-003', 'ADSA-PRV-004', 'ADSA-PRV-005', 'ADSA-PRV-006', 'ADSA-PRV-007', 'ADSA-PRV-008'

    $users = Get-ADSASectionState -Context $ctx -Name 'Users'
    $groups = Get-ADSASectionState -Context $ctx -Name 'Groups'
    $unusable = @()
    if ($users.State -ne 'Ok') { $unusable += , @{ Name = 'Users'; State = $users } }
    if ($groups.State -ne 'Ok') { $unusable += , @{ Name = 'Groups'; State = $groups } }
    if ($unusable.Count -gt 0) {
        $first = $unusable[0]
        $secName = (@($unusable | ForEach-Object { $_.Name }) -join '/')
        foreach ($r in $rules) { New-ADSASectionResult -Context $ctx -RuleId $r -Section $first.State -SectionName $secName }
        return
    }
    # Computers are only used to classify members; a missing section degrades resolution but is not fatal
    $computers = Get-ADSASectionState -Context $ctx -Name 'Computers'
    $compNote = if ($computers.State -ne 'Ok') { 'Computers section unavailable: computer members of privileged groups are reported as unresolved.' } else { '' }

    $index = Get-ADSAPrivilegedIndex -Context $ctx
    if (-not $index.AnyFound) {
        foreach ($r in $rules) {
            New-ADSAResult -Context $ctx -RuleId $r -Status 'NOT_ASSESSED' -Explanation 'None of the configured privileged groups were found in the collected Groups data (check collection completeness and the privilegedGroups configuration).' -Evidence ([ordered]@{ ConfiguredGroups = @($index.Groups | ForEach-Object { $_.Name }) })
        }
        return
    }

    # ---- PRV-001 group size
    $fail1 = New-Object System.Collections.Generic.List[object]; $eval1 = 0
    $maxMap = $Config['privilegedGroupMaxMembers']
    foreach ($g in $index.Groups) {
        if (-not $g.Found) { continue }
        if (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-PRV-001' -Name $g.Name -DistinguishedName $g.Dn -Kind group) { continue }
        $eval1++
        $max = if ($maxMap.Contains($g.Name)) { [int]$maxMap[$g.Name] } else { [int]$maxMap['default'] }
        $count = @($g.Members).Count
        if ($count -gt $max) {
            $names = @($g.Members | ForEach-Object { ($_.DistinguishedName -split ',')[0] -replace '^CN=', '' } | Select-Object -First 25)
            $fail1.Add(@{ Object = $g.Name; ObjectType = 'Group'; Evidence = [ordered]@{ DistinguishedName = $g.Dn; EffectiveMemberCount = $count; Maximum = $max; NestedGroupCount = @($g.NestedGroups).Count; SampleMembers = $names } })
        }
    }
    Complete-ADSARule -Context $ctx -RuleId 'ADSA-PRV-001' -Fail $fail1.ToArray() -Evaluated $eval1 -ObjectType 'Group' -Scope 'privileged groups' -ExtraLimitation $compNote

    # ---- Per-principal rules (users only; computers in privileged groups are DCs or documented separately)
    $userPrincipals = @($index.Principals.Values | Where-Object { $_.ObjectClass -eq 'user' })
    $principalRules = @(
        @{ Id = 'ADSA-PRV-002' }, @{ Id = 'ADSA-PRV-003' }, @{ Id = 'ADSA-PRV-004' }, @{ Id = 'ADSA-PRV-006' }
    )
    foreach ($pr in $principalRules) {
        $ruleId = $pr.Id
        Invoke-ADSAObjectRule -Context $ctx -RuleId $ruleId -Objects @($userPrincipals | ForEach-Object { $_.Object }) -Kind user -ObjectType 'PrivilegedUser' -Scope 'privileged user accounts' -Evaluator {
            param($u)
            $dn = "$(Get-ADSAProp -InputObject $u -Name 'DistinguishedName')"
            $member = $index.Principals[$dn]
            $via = @($member.Memberships | ForEach-Object { if ($_.IsNested) { "$($_.Group) (nested via $(@($_.Path | Select-Object -Skip 1 | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }) -join ' > '))" } else { $_.Group } })
            $uac = Get-ADSAUac -InputObject $u
            $enabled = Get-ADSAEnabled -InputObject $u
            if ($null -eq $uac -or $null -eq $enabled) { return @{ Outcome = 'Skip'; SkipReason = 'userAccountControl unavailable' } }
            switch ($ruleId) {
                'ADSA-PRV-002' {
                    if (-not $enabled) { return @{ Outcome = 'Fail'; Severity = 'Low'; Evidence = [ordered]@{ DistinguishedName = $dn; Reason = 'Disabled'; Groups = $via } } }
                    if (-not (Test-ADSAHasProp -InputObject $u -Name 'LastLogonTimestamp')) { return @{ Outcome = 'Skip'; SkipReason = 'lastLogonTimestamp was not retrieved' } }
                    $last = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $u -Name 'LastLogonTimestamp')
                    if ($null -eq $last) { return @{ Outcome = 'Pass' } }
                    $days = Get-ADSADaysBetween -From $last -To $now
                    if ($days -gt [int]$th['staleUserDays']) { return @{ Outcome = 'Fail'; Severity = 'High'; Evidence = [ordered]@{ DistinguishedName = $dn; Reason = 'Stale'; DaysSinceLastLogon = $days; ThresholdDays = [int]$th['staleUserDays']; Groups = $via } } }
                    return @{ Outcome = 'Pass' }
                }
                'ADSA-PRV-003' {
                    if (-not $enabled) { return @{ Outcome = 'NotInScope' } }
                    if (Test-ADSAUacFlag -Uac $uac -Flag 'DONT_EXPIRE_PASSWORD') { return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = $dn; Flag = 'DONT_EXPIRE_PASSWORD'; Groups = $via } } }
                    return @{ Outcome = 'Pass' }
                }
                'ADSA-PRV-004' {
                    if (-not $enabled) { return @{ Outcome = 'NotInScope' } }
                    $spns = Get-ADSAList -InputObject $u -Name 'ServicePrincipalNames'
                    if ($spns.Count -gt 0) { return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = $dn; ServicePrincipalNames = $spns; Groups = $via } } }
                    return @{ Outcome = 'Pass' }
                }
                'ADSA-PRV-006' {
                    if (-not $enabled) { return @{ Outcome = 'NotInScope' } }
                    if (-not (Test-ADSAUacFlag -Uac $uac -Flag 'NOT_DELEGATED')) { return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = $dn; AccountIsSensitiveAndCannotBeDelegated = $false; Groups = $via } } }
                    return @{ Outcome = 'Pass' }
                }
            }
        }
    }

    # ---- PRV-005 Schema Admins populated
    $schemaGroup = $index.Groups | Where-Object { $_.Found -and $_.Sid -and (Get-ADSASidRid -Sid $_.Sid) -eq 518 } | Select-Object -First 1
    if ($null -eq $schemaGroup) {
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-PRV-005' -Fail @() -Evaluated 0 -Scope 'Schema Admins groups'
    } elseif (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-PRV-005' -Name $schemaGroup.Name -DistinguishedName $schemaGroup.Dn -Kind group) {
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-PRV-005' -Fail @() -Evaluated 0 -Scope 'Schema Admins groups'
    } else {
        $fail5 = @()
        if (@($schemaGroup.Members).Count -gt 0) {
            $fail5 = @(@{ Object = $schemaGroup.Name; ObjectType = 'Group'; Evidence = [ordered]@{ DistinguishedName = $schemaGroup.Dn; MemberCount = @($schemaGroup.Members).Count; Members = @($schemaGroup.Members | ForEach-Object { ($_.DistinguishedName -split ',')[0] -replace '^CN=', '' }) } })
        }
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-PRV-005' -Fail $fail5 -Evaluated 1 -ObjectType 'Group' -Scope 'Schema Admins groups'
    }

    # ---- PRV-007 membership cycles reachable from privileged groups
    $fail7 = New-Object System.Collections.Generic.List[object]
    foreach ($c in $index.Cycles) {
        $names = @($c.Path | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' })
        if (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-PRV-007' -Name $names[0] -DistinguishedName $c.Path[0] -Kind group) { continue }
        $fail7.Add(@{ Object = $names[0]; ObjectType = 'Group'; Evidence = [ordered]@{ Cycle = $names; CycleDistinguishedNames = @($c.Path) } })
    }
    Complete-ADSARule -Context $ctx -RuleId 'ADSA-PRV-007' -Fail $fail7.ToArray() -Evaluated 1 -ObjectType 'Group' -Scope 'privileged group graphs'

    # ---- PRV-008 orphaned adminCount=1
    $allUsers = @($users.Data)
    $privDns = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $index.Principals.Keys) { [void]$privDns.Add($k) }
    Invoke-ADSAObjectRule -Context $ctx -RuleId 'ADSA-PRV-008' -Objects $allUsers -Kind user -ObjectType 'User' -Scope 'user accounts' -Evaluator {
        param($u)
        if (-not (Test-ADSAHasProp -InputObject $u -Name 'AdminCount')) { return @{ Outcome = 'Skip'; SkipReason = 'adminCount was not retrieved' } }
        $dn = "$(Get-ADSAProp -InputObject $u -Name 'DistinguishedName')"
        $sid = "$(Get-ADSAProp -InputObject $u -Name 'Sid' -Default '')"
        if ((Get-ADSASidRid -Sid $sid) -eq 502) { return @{ Outcome = 'NotInScope' } }   # krbtgt always carries adminCount=1
        if ("$(Get-ADSAProp -InputObject $u -Name 'AdminCount')" -ne '1') { return @{ Outcome = 'Pass' } }
        if ($privDns.Contains($dn)) { return @{ Outcome = 'Pass' } }
        return @{ Outcome = 'Fail'; Evidence = [ordered]@{ DistinguishedName = $dn; AdminCount = 1; Enabled = (Get-ADSAEnabled -InputObject $u) } }
    }
}
