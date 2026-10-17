# ACL analysis module. Independent of the other audit modules: it consumes only the 'Acls' and 'Gpos'
# snapshot sections and the shared result helpers. It interprets already-collected ACEs; it never writes ACLs.
#
# Coverage is deliberately selective: domain root, AdminSDHolder, privileged groups, the Domain Controllers OU,
# domain controller objects and GPO containers. It does not claim to find every ACL-based attack path.

$script:ADSAEmptyGuid = '00000000-0000-0000-0000-000000000000'
$script:ADSARightGuid = @{
    ReplGetChanges          = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    ReplGetChangesAll       = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    ReplGetChangesFiltered  = '89e95b76-444d-4c62-991a-0facbeda640c'
    UserForceChangePassword = '00299570-246d-11d0-a768-00c04fc2dcd2'
    GroupMember             = 'bf9679c0-0de6-11d0-a285-00c04fc2dcd2'
    GpLink                  = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
}

function ConvertTo-ADSAAce {
    <#
    .SYNOPSIS
        Normalizes an ActiveDirectoryAccessRule (or any object with the same property names) to a plain ACE record.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $AccessRule, [AllowNull()] [string] $IdentitySid)
    $identity = Get-ADSAProp -InputObject $AccessRule -Name 'IdentityReference'
    $identityText = if ($null -ne $identity) { "$(Get-ADSAProp -InputObject $identity -Name 'Value' -Default "$identity")" } else { '' }
    $sid = if ($IdentitySid) { $IdentitySid } elseif ($identityText -match '^S-1-') { $identityText } else { $null }
    $rightsText = "$(Get-ADSAProp -InputObject $AccessRule -Name 'ActiveDirectoryRights' -Default '')"
    $rights = @($rightsText -split '\s*,\s*' | Where-Object { $_ })
    $inheritance = "$(Get-ADSAProp -InputObject $AccessRule -Name 'InheritanceType' -Default 'None')"
    $objType = "$(Get-ADSAProp -InputObject $AccessRule -Name 'ObjectType' -Default $script:ADSAEmptyGuid)"
    return [pscustomobject]@{
        IdentitySid         = $sid
        IdentityName        = $(if ($sid) { '' } else { $identityText })
        Rights              = $rights
        AccessControlType   = "$(Get-ADSAProp -InputObject $AccessRule -Name 'AccessControlType' -Default 'Allow')"
        ObjectType          = $objType.ToLowerInvariant()
        InheritedObjectType = "$(Get-ADSAProp -InputObject $AccessRule -Name 'InheritedObjectType' -Default $script:ADSAEmptyGuid)".ToLowerInvariant()
        IsInherited         = [bool](Get-ADSAProp -InputObject $AccessRule -Name 'IsInherited' -Default $false)
        InheritanceType     = $inheritance
    }
}

function Test-ADSAAceAppliesToObject {
    # 'Descendents' and 'Children' inheritance types are inherit-only: they never apply to the object carrying the ACE.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Ace)
    $type = "$(Get-ADSAProp -InputObject $Ace -Name 'InheritanceType' -Default 'None')"
    return ($type -notin 'Descendents', 'Children')
}

function Get-ADSATrustedSidSet {
    # Principals expected to hold powerful rights on sensitive objects, derived from well-known SIDs and configuration.
    [CmdletBinding()]
    param([AllowNull()] [string] $DomainSid, [System.Collections.IDictionary] $Config)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', 'S-1-5-10', 'S-1-5-9') { [void]$set.Add($s) }
    # 500 Administrator, 512 Domain Admins, 516 Domain Controllers, 518 Schema Admins, 519 Enterprise Admins, 498/521 (Enterprise) read-only DCs
    if ($DomainSid) { foreach ($rid in 498, 500, 512, 516, 518, 519, 521) { [void]$set.Add("$DomainSid-$rid") } }
    if ($Config) {
        $tp = $Config['trustedPrincipals']
        if ($tp) { foreach ($s in @($tp['sids'])) { if ($s) { [void]$set.Add("$s") } } }
    }
    return , $set
}

function Test-ADSAPrincipalTrusted {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Ace, [Parameter(Mandatory)] $TrustedSids, [System.Collections.IDictionary] $Config, [AllowNull()] [hashtable] $NameMap)
    $sid = Get-ADSAProp -InputObject $Ace -Name 'IdentitySid'
    if ($sid -and $TrustedSids.Contains("$sid")) { return $true }
    $name = "$(Get-ADSAProp -InputObject $Ace -Name 'IdentityName' -Default '')"
    if (-not $name -and $sid -and $NameMap -and $NameMap.ContainsKey("$sid")) { $name = "$($NameMap["$sid"])" }
    if ($name -and $Config) {
        $tp = $Config['trustedPrincipals']
        if ($tp) { foreach ($n in @($tp['names'])) { if ($n -and $name -ieq "$n") { return $true } } }
    }
    return $false
}

function Get-ADSAAceRisk {
    <#
    .SYNOPSIS
        Classifies the rights of one Allow ACE. Returns a list of risk labels (empty when no high-risk right is granted).
    .PARAMETER TargetClass
        AD object class of the object that carries the ACE (user, group, domainDNS, organizationalUnit, groupPolicyContainer, ...).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Ace, [string] $TargetClass = '')
    $risks = New-Object System.Collections.Generic.List[string]
    if ("$(Get-ADSAProp -InputObject $Ace -Name 'AccessControlType' -Default 'Allow')" -ne 'Allow') { return , $risks.ToArray() }
    if (-not (Test-ADSAAceAppliesToObject -Ace $Ace)) { return , $risks.ToArray() }
    $rights = @(Get-ADSAProp -InputObject $Ace -Name 'Rights' -Default @())
    $obj = "$(Get-ADSAProp -InputObject $Ace -Name 'ObjectType' -Default $script:ADSAEmptyGuid)".ToLowerInvariant()
    $allProps = ($obj -eq $script:ADSAEmptyGuid)
    $g = $script:ADSARightGuid

    if ('GenericAll' -in $rights) { $risks.Add('GenericAll') }
    if ('WriteDacl' -in $rights) { $risks.Add('WriteDacl') }
    if ('WriteOwner' -in $rights) { $risks.Add('WriteOwner') }
    if ('GenericWrite' -in $rights) { $risks.Add('GenericWrite') }
    if (('WriteProperty' -in $rights) -and $allProps) { $risks.Add('WriteAllProperties') }
    if (('ExtendedRight' -in $rights) -and $allProps) { $risks.Add('AllExtendedRights') }
    if (('ExtendedRight' -in $rights) -and $obj -eq $g.UserForceChangePassword -and $TargetClass -in 'user', 'inetOrgPerson', 'computer') { $risks.Add('ResetPassword') }
    if ((('WriteProperty' -in $rights) -or ('Self' -in $rights)) -and $obj -eq $g.GroupMember -and $TargetClass -eq 'group') { $risks.Add('WriteGroupMembership') }
    if (('WriteProperty' -in $rights) -and $obj -eq $g.GpLink -and $TargetClass -in 'domainDNS', 'organizationalUnit') { $risks.Add('WriteGPLink') }
    return , $risks.ToArray()
}

function Get-ADSAReplicationGrant {
    <#
    .SYNOPSIS
        For one principal's ACEs on the domain root: does it hold both directory replication rights (DCSync-capable)?
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Aces)
    $changes = $false; $changesAll = $false; $via = New-Object System.Collections.Generic.List[string]
    foreach ($ace in $Aces) {
        if ("$(Get-ADSAProp -InputObject $ace -Name 'AccessControlType' -Default 'Allow')" -ne 'Allow') { continue }
        if (-not (Test-ADSAAceAppliesToObject -Ace $ace)) { continue }
        $rights = @(Get-ADSAProp -InputObject $ace -Name 'Rights' -Default @())
        $obj = "$(Get-ADSAProp -InputObject $ace -Name 'ObjectType' -Default $script:ADSAEmptyGuid)".ToLowerInvariant()
        $isAll = ('GenericAll' -in $rights) -or (('ExtendedRight' -in $rights) -and $obj -eq $script:ADSAEmptyGuid)
        if ($isAll -or (('ExtendedRight' -in $rights) -and $obj -eq $script:ADSARightGuid.ReplGetChanges)) { $changes = $true; $via.Add($(if ($isAll) { 'GenericAll/AllExtendedRights' } else { 'DS-Replication-Get-Changes' })) }
        if ($isAll -or (('ExtendedRight' -in $rights) -and $obj -eq $script:ADSARightGuid.ReplGetChangesAll)) { $changesAll = $true; $via.Add($(if ($isAll) { 'GenericAll/AllExtendedRights' } else { 'DS-Replication-Get-Changes-All' })) }
    }
    return [pscustomobject]@{ HasBoth = ($changes -and $changesAll); GetChanges = $changes; GetChangesAll = $changesAll; Via = @($via | Select-Object -Unique) }
}

function Get-ADSAPrincipalLabel {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Ace, [AllowNull()] [hashtable] $NameMap)
    $sid = Get-ADSAProp -InputObject $Ace -Name 'IdentitySid'
    $name = "$(Get-ADSAProp -InputObject $Ace -Name 'IdentityName' -Default '')"
    if (-not $name -and $sid -and $NameMap -and $NameMap.ContainsKey("$sid")) { $name = "$($NameMap["$sid"])" }
    if ($name -and $sid) { return "$name ($sid)" }
    if ($name) { return $name }
    return "$sid"
}

function Get-ADSASeverityForPrincipal {
    # Broad principals (Everyone, Authenticated Users, Domain Users, Domain Computers, Users) escalate to Critical.
    [CmdletBinding()]
    param([AllowNull()] [string] $Sid, [AllowNull()] [string] $DomainSid, [string] $Default = 'High')
    if (-not $Sid) { return $Default }
    if ($Sid -in 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545') { return 'Critical' }
    if ($DomainSid -and ($Sid -eq "$DomainSid-513" -or $Sid -eq "$DomainSid-515")) { return 'Critical' }
    return $Default
}

function Invoke-ADSAAclAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config)
    $ctx = New-ADSAContext -Snapshot $Snapshot -Config $Config
    $domainSid = "$(Get-ADSAProp -InputObject (Get-ADSAProp -InputObject $Snapshot -Name 'domain') -Name 'sid' -Default '')"
    $trusted = Get-ADSATrustedSidSet -DomainSid $domainSid -Config $Config

    # SID -> name map (best effort) for readable evidence
    $nameMap = @{}
    foreach ($sec in 'Users', 'Groups', 'Computers') {
        $st = Get-ADSASectionState -Context $ctx -Name $sec
        if ($st.State -eq 'Ok') {
            foreach ($o in @($st.Data)) {
                $s = Get-ADSAProp -InputObject $o -Name 'Sid'
                if ($s) { $nameMap["$s"] = "$(Get-ADSAProp -InputObject $o -Name 'SamAccountName' -Default (Get-ADSAProp -InputObject $o -Name 'Name' -Default ''))" }
            }
        }
    }
    $nameMap['S-1-1-0'] = 'Everyone'; $nameMap['S-1-5-11'] = 'Authenticated Users'; $nameMap['S-1-5-32-545'] = 'BUILTIN\Users'

    $acls = Get-ADSASectionState -Context $ctx -Name 'Acls'
    $gpos = Get-ADSASectionState -Context $ctx -Name 'Gpos'

    # ---- ADSA-ACL-001 / 002 / 003 over the 'Acls' section
    if ($acls.State -ne 'Ok') {
        foreach ($r in 'ADSA-ACL-001', 'ADSA-ACL-002', 'ADSA-ACL-003') { New-ADSASectionResult -Context $ctx -RuleId $r -Section $acls -SectionName 'Acls' }
    } else {
        $targets = @($acls.Data)
        $fail1 = New-Object System.Collections.Generic.List[object]
        $fail2 = New-Object System.Collections.Generic.List[object]
        $fail3 = New-Object System.Collections.Generic.List[object]
        $eval1 = 0; $eval2 = 0; $eval3 = 0; $skip3 = 0

        foreach ($t in $targets) {
            $dn = "$(Get-ADSAProp -InputObject $t -Name 'DistinguishedName' -Default '')"
            $class = "$(Get-ADSAProp -InputObject $t -Name 'ObjectClass' -Default '')"
            $role = "$(Get-ADSAProp -InputObject $t -Name 'Role' -Default '')"
            $aces = @(Get-ADSAProp -InputObject $t -Name 'Aces' -Default @())
            $owner = Get-ADSAProp -InputObject $t -Name 'OwnerSid'

            if (-not (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-ACL-001' -DistinguishedName $dn -Name $dn)) {
                $eval1++
                $byPrincipal = @{}
                foreach ($ace in $aces) {
                    if (Test-ADSAPrincipalTrusted -Ace $ace -TrustedSids $trusted -Config $Config -NameMap $nameMap) { continue }
                    $risk = Get-ADSAAceRisk -Ace $ace -TargetClass $class
                    if ($risk.Count -eq 0) { continue }
                    $key = "$(Get-ADSAProp -InputObject $ace -Name 'IdentitySid' -Default (Get-ADSAProp -InputObject $ace -Name 'IdentityName' -Default ''))"
                    if (-not $byPrincipal.ContainsKey($key)) { $byPrincipal[$key] = @{ Ace = $ace; Risks = (New-Object System.Collections.Generic.List[string]); Inherited = $false } }
                    foreach ($x in $risk) { if ($x -notin $byPrincipal[$key].Risks) { $byPrincipal[$key].Risks.Add($x) } }
                    if (Get-ADSAProp -InputObject $ace -Name 'IsInherited' -Default $false) { $byPrincipal[$key].Inherited = $true }
                }
                foreach ($key in $byPrincipal.Keys) {
                    $entry = $byPrincipal[$key]
                    $sid = Get-ADSAProp -InputObject $entry.Ace -Name 'IdentitySid'
                    $fail1.Add(@{
                            Object = $dn; ObjectType = $(if ($class) { $class } else { 'AdObject' })
                            Severity = (Get-ADSASeverityForPrincipal -Sid $sid -DomainSid $domainSid)
                            Evidence = [ordered]@{ TargetRole = $role; Principal = (Get-ADSAPrincipalLabel -Ace $entry.Ace -NameMap $nameMap); HighRiskRights = $entry.Risks.ToArray(); InheritedAce = $entry.Inherited }
                        })
                }
            }

            if ($role -eq 'DomainRoot') {
                if (-not (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-ACL-002' -DistinguishedName $dn -Name $dn)) {
                    $eval2++
                    $groupsBySid = @{}
                    foreach ($ace in $aces) {
                        if (Test-ADSAPrincipalTrusted -Ace $ace -TrustedSids $trusted -Config $Config -NameMap $nameMap) { continue }
                        $key = "$(Get-ADSAProp -InputObject $ace -Name 'IdentitySid' -Default (Get-ADSAProp -InputObject $ace -Name 'IdentityName' -Default ''))"
                        if (-not $groupsBySid.ContainsKey($key)) { $groupsBySid[$key] = New-Object System.Collections.Generic.List[object] }
                        $groupsBySid[$key].Add($ace)
                    }
                    foreach ($key in $groupsBySid.Keys) {
                        $grant = Get-ADSAReplicationGrant -Aces $groupsBySid[$key].ToArray()
                        if ($grant.HasBoth) {
                            $fail2.Add(@{ Object = $dn; ObjectType = 'domainDNS'; Evidence = [ordered]@{ Principal = (Get-ADSAPrincipalLabel -Ace $groupsBySid[$key][0] -NameMap $nameMap); GrantedVia = $grant.Via; GetChanges = $grant.GetChanges; GetChangesAll = $grant.GetChangesAll } })
                        }
                    }
                }
            }

            if (-not (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-ACL-003' -DistinguishedName $dn -Name $dn)) {
                if (-not $owner) { $skip3++ } else {
                    $eval3++
                    $ownerTrusted = $trusted.Contains("$owner")
                    if (-not $ownerTrusted) {
                        $ownerName = if ($nameMap.ContainsKey("$owner")) { "$($nameMap["$owner"]) ($owner)" } else { "$owner" }
                        $fail3.Add(@{ Object = $dn; ObjectType = $(if ($class) { $class } else { 'AdObject' }); Evidence = [ordered]@{ TargetRole = $role; Owner = $ownerName } })
                    }
                }
            }
        }
        $noTargets = if ($targets.Count -eq 0) { 1 } else { 0 }
        $aclWarn = if (@($acls.Warnings).Count -gt 0) { "$(@($acls.Warnings).Count) ACL target(s) could not be read or were truncated (see collection errors); the result covers only the targets that were read." } else { '' }
        if ($targets.Count -eq 0) { $skip3 = 1 }
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-ACL-001' -Fail $fail1.ToArray() -Evaluated $eval1 -Skipped $noTargets -SkipReason 'no ACL targets were collected' -ObjectType 'AdObject' -Scope 'sensitive objects' -ExtraLimitation $aclWarn
        $noRoot = if ($eval2 -eq 0) { 1 } else { 0 }
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-ACL-002' -Fail $fail2.ToArray() -Evaluated $eval2 -Skipped $noRoot -SkipReason 'the domain root ACL was not collected' -ObjectType 'domainDNS' -Scope 'domain root objects' -ExtraLimitation $aclWarn
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-ACL-003' -Fail $fail3.ToArray() -Evaluated $eval3 -Skipped $skip3 -SkipReason 'owner SID not present in collected data' -ObjectType 'AdObject' -Scope 'sensitive objects' -ExtraLimitation $aclWarn
    }

    # ---- ADSA-ACL-004 over GPO containers
    if ($gpos.State -ne 'Ok') {
        New-ADSASectionResult -Context $ctx -RuleId 'ADSA-ACL-004' -Section $gpos -SectionName 'Gpos'
    } else {
        $fail4 = New-Object System.Collections.Generic.List[object]; $eval4 = 0; $skip4 = 0
        foreach ($gpo in @($gpos.Data)) {
            $name = "$(Get-ADSAProp -InputObject $gpo -Name 'DisplayName' -Default (Get-ADSAProp -InputObject $gpo -Name 'Id' -Default ''))"
            if (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-ACL-004' -Name $name -DistinguishedName "$(Get-ADSAProp -InputObject $gpo -Name 'DistinguishedName' -Default '')") { continue }
            if (-not (Test-ADSAHasProp -InputObject $gpo -Name 'Aces')) { $skip4++; continue }
            $eval4++
            $byPrincipal = @{}
            foreach ($ace in @(Get-ADSAProp -InputObject $gpo -Name 'Aces' -Default @())) {
                if (Test-ADSAPrincipalTrusted -Ace $ace -TrustedSids $trusted -Config $Config -NameMap $nameMap) { continue }
                $risk = Get-ADSAAceRisk -Ace $ace -TargetClass 'groupPolicyContainer'
                if ($risk.Count -eq 0) { continue }
                $key = "$(Get-ADSAProp -InputObject $ace -Name 'IdentitySid' -Default (Get-ADSAProp -InputObject $ace -Name 'IdentityName' -Default ''))"
                if (-not $byPrincipal.ContainsKey($key)) { $byPrincipal[$key] = @{ Ace = $ace; Risks = (New-Object System.Collections.Generic.List[string]) } }
                foreach ($x in $risk) { if ($x -notin $byPrincipal[$key].Risks) { $byPrincipal[$key].Risks.Add($x) } }
            }
            foreach ($key in $byPrincipal.Keys) {
                $sid = Get-ADSAProp -InputObject $byPrincipal[$key].Ace -Name 'IdentitySid'
                $linked = @(foreach ($l in (Get-ADSAList -InputObject $gpo -Name 'LinkedTo')) { "$(Get-ADSAProp -InputObject $l -Name 'Target' -Default $l)" })
                $fail4.Add(@{ Object = $name; ObjectType = 'groupPolicyContainer'; Severity = (Get-ADSASeverityForPrincipal -Sid $sid -DomainSid $domainSid)
                        Evidence = [ordered]@{ GpoId = "$(Get-ADSAProp -InputObject $gpo -Name 'Id' -Default '')"; Principal = (Get-ADSAPrincipalLabel -Ace $byPrincipal[$key].Ace -NameMap $nameMap); HighRiskRights = $byPrincipal[$key].Risks.ToArray(); LinkedTo = $linked } })
            }
        }
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-ACL-004' -Fail $fail4.ToArray() -Evaluated $eval4 -Skipped $skip4 -SkipReason 'GPO ACL not collected' -ObjectType 'groupPolicyContainer' -Scope 'GPOs'
    }
}
