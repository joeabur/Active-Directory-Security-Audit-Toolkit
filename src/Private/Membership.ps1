# Nested group membership resolution with cycle detection. Pure functions over in-memory data.

function New-ADSADnIndex {
    # Case-insensitive DN -> object index.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param([AllowNull()] [object[]] $Objects)
    $index = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($o in @($Objects)) {
        $dn = Get-ADSAProp -InputObject $o -Name 'DistinguishedName'
        if ($dn) { $index["$dn"] = $o }
    }
    return , $index
}

function Find-ADSAGroupCycle {
    <#
    .SYNOPSIS
        Detects membership cycles (A in B in ... in A) reachable from the given root groups using depth-first colouring.
    .OUTPUTS
        One object per distinct cycle: @{ Path = <DN list, first DN repeated at end> }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GroupIndex,
        [Parameter(Mandatory)] [string[]] $RootDn
    )
    $color = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)
    $found = New-Object System.Collections.Generic.List[object]
    $signatures = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($root in $RootDn) {
        if ($color.ContainsKey($root)) { continue }
        # Iterative DFS: stack of frames (dn, member-array, next-position)
        $stack = New-Object System.Collections.Generic.List[object]
        $pathList = New-Object System.Collections.Generic.List[string]
        if (-not $GroupIndex.ContainsKey($root)) { continue }
        $color[$root] = 1
        $pathList.Add($root)
        $stack.Add(@{ Dn = $root; Members = (Get-ADSAList -InputObject $GroupIndex[$root] -Name 'Members'); Pos = 0 })
        while ($stack.Count -gt 0) {
            $frame = $stack[$stack.Count - 1]
            if ($frame.Pos -ge $frame.Members.Count) {
                $color[$frame.Dn] = 2
                $stack.RemoveAt($stack.Count - 1)
                $pathList.RemoveAt($pathList.Count - 1)
                continue
            }
            $member = "$($frame.Members[$frame.Pos])"
            $frame.Pos++
            if (-not $GroupIndex.ContainsKey($member)) { continue }
            $state = 0
            [void]$color.TryGetValue($member, [ref]$state)
            if ($state -eq 1) {
                $start = -1
                for ($i = 0; $i -lt $pathList.Count; $i++) { if ($pathList[$i] -ieq $member) { $start = $i; break } }
                $cycle = @($pathList.GetRange($start, $pathList.Count - $start)) + $member
                # canonical signature: rotate to smallest DN so the same cycle is reported once
                $nodes = @($cycle[0..($cycle.Count - 2)])
                $min = ($nodes | Sort-Object { $_.ToLowerInvariant() } | Select-Object -First 1)
                $idx = [array]::IndexOf(@($nodes | ForEach-Object { $_.ToLowerInvariant() }), $min.ToLowerInvariant())
                $rot = @($nodes[$idx..($nodes.Count - 1)]) + @(if ($idx -gt 0) { $nodes[0..($idx - 1)] })
                $sig = ($rot | ForEach-Object { $_.ToLowerInvariant() }) -join '|'
                if ($signatures.Add($sig)) { $found.Add([pscustomobject]@{ Path = @($rot) + $rot[0] }) }
            } elseif ($state -eq 0) {
                $color[$member] = 1
                $pathList.Add($member)
                $stack.Add(@{ Dn = $member; Members = (Get-ADSAList -InputObject $GroupIndex[$member] -Name 'Members'); Pos = 0 })
            }
        }
    }
    return , $found.ToArray()
}

function Resolve-ADSAGroupMembership {
    <#
    .SYNOPSIS
        Expands a group into its transitive non-group members (breadth-first, shortest path recorded).
    .DESCRIPTION
        Cycles never cause infinite loops: every group is expanded at most once.
        Members whose DN is not found in any index are returned as Unresolved (e.g. foreign security principals).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $GroupDn,
        [Parameter(Mandatory)] $GroupIndex,
        [Parameter(Mandatory)] $UserIndex,
        [Parameter(Mandatory)] $ComputerIndex,
        [AllowNull()] [string[]] $PrimaryGroupMemberDn
    )
    $members = New-Object System.Collections.Generic.List[object]
    $unresolved = New-Object System.Collections.Generic.List[string]
    $visited = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $seenMember = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $nestedGroups = New-Object System.Collections.Generic.List[string]
    $queue = New-Object System.Collections.Generic.Queue[object]

    if ($GroupIndex.ContainsKey($GroupDn)) {
        [void]$visited.Add($GroupDn)
        $queue.Enqueue(@{ Dn = $GroupDn; Path = @($GroupDn) })
    }
    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $group = $GroupIndex[$item.Dn]
        $direct = Get-ADSAList -InputObject $group -Name 'Members'
        if ($item.Dn -ieq $GroupDn -and $PrimaryGroupMemberDn) { $direct = @($direct) + @($PrimaryGroupMemberDn) }
        foreach ($m in $direct) {
            $mdn = "$m"
            if ($GroupIndex.ContainsKey($mdn)) {
                if ($visited.Add($mdn)) {
                    $nestedGroups.Add($mdn)
                    $queue.Enqueue(@{ Dn = $mdn; Path = @($item.Path) + $mdn })
                }
                continue
            }
            $class = $null
            if ($UserIndex.ContainsKey($mdn)) { $class = 'user' } elseif ($ComputerIndex.ContainsKey($mdn)) { $class = 'computer' }
            if ($null -eq $class) { if ($seenMember.Add("unresolved:$mdn")) { $unresolved.Add($mdn) }; continue }
            if ($seenMember.Add($mdn)) {
                $members.Add([pscustomobject]@{ DistinguishedName = $mdn; ObjectClass = $class; Path = @($item.Path); Depth = ($item.Path.Count - 1); IsNested = ($item.Path.Count -gt 1) })
            }
        }
    }
    return [pscustomobject]@{
        GroupDn      = $GroupDn
        GroupFound   = $GroupIndex.ContainsKey($GroupDn)
        Members      = $members.ToArray()
        Unresolved   = $unresolved.ToArray()
        NestedGroups = $nestedGroups.ToArray()
    }
}

function Get-ADSAPrivilegedIndex {
    <#
    .SYNOPSIS
        Resolves every configured privileged group (with nesting) once per run and caches the result on the context.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context)
    if ($Context.Cache.ContainsKey('PrivilegedIndex')) { return $Context.Cache['PrivilegedIndex'] }

    $snapshot = $Context.Snapshot
    $domainSid = "$(Get-ADSAProp -InputObject (Get-ADSAProp -InputObject $snapshot -Name 'domain') -Name 'sid' -Default '')"
    $groups = @((Get-ADSASectionState -Context $Context -Name 'Groups').Data)
    $users = @((Get-ADSASectionState -Context $Context -Name 'Users').Data)
    $computers = @((Get-ADSASectionState -Context $Context -Name 'Computers').Data)
    $groupIndex = New-ADSADnIndex -Objects $groups
    $userIndex = New-ADSADnIndex -Objects $users
    $computerIndex = New-ADSADnIndex -Objects $computers

    $groupResults = New-Object System.Collections.Generic.List[object]
    $principals = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $rootDns = New-Object System.Collections.Generic.List[string]

    foreach ($cfg in @($Context.Config['privilegedGroups'])) {
        $targetSid = if ($cfg['sid']) { "$($cfg['sid'])" } elseif ($domainSid) { "$domainSid-$($cfg['rid'])" } else { $null }
        $group = $null
        if ($targetSid) { $group = $groups | Where-Object { (Get-ADSAProp -InputObject $_ -Name 'Sid') -eq $targetSid } | Select-Object -First 1 }
        if ($null -eq $group) {
            $groupResults.Add([pscustomobject]@{ Name = "$($cfg['name'])"; Sid = $targetSid; Found = $false; Dn = $null; MembersCollected = $true; Members = @(); Unresolved = @(); NestedGroups = @() })
            continue
        }
        $dn = "$(Get-ADSAProp -InputObject $group -Name 'DistinguishedName')"
        $rootDns.Add($dn)
        $rid = Get-ADSASidRid -Sid $targetSid
        $primary = @()
        if ($targetSid -like "$domainSid-*" -and $null -ne $rid) {
            $primary = @($users | Where-Object { "$(Get-ADSAProp -InputObject $_ -Name 'PrimaryGroupId')" -eq "$rid" } | ForEach-Object { Get-ADSAProp -InputObject $_ -Name 'DistinguishedName' })
        }
        $res = Resolve-ADSAGroupMembership -GroupDn $dn -GroupIndex $groupIndex -UserIndex $userIndex -ComputerIndex $computerIndex -PrimaryGroupMemberDn $primary
        $groupResults.Add([pscustomobject]@{ Name = "$($cfg['name'])"; Sid = $targetSid; Found = $true; Dn = $dn; MembersCollected = [bool](Get-ADSAProp -InputObject $group -Name 'MembersCollected' -Default $true); Members = $res.Members; Unresolved = $res.Unresolved; NestedGroups = $res.NestedGroups })
        foreach ($m in $res.Members) {
            if (-not $principals.ContainsKey($m.DistinguishedName)) {
                $obj = if ($m.ObjectClass -eq 'user') { $userIndex[$m.DistinguishedName] } else { $computerIndex[$m.DistinguishedName] }
                $principals[$m.DistinguishedName] = [pscustomobject]@{ DistinguishedName = $m.DistinguishedName; ObjectClass = $m.ObjectClass; Object = $obj; Memberships = (New-Object System.Collections.Generic.List[object]) }
            }
            $principals[$m.DistinguishedName].Memberships.Add([pscustomobject]@{ Group = "$($cfg['name'])"; Path = $m.Path; IsNested = $m.IsNested })
        }
    }
    $cycles = @()
    if ($rootDns.Count -gt 0) { $cycles = Find-ADSAGroupCycle -GroupIndex $groupIndex -RootDn $rootDns.ToArray() }

    $index = [pscustomobject]@{
        Groups     = $groupResults.ToArray()
        Principals = $principals
        Cycles     = $cycles
        AnyFound   = ($rootDns.Count -gt 0)
    }
    $Context.Cache['PrivilegedIndex'] = $index
    return $index
}
