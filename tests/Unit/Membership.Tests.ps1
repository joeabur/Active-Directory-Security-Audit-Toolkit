BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../src/ADSecurityAudit.psd1') -Force
}

Describe 'Nested group membership and cycle detection' {
    BeforeAll {
        $script:u = @('CN=u1,DC=t', 'CN=u2,DC=t', 'CN=u3,DC=t') | ForEach-Object { [pscustomobject]@{ DistinguishedName = $_ } }
        function g($n, $m) { [pscustomobject]@{ DistinguishedName = "CN=$n,DC=t"; Members = $m } }
    }

    It 'resolves nested members with the shortest path and depth' {
        InModuleScope ADSecurityAudit {
            function g($n, $m) { [pscustomobject]@{ DistinguishedName = "CN=$n,DC=t"; Members = $m } }
            $groups = New-ADSADnIndex -Objects @((g 'Top' @('CN=Mid,DC=t', 'CN=u1,DC=t')), (g 'Mid' @('CN=Low,DC=t')), (g 'Low' @('CN=u2,DC=t')))
            $users = New-ADSADnIndex -Objects @([pscustomobject]@{ DistinguishedName = 'CN=u1,DC=t' }, [pscustomobject]@{ DistinguishedName = 'CN=u2,DC=t' })
            $comps = New-ADSADnIndex -Objects @()
            $r = Resolve-ADSAGroupMembership -GroupDn 'CN=Top,DC=t' -GroupIndex $groups -UserIndex $users -ComputerIndex $comps
            $r.Members.Count | Should -Be 2
            $nested = $r.Members | Where-Object DistinguishedName -eq 'CN=u2,DC=t'
            $nested.IsNested | Should -BeTrue
            $nested.Depth | Should -Be 2
            ($nested.Path -join '>') | Should -Be 'CN=Top,DC=t>CN=Mid,DC=t>CN=Low,DC=t'
            ($r.Members | Where-Object DistinguishedName -eq 'CN=u1,DC=t').IsNested | Should -BeFalse
            $r.NestedGroups.Count | Should -Be 2
        }
    }
    It 'terminates on a membership cycle and still returns members' {
        InModuleScope ADSecurityAudit {
            function g($n, $m) { [pscustomobject]@{ DistinguishedName = "CN=$n,DC=t"; Members = $m } }
            $groups = New-ADSADnIndex -Objects @((g 'A' @('CN=B,DC=t', 'CN=u1,DC=t')), (g 'B' @('CN=A,DC=t', 'CN=u2,DC=t')))
            $users = New-ADSADnIndex -Objects @([pscustomobject]@{ DistinguishedName = 'CN=u1,DC=t' }, [pscustomobject]@{ DistinguishedName = 'CN=u2,DC=t' })
            $r = Resolve-ADSAGroupMembership -GroupDn 'CN=A,DC=t' -GroupIndex $groups -UserIndex $users -ComputerIndex (New-ADSADnIndex -Objects @())
            $r.Members.Count | Should -Be 2
        }
    }
    It 'detects a two-group cycle once' {
        InModuleScope ADSecurityAudit {
            function g($n, $m) { [pscustomobject]@{ DistinguishedName = "CN=$n,DC=t"; Members = $m } }
            $groups = New-ADSADnIndex -Objects @((g 'A' @('CN=B,DC=t')), (g 'B' @('CN=A,DC=t')))
            $c = Find-ADSAGroupCycle -GroupIndex $groups -RootDn @('CN=A,DC=t', 'CN=B,DC=t')
            $c.Count | Should -Be 1
            $c[0].Path.Count | Should -Be 3
            $c[0].Path[0] | Should -Be $c[0].Path[2]
        }
    }
    It 'detects a self-membership cycle' {
        InModuleScope ADSecurityAudit {
            function g($n, $m) { [pscustomobject]@{ DistinguishedName = "CN=$n,DC=t"; Members = $m } }
            $groups = New-ADSADnIndex -Objects @((g 'A' @('CN=A,DC=t')))
            (Find-ADSAGroupCycle -GroupIndex $groups -RootDn @('CN=A,DC=t')).Count | Should -Be 1
        }
    }
    It 'detects a cycle reachable only through a diamond' {
        InModuleScope ADSecurityAudit {
            function g($n, $m) { [pscustomobject]@{ DistinguishedName = "CN=$n,DC=t"; Members = $m } }
            # R -> X -> Z, R -> Y -> Z, Z -> Y  (cycle Y <-> Z)
            $groups = New-ADSADnIndex -Objects @((g 'R' @('CN=X,DC=t', 'CN=Y,DC=t')), (g 'X' @('CN=Z,DC=t')), (g 'Y' @('CN=Z,DC=t')), (g 'Z' @('CN=Y,DC=t')))
            $c = Find-ADSAGroupCycle -GroupIndex $groups -RootDn @('CN=R,DC=t')
            $c.Count | Should -Be 1
        }
    }
    It 'reports no cycle for an acyclic diamond' {
        InModuleScope ADSecurityAudit {
            function g($n, $m) { [pscustomobject]@{ DistinguishedName = "CN=$n,DC=t"; Members = $m } }
            $groups = New-ADSADnIndex -Objects @((g 'R' @('CN=X,DC=t', 'CN=Y,DC=t')), (g 'X' @('CN=Z,DC=t')), (g 'Y' @('CN=Z,DC=t')), (g 'Z' @()))
            (Find-ADSAGroupCycle -GroupIndex $groups -RootDn @('CN=R,DC=t')).Count | Should -Be 0
        }
    }
    It 'returns unresolved members (foreign principals) separately and includes primary-group members' {
        InModuleScope ADSecurityAudit {
            function g($n, $m) { [pscustomobject]@{ DistinguishedName = "CN=$n,DC=t"; Members = $m } }
            $groups = New-ADSADnIndex -Objects @((g 'A' @('CN=S-1-5-21-9-9-9-500,CN=ForeignSecurityPrincipals,DC=t')))
            $users = New-ADSADnIndex -Objects @([pscustomobject]@{ DistinguishedName = 'CN=pg,DC=t' })
            $r = Resolve-ADSAGroupMembership -GroupDn 'CN=A,DC=t' -GroupIndex $groups -UserIndex $users -ComputerIndex (New-ADSADnIndex -Objects @()) -PrimaryGroupMemberDn @('CN=pg,DC=t')
            $r.Unresolved.Count | Should -Be 1
            $r.Members.Count | Should -Be 1
            $r.Members[0].DistinguishedName | Should -Be 'CN=pg,DC=t'
        }
    }
    It 'handles a group that is missing from the data' {
        InModuleScope ADSecurityAudit {
            $r = Resolve-ADSAGroupMembership -GroupDn 'CN=Nope,DC=t' -GroupIndex (New-ADSADnIndex -Objects @()) -UserIndex (New-ADSADnIndex -Objects @()) -ComputerIndex (New-ADSADnIndex -Objects @())
            $r.GroupFound | Should -BeFalse
            $r.Members.Count | Should -Be 0
        }
    }
}
