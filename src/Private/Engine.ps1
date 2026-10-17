# Audit engine internals: module registry, exception handling, coverage and report assembly.

$script:ADSAModuleRegistry = [ordered]@{
    AccountLifecycle     = 'Invoke-ADSAAccountLifecycleAudit'
    PrivilegedAccess     = 'Invoke-ADSAPrivilegedAccessAudit'
    Delegation           = 'Invoke-ADSADelegationAudit'
    Acl                  = 'Invoke-ADSAAclAudit'
    AuthenticationPolicy = 'Invoke-ADSAAuthenticationPolicyAudit'
    GroupPolicy          = 'Invoke-ADSAGroupPolicyAudit'
    Infrastructure       = 'Invoke-ADSAInfrastructureAudit'
}

function Get-ADSAModuleName {
    return @($script:ADSAModuleRegistry.Keys)
}

function Invoke-ADSAAuditModule {
    <#
    .SYNOPSIS
        Runs one audit module. Crashes become ERROR results for every rule of that module; silent rules become ERROR too.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Module, [Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config)
    $ctx = New-ADSAContext -Snapshot $Snapshot -Config $Config
    $ruleIds = @((Get-ADSARuleCatalogData).Rules | Where-Object { $_.Module -eq $Module } | ForEach-Object { $_.Id })
    $results = New-Object System.Collections.Generic.List[object]
    try {
        $fn = $script:ADSAModuleRegistry[$Module]
        foreach ($item in @(& $fn -Snapshot $Snapshot -Config $Config)) {
            if ($null -ne $item -and $null -ne $item.PSObject.Properties['RuleId'] -and $null -ne $item.PSObject.Properties['Status']) { $results.Add($item) }
        }
    } catch {
        Write-ADSALog -Level Error -Message "Module $Module failed: $($_.Exception.Message)"
        $results.Clear()
        foreach ($id in $ruleIds) {
            $results.Add((New-ADSAResult -Context $ctx -RuleId $id -Status 'ERROR' -Explanation "The $Module audit module failed unexpectedly: $($_.Exception.Message)" -Evidence ([ordered]@{ ErrorCategory = 'ModuleFailure' }) -Limitations 'The rule was not evaluated.'))
        }
        return $results.ToArray()
    }
    foreach ($id in $ruleIds) {
        if (-not ($results | Where-Object { $_.RuleId -eq $id })) {
            $results.Add((New-ADSAResult -Context $ctx -RuleId $id -Status 'ERROR' -Explanation 'The rule produced no result. This is a toolkit defect; it is reported as ERROR instead of being treated as a pass.' -Evidence ([ordered]@{ ErrorCategory = 'NoResult' })))
        }
    }
    return $results.ToArray()
}

function Add-ADSAExceptionInfo {
    <#
    .SYNOPSIS
        Marks FAIL results covered by a documented, unexpired exception. Results are never removed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Result, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config, [Parameter(Mandatory)] [datetime] $ReferenceTime)
    $used = @{}
    foreach ($r in $Result) {
        if ($r.Status -ne 'FAIL') { continue }
        foreach ($x in @($Config['exceptions'])) {
            if ($null -eq $x) { continue }
            if ("$($x['ruleId'])" -ne $r.RuleId) { continue }
            $exp = ConvertTo-ADSADateTime -Value $x['expires']
            if ($null -eq $exp -or $exp.Date.AddDays(1) -le $ReferenceTime) { continue }
            $candidates = @($r.AffectedObject, "$(Get-ADSAProp -InputObject $r.Evidence -Name 'DistinguishedName' -Default '')", "$(Get-ADSAProp -InputObject $r.Evidence -Name 'Principal' -Default '')")
            $match = $false
            foreach ($c in $candidates) { if ($c -and (Test-ADSAWildcardMatch -Value $c -Pattern "$($x['objectPattern'])")) { $match = $true; break } }
            if (-not $match) { continue }
            $r.Excepted = $true
            $r.Exception = [pscustomobject][ordered]@{ Id = "$($x['id'])"; Reason = "$($x['reason'])"; Owner = "$($x['owner'])"; ApprovedBy = "$($x['approvedBy'])"; Expires = $exp.ToString('yyyy-MM-dd') }
            $used["$($x['id'])"] = $true
            break
        }
    }
    $unused = @()
    foreach ($x in @($Config['exceptions'])) {
        if ($null -eq $x) { continue }
        $exp = ConvertTo-ADSADateTime -Value $x['expires']
        if ($null -ne $exp -and $exp.Date.AddDays(1) -gt $ReferenceTime -and -not $used.ContainsKey("$($x['id'])")) { $unused += "Exception '$($x['id'])' (rule $($x['ruleId'])) matched no finding and may be obsolete." }
    }
    return , $unused
}

function Get-ADSAAggregateStatus {
    # Worst-case status across results of one rule: FAIL > ERROR > NOT_ASSESSED > PASS > NOT_APPLICABLE.
    [CmdletBinding()]
    param([AllowEmptyCollection()] [string[]] $Status)
    foreach ($s in 'FAIL', 'ERROR', 'NOT_ASSESSED', 'PASS', 'NOT_APPLICABLE') { if ($s -in $Status) { return $s } }
    return 'NOT_ASSESSED'
}

function New-ADSAReportObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Result, [Parameter(Mandatory)] [string[]] $ModulesRun,
        [Parameter(Mandatory)] [string] $AnalysisMode, [AllowEmptyCollection()] [string[]] $ConfigWarning = @()
    )
    $ctx = New-ADSAContext -Snapshot $Snapshot -Config $Config
    $catalog = Get-ADSARuleCatalogData
    $domain = Get-ADSAProp -InputObject $Snapshot -Name 'domain'
    $dataSource = $ctx.DataSource

    $sorted = @($Result | Sort-Object @{ Expression = { switch ($_.Status) { 'FAIL' { 0 } 'ERROR' { 1 } 'NOT_ASSESSED' { 2 } 'PASS' { 3 } default { 4 } } } },
        @{ Expression = { $script:ADSASeverities.IndexOf($_.Severity) } }, RuleId, AffectedObject)

    # Summary
    $statusCounts = [ordered]@{}
    foreach ($s in $script:ADSAStatuses) { $statusCounts[$s] = @($sorted | Where-Object { $_.Status -eq $s }).Count }
    $failActive = @($sorted | Where-Object { $_.Status -eq 'FAIL' -and -not $_.Excepted })
    $sevCounts = [ordered]@{}
    foreach ($s in $script:ADSASeverities) { $sevCounts[$s] = @($failActive | Where-Object { $_.Severity -eq $s }).Count }

    # Coverage per rule
    $ruleCoverage = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $catalog.Rules) {
        $rr = @($sorted | Where-Object { $_.RuleId -eq $rule.Id })
        if ($rule.Module -notin $ModulesRun) {
            $ruleCoverage.Add([pscustomobject][ordered]@{ RuleId = $rule.Id; Title = $rule.Title; Module = $rule.Module; Status = 'NOT_ASSESSED'; Partial = $false; Results = 0; Note = 'Module was not selected for this run.' })
            continue
        }
        $agg = Get-ADSAAggregateStatus -Status @($rr | ForEach-Object { $_.Status })
        $hasAssessed = @($rr | Where-Object { $_.Status -in 'PASS', 'FAIL' }).Count -gt 0
        $hasGap = @($rr | Where-Object { $_.Status -in 'ERROR', 'NOT_ASSESSED' }).Count -gt 0
        $ruleCoverage.Add([pscustomobject][ordered]@{ RuleId = $rule.Id; Title = $rule.Title; Module = $rule.Module; Status = $agg; Partial = ($hasGap -and $hasAssessed); Results = $rr.Count; Note = '' })
    }
    $assessed = @($ruleCoverage | Where-Object { $_.Status -in 'PASS', 'FAIL' }).Count
    $notAssessed = @($ruleCoverage | Where-Object { $_.Status -in 'ERROR', 'NOT_ASSESSED' -or $_.Partial }).Count

    # Section coverage and collection errors
    $sectionCoverage = New-Object System.Collections.Generic.List[object]
    $collectionErrors = New-Object System.Collections.Generic.List[object]
    $sectionsObj = Get-ADSAProp -InputObject $Snapshot -Name 'sections'
    $sectionNames = if ($null -eq $sectionsObj) { @() } elseif ($sectionsObj -is [System.Collections.IDictionary]) { @($sectionsObj.Keys) } else { @($sectionsObj.PSObject.Properties.Name) }
    foreach ($n in $sectionNames) {
        $sec = Get-ADSAProp -InputObject $sectionsObj -Name $n
        $data = Get-ADSAProp -InputObject $sec -Name 'data'
        $count = if ($null -eq $data) { 0 } else { @($data).Count }
        $warn = @(Get-ADSAProp -InputObject $sec -Name 'warnings' -Default @())
        $sectionCoverage.Add([pscustomobject][ordered]@{ Section = $n; Status = "$(Get-ADSAProp -InputObject $sec -Name 'status')"; ObjectCount = $count; ErrorCategory = "$(Get-ADSAProp -InputObject $sec -Name 'errorCategory' -Default '')"; WarningCount = $warn.Count })
        if ("$(Get-ADSAProp -InputObject $sec -Name 'status')" -ne 'Collected') {
            $collectionErrors.Add([pscustomobject][ordered]@{ Source = $n; Target = ''; Category = "$(Get-ADSAProp -InputObject $sec -Name 'errorCategory' -Default 'Error')"; Message = "$(Get-ADSAProp -InputObject $sec -Name 'error' -Default '')" })
        }
        foreach ($w in $warn) { $collectionErrors.Add([pscustomobject][ordered]@{ Source = $n; Target = "$(Get-ADSAProp -InputObject $w -Name 'target' -Default '')"; Category = "$(Get-ADSAProp -InputObject $w -Name 'category' -Default 'Warning')"; Message = "$(Get-ADSAProp -InputObject $w -Name 'message' -Default '')" }) }
    }
    $dcHosts = Get-ADSASectionState -Context $ctx -Name 'DcHosts'
    if ($dcHosts.State -eq 'Ok') {
        foreach ($dc in @($dcHosts.Data)) {
            if ((Get-ADSAProp -InputObject $dc -Name 'Reachable' -Default $true) -eq $false) { $collectionErrors.Add([pscustomobject][ordered]@{ Source = 'DcHosts'; Target = "$(Get-ADSAProp -InputObject $dc -Name 'Name')"; Category = "$(Get-ADSAProp -InputObject $dc -Name 'ErrorCategory' -Default 'Unreachable')"; Message = "$(Get-ADSAProp -InputObject $dc -Name 'Error' -Default '')" }) }
        }
    }
    $gpoSec = Get-ADSASectionState -Context $ctx -Name 'Gpos'
    if ($gpoSec.State -eq 'Ok') {
        foreach ($g in @($gpoSec.Data)) {
            $st = "$(Get-ADSAProp -InputObject $g -Name 'SysvolStatus' -Default '')"
            if ($st -notin 'Read', 'NoSecurityTemplate', 'Skipped', '') { $collectionErrors.Add([pscustomobject][ordered]@{ Source = 'Gpos'; Target = "$(Get-ADSAProp -InputObject $g -Name 'DisplayName' -Default (Get-ADSAProp -InputObject $g -Name 'Id' -Default ''))"; Category = $st; Message = 'SYSVOL content for this GPO could not be read.' }) }
        }
    }

    # Inventories (informational, not pass/fail)
    $inv = [ordered]@{ ServiceAccounts = @(); PrivilegedGroups = @(); PasswordNeverExpiresCount = 0; DomainControllers = @(); Trusts = @(); FineGrainedPolicies = @() }
    try {
        $users = Get-ADSASectionState -Context $ctx -Name 'Users'
        $groups = Get-ADSASectionState -Context $ctx -Name 'Groups'
        $priv = $null
        if ($users.State -eq 'Ok' -and $groups.State -eq 'Ok') {
            $priv = Get-ADSAPrivilegedIndex -Context $ctx
            $inv.PrivilegedGroups = @($priv.Groups | ForEach-Object { [pscustomobject][ordered]@{ Name = $_.Name; Found = $_.Found; EffectiveMemberCount = @($_.Members).Count; NestedGroupCount = @($_.NestedGroups).Count; UnresolvedMemberCount = @($_.Unresolved).Count } })
        }
        if ($users.State -eq 'Ok') {
            $inv.ServiceAccounts = @($users.Data | Where-Object { (Get-ADSAList -InputObject $_ -Name 'ServicePrincipalNames').Count -gt 0 } | ForEach-Object {
                    $uac = Get-ADSAUac -InputObject $_
                    [pscustomobject][ordered]@{ SamAccountName = "$(Get-ADSAProp -InputObject $_ -Name 'SamAccountName')"; Enabled = (Get-ADSAEnabled -InputObject $_); PasswordLastSet = (Format-ADSAIsoTime -Value (Get-ADSAProp -InputObject $_ -Name 'PasswordLastSet')); PasswordNeverExpires = $(if ($null -ne $uac) { Test-ADSAUacFlag -Uac $uac -Flag 'DONT_EXPIRE_PASSWORD' } else { $null }); Privileged = $(if ($priv) { $priv.Principals.ContainsKey("$(Get-ADSAProp -InputObject $_ -Name 'DistinguishedName')") } else { $null }); SpnCount = (Get-ADSAList -InputObject $_ -Name 'ServicePrincipalNames').Count }
                })
            $inv.PasswordNeverExpiresCount = @($users.Data | Where-Object { $u = Get-ADSAUac -InputObject $_; $null -ne $u -and (Test-ADSAUacFlag -Uac $u -Flag 'DONT_EXPIRE_PASSWORD') -and (Get-ADSAEnabled -InputObject $_) }).Count
        }
        $dcs = Get-ADSASectionState -Context $ctx -Name 'DomainControllers'
        if ($dcs.State -eq 'Ok') { $inv.DomainControllers = @($dcs.Data | ForEach-Object { [pscustomobject][ordered]@{ Name = "$(Get-ADSAProp -InputObject $_ -Name 'Name')"; OperatingSystem = "$(Get-ADSAProp -InputObject $_ -Name 'OperatingSystem' -Default '')"; Site = "$(Get-ADSAProp -InputObject $_ -Name 'Site' -Default '')"; IsReadOnly = (Get-ADSAProp -InputObject $_ -Name 'IsReadOnly' -Default $false) } }) }
        $tr = Get-ADSASectionState -Context $ctx -Name 'Trusts'
        if ($tr.State -eq 'Ok') { $inv.Trusts = @($tr.Data | ForEach-Object { [pscustomobject][ordered]@{ Name = "$(Get-ADSAProp -InputObject $_ -Name 'Name')"; Direction = "$(Get-ADSAProp -InputObject $_ -Name 'TrustDirection')"; Attributes = "$(Get-ADSAProp -InputObject $_ -Name 'TrustAttributes')" } }) }
        $fg = Get-ADSASectionState -Context $ctx -Name 'FineGrainedPolicies'
        if ($fg.State -eq 'Ok') { $inv.FineGrainedPolicies = @($fg.Data | ForEach-Object { [pscustomobject][ordered]@{ Name = "$(Get-ADSAProp -InputObject $_ -Name 'Name')"; Precedence = (Get-ADSAProp -InputObject $_ -Name 'Precedence'); MinPasswordLength = (Get-ADSAProp -InputObject $_ -Name 'MinPasswordLength'); LockoutThreshold = (Get-ADSAProp -InputObject $_ -Name 'LockoutThreshold') } }) }
    } catch {
        Write-ADSALog -Level Warning -Message "Inventory generation was incomplete: $($_.Exception.Message)"
    }

    $notice = if ($dataSource -eq 'Simulated') { 'SIMULATED DATA: these results come from a synthetic fixture. They are not observations of a real domain and say nothing about the security of any real environment.' } else { 'Results describe the directory state observed at the collection time. Absence of a finding is not proof of security; see limitations and coverage.' }
    $headline = "$($failActive.Count) active finding(s) across $assessed assessed rule(s); $notAssessed rule(s) could not be fully assessed; $(@($sorted | Where-Object { $_.Excepted }).Count) finding(s) covered by documented exceptions."

    return [pscustomobject][ordered]@{
        SchemaVersion    = '1.0'
        Tool             = [pscustomobject][ordered]@{ Name = 'ADSecurityAudit'; Version = $script:ADSAVersion }
        Metadata         = [pscustomobject][ordered]@{
            GeneratedAt    = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
            CollectionTime = $ctx.CollectionTime
            DataSource     = $dataSource
            AnalysisMode   = $AnalysisMode
            Notice         = $notice
            Domain         = [pscustomobject][ordered]@{ Name = "$(Get-ADSAProp -InputObject $domain -Name 'name' -Default '')"; NetBiosName = "$(Get-ADSAProp -InputObject $domain -Name 'netBiosName' -Default '')"; DomainFunctionalLevel = "$(Get-ADSAProp -InputObject $domain -Name 'domainMode' -Default '')"; ForestFunctionalLevel = "$(Get-ADSAProp -InputObject $domain -Name 'forestMode' -Default '')" }
            ConfigVersion  = "$($Config['configVersion'])"
            Modules        = @($ModulesRun)
            Warnings       = @($ConfigWarning)
            Exclusions     = [pscustomobject]@{ Count = @($Config['exclusions'] | Where-Object { $_ }).Count }
        }
        Summary          = [pscustomobject][ordered]@{
            Headline           = $headline
            ResultsByStatus    = [pscustomobject]$statusCounts
            ActiveFindingsBySeverity = [pscustomobject]$sevCounts
            ActiveFindings     = $failActive.Count
            ExceptedFindings   = @($sorted | Where-Object { $_.Excepted }).Count
            RulesInCatalog     = $catalog.Rules.Count
            RulesAssessed      = $assessed
            RulesNotFullyAssessed = $notAssessed
        }
        Coverage         = [pscustomobject][ordered]@{ Rules = $ruleCoverage.ToArray(); Sections = $sectionCoverage.ToArray() }
        CollectionErrors = $collectionErrors.ToArray()
        Inventories      = [pscustomobject]$inv
        Findings         = $sorted
    }
}
