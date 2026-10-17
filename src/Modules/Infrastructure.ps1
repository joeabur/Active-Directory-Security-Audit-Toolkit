# Infrastructure audit module: domain controller OS support, functional levels and trust configuration.

$script:ADSAFunctionalLevelRank = @{
    'windows2000domain' = 0; 'windows2003interimdomain' = 1; 'windows2003domain' = 2; 'windows2008domain' = 3
    'windows2008r2domain' = 4; 'windows2012domain' = 5; 'windows2012r2domain' = 6; 'windows2016domain' = 7; 'windows2025domain' = 8
    'windows2000forest' = 0; 'windows2003interimforest' = 1; 'windows2003forest' = 2; 'windows2008forest' = 3
    'windows2008r2forest' = 4; 'windows2012forest' = 5; 'windows2012r2forest' = 6; 'windows2016forest' = 7; 'windows2025forest' = 8
}

function Get-ADSAFunctionalLevelRank {
    [CmdletBinding()]
    param([AllowNull()] [string] $Level)
    if ([string]::IsNullOrWhiteSpace($Level)) { return $null }
    $key = $Level.Trim().ToLowerInvariant()
    if ($script:ADSAFunctionalLevelRank.ContainsKey($key)) { return $script:ADSAFunctionalLevelRank[$key] }
    return $null
}

function Get-ADSATrustFlag {
    # Decodes trustAttributes into named flags.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [int64] $Attributes)
    $map = [ordered]@{
        NonTransitive = 0x1; UplevelOnly = 0x2; QuarantinedDomain = 0x4; ForestTransitive = 0x8; CrossOrganization = 0x10
        WithinForest = 0x20; TreatAsExternal = 0x40; UsesRc4Encryption = 0x80
    }
    $out = [ordered]@{}
    foreach ($k in $map.Keys) { $out[$k] = (($Attributes -band $map[$k]) -ne 0) }
    return [pscustomobject]$out
}

function Invoke-ADSAInfrastructureAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config)
    $ctx = New-ADSAContext -Snapshot $Snapshot -Config $Config
    $dcCfg = $Config['domainControllers']
    $domain = Get-ADSAProp -InputObject $Snapshot -Name 'domain'
    $domainName = "$(Get-ADSAProp -InputObject $domain -Name 'name' -Default '')"

    # ---- INF-001 unsupported DC operating systems
    $dcs = Get-ADSASectionState -Context $ctx -Name 'DomainControllers'
    if ($dcs.State -ne 'Ok') {
        New-ADSASectionResult -Context $ctx -RuleId 'ADSA-INF-001' -Section $dcs -SectionName 'DomainControllers'
    } else {
        $pattern = "$($dcCfg['unsupportedOsPattern'])"
        Invoke-ADSAObjectRule -Context $ctx -RuleId 'ADSA-INF-001' -Objects @($dcs.Data) -Kind computer -ObjectType 'DomainController' -Scope 'domain controllers' -Evaluator {
            param($dc)
            $os = "$(Get-ADSAProp -InputObject $dc -Name 'OperatingSystem' -Default '')"
            if (-not $os) { return @{ Outcome = 'Skip'; SkipReason = 'operatingSystem was not retrieved' } }
            if ($pattern -and $os -match $pattern) {
                return @{ Outcome = 'Fail'; Evidence = [ordered]@{ HostName = "$(Get-ADSAProp -InputObject $dc -Name 'HostName' -Default '')"; OperatingSystem = $os; OperatingSystemVersion = "$(Get-ADSAProp -InputObject $dc -Name 'OperatingSystemVersion' -Default '')"; MatchedPattern = $pattern } }
            }
            return @{ Outcome = 'Pass' }
        }
    }

    # ---- INF-002 functional levels
    $domainLevel = Get-ADSAProp -InputObject $domain -Name 'domainMode'
    $forestLevel = Get-ADSAProp -InputObject $domain -Name 'forestMode'
    $fail2 = New-Object System.Collections.Generic.List[object]; $eval2 = 0; $skip2 = 0
    foreach ($item in @(
            @{ Kind = 'Domain'; Level = $domainLevel; Min = "$($dcCfg['minDomainFunctionalLevel'])"; Name = $domainName }
            @{ Kind = 'Forest'; Level = $forestLevel; Min = "$($dcCfg['minForestFunctionalLevel'])"; Name = "$(Get-ADSAProp -InputObject $domain -Name 'forestName' -Default $domainName)" }
        )) {
        $rank = Get-ADSAFunctionalLevelRank -Level "$($item.Level)"
        $minRank = Get-ADSAFunctionalLevelRank -Level $item.Min
        if ($null -eq $rank -or $null -eq $minRank) { $skip2++; continue }
        $eval2++
        if ($rank -lt $minRank) { $fail2.Add(@{ Object = $item.Name; ObjectType = "$($item.Kind)FunctionalLevel"; Evidence = [ordered]@{ Scope = $item.Kind; CurrentLevel = "$($item.Level)"; MinimumLevel = $item.Min } }) }
    }
    Complete-ADSARule -Context $ctx -RuleId 'ADSA-INF-002' -Fail $fail2.ToArray() -Evaluated $eval2 -Skipped $skip2 -SkipReason 'functional level missing or not recognised' -ObjectType 'Domain' -Scope 'functional levels'

    # ---- INF-003 / INF-004 trusts
    $trusts = Get-ADSASectionState -Context $ctx -Name 'Trusts'
    if ($trusts.State -ne 'Ok') {
        foreach ($r in 'ADSA-INF-003', 'ADSA-INF-004') { New-ADSASectionResult -Context $ctx -RuleId $r -Section $trusts -SectionName 'Trusts' }
    } else {
        $fail3 = New-Object System.Collections.Generic.List[object]; $eval3 = 0; $skip3 = 0
        $fail4 = New-Object System.Collections.Generic.List[object]; $eval4 = 0
        foreach ($t in @($trusts.Data)) {
            $name = "$(Get-ADSAProp -InputObject $t -Name 'Name' -Default '')"
            $attrRaw = Get-ADSAProp -InputObject $t -Name 'TrustAttributes'
            $dirRaw = Get-ADSAProp -InputObject $t -Name 'TrustDirection'
            $a = [int64]0; $d = 0
            if ($null -eq $attrRaw -or $null -eq $dirRaw -or -not [int64]::TryParse("$attrRaw", [ref]$a) -or -not [int]::TryParse("$dirRaw", [ref]$d)) {
                if (-not (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-INF-003' -Name $name -DistinguishedName '' -Kind any)) { $skip3++ }
                continue
            }
            $flags = Get-ADSATrustFlag -Attributes $a
            $weOutbound = (($d -band 2) -ne 0)   # this domain trusts the other: its SIDs are accepted here
            $dirLabel = switch ($d) { 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' } default { "Unknown($d)" } }
            if (-not $flags.WithinForest -and -not (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-INF-003' -Name $name -DistinguishedName '' -Kind any)) {
                $eval3++
                if ($weOutbound) {
                    $reason = $null
                    if ($flags.TreatAsExternal) { $reason = 'Forest trust is treated as external (TREAT_AS_EXTERNAL), weakening SID filtering.' }
                    elseif (-not $flags.ForestTransitive -and -not $flags.QuarantinedDomain) { $reason = 'External trust without SID filtering (QUARANTINED_DOMAIN is not set).' }
                    if ($reason) { $fail3.Add(@{ Object = $name; ObjectType = 'Trust'; Evidence = [ordered]@{ Direction = $dirLabel; TrustAttributes = [int64]$a; Reason = $reason } }) }
                }
            }
            if (-not $flags.WithinForest -and -not (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-INF-004' -Name $name -DistinguishedName '' -Kind any)) {
                if ($weOutbound) {
                    $eval4++
                    if (-not $flags.CrossOrganization) { $fail4.Add(@{ Object = $name; ObjectType = 'Trust'; Evidence = [ordered]@{ Direction = $dirLabel; TrustAttributes = [int64]$a; SelectiveAuthentication = $false } }) }
                }
            }
        }
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-INF-003' -Fail $fail3.ToArray() -Evaluated $eval3 -Skipped $skip3 -SkipReason 'trust attributes or direction missing' -ObjectType 'Trust' -Scope 'trusts'
        Complete-ADSARule -Context $ctx -RuleId 'ADSA-INF-004' -Fail $fail4.ToArray() -Evaluated $eval4 -ObjectType 'Trust' -Scope 'trusts'
    }
}
