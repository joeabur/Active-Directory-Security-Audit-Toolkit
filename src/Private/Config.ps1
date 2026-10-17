# Versioned configuration loading, merging and strict validation.
# Configuration holds thresholds and documented exceptions only. It must never hold credentials.

$script:ADSASupportedConfigMajor = 1

function ConvertTo-ADSAHashtable {
    # Recursively converts ConvertFrom-Json output (PSCustomObject) to ordered hashtables; arrays stay arrays.
    [CmdletBinding()]
    param([AllowNull()] $InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($k in $InputObject.Keys) { $out["$k"] = ConvertTo-ADSAHashtable -InputObject $InputObject[$k] }
        return $out
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $out = [ordered]@{}
        foreach ($p in $InputObject.PSObject.Properties) { $out[$p.Name] = ConvertTo-ADSAHashtable -InputObject $p.Value }
        return $out
    }
    if (($InputObject -is [System.Collections.IEnumerable]) -and ($InputObject -isnot [string])) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($item in $InputObject) { $list.Add((ConvertTo-ADSAHashtable -InputObject $item)) }
        return , $list.ToArray()
    }
    return $InputObject
}

function Merge-ADSAHashtable {
    # Overlays $Override on $Base. Dictionaries merge recursively; arrays and scalars replace.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Base, [Parameter(Mandatory)] [System.Collections.IDictionary] $Override)
    $result = [ordered]@{}
    foreach ($k in $Base.Keys) { $result[$k] = $Base[$k] }
    foreach ($k in $Override.Keys) {
        if ($result.Contains($k) -and ($result[$k] -is [System.Collections.IDictionary]) -and ($Override[$k] -is [System.Collections.IDictionary])) {
            $result[$k] = Merge-ADSAHashtable -Base $result[$k] -Override $Override[$k]
        } else {
            $result[$k] = $Override[$k]
        }
    }
    return $result
}

function Get-ADSADefaultConfigPath {
    return (Join-Path $script:ADSARoot 'config/default.config.json')
}

function Read-ADSAJsonFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path, [string] $Description = 'JSON file')
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Description not found: '$Path'." }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "$Description '$Path' is empty." }
    try {
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        throw "$Description '$Path' is not valid JSON: $($_.Exception.Message)"
    }
}

function Test-ADSAConfigData {
    # Validates a merged configuration hashtable. Returns @{ IsValid; Errors; Warnings }.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Config, [Parameter(Mandatory)] [System.Collections.IDictionary] $Defaults, [Nullable[datetime]] $ReferenceTime)
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    if ($null -eq $ReferenceTime) { $ReferenceTime = [datetime]::UtcNow }

    # configVersion
    $ver = "$($Config['configVersion'])"
    if ($ver -notmatch '^(\d+)\.(\d+)$') {
        $errors.Add("configVersion '$ver' is not in 'major.minor' form.")
    } elseif ([int]$Matches[1] -ne $script:ADSASupportedConfigMajor) {
        $errors.Add("configVersion '$ver' is not supported (this toolkit reads major version $($script:ADSASupportedConfigMajor)).")
    }

    # Unknown top-level and section keys (typos must not silently disable a check)
    foreach ($k in $Config.Keys) {
        if (-not $Defaults.Contains($k)) { $errors.Add("Unknown configuration key '$k'.") }
    }
    foreach ($section in 'thresholds', 'passwordPolicy', 'domainControllers', 'securityLog', 'collection', 'logging', 'trustedPrincipals') {
        if ($Config.Contains($section)) {
            if ($Config[$section] -isnot [System.Collections.IDictionary]) { $errors.Add("'$section' must be an object."); continue }
            foreach ($k in $Config[$section].Keys) {
                if (-not $Defaults[$section].Contains($k)) { $errors.Add("Unknown configuration key '$section.$k'.") }
            }
        }
    }

    # Numeric ranges
    $ranges = @(
        @('thresholds', 'staleUserDays', 15, 3650), @('thresholds', 'staleComputerDays', 15, 3650),
        @('thresholds', 'neverLoggedOnGraceDays', 0, 3650), @('thresholds', 'servicePasswordMaxAgeDays', 30, 3650),
        @('thresholds', 'krbtgtMaxAgeDays', 30, 3650),
        @('passwordPolicy', 'minLength', 1, 128), @('passwordPolicy', 'minHistory', 0, 24),
        @('passwordPolicy', 'lockoutThresholdMax', 1, 999), @('passwordPolicy', 'lockoutDurationMinMinutes', 0, 100000),
        @('securityLog', 'minSizeMB', 1, 1048576), @('collection', 'aclMaxObjects', 1, 100000)
    )
    foreach ($r in $ranges) {
        $section = $r[0]; $key = $r[1]
        if ($Config.Contains($section) -and ($Config[$section] -is [System.Collections.IDictionary]) -and $Config[$section].Contains($key)) {
            $v = $Config[$section][$key]
            $n = 0
            if ($v -is [bool] -or -not [int]::TryParse("$v", [ref]$n) -or ("$v" -notmatch '^-?\d+$')) {
                $errors.Add("$section.$key must be an integer (got '$v').")
            } elseif ($n -lt $r[2] -or $n -gt $r[3]) {
                $errors.Add("$section.$key must be between $($r[2]) and $($r[3]) (got $n).")
            }
        }
    }
    foreach ($b in @(@('passwordPolicy', 'complexityRequired'), @('collection', 'collectDcHostSettings'), @('collection', 'collectSysvol'), @('collection', 'collectAcls'))) {
        if ($Config.Contains($b[0]) -and ($Config[$b[0]] -is [System.Collections.IDictionary]) -and $Config[$b[0]].Contains($b[1]) -and ($Config[$b[0]][$b[1]] -isnot [bool])) {
            $errors.Add("$($b[0]).$($b[1]) must be true or false.")
        }
    }
    if ($Config.Contains('logging') -and ($Config['logging'] -is [System.Collections.IDictionary])) {
        $lvl = $Config['logging']['level']
        if ($lvl -notin 'Debug', 'Information', 'Warning', 'Error') { $errors.Add("logging.level '$lvl' is invalid (Debug, Information, Warning, Error).") }
    }

    # Regex pattern must compile
    if ($Config.Contains('domainControllers') -and ($Config['domainControllers'] -is [System.Collections.IDictionary])) {
        $pattern = $Config['domainControllers']['unsupportedOsPattern']
        if ($pattern) { try { [void][regex]::new("$pattern") } catch { $errors.Add("domainControllers.unsupportedOsPattern is not a valid regular expression: $($_.Exception.Message)") } }
    }

    # Max members map
    if ($Config.Contains('privilegedGroupMaxMembers')) {
        $map = $Config['privilegedGroupMaxMembers']
        if ($map -isnot [System.Collections.IDictionary]) { $errors.Add('privilegedGroupMaxMembers must be an object.') }
        else {
            foreach ($k in $map.Keys) {
                $n = 0
                if (-not [int]::TryParse("$($map[$k])", [ref]$n) -or $n -lt 0) { $errors.Add("privilegedGroupMaxMembers.'$k' must be a non-negative integer.") }
            }
            if (-not $map.Contains('default')) { $errors.Add("privilegedGroupMaxMembers must define 'default'.") }
        }
    }

    # privilegedGroups
    if ($Config.Contains('privilegedGroups')) {
        $i = 0
        foreach ($g in @($Config['privilegedGroups'])) {
            $i++
            if ($g -isnot [System.Collections.IDictionary]) { $errors.Add("privilegedGroups[$i] must be an object."); continue }
            if (-not $g['name']) { $errors.Add("privilegedGroups[$i] requires 'name'.") }
            $hasSid = [bool]$g['sid']; $hasRid = $g.Contains('rid')
            if ($hasSid -eq $hasRid) { $errors.Add("privilegedGroups[$i] requires exactly one of 'sid' or 'rid'.") }
            if ($hasSid -and "$($g['sid'])" -notmatch '^S-1-\d+(-\d+)+$') { $errors.Add("privilegedGroups[$i].sid is not a valid SID.") }
            if ($hasRid -and "$($g['rid'])" -notmatch '^\d+$') { $errors.Add("privilegedGroups[$i].rid must be a number.") }
        }
    }

    # trusted principals
    if ($Config.Contains('trustedPrincipals') -and ($Config['trustedPrincipals'] -is [System.Collections.IDictionary])) {
        foreach ($sid in @($Config['trustedPrincipals']['sids'])) {
            if ($sid -and "$sid" -notmatch '^S-1-\d+(-\d+)+$') { $errors.Add("trustedPrincipals.sids contains an invalid SID '$sid'.") }
        }
    }

    # audit policy
    if ($Config.Contains('auditPolicy')) {
        $req = $null
        if ($Config['auditPolicy'] -is [System.Collections.IDictionary]) { $req = $Config['auditPolicy']['required'] }
        $i = 0
        foreach ($a in @($req)) {
            $i++
            if ($a -isnot [System.Collections.IDictionary]) { $errors.Add("auditPolicy.required[$i] must be an object."); continue }
            if (-not $a['name'] -or -not $a['guid']) { $errors.Add("auditPolicy.required[$i] requires 'name' and 'guid'.") }
            elseif ("$($a['guid'])" -notmatch '^\{?[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?$') { $errors.Add("auditPolicy.required[$i].guid is not a GUID.") }
            foreach ($f in 'success', 'failure') { if ($a.Contains($f) -and $a[$f] -isnot [bool]) { $errors.Add("auditPolicy.required[$i].$f must be true or false.") } }
        }
    }

    # exclusions: reason is mandatory so every blind spot is documented
    $i = 0
    foreach ($e in @($Config['exclusions'])) {
        if ($null -eq $e) { continue }
        $i++
        if ($e -isnot [System.Collections.IDictionary]) { $errors.Add("exclusions[$i] must be an object."); continue }
        foreach ($k in $e.Keys) { if ($k -notin 'pattern', 'appliesTo', 'ruleIds', 'reason') { $errors.Add("exclusions[$i] has unknown key '$k'.") } }
        if (-not $e['pattern']) { $errors.Add("exclusions[$i] requires 'pattern'.") }
        if (-not $e['reason']) { $errors.Add("exclusions[$i] requires a documented 'reason'.") }
        foreach ($a in @($e['appliesTo'])) { if ($a -and $a -notin 'user', 'computer', 'group', 'any') { $errors.Add("exclusions[$i].appliesTo '$a' is invalid (user, computer, group, any).") } }
        foreach ($rid in @($e['ruleIds'])) { if ($rid -and "$rid" -notmatch '^ADSA-[A-Z]+-\d{3}$') { $errors.Add("exclusions[$i].ruleIds '$rid' is not a valid rule ID.") } }
    }

    # exceptions: documented, owned and time-boxed
    $i = 0
    $seen = @{}
    foreach ($x in @($Config['exceptions'])) {
        if ($null -eq $x) { continue }
        $i++
        if ($x -isnot [System.Collections.IDictionary]) { $errors.Add("exceptions[$i] must be an object."); continue }
        foreach ($k in $x.Keys) { if ($k -notin 'id', 'ruleId', 'objectPattern', 'reason', 'owner', 'approvedBy', 'expires') { $errors.Add("exceptions[$i] has unknown key '$k'.") } }
        foreach ($req in 'id', 'ruleId', 'objectPattern', 'reason', 'owner', 'expires') { if (-not $x[$req]) { $errors.Add("exceptions[$i] requires '$req'.") } }
        if ($x['id']) {
            if ($seen.ContainsKey("$($x['id'])")) { $errors.Add("exceptions[$i].id '$($x['id'])' is duplicated.") }
            $seen["$($x['id'])"] = $true
        }
        if ($x['ruleId'] -and "$($x['ruleId'])" -notmatch '^ADSA-[A-Z]+-\d{3}$') { $errors.Add("exceptions[$i].ruleId '$($x['ruleId'])' is not a valid rule ID.") }
        if ($x['expires']) {
            $exp = ConvertTo-ADSADateTime -Value $x['expires']
            if ($null -eq $exp) { $errors.Add("exceptions[$i].expires '$($x['expires'])' is not a valid date (use yyyy-MM-dd).") }
            elseif ($exp -lt $ReferenceTime) { $warnings.Add("Exception '$($x['id'])' expired on $($exp.ToString('yyyy-MM-dd')) and will not be applied.") }
        }
    }

    return [pscustomobject]@{ IsValid = ($errors.Count -eq 0); Errors = $errors.ToArray(); Warnings = $warnings.ToArray() }
}

function Import-ADSAConfigData {
    # Loads defaults, overlays an optional user file, validates, and returns @{ Config; Warnings }. Throws on invalid config.
    [CmdletBinding()]
    param([AllowNull()] [string] $Path, [Nullable[datetime]] $ReferenceTime)
    $defaultsRaw = Read-ADSAJsonFile -Path (Get-ADSADefaultConfigPath) -Description 'Default configuration'
    $defaults = ConvertTo-ADSAHashtable -InputObject $defaultsRaw
    $merged = $defaults
    if ($Path) {
        $userRaw = Read-ADSAJsonFile -Path $Path -Description 'Configuration file'
        if ($userRaw -isnot [System.Management.Automation.PSCustomObject]) { throw "Configuration file '$Path' must contain a JSON object." }
        $user = ConvertTo-ADSAHashtable -InputObject $userRaw
        $merged = Merge-ADSAHashtable -Base $defaults -Override $user
    }
    $check = Test-ADSAConfigData -Config $merged -Defaults $defaults -ReferenceTime $ReferenceTime
    if (-not $check.IsValid) {
        throw ("Configuration is invalid:`n - " + ($check.Errors -join "`n - "))
    }
    return [pscustomobject]@{ Config = $merged; Warnings = $check.Warnings }
}

function Test-ADSAExcluded {
    # True when the object matches a documented exclusion for this rule. Increments the per-rule exclusion counter.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string] $RuleId,
        [string] $Name,
        [string] $DistinguishedName,
        [ValidateSet('user', 'computer', 'group', 'any')] [string] $Kind = 'any'
    )
    foreach ($e in @($Context.Config['exclusions'])) {
        if ($null -eq $e) { continue }
        $rules = @($e['ruleIds'] | Where-Object { $_ })
        if ($rules.Count -gt 0 -and $RuleId -notin $rules) { continue }
        $applies = @($e['appliesTo'] | Where-Object { $_ })
        if ($applies.Count -gt 0 -and 'any' -notin $applies -and $Kind -notin $applies) { continue }
        if ((Test-ADSAWildcardMatch -Value $Name -Pattern "$($e['pattern'])") -or (Test-ADSAWildcardMatch -Value $DistinguishedName -Pattern "$($e['pattern'])")) {
            if (-not $Context.Excluded.ContainsKey($RuleId)) { $Context.Excluded[$RuleId] = 0 }
            $Context.Excluded[$RuleId]++
            return $true
        }
    }
    return $false
}
