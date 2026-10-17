# Optional pseudonymisation of object names in a report, so it can be shared with fewer directory details exposed.
# Scope: AffectedObject, Evidence, Inventories, CollectionErrors, domain names, and the explanation text of ERROR /
# NOT_ASSESSED results (which can quote error messages). Rule text (titles, remediation) is never touched.
# Redaction reduces exposure; it is not anonymisation. Group-membership structure, counts and timing remain visible.

$script:ADSAWellKnownNames = @(
    'Administrator', 'Administrators', 'Guest', 'krbtgt', 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Account Operators', 'Server Operators',
    'Print Operators', 'Backup Operators', 'Replicator', 'Domain Users', 'Domain Computers', 'Domain Controllers', 'Users', 'Computers', 'Builtin', 'System',
    'AdminSDHolder', 'Policies', 'Default Domain Policy', 'Default Domain Controllers Policy', 'Group Policy Creator Owners', 'Authenticated Users', 'Everyone',
    'Protected Users', 'Managed Service Accounts', 'ForeignSecurityPrincipals', 'Program Data', 'Microsoft Exchange'
)

function Get-ADSARedactionToken {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] [string] $Salt)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Salt + '|' + $Name.ToLowerInvariant()))
    } finally { $sha.Dispose() }
    return 'redacted-' + (($bytes[0..3] | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-ADSAStringLeaf {
    # Yields every string value in a nested object.
    [CmdletBinding()]
    param([AllowNull()] $InputObject)
    if ($null -eq $InputObject) { return }
    if ($InputObject -is [string]) { $InputObject; return }
    if ($InputObject -is [ValueType]) { return }
    if ($InputObject -is [System.Collections.IDictionary]) { foreach ($k in $InputObject.Keys) { Get-ADSAStringLeaf -InputObject $InputObject[$k] }; return }
    if ($InputObject -is [System.Collections.IEnumerable]) { foreach ($i in $InputObject) { Get-ADSAStringLeaf -InputObject $i }; return }
    foreach ($p in $InputObject.PSObject.Properties) { Get-ADSAStringLeaf -InputObject $p.Value }
}

function Convert-ADSAStringTree {
    # Returns a copy of a nested value with a string transform applied to every string.
    [CmdletBinding()]
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] [scriptblock] $Transform)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string]) { return (& $Transform $InputObject) }
    if ($InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [System.Collections.IDictionary]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($i in $InputObject) { $list.Add((Convert-ADSAStringTree -InputObject $i -Transform $Transform)) }
        return , $list.ToArray()
    }
    $out = [ordered]@{}
    $names = Get-ADSAKeyName -InputObject $InputObject
    foreach ($n in $names) { $out[$n] = Convert-ADSAStringTree -InputObject (Get-ADSAProp -InputObject $InputObject -Name $n) -Transform $Transform }
    return [pscustomobject]$out
}

function Protect-ADSAReportData {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Report, [string] $Salt)
    if (-not $Salt) {
        $rnd = New-Object byte[] 16
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($rnd) } finally { $rng.Dispose() }
        $Salt = ($rnd | ForEach-Object { $_.ToString('x2') }) -join ''
    }
    $wellKnown = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($w in $script:ADSAWellKnownNames) { [void]$wellKnown.Add($w) }

    # 1) collect candidate names from the fields in scope
    $scoped = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($Report.Findings)) {
        if ($f.AffectedObject) { $scoped.Add("$($f.AffectedObject)") }
        foreach ($s in (Get-ADSAStringLeaf -InputObject $f.Evidence)) { $scoped.Add($s) }
    }
    foreach ($s in (Get-ADSAStringLeaf -InputObject $Report.Inventories)) { $scoped.Add($s) }
    foreach ($e in @($Report.CollectionErrors)) { if ($e.Target) { $scoped.Add("$($e.Target)") } }
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $scoped) {
        if ($s -match '^S-1-') { continue }
        $parts = New-Object System.Collections.Generic.List[string]
        if ($s -match '(?i)(CN|OU)=') { foreach ($m in [regex]::Matches($s, '(?i)(?:CN|OU)=((?:[^,\\]|\\.)+)')) { $parts.Add($m.Groups[1].Value) } }
        else { $parts.Add($s) }
        foreach ($p in $parts) {
            $p = $p.Trim()
            if ($p.Length -ge 3 -and $p.Length -le 64 -and -not $wellKnown.Contains($p) -and $p -notmatch '^(True|False|Enabled|Disabled|Stale|Running|Stopped|Allow|Deny)$' -and $p -notmatch '^[\d\s.:;/-]+$') { [void]$names.Add($p) }
        }
    }
    $domainNames = @($Report.Metadata.Domain.Name, $Report.Metadata.Domain.NetBiosName) | Where-Object { $_ -and $_ -ne '(unknown)' }
    foreach ($d in $domainNames) { [void]$names.Add("$d") }
    foreach ($d in @($Report.Metadata.Domain.Name)) { if ($d) { foreach ($label in ("$d" -split '\.')) { if ($label.Length -ge 3) { [void]$names.Add($label) } } } }
    $ordered = @($names | Sort-Object { $_.Length } -Descending)

    $transform = {
        param([string] $text)
        $t = $text
        foreach ($n in $ordered) {
            if ($t.IndexOf($n, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $t = [regex]::Replace($t, [regex]::Escape($n), (Get-ADSARedactionToken -Name $n -Salt $Salt), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
        }
        return [regex]::Replace($t, 'S-1-5-21-\d+-\d+-\d+', 'S-1-5-21-REDACTED')
    }

    # 2) apply to a deep copy, only in scoped fields
    $copy = ($Report | ConvertTo-Json -Depth 12) | ConvertFrom-Json
    foreach ($f in @($copy.Findings)) {
        if ($f.AffectedObject) { $f.AffectedObject = & $transform "$($f.AffectedObject)" }
        $f.Evidence = Convert-ADSAStringTree -InputObject $f.Evidence -Transform $transform
        if ($f.Status -in 'ERROR', 'NOT_ASSESSED') { $f.Explanation = & $transform "$($f.Explanation)" }
    }
    $copy.Summary.TopFindings = Convert-ADSAStringTree -InputObject $copy.Summary.TopFindings -Transform $transform
    $copy.Inventories = Convert-ADSAStringTree -InputObject $copy.Inventories -Transform $transform
    foreach ($e in @($copy.CollectionErrors)) { $e.Target = & $transform "$($e.Target)"; $e.Message = & $transform "$($e.Message)" }
    $copy.Metadata.Domain = Convert-ADSAStringTree -InputObject $copy.Metadata.Domain -Transform $transform
    foreach ($c in @($copy.Coverage.Sections)) { $c.ErrorCategory = "$($c.ErrorCategory)" }
    Add-Member -InputObject $copy.Metadata -MemberType NoteProperty -Name Redacted -Value $true -Force
    $copy.Metadata.Notice = "$($copy.Metadata.Notice) Object names are pseudonymised (redacted-xxxxxxxx); redaction reduces exposure but is not anonymisation."
    return $copy
}
