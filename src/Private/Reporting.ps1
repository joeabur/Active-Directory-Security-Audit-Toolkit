# Report renderers. All dynamic content is escaped for its output context.
# HTML: every value passes through HtmlEncode; class names come from whitelists; no script, no external resources.
# CSV: cells that could be interpreted as formulas are neutralised.

function ConvertTo-ADSAHtmlText {
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode("$Value")
}

function Get-ADSASafeToken {
    # Returns the value only if it is in the allowed list, otherwise 'unknown'. Used for CSS class names.
    [CmdletBinding()]
    param([AllowNull()] $Value, [Parameter(Mandatory)] [string[]] $Allowed)
    $text = "$Value"
    if ($text -in $Allowed) { return $text.ToLowerInvariant().Replace('_', '-') }
    return 'unknown'
}

function Protect-ADSACsvCell {
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return '' }
    $text = "$Value"
    if ($text -match '^[=+\-@\t\r]') { return "'" + $text }
    return $text
}

function ConvertTo-ADSAEvidenceText {
    [CmdletBinding()]
    param([AllowNull()] $Evidence)
    if ($null -eq $Evidence) { return '' }
    return ($Evidence | ConvertTo-Json -Depth 6 -Compress)
}

function ConvertTo-ADSAJsonReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Report)
    return ($Report | ConvertTo-Json -Depth 12)
}

function ConvertTo-ADSACsvReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Report)
    $rows = foreach ($f in @($Report.Findings)) {
        [pscustomobject][ordered]@{
            RuleId             = Protect-ADSACsvCell $f.RuleId
            Status             = Protect-ADSACsvCell $f.Status
            Severity           = Protect-ADSACsvCell $f.Severity
            Confidence         = Protect-ADSACsvCell $f.Confidence
            FindingType        = Protect-ADSACsvCell $f.FindingType
            Category           = Protect-ADSACsvCell $f.Category
            AffectedObjectType = Protect-ADSACsvCell $f.AffectedObjectType
            AffectedObject     = Protect-ADSACsvCell $f.AffectedObject
            Title              = Protect-ADSACsvCell $f.Title
            Explanation        = Protect-ADSACsvCell $f.Explanation
            Evidence           = Protect-ADSACsvCell (ConvertTo-ADSAEvidenceText $f.Evidence)
            Remediation        = Protect-ADSACsvCell $f.Remediation
            CollectionTime     = Protect-ADSACsvCell $f.CollectionTime
            Limitations        = Protect-ADSACsvCell $f.Limitations
            Excepted           = $f.Excepted
            ExceptionId        = Protect-ADSACsvCell $(if ($f.Exception) { $f.Exception.Id } else { '' })
            DataSource         = Protect-ADSACsvCell $f.DataSource
        }
    }
    if (-not $rows) {
        return 'RuleId,Status,Severity,Confidence,FindingType,Category,AffectedObjectType,AffectedObject,Title,Explanation,Evidence,Remediation,CollectionTime,Limitations,Excepted,ExceptionId,DataSource'
    }
    return (($rows | ConvertTo-Csv -NoTypeInformation) -join [System.Environment]::NewLine)
}

function ConvertTo-ADSAEvidenceHtml {
    [CmdletBinding()]
    param([AllowNull()] $Evidence)
    if ($null -eq $Evidence) { return '' }
    $names = Get-ADSAKeyName -InputObject $Evidence
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<dl class="ev">')
    foreach ($n in $names) {
        $v = Get-ADSAProp -InputObject $Evidence -Name $n
        $text = if ($null -eq $v) { '' } elseif (($v -is [System.Collections.IEnumerable]) -and ($v -isnot [string])) { (@($v) | ForEach-Object { if ($_ -is [string] -or $_ -is [ValueType]) { "$_" } else { $_ | ConvertTo-Json -Depth 4 -Compress } }) -join '; ' } elseif ($v -is [string] -or $v -is [ValueType]) { "$v" } else { $v | ConvertTo-Json -Depth 4 -Compress }
        [void]$sb.Append('<dt>').Append((ConvertTo-ADSAHtmlText $n)).Append('</dt><dd>').Append((ConvertTo-ADSAHtmlText $text)).Append('</dd>')
    }
    [void]$sb.Append('</dl>')
    return $sb.ToString()
}

function ConvertTo-ADSAHtmlReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Report)
    $e = { param($v) ConvertTo-ADSAHtmlText $v }
    $sevAllowed = @('Critical', 'High', 'Medium', 'Low', 'Informational')
    $statusAllowed = @('PASS', 'FAIL', 'ERROR', 'NOT_APPLICABLE', 'NOT_ASSESSED')
    $m = $Report.Metadata
    $s = $Report.Summary
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; img-src data:">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">')
    $null = $sb.AppendLine('<title>AD Security Audit Report</title>')
    $null = $sb.AppendLine(@'
<style>
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--card:#f6f8fa;--crit:#82071e;--high:#cf222e;--med:#9a6700;--low:#0969da;--info:#57606a;--ok:#1a7f37;--warn:#bf8700}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;--card:#161b22;--crit:#ff7b72;--high:#ffa198;--med:#e3b341;--low:#79c0ff;--info:#8b949e;--ok:#56d364;--warn:#e3b341}}
body{font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px;max-width:1200px;margin-inline:auto}
h1{font-size:22px}h2{font-size:18px;margin-top:32px;border-bottom:1px solid var(--line);padding-bottom:4px}
.banner{padding:10px 14px;border:2px solid var(--warn);border-radius:6px;background:var(--card);margin:12px 0}
.banner.sim{border-color:var(--high)}
.cards{display:flex;flex-wrap:wrap;gap:10px}.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 14px;min-width:110px}
.card b{display:block;font-size:22px}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--card)}
.wrap{overflow-x:auto}
.sev-critical{color:var(--crit);font-weight:700}.sev-high{color:var(--high);font-weight:700}.sev-medium{color:var(--med);font-weight:700}.sev-low{color:var(--low);font-weight:700}.sev-informational,.sev-unknown{color:var(--info)}
.st-fail{color:var(--high);font-weight:700}.st-pass{color:var(--ok);font-weight:700}.st-error{color:var(--warn);font-weight:700}.st-not-assessed{color:var(--warn)}.st-not-applicable,.st-unknown{color:var(--muted)}
dl.ev{margin:0}dl.ev dt{font-weight:600;float:left;clear:left;margin-right:6px}dl.ev dd{margin:0 0 2px 0;word-break:break-word}
.small{color:var(--muted);font-size:12px}details{margin:6px 0}
</style>
'@)
    $null = $sb.AppendLine('</head><body>')
    $null = $sb.AppendLine('<h1>Active Directory Security Audit Report</h1>')
    $bannerClass = if ($m.DataSource -eq 'Simulated') { 'banner sim' } else { 'banner' }
    $null = $sb.AppendLine("<div class=""$bannerClass""><strong>Data source: $(& $e $m.DataSource)</strong> ($(& $e $m.AnalysisMode)). $(& $e $m.Notice)</div>")
    $null = $sb.AppendLine("<p class=""small"">Domain: $(& $e $m.Domain.Name) &middot; Collected: $(& $e $m.CollectionTime) &middot; Generated: $(& $e $m.GeneratedAt) &middot; Tool: $(& $e $Report.Tool.Name) $(& $e $Report.Tool.Version) &middot; Schema $(& $e $Report.SchemaVersion)</p>")
    $null = $sb.AppendLine('<p class="small"><strong>Handle as sensitive:</strong> this report contains directory information (account names, group membership, configuration). Store and share it accordingly.</p>')

    # Executive summary
    $null = $sb.AppendLine('<h2 id="summary">Executive summary</h2>')
    $null = $sb.AppendLine("<p>$(& $e $s.Headline)</p>")
    $null = $sb.AppendLine('<div class="cards">')
    foreach ($sev in $sevAllowed) {
        $n = $s.ActiveFindingsBySeverity.$sev
        $null = $sb.AppendLine("<div class=""card""><b class=""sev-$(Get-ADSASafeToken $sev $sevAllowed)"">$(& $e $n)</b>$(& $e $sev)</div>")
    }
    $null = $sb.AppendLine("<div class=""card""><b>$(& $e $s.ExceptedFindings)</b>Excepted</div>")
    $null = $sb.AppendLine("<div class=""card""><b>$(& $e $s.RulesAssessed) / $(& $e $s.RulesInCatalog)</b>Rules assessed</div>")
    $null = $sb.AppendLine("<div class=""card""><b>$(& $e $s.RulesNotFullyAssessed)</b>Not fully assessed</div>")
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine('<p class="small">Severity counts include only FAIL results not covered by a documented exception. ERROR and NOT_ASSESSED results are coverage gaps, never passes. A stale-account finding is hygiene evidence, not a confirmed vulnerability; see each finding''s type and confidence.</p>')
    foreach ($w in @($m.Warnings)) { if ($w) { $null = $sb.AppendLine("<p class=""small"">Configuration warning: $(& $e $w)</p>") } }

    # Findings
    $active = @($Report.Findings | Where-Object { $_.Status -eq 'FAIL' -and -not $_.Excepted })
    $null = $sb.AppendLine('<h2 id="findings">Technical findings (FAIL)</h2>')
    if ($active.Count -eq 0) { $null = $sb.AppendLine('<p>No active FAIL findings. Review the coverage section before drawing conclusions.</p>') }
    foreach ($f in $active) {
        $null = $sb.AppendLine("<details open><summary><span class=""sev-$(Get-ADSASafeToken $f.Severity $sevAllowed)"">$(& $e $f.Severity)</span> &middot; $(& $e $f.RuleId) &middot; $(& $e $f.Title) &mdash; <em>$(& $e $f.AffectedObject)</em></summary>")
        $null = $sb.AppendLine('<div class="wrap"><table>')
        $null = $sb.AppendLine("<tr><th>Affected object</th><td>$(& $e $f.AffectedObject) <span class=""small"">($(& $e $f.AffectedObjectType))</span></td></tr>")
        $null = $sb.AppendLine("<tr><th>Finding type / confidence</th><td>$(& $e $f.FindingType) / $(& $e $f.Confidence)</td></tr>")
        $null = $sb.AppendLine("<tr><th>Evidence</th><td>$(ConvertTo-ADSAEvidenceHtml $f.Evidence)</td></tr>")
        $null = $sb.AppendLine("<tr><th>Explanation</th><td>$(& $e $f.Explanation)</td></tr>")
        $null = $sb.AppendLine("<tr><th>Remediation</th><td>$(& $e $f.Remediation)</td></tr>")
        $null = $sb.AppendLine("<tr><th>Limitations</th><td>$(& $e $f.Limitations)</td></tr>")
        $null = $sb.AppendLine("<tr><th>Collected / source</th><td>$(& $e $f.CollectionTime) / $(& $e $f.DataSource)</td></tr>")
        $null = $sb.AppendLine('</table></div></details>')
    }

    $excepted = @($Report.Findings | Where-Object { $_.Excepted })
    $null = $sb.AppendLine('<h2 id="exceptions">Findings covered by documented exceptions</h2>')
    if ($excepted.Count -eq 0) { $null = $sb.AppendLine('<p>None.</p>') } else {
        $null = $sb.AppendLine('<div class="wrap"><table><tr><th>Rule</th><th>Object</th><th>Exception</th><th>Owner</th><th>Expires</th><th>Reason</th></tr>')
        foreach ($f in $excepted) { $null = $sb.AppendLine("<tr><td>$(& $e $f.RuleId)</td><td>$(& $e $f.AffectedObject)</td><td>$(& $e $f.Exception.Id)</td><td>$(& $e $f.Exception.Owner)</td><td>$(& $e $f.Exception.Expires)</td><td>$(& $e $f.Exception.Reason)</td></tr>") }
        $null = $sb.AppendLine('</table></div>')
    }

    $gaps = @($Report.Findings | Where-Object { $_.Status -in 'ERROR', 'NOT_ASSESSED' })
    $null = $sb.AppendLine('<h2 id="gaps">Not assessed and errors</h2>')
    if ($gaps.Count -eq 0) { $null = $sb.AppendLine('<p>None.</p>') } else {
        $null = $sb.AppendLine('<div class="wrap"><table><tr><th>Status</th><th>Rule</th><th>Object</th><th>Detail</th></tr>')
        foreach ($f in $gaps) { $null = $sb.AppendLine("<tr><td class=""st-$(Get-ADSASafeToken $f.Status $statusAllowed)"">$(& $e $f.Status)</td><td>$(& $e $f.RuleId) $(& $e $f.Title)</td><td>$(& $e $f.AffectedObject)</td><td>$(& $e $f.Explanation)</td></tr>") }
        $null = $sb.AppendLine('</table></div>')
    }

    # Coverage
    $null = $sb.AppendLine('<h2 id="coverage">Coverage</h2>')
    $null = $sb.AppendLine('<div class="wrap"><table><tr><th>Rule</th><th>Title</th><th>Module</th><th>Status</th><th>Note</th></tr>')
    foreach ($r in $Report.Coverage.Rules) {
        $note = if ($r.Partial) { 'Partial: some objects could not be assessed. ' + $r.Note } else { $r.Note }
        $null = $sb.AppendLine("<tr><td>$(& $e $r.RuleId)</td><td>$(& $e $r.Title)</td><td>$(& $e $r.Module)</td><td class=""st-$(Get-ADSASafeToken $r.Status $statusAllowed)"">$(& $e $r.Status)</td><td>$(& $e $note)</td></tr>")
    }
    $null = $sb.AppendLine('</table></div>')
    $null = $sb.AppendLine('<div class="wrap"><table><tr><th>Data section</th><th>Status</th><th>Objects</th><th>Error category</th><th>Warnings</th></tr>')
    foreach ($c in $Report.Coverage.Sections) { $null = $sb.AppendLine("<tr><td>$(& $e $c.Section)</td><td>$(& $e $c.Status)</td><td>$(& $e $c.ObjectCount)</td><td>$(& $e $c.ErrorCategory)</td><td>$(& $e $c.WarningCount)</td></tr>") }
    $null = $sb.AppendLine('</table></div>')

    $null = $sb.AppendLine('<h2 id="errors">Collection errors</h2>')
    if (@($Report.CollectionErrors).Count -eq 0) { $null = $sb.AppendLine('<p>None.</p>') } else {
        $null = $sb.AppendLine('<div class="wrap"><table><tr><th>Source</th><th>Target</th><th>Category</th><th>Message</th></tr>')
        foreach ($c in $Report.CollectionErrors) { $null = $sb.AppendLine("<tr><td>$(& $e $c.Source)</td><td>$(& $e $c.Target)</td><td>$(& $e $c.Category)</td><td>$(& $e $c.Message)</td></tr>") }
        $null = $sb.AppendLine('</table></div>')
    }

    # Inventories
    $inv = $Report.Inventories
    $null = $sb.AppendLine('<h2 id="inventory">Inventories (informational)</h2>')
    $null = $sb.AppendLine('<h3>Privileged groups</h3><div class="wrap"><table><tr><th>Group</th><th>Found</th><th>Effective members</th><th>Nested groups</th><th>Unresolved</th></tr>')
    foreach ($g in @($inv.PrivilegedGroups)) { $null = $sb.AppendLine("<tr><td>$(& $e $g.Name)</td><td>$(& $e $g.Found)</td><td>$(& $e $g.EffectiveMemberCount)</td><td>$(& $e $g.NestedGroupCount)</td><td>$(& $e $g.UnresolvedMemberCount)</td></tr>") }
    $null = $sb.AppendLine('</table></div>')
    $null = $sb.AppendLine('<h3>Service accounts (users with SPNs)</h3><div class="wrap"><table><tr><th>Account</th><th>Enabled</th><th>Password last set</th><th>Never expires</th><th>Privileged</th><th>SPNs</th></tr>')
    foreach ($a in @($inv.ServiceAccounts)) { $null = $sb.AppendLine("<tr><td>$(& $e $a.SamAccountName)</td><td>$(& $e $a.Enabled)</td><td>$(& $e $a.PasswordLastSet)</td><td>$(& $e $a.PasswordNeverExpires)</td><td>$(& $e $a.Privileged)</td><td>$(& $e $a.SpnCount)</td></tr>") }
    $null = $sb.AppendLine('</table></div>')
    $null = $sb.AppendLine("<p>Enabled accounts with password-expiration exception: $(& $e $inv.PasswordNeverExpiresCount)</p>")
    $null = $sb.AppendLine('<h3>Domain controllers</h3><div class="wrap"><table><tr><th>Name</th><th>Operating system</th><th>Site</th><th>Read-only</th></tr>')
    foreach ($d in @($inv.DomainControllers)) { $null = $sb.AppendLine("<tr><td>$(& $e $d.Name)</td><td>$(& $e $d.OperatingSystem)</td><td>$(& $e $d.Site)</td><td>$(& $e $d.IsReadOnly)</td></tr>") }
    $null = $sb.AppendLine('</table></div>')
    $null = $sb.AppendLine('<h3>Trusts</h3><div class="wrap"><table><tr><th>Name</th><th>Direction</th><th>Attributes</th></tr>')
    foreach ($t in @($inv.Trusts)) { $null = $sb.AppendLine("<tr><td>$(& $e $t.Name)</td><td>$(& $e $t.Direction)</td><td>$(& $e $t.Attributes)</td></tr>") }
    $null = $sb.AppendLine('</table></div>')

    $null = $sb.AppendLine('<h2 id="limits">Limitations</h2><ul><li>This toolkit performs selected, read-only checks. It does not claim to find every Active Directory attack path or misconfiguration.</li><li>PASS means the checked objects did not violate the rule, within the stated limitations; it is not a certification.</li><li>Results from mock or simulated data demonstrate the tooling only and never establish the security of a real domain.</li></ul>')
    $null = $sb.AppendLine('</body></html>')
    return $sb.ToString()
}
