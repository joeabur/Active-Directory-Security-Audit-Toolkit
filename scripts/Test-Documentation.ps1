<#
.SYNOPSIS
    Validates documentation against the code: links and anchors, Mermaid diagrams, PowerShell examples, JSON examples,
    sample files and reports, generated references, and numbers quoted in the guides.
.DESCRIPTION
    Nothing here contacts a domain. Exits non-zero when any check fails (unless -PassThru, which returns the problem list).
    PowerShell example blocks are parsed; every toolkit command and parameter they use must exist; relative file paths must
    exist (paths under ./output are treated as generated output).
.EXAMPLE
    ./scripts/Test-Documentation.ps1
#>
[CmdletBinding()]
param([switch] $PassThru)
Set-StrictMode -Version 2.0
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $root 'src/ADSecurityAudit.psd1') -Force
$problems = New-Object System.Collections.Generic.List[string]
function Add-Problem([string] $Text) { $script:problems.Add($Text) }

$requiredDocs = 'getting-started', 'walkthrough', 'user-guide', 'configuration', 'troubleshooting', 'security-and-limitations', 'examples'
$markdown = @(Get-Item (Join-Path $root 'README.md')) + @(Get-ChildItem (Join-Path $root 'docs') -Filter '*.md')

# --- A/B: required guides exist and README links to them
foreach ($d in $requiredDocs) {
    if (-not (Test-Path (Join-Path $root "docs/$d.md"))) { Add-Problem "Missing docs/$d.md" }
}
$readme = Get-Content -Raw (Join-Path $root 'README.md')
foreach ($d in ($requiredDocs + 'rule-reference' + 'test-results')) {
    if ($readme -notmatch [regex]::Escape("docs/$d.md")) { Add-Problem "README.md does not link docs/$d.md" }
}

function Get-FenceBlock([string] $Text) {
    # returns objects with Lang and Body for fenced code blocks; flags unbalanced fences via Unclosed
    $blocks = New-Object System.Collections.Generic.List[object]
    $inside = $false; $lang = ''; $buf = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*```(\S*)\s*$') {
            if (-not $inside) { $inside = $true; $lang = $Matches[1]; $buf.Clear() }
            else { $blocks.Add([pscustomobject]@{ Lang = $lang; Body = ($buf -join "`n") }); $inside = $false }
            continue
        }
        if ($inside) { $buf.Add($line) }
    }
    if ($inside) { $blocks.Add([pscustomobject]@{ Lang = '__unclosed__'; Body = '' }) }
    return , $blocks.ToArray()
}
function Get-Slug([string] $Heading) {
    $h = $Heading.Trim().ToLowerInvariant() -replace '`', ''
    $h = [regex]::Replace($h, '[^\p{L}\p{N}\s_-]', '')
    return ($h -replace '\s', '-')
}
function Get-AnchorSet([string] $Text) {
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $stripped = [regex]::Replace($Text, '(?ms)^\s*```.*?^\s*```', '')
    foreach ($m in [regex]::Matches($stripped, '(?m)^#{1,6}\s+(.+?)\s*$')) { [void]$set.Add((Get-Slug $m.Groups[1].Value)) }
    return , $set
}

# --- C: links and anchors
$anchorCache = @{}
foreach ($f in $markdown) {
    $text = Get-Content -Raw $f.FullName
    $noCode = [regex]::Replace($text, '(?ms)^\s*```.*?^\s*```', '')
    $rel = $f.FullName.Substring($root.Length + 1)
    foreach ($m in [regex]::Matches($noCode, '\[[^\]]*\]\(([^)\s]+)\)')) {
        $target = $m.Groups[1].Value
        if ($target -match '^(https?:|mailto:)') { continue }
        $path, $anchor = $target, ''
        if ($target.Contains('#')) { $path = $target.Substring(0, $target.IndexOf('#')); $anchor = $target.Substring($target.IndexOf('#') + 1) }
        $full = if ($path) { [System.IO.Path]::GetFullPath((Join-Path $f.DirectoryName $path)) } else { $f.FullName }
        if (-not (Test-Path -LiteralPath $full)) { Add-Problem "$rel : broken link target '$target'"; continue }
        if ($anchor -and $full -like '*.md') {
            if (-not $anchorCache.ContainsKey($full)) { $anchorCache[$full] = Get-AnchorSet (Get-Content -Raw $full) }
            if (-not $anchorCache[$full].Contains($anchor)) { Add-Problem "$rel : missing anchor '#$anchor' in $(Split-Path $full -Leaf)" }
        }
    }
}

# --- D: fences and Mermaid
$srcText = (Get-ChildItem (Join-Path $root 'src') -Filter '*.ps1' -Recurse | ForEach-Object { Get-Content -Raw $_.FullName }) -join "`n"
foreach ($f in $markdown) {
    $rel = $f.FullName.Substring($root.Length + 1)
    foreach ($b in (Get-FenceBlock (Get-Content -Raw $f.FullName))) {
        if ($b.Lang -eq '__unclosed__') { Add-Problem "$rel : unclosed code fence"; continue }
        if ($b.Lang -ne 'mermaid') { continue }
        $body = $b.Body
        if ($body -notmatch '^\s*(flowchart|graph|sequenceDiagram|classDiagram|stateDiagram)') { Add-Problem "$rel : mermaid block has no recognised diagram type" }
        if ($body -match '^\s*(flowchart|graph)') {
            foreach ($pair in @(@('[', ']'), @('{', '}'))) {
                $o = @($body.ToCharArray() | Where-Object { $_ -eq $pair[0] }).Count; $c = @($body.ToCharArray() | Where-Object { $_ -eq $pair[1] }).Count
                if ($o -ne $c) { Add-Problem "$rel : mermaid brackets $($pair[0])$($pair[1]) unbalanced ($o vs $c)" }
            }
            $sg = [regex]::Matches($body, '(?m)^\s*subgraph\b').Count; $en = [regex]::Matches($body, '(?m)^\s*end\s*$').Count
            if ($sg -ne $en) { Add-Problem "$rel : mermaid subgraph/end mismatch ($sg vs $en)" }
        }
        if ($body -match '^\s*sequenceDiagram') {
            $open = [regex]::Matches($body, '(?m)^\s*(alt|loop|opt|par)\b').Count; $en = [regex]::Matches($body, '(?m)^\s*end\s*$').Count
            if ($open -ne $en) { Add-Problem "$rel : mermaid block/end mismatch ($open vs $en)" }
        }
        foreach ($m in [regex]::Matches($body, '\b(?:Invoke|Get|Import|Export|Test|Protect|Add|New|Complete|ConvertTo)-ADSA\w+|Invoke-ADSecurityAudit')) {
            if ($srcText -notmatch ('function\s+' + [regex]::Escape($m.Value) + '\b')) { Add-Problem "$rel : mermaid references unknown function $($m.Value)" }
        }
        foreach ($m in [regex]::Matches($body, '\b(?:AccountLifecycle|PrivilegedAccess|Delegation|Acl|AuthenticationPolicy|GroupPolicy|Infrastructure)\b')) {
            if (-not (Get-ADSARuleCatalog -Module $m.Value)) { Add-Problem "$rel : mermaid references module with no rules $($m.Value)" }
        }
    }
}

# --- E: PowerShell example blocks
$scriptCommand = @{}
foreach ($s in (Get-ChildItem (Join-Path $root 'scripts'), (Join-Path $root 'examples') -Filter '*.ps1')) { $scriptCommand[$s.Name.ToLowerInvariant()] = $s.FullName }
foreach ($f in $markdown) {
    $rel = $f.FullName.Substring($root.Length + 1)
    $n = 0
    foreach ($b in (Get-FenceBlock (Get-Content -Raw $f.FullName))) {
        if ($b.Lang -notin 'powershell', 'pwsh') { continue }
        $n++
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($b.Body, [ref]$tokens, [ref]$errs)
        if ($errs.Count -gt 0) { Add-Problem "$rel : powershell block $n has a syntax error: $($errs[0].Message)"; continue }
        foreach ($cmd in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $name = $cmd.GetCommandName()
            if (-not $name) { continue }
            $info = $null
            if ($name -match '^\.[\\/].*\.ps1$') {
                $p = [System.IO.Path]::GetFullPath((Join-Path $root $name))
                if (-not (Test-Path -LiteralPath $p)) { Add-Problem "$rel : block $n runs missing script $name"; continue }
                $info = Get-Command $p
            } elseif ($name -match 'ADSA|ADSecurityAudit') {
                $info = Get-Command $name -ErrorAction SilentlyContinue
                if (-not $info) { Add-Problem "$rel : block $n uses unknown command $name"; continue }
            } else { continue }
            $common = [System.Management.Automation.Cmdlet]::CommonParameters
            foreach ($el in $cmd.CommandElements) {
                if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                    $pn = $el.ParameterName
                    if ($info.Parameters.ContainsKey($pn) -or $pn -in $common) { continue }
                    Add-Problem "$rel : block $n passes unknown parameter -$pn to $name"
                }
            }
        }
        foreach ($str in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)) {
            $v = $str.Value
            if ($v -match '^\.[\\/]' -and $v -notmatch '^\.[\\/]output' -and $v -notmatch '\*') {
                if (-not (Test-Path -LiteralPath (Join-Path $root $v))) { Add-Problem "$rel : block $n references missing path $v" }
            }
        }
    }
}

# --- F: JSON example blocks are valid configuration overlays
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("adsa-doc-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    foreach ($f in $markdown) {
        $rel = $f.FullName.Substring($root.Length + 1)
        $n = 0
        foreach ($b in (Get-FenceBlock (Get-Content -Raw $f.FullName))) {
            if ($b.Lang -ne 'json') { continue }
            $n++
            $file = Join-Path $tmp "block$n.json"
            [System.IO.File]::WriteAllText($file, $b.Body)
            $r = Test-ADSAConfig -Path $file
            if (-not $r.IsValid) { Add-Problem "$rel : json block $n is not a valid configuration: $($r.Errors -join '; ')" }
        }
    }

    # --- G: example files, samples and reports
    foreach ($c in (Get-ChildItem (Join-Path $root 'examples') -Filter '*config*.json')) {
        $r = Test-ADSAConfig -Path $c.FullName
        if (-not $r.IsValid) { Add-Problem "examples/$($c.Name) is invalid: $($r.Errors -join '; ')" }
        if ($r.Warnings.Count -gt 0) { Add-Problem "examples/$($c.Name) has warnings (expired exception?): $($r.Warnings -join '; ')" }
    }
    $sampleFile = Join-Path $root 'sample-data/contoso-sim.snapshot.json'
    try { $snap = Import-ADSASnapshot -Path $sampleFile; if ($snap.dataSource -ne 'Simulated') { Add-Problem 'sample snapshot is not labelled Simulated' } } catch { Add-Problem "sample snapshot invalid: $($_.Exception.Message)" }
    $hasTestJson = [bool](Get-Command Test-Json -ErrorAction SilentlyContinue)
    if ($hasTestJson) {
        if (-not (Test-Json -Json (Get-Content -Raw $sampleFile) -Schema (Get-Content -Raw (Join-Path $root 'config/schemas/snapshot.schema.json')) -ErrorAction SilentlyContinue)) { Add-Problem 'sample snapshot violates snapshot.schema.json' }
    }
    foreach ($rp in 'sample-report.json', 'sample-report-redacted.json') {
        $path = Join-Path $root "examples/sample-reports/$rp"
        if (-not (Test-Path $path)) { Add-Problem "missing examples/sample-reports/$rp"; continue }
        $v = Test-ADSAReport -Path $path
        if (-not $v.IsValid) { Add-Problem "examples/sample-reports/$rp invalid: $($v.Errors -join '; ')" }
        if ($hasTestJson -and -not (Test-Json -Json (Get-Content -Raw $path) -Schema (Get-Content -Raw (Join-Path $root 'config/schemas/report.schema.json')) -ErrorAction SilentlyContinue)) { Add-Problem "examples/sample-reports/$rp violates report.schema.json" }
        if (((Get-Content -Raw $path | ConvertFrom-Json).Metadata.DataSource) -ne 'Simulated') { Add-Problem "examples/sample-reports/$rp is not labelled Simulated" }
    }
    $csv = Join-Path $root 'examples/sample-reports/sample-report.csv'
    if (Test-Path $csv) {
        $header = (Get-Content -Path $csv -TotalCount 1)
        foreach ($col in 'RuleId', 'Status', 'Severity', 'AffectedObject', 'Evidence', 'Confidence', 'Remediation', 'CollectionTime', 'Limitations') { if ($header -notmatch $col) { Add-Problem "sample-report.csv lacks column $col" } }
    } else { Add-Problem 'missing examples/sample-reports/sample-report.csv' }
    $html = Join-Path $root 'examples/sample-reports/sample-report.html'
    if (Test-Path $html) {
        $h = Get-Content -Raw $html
        if ($h -notmatch 'SIMULATED DATA') { Add-Problem 'sample-report.html lacks the simulated-data banner' }
        if ($h -match '<script') { Add-Problem 'sample-report.html contains a script element' }
    } else { Add-Problem 'missing examples/sample-reports/sample-report.html' }

    # --- H: rule IDs mentioned in docs exist
    $ids = (Get-ADSARuleCatalog).Id
    foreach ($f in $markdown) {
        $rel = $f.FullName.Substring($root.Length + 1)
        foreach ($m in [regex]::Matches((Get-Content -Raw $f.FullName), 'ADSA-[A-Z]+-\d{3}')) { if ($m.Value -notin $ids) { Add-Problem "$rel : unknown rule ID $($m.Value)" } }
    }

    # --- I: generated rule reference is current
    $regen = Join-Path $tmp 'rule-reference.md'
    & (Join-Path $PSScriptRoot 'New-RuleReference.ps1') -OutputFile $regen 6>$null
    $a = (Get-Content -Raw $regen) -replace "`r`n", "`n"
    $b = (Get-Content -Raw (Join-Path $root 'docs/rule-reference.md')) -replace "`r`n", "`n"
    if ($a -ne $b) { Add-Problem 'docs/rule-reference.md is out of date; run ./scripts/New-RuleReference.ps1' }

    # --- J: numbers quoted in guides match a real offline run
    $run = Invoke-ADSecurityAudit -SnapshotPath $sampleFile
    $head = $run.Summary.Headline
    foreach ($doc in 'docs/walkthrough.md', 'docs/getting-started.md') {
        $t = Get-Content -Raw (Join-Path $root $doc)
        if ($t -notlike "*$head*") { Add-Problem "$doc does not quote the current demo headline: $head" }
        foreach ($sev in 'Critical', 'High', 'Medium', 'Low') {
            $line = '{0,-13} : {1}' -f $sev, $run.Summary.ActiveFindingsBySeverity.$sev
            if ($t -notlike "*$line*") { Add-Problem "$doc does not quote '$line'" }
        }
    }
    $walk = Get-Content -Raw (Join-Path $root 'docs/walkthrough.md')
    $st = $run.Summary.ResultsByStatus
    $row = '{0,4} {1,4} {2,5} {3,14} {4,12}' -f $st.PASS, $st.FAIL, $st.ERROR, $st.NOT_APPLICABLE, $st.NOT_ASSESSED
    if ($walk -notlike "*$row*") { Add-Problem "walkthrough does not quote the status counts row '$row'" }
    foreach ($acc in $run.Findings | Where-Object { $_.RuleId -eq 'ADSA-ACC-001' -and $_.Status -eq 'FAIL' }) {
        $needle = ('{0}\s+Low\s+Medium\s+Hygiene\s+{1}' -f [regex]::Escape($acc.AffectedObject), $acc.Evidence.DaysSinceLastLogon)
        if ($walk -notmatch $needle) { Add-Problem "walkthrough does not quote the days since last logon for $($acc.AffectedObject)" }
    }
    $dagroup = $run.Findings | Where-Object { $_.RuleId -eq 'ADSA-PRV-001' -and $_.Status -eq 'FAIL' }
    if ($walk -notmatch ("EffectiveMemberCount : {0}" -f $dagroup.Evidence.EffectiveMemberCount)) { Add-Problem 'walkthrough does not quote the Domain Admins effective member count' }

    # --- K: counts quoted in prose
    $words = @{ ten = 10; eleven = 11; nine = 9; twelve = 12 }
    foreach ($f in $markdown) {
        foreach ($m in [regex]::Matches((Get-Content -Raw $f.FullName), 'exports (\w+) commands')) {
            $w = $m.Groups[1].Value.ToLowerInvariant()
            if ($words.ContainsKey($w) -and $words[$w] -ne (Get-Module ADSecurityAudit).ExportedFunctions.Count) { Add-Problem "$($f.Name) claims $w exported commands but the module exports $((Get-Module ADSecurityAudit).ExportedFunctions.Count)" }
        }
        foreach ($m in [regex]::Matches((Get-Content -Raw $f.FullName), 'evaluates (\d+) documented rules|implements (\d+) rules')) {
            $num = if ($m.Groups[1].Success) { [int]$m.Groups[1].Value } else { [int]$m.Groups[2].Value }
            if ($num -ne @(Get-ADSARuleCatalog).Count) { Add-Problem "$($f.Name) claims $num rules but the catalog has $(@(Get-ADSARuleCatalog).Count)" }
        }
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($PassThru) { return $problems.ToArray() }
foreach ($p in $problems) { Write-Output "DOC PROBLEM: $p" }
Write-Information "Documentation problems: $($problems.Count)" -InformationAction Continue
if ($problems.Count -gt 0) { exit 1 }
