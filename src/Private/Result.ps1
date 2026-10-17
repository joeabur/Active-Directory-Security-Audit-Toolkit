# Rule catalog access, run context and result construction.
# Every result carries: rule ID, severity, affected object, evidence, explanation, confidence,
# remediation, collection time, limitations and the data source (Live or Simulated).

$script:ADSAStatuses = @('PASS', 'FAIL', 'ERROR', 'NOT_APPLICABLE', 'NOT_ASSESSED')
$script:ADSASeverities = @('Critical', 'High', 'Medium', 'Low', 'Informational')

function Get-ADSARuleCatalogData {
    if ($null -eq $script:ADSARuleCatalogCache) {
        $path = Join-Path $script:ADSAModuleRoot 'Rules/RuleCatalog.psd1'
        $data = Import-PowerShellDataFile -Path $path
        $index = @{}
        foreach ($rule in $data.Rules) { $index[$rule.Id] = [pscustomobject]$rule }
        $script:ADSARuleCatalogCache = [pscustomobject]@{ SchemaVersion = $data.SchemaVersion; Rules = $data.Rules | ForEach-Object { [pscustomobject]$_ }; Index = $index }
    }
    return $script:ADSARuleCatalogCache
}

function Get-ADSARuleDefinition {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Id)
    $catalog = Get-ADSARuleCatalogData
    if (-not $catalog.Index.ContainsKey($Id)) { throw "Rule '$Id' is not defined in the rule catalog." }
    return $catalog.Index[$Id]
}

function New-ADSAContext {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config)
    $collected = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $Snapshot -Name 'collectionTime')
    if ($null -eq $collected) { $collected = [datetime]::UtcNow }
    return [pscustomobject]@{
        Snapshot       = $Snapshot
        Config         = $Config
        ReferenceTime  = $collected
        CollectionTime = (Format-ADSAIsoTime -Value $collected)
        DataSource     = "$(Get-ADSAProp -InputObject $Snapshot -Name 'dataSource' -Default 'Unknown')"
        Excluded       = @{}
        Cache          = @{}
    }
}

function New-ADSAResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string] $RuleId,
        [Parameter(Mandatory)] [ValidateSet('PASS', 'FAIL', 'ERROR', 'NOT_APPLICABLE', 'NOT_ASSESSED')] [string] $Status,
        [string] $AffectedObject,
        [string] $AffectedObjectType,
        [System.Collections.IDictionary] $Evidence,
        [string] $Explanation,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational', '')] [string] $Severity = '',
        [ValidateSet('High', 'Medium', 'Low', '')] [string] $Confidence = '',
        [string] $Limitations
    )
    $rule = Get-ADSARuleDefinition -Id $RuleId
    $domainName = "$(Get-ADSAProp -InputObject (Get-ADSAProp -InputObject $Context.Snapshot -Name 'domain') -Name 'name' -Default '')"
    if (-not $AffectedObject) { $AffectedObject = $domainName }
    if (-not $AffectedObjectType) { $AffectedObjectType = 'Domain' }
    $limits = @($rule.Limitations, $Limitations | Where-Object { $_ }) -join ' '
    $text = if ($Explanation) { "$($rule.Description) $Explanation" } else { $rule.Description }
    return [pscustomobject][ordered]@{
        RuleId             = $rule.Id
        Title              = $rule.Title
        Category           = $rule.Category
        Module             = $rule.Module
        Status             = $Status
        Severity           = $(if ($Severity) { $Severity } else { $rule.Severity })
        FindingType        = $rule.FindingType
        AffectedObject     = $AffectedObject
        AffectedObjectType = $AffectedObjectType
        Evidence           = $(if ($Evidence) { $Evidence } else { [ordered]@{} })
        Explanation        = $text
        Confidence         = $(if ($Confidence) { $Confidence } else { $rule.Confidence })
        Remediation        = $rule.Remediation
        CollectionTime     = $Context.CollectionTime
        Limitations        = $limits
        DataSource         = $Context.DataSource
        Excepted           = $false
        Exception          = $null
    }
}

function Get-ADSASectionState {
    # Normalizes a snapshot section to @{ State = Ok|Error|NotAssessed|Missing; Data; Error; Category }.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] [string] $Name)
    $sections = Get-ADSAProp -InputObject $Context.Snapshot -Name 'sections'
    $section = Get-ADSAProp -InputObject $sections -Name $Name
    if ($null -eq $section) {
        return [pscustomobject]@{ State = 'Missing'; Data = @(); Error = "Section '$Name' is not present in the snapshot."; Category = 'NotCollected' }
    }
    $status = "$(Get-ADSAProp -InputObject $section -Name 'status')"
    $state = switch ($status) { 'Collected' { 'Ok' } 'Error' { 'Error' } 'NotAssessed' { 'NotAssessed' } default { 'Error' } }
    $data = Get-ADSAProp -InputObject $section -Name 'data'
    return [pscustomobject]@{
        State    = $state
        Data     = $data
        Error    = "$(Get-ADSAProp -InputObject $section -Name 'error' -Default $(if ($status -notin 'Collected', 'Error', 'NotAssessed') { "Unrecognised section status '$status'." } else { '' }))"
        Category = "$(Get-ADSAProp -InputObject $section -Name 'errorCategory' -Default '')"
    }
}

function New-ADSASectionResult {
    # Turns an unusable section into ERROR (collection failed, incl. denied access) or NOT_ASSESSED. Never PASS.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] [string] $RuleId, [Parameter(Mandatory)] $Section, [Parameter(Mandatory)] [string] $SectionName)
    $status = if ($Section.State -eq 'Error') { 'ERROR' } else { 'NOT_ASSESSED' }
    $detail = "Required data section '$SectionName' is unavailable ($($Section.State))."
    if ($Section.Category) { $detail += " Category: $($Section.Category)." }
    if ($Section.Error) { $detail += " Detail: $($Section.Error)" }
    return New-ADSAResult -Context $Context -RuleId $RuleId -Status $status -Explanation $detail `
        -Evidence ([ordered]@{ Section = $SectionName; SectionState = $Section.State; ErrorCategory = $Section.Category }) `
        -Limitations 'This rule could not be evaluated; absence of a finding must not be read as a pass.'
}

function Complete-ADSARule {
    <#
    .SYNOPSIS
        Converts rule accumulators into results.
    .DESCRIPTION
        FAIL per failing object; ERROR per object that could not be queried; NOT_ASSESSED per undecidable object.
        A PASS is emitted only when at least one object was genuinely evaluated and nothing failed.
        When nothing was evaluated: NOT_ASSESSED if objects were skipped for missing data, otherwise NOT_APPLICABLE.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string] $RuleId,
        [AllowEmptyCollection()] [object[]] $Fail = @(),
        [AllowEmptyCollection()] [object[]] $Errors = @(),
        [AllowEmptyCollection()] [object[]] $NotAssessed = @(),
        [int] $Evaluated = 0,
        [int] $Skipped = 0,
        [string] $SkipReason = '',
        [string] $ObjectType = 'Object',
        [string] $Scope = 'objects',
        [string] $ExtraLimitation = ''
    )
    $excluded = 0
    if ($Context.Excluded.ContainsKey($RuleId)) { $excluded = $Context.Excluded[$RuleId] }
    $notes = New-Object System.Collections.Generic.List[string]
    if ($Skipped -gt 0) { $notes.Add("$Skipped $Scope could not be evaluated: $SkipReason.") }
    if ($excluded -gt 0) { $notes.Add("$excluded $Scope were excluded by documented configuration exclusions.") }
    if ($Errors.Count -gt 0) { $notes.Add("$($Errors.Count) $Scope could not be queried (see ERROR results).") }
    if ($NotAssessed.Count -gt 0) { $notes.Add("$($NotAssessed.Count) $Scope could not be assessed (see NOT_ASSESSED results).") }
    if ($ExtraLimitation) { $notes.Add($ExtraLimitation) }
    $limit = $notes -join ' '

    foreach ($f in $Fail) {
        $p = @{ Context = $Context; RuleId = $RuleId; Status = 'FAIL'; AffectedObject = $f.Object; AffectedObjectType = $(if ($f.ObjectType) { $f.ObjectType } else { $ObjectType }); Evidence = $f.Evidence; Limitations = (@($f.Limitations, $limit | Where-Object { $_ }) -join ' ') }
        if ($f.Explanation) { $p.Explanation = $f.Explanation }
        if ($f.Severity) { $p.Severity = $f.Severity }
        if ($f.Confidence) { $p.Confidence = $f.Confidence }
        New-ADSAResult @p
    }
    foreach ($e in $Errors) {
        New-ADSAResult -Context $Context -RuleId $RuleId -Status 'ERROR' -AffectedObject $e.Object -AffectedObjectType $(if ($e.ObjectType) { $e.ObjectType } else { $ObjectType }) `
            -Evidence ([ordered]@{ ErrorCategory = $e.Category; Detail = $e.Message }) -Explanation "Evaluation failed: $($e.Message)" `
            -Limitations 'Insufficient permission or connectivity is never treated as a pass.'
    }
    foreach ($n in $NotAssessed) {
        New-ADSAResult -Context $Context -RuleId $RuleId -Status 'NOT_ASSESSED' -AffectedObject $n.Object -AffectedObjectType $(if ($n.ObjectType) { $n.ObjectType } else { $ObjectType }) `
            -Evidence ([ordered]@{ Detail = $n.Message }) -Explanation "Not assessed: $($n.Message)"
    }
    if ($Fail.Count -eq 0) {
        if ($Evaluated -gt 0) {
            New-ADSAResult -Context $Context -RuleId $RuleId -Status 'PASS' `
                -Evidence ([ordered]@{ ObjectsEvaluated = $Evaluated; ObjectsSkipped = $Skipped; ObjectsExcluded = $excluded; ObjectsErrored = $Errors.Count; ObjectsNotAssessed = $NotAssessed.Count }) `
                -Explanation "No $Scope violated this rule among the $Evaluated evaluated." -Limitations $limit
        } elseif ($Errors.Count -eq 0 -and $NotAssessed.Count -eq 0) {
            if ($Skipped -gt 0) {
                New-ADSAResult -Context $Context -RuleId $RuleId -Status 'NOT_ASSESSED' -Evidence ([ordered]@{ ObjectsSkipped = $Skipped; Reason = $SkipReason }) `
                    -Explanation "Not assessed: $Skipped $Scope were skipped ($SkipReason)." -Limitations $limit
            } else {
                $why = if ($excluded -gt 0) { "All $excluded in-scope $Scope were excluded by configuration." } else { "No $Scope in scope for this rule." }
                New-ADSAResult -Context $Context -RuleId $RuleId -Status 'NOT_APPLICABLE' -Evidence ([ordered]@{ ObjectsExcluded = $excluded }) -Explanation $why -Limitations $limit
            }
        }
    }
}

function Invoke-ADSAObjectRule {
    <#
    .SYNOPSIS
        Runs an evaluator over objects and completes the rule.
    .DESCRIPTION
        The evaluator returns a hashtable: @{ Outcome = 'NotInScope'|'Pass'|'Fail'|'Skip'; Evidence; Severity; Confidence; Explanation; SkipReason }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string] $RuleId,
        [AllowEmptyCollection()] [object[]] $Objects = @(),
        [Parameter(Mandatory)] [scriptblock] $Evaluator,
        [ValidateSet('user', 'computer', 'group', 'any')] [string] $Kind = 'any',
        [string] $ObjectType = 'Object',
        [string] $Scope = 'objects'
    )
    $fails = New-Object System.Collections.Generic.List[object]
    $evaluated = 0; $skipped = 0; $reason = ''
    foreach ($obj in $Objects) {
        $name = "$(Get-ADSAProp -InputObject $obj -Name 'SamAccountName' -Default (Get-ADSAProp -InputObject $obj -Name 'Name' -Default ''))"
        $dn = "$(Get-ADSAProp -InputObject $obj -Name 'DistinguishedName' -Default '')"
        if (Test-ADSAExcluded -Context $Context -RuleId $RuleId -Name $name -DistinguishedName $dn -Kind $Kind) { continue }
        $r = & $Evaluator $obj
        switch ($r.Outcome) {
            'Pass' { $evaluated++ }
            'Fail' {
                $evaluated++
                $label = if ($name) { $name } else { $dn }
                $fails.Add(@{ Object = $label; ObjectType = $ObjectType; Evidence = $r.Evidence; Severity = $r.Severity; Confidence = $r.Confidence; Explanation = $r.Explanation })
            }
            'Skip' { $skipped++; $reason = $r.SkipReason }
            default { }
        }
    }
    Complete-ADSARule -Context $Context -RuleId $RuleId -Fail $fails.ToArray() -Evaluated $evaluated -Skipped $skipped -SkipReason $reason -ObjectType $ObjectType -Scope $Scope
}
