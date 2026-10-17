function Test-ADSAReport {
    <#
    .SYNOPSIS
        Validates a report object or JSON file against the toolkit's report schema (portable, no external validator).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Object', ValueFromPipeline)] $Report,
        [Parameter(Mandatory, ParameterSetName = 'Path')] [string] $Path
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Path') { $Report = Read-ADSAJsonFile -Path $Path -Description 'Report file' }
        $errors = New-Object System.Collections.Generic.List[string]
        foreach ($k in 'SchemaVersion', 'Tool', 'Metadata', 'Summary', 'Coverage', 'CollectionErrors', 'Inventories', 'Findings') {
            if (-not (Test-ADSAHasProp -InputObject $Report -Name $k)) { $errors.Add("Missing top-level property '$k'.") }
        }
        if ($errors.Count -eq 0) {
            if ("$($Report.SchemaVersion)" -notmatch '^1\.\d+$') { $errors.Add("SchemaVersion '$($Report.SchemaVersion)' is not 1.x.") }
            if ("$($Report.Metadata.DataSource)" -notin 'Live', 'Simulated') { $errors.Add("Metadata.DataSource '$($Report.Metadata.DataSource)' must be Live or Simulated.") }
            $required = 'RuleId', 'Title', 'Category', 'Status', 'Severity', 'AffectedObject', 'Evidence', 'Explanation', 'Confidence', 'Remediation', 'CollectionTime', 'Limitations', 'FindingType', 'DataSource'
            $i = 0
            foreach ($f in @($Report.Findings)) {
                $i++
                foreach ($k in $required) { if (-not (Test-ADSAHasProp -InputObject $f -Name $k)) { $errors.Add("Findings[$i] is missing '$k'.") } }
                if ("$($f.RuleId)" -notmatch '^ADSA-[A-Z]+-\d{3}$') { $errors.Add("Findings[$i].RuleId '$($f.RuleId)' is not a stable rule ID.") }
                if ("$($f.Status)" -notin $script:ADSAStatuses) { $errors.Add("Findings[$i].Status '$($f.Status)' is invalid.") }
                if ("$($f.Severity)" -notin $script:ADSASeverities) { $errors.Add("Findings[$i].Severity '$($f.Severity)' is invalid.") }
                if ("$($f.Confidence)" -notin 'High', 'Medium', 'Low') { $errors.Add("Findings[$i].Confidence '$($f.Confidence)' is invalid.") }
                if ($null -eq (ConvertTo-ADSADateTime -Value $f.CollectionTime)) { $errors.Add("Findings[$i].CollectionTime is not a valid date.") }
                if ("$($f.Status)" -eq 'FAIL' -and -not $f.AffectedObject) { $errors.Add("Findings[$i] is FAIL without an affected object.") }
            }
            foreach ($c in @($Report.Coverage.Rules)) { if ("$($c.Status)" -notin $script:ADSAStatuses) { $errors.Add("Coverage rule '$($c.RuleId)' has invalid status '$($c.Status)'.") } }
        }
        return [pscustomobject]@{ IsValid = ($errors.Count -eq 0); Errors = $errors.ToArray() }
    }
}
