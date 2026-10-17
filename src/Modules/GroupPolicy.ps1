# Group Policy audit module: selected security settings read from SYSVOL (GptTmpl.inf) in GPOs linked to the
# domain root or Domain Controllers OU, and detection of Group Policy Preferences cpassword files.
# Read-only: SYSVOL files are read, never written. cpassword values are NEVER stored; only file paths are recorded.
#
# Limitation: GPO precedence/RSOP is not modelled. Results describe settings as defined in GPOs, not effective policy.

function ConvertFrom-ADSAGptTmplText {
    <#
    .SYNOPSIS
        Parses the '[Registry Values]' section of a GptTmpl.inf into a hashtable keyed by lower-case registry path.
    .DESCRIPTION
        Lines look like:  MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
        The value before the comma is the registry type; the remainder is the data.
    #>
    [CmdletBinding()]
    param([AllowNull()] [string] $Text)
    $settings = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return , $settings }
    $inSection = $false
    foreach ($line in ($Text -split "`r?`n")) {
        $trim = $line.Trim()
        if ($trim -match '^\[(.+)\]$') { $inSection = ($Matches[1] -ieq 'Registry Values'); continue }
        if (-not $inSection -or $trim -eq '' -or $trim.StartsWith(';')) { continue }
        $eq = $trim.IndexOf('=')
        if ($eq -lt 1) { continue }
        $key = $trim.Substring(0, $eq).Trim().ToLowerInvariant()
        $val = $trim.Substring($eq + 1).Trim()
        $comma = $val.IndexOf(',')
        $data = if ($comma -ge 0) { $val.Substring($comma + 1) } else { $val }
        $settings[$key] = $data.Trim('"')
    }
    return , $settings
}

function Get-ADSAGpoLinkedScope {
    # True when the GPO has an enabled link at the domain root or the Domain Controllers OU.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Gpo, [Parameter(Mandatory)] [string[]] $ScopeDn)
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($link in @(Get-ADSAProp -InputObject $Gpo -Name 'LinkedTo' -Default @())) {
        $target = "$(Get-ADSAProp -InputObject $link -Name 'Target' -Default $link)"
        $enabled = Get-ADSAProp -InputObject $link -Name 'Enabled' -Default $true
        if ($enabled -and ($ScopeDn | Where-Object { $_ -ieq $target })) { $hits.Add($target) }
    }
    return , $hits.ToArray()
}

function Invoke-ADSAGpoSettingRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context, [Parameter(Mandatory)] $Gpos, [Parameter(Mandatory)] [string] $RuleId,
        [Parameter(Mandatory)] [string] $RegistryKey, [Parameter(Mandatory)] [scriptblock] $IsCompliant, [Parameter(Mandatory)] [string] $SettingLabel
    )
    $domain = Get-ADSAProp -InputObject $Context.Snapshot -Name 'domain'
    $scope = @("$(Get-ADSAProp -InputObject $domain -Name 'distinguishedName' -Default '')", "$(Get-ADSAProp -InputObject $domain -Name 'domainControllersContainer' -Default '')") | Where-Object { $_ }
    $key = $RegistryKey.ToLowerInvariant()
    $defining = New-Object System.Collections.Generic.List[object]
    $errs = New-Object System.Collections.Generic.List[object]
    $consideredCount = 0
    foreach ($gpo in @($Gpos)) {
        $name = "$(Get-ADSAProp -InputObject $gpo -Name 'DisplayName' -Default (Get-ADSAProp -InputObject $gpo -Name 'Id' -Default ''))"
        $linked = Get-ADSAGpoLinkedScope -Gpo $gpo -ScopeDn $scope
        if ($linked.Count -eq 0) { continue }
        if (Test-ADSAExcluded -Context $Context -RuleId $RuleId -Name $name -DistinguishedName '' -Kind any) { continue }
        $consideredCount++
        $status = "$(Get-ADSAProp -InputObject $gpo -Name 'SysvolStatus' -Default 'NotCollected')"
        if ($status -notin 'Read', 'NoSecurityTemplate') {
            $errs.Add(@{ Object = $name; ObjectType = 'GPO'; Category = $status; Message = "SYSVOL security template could not be read ($status)." })
            continue
        }
        $settings = Get-ADSAProp -InputObject $gpo -Name 'Settings' -Default @{}
        if (Test-ADSAHasProp -InputObject $settings -Name $key) {
            $defining.Add(@{ Gpo = $name; Id = "$(Get-ADSAProp -InputObject $gpo -Name 'Id' -Default '')"; Value = "$(Get-ADSAProp -InputObject $settings -Name $key)"; Linked = $linked })
        }
    }
    $fails = @(); $na = @()
    if ($defining.Count -eq 0) {
        if ($errs.Count -eq 0) {
            $na = @(@{ Object = (Get-ADSAProp -InputObject $domain -Name 'name' -Default ''); ObjectType = 'Domain'; Message = "$SettingLabel is not defined in any assessed GPO linked to the domain root or Domain Controllers OU; the effective default depends on OS version and local policy." })
        }
        Complete-ADSARule -Context $Context -RuleId $RuleId -Fail @() -Errors $errs.ToArray() -NotAssessed $na -Evaluated 0 -ObjectType 'GPO' -Scope 'GPOs'
        return
    }
    $weak = @($defining | Where-Object { -not (& $IsCompliant $_.Value) })
    $strong = @($defining | Where-Object { & $IsCompliant $_.Value })
    $conflict = ($weak.Count -gt 0 -and $strong.Count -gt 0)
    $fails = @(foreach ($w in $weak) {
            @{ Object = $w.Gpo; ObjectType = 'GPO'; Confidence = $(if ($conflict) { 'Low' } else { 'Medium' })
                Evidence = [ordered]@{ GpoId = $w.Id; Setting = $SettingLabel; ConfiguredValue = $w.Value; LinkedTo = $w.Linked; ConflictingCompliantGpos = @($strong | ForEach-Object { $_.Gpo }) }
                Limitations = $(if ($conflict) { 'Another assessed GPO sets a compliant value; precedence was not evaluated, so the weaker setting may be overridden. Use RSOP to confirm.' } else { '' }) }
        })
    Complete-ADSARule -Context $Context -RuleId $RuleId -Fail $fails -Errors $errs.ToArray() -Evaluated $defining.Count -ObjectType 'GPO' -Scope 'GPOs'
}

function Invoke-ADSAGroupPolicyAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [System.Collections.IDictionary] $Config)
    $ctx = New-ADSAContext -Snapshot $Snapshot -Config $Config
    $gpos = Get-ADSASectionState -Context $ctx -Name 'Gpos'
    if ($gpos.State -ne 'Ok') {
        foreach ($r in 'ADSA-GPO-001', 'ADSA-GPO-002', 'ADSA-GPO-003') { New-ADSASectionResult -Context $ctx -RuleId $r -Section $gpos -SectionName 'Gpos' }
        return
    }
    $list = @($gpos.Data)

    Invoke-ADSAGpoSettingRule -Context $ctx -Gpos $list -RuleId 'ADSA-GPO-001' -SettingLabel 'LAN Manager authentication level (LmCompatibilityLevel)' `
        -RegistryKey 'machine\system\currentcontrolset\control\lsa\lmcompatibilitylevel' -IsCompliant { param($v) $n = 0; [int]::TryParse("$v", [ref]$n) -and $n -ge 5 }
    Invoke-ADSAGpoSettingRule -Context $ctx -Gpos $list -RuleId 'ADSA-GPO-002' -SettingLabel 'Microsoft network server: digitally sign communications (always)' `
        -RegistryKey 'machine\system\currentcontrolset\services\lanmanserver\parameters\requiresecuritysignature' -IsCompliant { param($v) "$v" -eq '1' }

    # GPO-003 cpassword in SYSVOL (all GPOs, linked or not: the file is readable by every domain user)
    $fails = New-Object System.Collections.Generic.List[object]; $errs = New-Object System.Collections.Generic.List[object]; $eval = 0
    foreach ($gpo in $list) {
        $name = "$(Get-ADSAProp -InputObject $gpo -Name 'DisplayName' -Default (Get-ADSAProp -InputObject $gpo -Name 'Id' -Default ''))"
        if (Test-ADSAExcluded -Context $ctx -RuleId 'ADSA-GPO-003' -Name $name -DistinguishedName '' -Kind any) { continue }
        $status = "$(Get-ADSAProp -InputObject $gpo -Name 'SysvolStatus' -Default 'NotCollected')"
        if ($status -notin 'Read', 'NoSecurityTemplate') { $errs.Add(@{ Object = $name; ObjectType = 'GPO'; Category = $status; Message = "SYSVOL content could not be scanned ($status)." }); continue }
        $eval++
        $files = Get-ADSAList -InputObject $gpo -Name 'CpasswordFiles'
        if ($files.Count -gt 0) {
            $fails.Add(@{ Object = $name; ObjectType = 'GPO'; Evidence = [ordered]@{ GpoId = "$(Get-ADSAProp -InputObject $gpo -Name 'Id' -Default '')"; Files = $files; Note = 'cpassword values were detected but are intentionally not recorded.' } })
        }
    }
    Complete-ADSARule -Context $ctx -RuleId 'ADSA-GPO-003' -Fail $fails.ToArray() -Errors $errs.ToArray() -Evaluated $eval -ObjectType 'GPO' -Scope 'GPOs'
}
