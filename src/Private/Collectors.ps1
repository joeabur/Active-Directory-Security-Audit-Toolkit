# Live collection of directory data into a normalized snapshot.
# Every call is a read: Get-AD*, Invoke-Command with a fixed read-only script block, and file reads from SYSVOL.
# Failures are classified and recorded per section; they never become silent passes.

function Get-ADSAErrorCategory {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord)
    $ex = $ErrorRecord.Exception
    $type = $ex.GetType().FullName
    $msg = "$($ex.Message)"
    if ($type -match 'CommandNotFoundException' -or $msg -match 'is not recognized as (the name of )?a(n)? (cmdlet|function)') { return 'ModuleUnavailable' }
    if ($type -match 'UnauthorizedAccess|SecurityException' -or $msg -match '(?i)access is denied|insufficient access|not have (the )?(required )?permission|unauthorized|logon failure') { return 'AccessDenied' }
    if ($type -match 'ADServerDown|ServerDown' -or $msg -match '(?i)server is not operational|unable to contact|rpc server is unavailable|network path was not found|timed? ?out|no such host|cannot connect|could not connect|WinRM cannot process') { return 'Unreachable' }
    if ($msg -match '(?i)(attribute|propert(y|ies)).*(not (recognized|valid|supported|found)|isn''t valid|invalid)|one or more properties are invalid') { return 'UnsupportedAttribute' }
    if ($type -match 'ADException|DirectoryOperation|DirectoryServices|ADInvalid|ADIdentityNotFound' -or $msg -match '(?i)ldap|referral|search filter|directory') { return 'LdapError' }
    return 'Error'
}

function Invoke-ADSACollector {
    # Runs a collection script block and converts success/failure into a snapshot section.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] [scriptblock] $Script, [switch] $Single)
    try {
        $result = & $Script
        $warnings = @()
        $data = $result
        if ($result -is [System.Collections.IDictionary] -and $result.Contains('__data')) { $data = $result['__data']; $warnings = @($result['__warnings']) }
        $section = [ordered]@{ status = 'Collected'; data = $(if ($Single) { $data } else { @($data | Where-Object { $null -ne $_ }) }); error = ''; errorCategory = '' }
        if ($warnings.Count -gt 0) { $section['warnings'] = $warnings }
        Write-ADSALog -Level Information -Message "Collected section $Name" -Data @{ section = $Name; count = @($data).Count }
        return $section
    } catch {
        $cat = Get-ADSAErrorCategory -ErrorRecord $_
        Write-ADSALog -Level Warning -Message "Collection of section $Name failed ($cat): $($_.Exception.Message)" -Data @{ section = $Name; category = $cat }
        $status = if ($cat -eq 'ModuleUnavailable') { 'NotAssessed' } else { 'Error' }
        return [ordered]@{ status = $status; data = @(); error = "$($_.Exception.Message)"; errorCategory = $cat }
    }
}

function New-ADSAFailedSection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param([string] $Status = 'NotAssessed', [string] $Category, [string] $Message)
    return [ordered]@{ status = $Status; data = @(); error = $Message; errorCategory = $Category }
}

function ConvertTo-ADSAUserRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $User)
    $sid = Get-ADSAProp -InputObject $User -Name 'SID'
    return [ordered]@{
        SamAccountName        = "$(Get-ADSAProp -InputObject $User -Name 'SamAccountName')"
        DistinguishedName     = "$(Get-ADSAProp -InputObject $User -Name 'DistinguishedName')"
        Sid                   = $(if ($sid) { "$(Get-ADSAProp -InputObject $sid -Name 'Value' -Default "$sid")" } else { $null })
        Enabled               = Get-ADSAProp -InputObject $User -Name 'Enabled'
        UserAccountControl    = Get-ADSAProp -InputObject $User -Name 'userAccountControl'
        LastLogonTimestamp    = Format-ADSAIsoTime -Value (Get-ADSAProp -InputObject $User -Name 'LastLogonTimestamp')
        PasswordLastSet       = Format-ADSAIsoTime -Value (Get-ADSAProp -InputObject $User -Name 'PasswordLastSet')
        WhenCreated           = Format-ADSAIsoTime -Value (Get-ADSAProp -InputObject $User -Name 'WhenCreated')
        ServicePrincipalNames = @(Get-ADSAProp -InputObject $User -Name 'ServicePrincipalNames' -Default @() | Where-Object { $_ })
        Manager               = Get-ADSAProp -InputObject $User -Name 'Manager'
        AdminCount            = Get-ADSAProp -InputObject $User -Name 'adminCount'
        PrimaryGroupId        = Get-ADSAProp -InputObject $User -Name 'PrimaryGroupID'
        AllowedToDelegateTo   = @(Get-ADSAProp -InputObject $User -Name 'msDS-AllowedToDelegateTo' -Default @() | Where-Object { $_ })
    }
}

function ConvertTo-ADSAComputerRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Computer)
    $sid = Get-ADSAProp -InputObject $Computer -Name 'SID'
    return [ordered]@{
        SamAccountName       = "$(Get-ADSAProp -InputObject $Computer -Name 'SamAccountName')"
        DistinguishedName    = "$(Get-ADSAProp -InputObject $Computer -Name 'DistinguishedName')"
        Sid                  = $(if ($sid) { "$(Get-ADSAProp -InputObject $sid -Name 'Value' -Default "$sid")" } else { $null })
        Enabled              = Get-ADSAProp -InputObject $Computer -Name 'Enabled'
        UserAccountControl   = Get-ADSAProp -InputObject $Computer -Name 'userAccountControl'
        LastLogonTimestamp   = Format-ADSAIsoTime -Value (Get-ADSAProp -InputObject $Computer -Name 'LastLogonTimestamp')
        PasswordLastSet      = Format-ADSAIsoTime -Value (Get-ADSAProp -InputObject $Computer -Name 'PasswordLastSet')
        WhenCreated          = Format-ADSAIsoTime -Value (Get-ADSAProp -InputObject $Computer -Name 'WhenCreated')
        OperatingSystem      = Get-ADSAProp -InputObject $Computer -Name 'OperatingSystem'
        AllowedToDelegateTo  = @(Get-ADSAProp -InputObject $Computer -Name 'msDS-AllowedToDelegateTo' -Default @() | Where-Object { $_ })
        AllowedToActOnBehalf = @(Get-ADSAProp -InputObject $Computer -Name 'PrincipalsAllowedToDelegateToAccount' -Default @() | Where-Object { $_ } | ForEach-Object { "$_" })
    }
}

function ConvertTo-ADSAAclRecord {
    # Reads owner and access rules from an object's nTSecurityDescriptor (ActiveDirectorySecurity). Read-only.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $AdObject, [string] $Role)
    $sd = Get-ADSAProp -InputObject $AdObject -Name 'nTSecurityDescriptor'
    if ($null -eq $sd) { throw 'nTSecurityDescriptor was not returned (insufficient access to read the security descriptor).' }
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $owner = $sd.GetOwner($sidType)
    $rules = $sd.GetAccessRules($true, $true, $sidType)
    $aces = @(foreach ($r in $rules) { ConvertTo-ADSAAce -AccessRule $r })
    return [ordered]@{
        DistinguishedName = "$(Get-ADSAProp -InputObject $AdObject -Name 'DistinguishedName')"
        ObjectClass       = "$(Get-ADSAProp -InputObject $AdObject -Name 'ObjectClass')"
        Role              = $Role
        OwnerSid          = $(if ($owner) { "$(Get-ADSAProp -InputObject $owner -Name 'Value' -Default "$owner")" } else { $null })
        Aces              = $aces
    }
}

function Get-ADSAGpoSysvolSettings {
    <#
    .SYNOPSIS
        Reads GptTmpl.inf registry settings and scans for GPP cpassword files in one GPO's SYSVOL folder (read-only).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Path)
    $result = [ordered]@{ SysvolStatus = 'Error'; Settings = @{}; CpasswordFiles = @() }
    if ([string]::IsNullOrWhiteSpace($Path)) { $result.SysvolStatus = 'NotFound'; return $result }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container -ErrorAction Stop)) { $result.SysvolStatus = 'NotFound'; return $result }
        $inf = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $Path 'Machine') 'Microsoft') 'Windows NT') 'SecEdit') 'GptTmpl.inf'
        $status = 'NoSecurityTemplate'
        if (Test-Path -LiteralPath $inf -PathType Leaf -ErrorAction Stop) {
            $text = Get-Content -LiteralPath $inf -Raw -ErrorAction Stop
            $result.Settings = ConvertFrom-ADSAGptTmplText -Text $text
            $status = 'Read'
        }
        $names = 'Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml'
        $hits = New-Object System.Collections.Generic.List[string]
        $files = Get-ChildItem -LiteralPath $Path -Recurse -File -Include $names -ErrorAction Stop
        foreach ($f in $files) {
            if (Select-String -LiteralPath $f.FullName -Pattern 'cpassword\s*=\s*"[^"]+"' -Quiet -ErrorAction Stop) {
                $hits.Add($f.FullName.Substring($Path.TrimEnd('\', '/').Length).TrimStart('\', '/'))
            }
        }
        $result.CpasswordFiles = $hits.ToArray()
        $result.SysvolStatus = $status
    } catch {
        $cat = Get-ADSAErrorCategory -ErrorRecord $_
        $result.SysvolStatus = if ($cat -eq 'AccessDenied') { 'AccessDenied' } else { 'Error' }
    }
    return $result
}

function ConvertFrom-ADSAGpLink {
    # '[LDAP://cn={GUID},cn=policies,cn=system,DC=x;0][...]' -> @{ Guid; Enabled; Enforced }
    [CmdletBinding()]
    param([AllowNull()] [string] $GpLink)
    if ([string]::IsNullOrWhiteSpace($GpLink)) { return , @() }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches($GpLink, '\[LDAP://[^\]]*?\{([0-9A-Fa-f-]{36})\}[^;\]]*;(\d+)\]')) {
        $opt = [int]$m.Groups[2].Value
        $out.Add([pscustomobject]@{ Guid = $m.Groups[1].Value.ToLowerInvariant(); Enabled = (($opt -band 1) -eq 0); Enforced = (($opt -band 2) -ne 0) })
    }
    return , $out.ToArray()
}

function Get-ADSADcHostData {
    # Collects per-DC settings with one fixed, read-only remote script block.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ComputerName, [AllowNull()] [pscredential] $Credential)
    $remote = {
        $out = @{}
        $cat = { param($m) if ($m -match '(?i)denied|unauthorized') { 'AccessDenied' } else { 'Error' } }
        try {
            $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction Stop
            $out.Ldap = @{
                Status          = 'Collected'
                ServerIntegrity = $(if ($null -ne $p.PSObject.Properties['LDAPServerIntegrity']) { [int]$p.LDAPServerIntegrity } else { $null })
                ChannelBinding  = $(if ($null -ne $p.PSObject.Properties['LdapEnforceChannelBinding']) { [int]$p.LdapEnforceChannelBinding } else { $null })
            }
        } catch { $out.Ldap = @{ Status = 'Error'; Error = $_.Exception.Message; ErrorCategory = (& $cat $_.Exception.Message) } }
        try {
            $s = Get-Service -Name 'Spooler' -ErrorAction Stop
            $out.Spooler = @{ Status = 'Collected'; State = "$($s.Status)" }
        } catch { $out.Spooler = @{ Status = 'Error'; Error = $_.Exception.Message; ErrorCategory = (& $cat $_.Exception.Message) } }
        try {
            $raw = & auditpol.exe /get /category:* /r 2>&1
            if ($LASTEXITCODE -ne 0) { throw "auditpol exited with code $LASTEXITCODE : $($raw -join ' ')" }
            $rows = @($raw | ConvertFrom-Csv)
            $out.AuditPolicy = @{ Status = 'Collected'; Entries = @($rows | ForEach-Object { @{ Guid = $_.'Subcategory GUID'; Subcategory = $_.Subcategory; Setting = $_.'Inclusion Setting' } }) }
        } catch { $out.AuditPolicy = @{ Status = 'Error'; Error = $_.Exception.Message; ErrorCategory = (& $cat $_.Exception.Message) } }
        try {
            $l = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
            $out.SecurityLog = @{ Status = 'Collected'; MaximumSizeInBytes = [int64]$l.MaximumSizeInBytes; LogMode = "$($l.LogMode)" }
        } catch { $out.SecurityLog = @{ Status = 'Error'; Error = $_.Exception.Message; ErrorCategory = (& $cat $_.Exception.Message) } }
        $out
    }
    $params = @{ ComputerName = $ComputerName; ScriptBlock = $remote; ErrorAction = 'Stop' }
    if ($Credential) { $params.Credential = $Credential }
    return Invoke-Command @params
}

function Get-ADSASnapshotData {
    <#
    .SYNOPSIS
        Collects a snapshot from a live domain. Internal implementation of Get-ADSASnapshot.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Config,
        [AllowNull()] [string] $Server,
        [AllowNull()] [pscredential] $Credential,
        [switch] $SkipDcHostChecks,
        [switch] $SkipSysvol,
        [switch] $SkipAcls
    )
    $started = [datetime]::UtcNow
    $common = @{}
    if ($Server) { $common.Server = $Server }
    if ($Credential) { $common.Credential = $Credential }
    $sections = [ordered]@{}
    $domain = [ordered]@{ name = $(if ($Server) { "$Server" } else { '(unknown)' }); distinguishedName = ''; netBiosName = ''; sid = ''; domainMode = ''; forestMode = ''; forestName = ''; domainControllersContainer = ''; pdcEmulator = '' }

    $adAvailable = [bool](Get-Command -Name 'Get-ADDomain' -ErrorAction SilentlyContinue)
    $allSections = 'Users', 'Computers', 'Groups', 'DomainControllers', 'PasswordPolicy', 'FineGrainedPolicies', 'Trusts', 'Acls', 'Gpos', 'DcHosts'
    if (-not $adAvailable) {
        foreach ($s in $allSections) { $sections[$s] = New-ADSAFailedSection -Status 'NotAssessed' -Category 'ModuleUnavailable' -Message 'The ActiveDirectory PowerShell module (RSAT) is not available on this host.' }
        return [ordered]@{ schemaVersion = '1.0'; dataSource = 'Live'; collectionTime = $started.ToString('yyyy-MM-ddTHH:mm:ssZ'); domain = $domain; sections = $sections; collector = @{ tool = 'ADSecurityAudit'; version = $script:ADSAVersion } }
    }

    $domainObj = $null
    try {
        $domainObj = Get-ADDomain @common -ErrorAction Stop
        $forestObj = Get-ADForest @common -ErrorAction Stop
        $domain = [ordered]@{
            name = "$($domainObj.DNSRoot)"; distinguishedName = "$($domainObj.DistinguishedName)"; netBiosName = "$($domainObj.NetBIOSName)"
            sid = "$(Get-ADSAProp -InputObject $domainObj.DomainSID -Name 'Value' -Default $domainObj.DomainSID)"
            domainMode = "$($domainObj.DomainMode)"; forestMode = "$($forestObj.ForestMode)"; forestName = "$($forestObj.Name)"
            domainControllersContainer = "$($domainObj.DomainControllersContainer)"; pdcEmulator = "$($domainObj.PDCEmulator)"
        }
    } catch {
        $cat = Get-ADSAErrorCategory -ErrorRecord $_
        Write-ADSALog -Level Error -Message "Could not read domain information ($cat): $($_.Exception.Message)"
        foreach ($s in $allSections) { $sections[$s] = New-ADSAFailedSection -Status 'Error' -Category $cat -Message "Domain information could not be read: $($_.Exception.Message)" }
        return [ordered]@{ schemaVersion = '1.0'; dataSource = 'Live'; collectionTime = $started.ToString('yyyy-MM-ddTHH:mm:ssZ'); domain = $domain; sections = $sections; collector = @{ tool = 'ADSecurityAudit'; version = $script:ADSAVersion } }
    }
    $dn = $domain.distinguishedName

    $sections['Users'] = Invoke-ADSACollector -Name 'Users' -Script {
        $props = 'SamAccountName', 'Enabled', 'userAccountControl', 'LastLogonTimestamp', 'PasswordLastSet', 'WhenCreated', 'ServicePrincipalNames', 'Manager', 'adminCount', 'PrimaryGroupID', 'msDS-AllowedToDelegateTo'
        Get-ADUser -Filter * -Properties $props @common -ErrorAction Stop | ForEach-Object { ConvertTo-ADSAUserRecord -User $_ }
    }
    $sections['Computers'] = Invoke-ADSACollector -Name 'Computers' -Script {
        $props = 'SamAccountName', 'Enabled', 'userAccountControl', 'LastLogonTimestamp', 'PasswordLastSet', 'WhenCreated', 'OperatingSystem', 'msDS-AllowedToDelegateTo', 'PrincipalsAllowedToDelegateToAccount'
        Get-ADComputer -Filter * -Properties $props @common -ErrorAction Stop | ForEach-Object { ConvertTo-ADSAComputerRecord -Computer $_ }
    }
    $sections['Groups'] = Invoke-ADSACollector -Name 'Groups' -Script {
        Get-ADGroup -Filter * -Properties 'Member', 'adminCount' @common -ErrorAction Stop | ForEach-Object {
            [ordered]@{ SamAccountName = "$($_.SamAccountName)"; Name = "$($_.Name)"; DistinguishedName = "$($_.DistinguishedName)"; Sid = "$(Get-ADSAProp -InputObject $_.SID -Name 'Value' -Default $_.SID)"; Members = @($_.Member | Where-Object { $_ }); AdminCount = (Get-ADSAProp -InputObject $_ -Name 'adminCount') }
        }
    }
    $sections['DomainControllers'] = Invoke-ADSACollector -Name 'DomainControllers' -Script {
        Get-ADDomainController -Filter * @common -ErrorAction Stop | ForEach-Object {
            [ordered]@{ Name = "$($_.Name)"; HostName = "$($_.HostName)"; OperatingSystem = "$($_.OperatingSystem)"; OperatingSystemVersion = "$($_.OperatingSystemVersion)"; Site = "$($_.Site)"; IsGlobalCatalog = [bool]$_.IsGlobalCatalog; IsReadOnly = [bool]$_.IsReadOnly; ComputerObjectDN = "$(Get-ADSAProp -InputObject $_ -Name 'ComputerObjectDN' -Default '')" }
        }
    }
    $sections['PasswordPolicy'] = Invoke-ADSACollector -Name 'PasswordPolicy' -Single -Script {
        $p = Get-ADDefaultDomainPasswordPolicy @common -ErrorAction Stop
        [ordered]@{
            MinPasswordLength = [int]$p.MinPasswordLength; PasswordHistoryCount = [int]$p.PasswordHistoryCount; ComplexityEnabled = [bool]$p.ComplexityEnabled
            LockoutThreshold = [int]$p.LockoutThreshold; LockoutDurationMinutes = [int]$p.LockoutDuration.TotalMinutes; LockoutObservationWindowMinutes = [int]$p.LockoutObservationWindow.TotalMinutes
            ReversibleEncryptionEnabled = [bool]$p.ReversibleEncryptionEnabled; MaxPasswordAgeDays = [int]$p.MaxPasswordAge.TotalDays; MinPasswordAgeDays = [int]$p.MinPasswordAge.TotalDays
        }
    }
    $sections['FineGrainedPolicies'] = Invoke-ADSACollector -Name 'FineGrainedPolicies' -Script {
        Get-ADFineGrainedPasswordPolicy -Filter * @common -ErrorAction Stop | ForEach-Object {
            [ordered]@{ Name = "$($_.Name)"; Precedence = [int]$_.Precedence; MinPasswordLength = [int]$_.MinPasswordLength; LockoutThreshold = [int]$_.LockoutThreshold; AppliesToCount = @($_.AppliesTo).Count }
        }
    }
    $sections['Trusts'] = Invoke-ADSACollector -Name 'Trusts' -Script {
        Get-ADObject -Filter 'objectClass -eq "trustedDomain"' -SearchBase "CN=System,$dn" -Properties 'trustAttributes', 'trustDirection', 'trustType', 'flatName' @common -ErrorAction Stop | ForEach-Object {
            [ordered]@{ Name = "$($_.Name)"; FlatName = "$(Get-ADSAProp -InputObject $_ -Name 'flatName' -Default '')"; TrustAttributes = Get-ADSAProp -InputObject $_ -Name 'trustAttributes'; TrustDirection = Get-ADSAProp -InputObject $_ -Name 'trustDirection'; TrustType = Get-ADSAProp -InputObject $_ -Name 'trustType' }
        }
    }

    # ACL targets: domain root, AdminSDHolder, privileged groups, Domain Controllers OU and DC objects (capped)
    if ($SkipAcls -or -not [bool]$Config['collection']['collectAcls']) {
        $sections['Acls'] = New-ADSAFailedSection -Status 'NotAssessed' -Category 'Skipped' -Message 'ACL collection was skipped by request or configuration.'
    } else {
        $interim = [pscustomobject]@{ domain = $domain; sections = $sections; collectionTime = $started.ToString('o'); dataSource = 'Live' }
        $sections['Acls'] = Invoke-ADSACollector -Name 'Acls' -Script {
            $ctx = New-ADSAContext -Snapshot $interim -Config $Config
            $targets = New-Object System.Collections.Generic.List[object]
            $targets.Add(@{ Dn = $dn; Role = 'DomainRoot' })
            $targets.Add(@{ Dn = "CN=AdminSDHolder,CN=System,$dn"; Role = 'AdminSDHolder' })
            if ($domain.domainControllersContainer) { $targets.Add(@{ Dn = $domain.domainControllersContainer; Role = 'DomainControllersOu' }) }
            $groupsOk = ((Get-ADSASectionState -Context $ctx -Name 'Groups').State -eq 'Ok')
            if ($groupsOk) { foreach ($g in (Get-ADSAPrivilegedIndex -Context $ctx).Groups) { if ($g.Found) { $targets.Add(@{ Dn = $g.Dn; Role = 'PrivilegedGroup' }) } } }
            $dcSection = Get-ADSASectionState -Context $ctx -Name 'DomainControllers'
            if ($dcSection.State -eq 'Ok') { foreach ($d in @($dcSection.Data)) { $cdn = Get-ADSAProp -InputObject $d -Name 'ComputerObjectDN'; if ($cdn) { $targets.Add(@{ Dn = "$cdn"; Role = 'DomainController' }) } } }
            $max = [int]$Config['collection']['aclMaxObjects']
            $records = New-Object System.Collections.Generic.List[object]
            $warn = New-Object System.Collections.Generic.List[object]
            foreach ($t in ($targets | Select-Object -First $max)) {
                try {
                    $o = Get-ADObject -Identity $t.Dn -Properties 'nTSecurityDescriptor' @common -ErrorAction Stop
                    $records.Add((ConvertTo-ADSAAclRecord -AdObject $o -Role $t.Role))
                } catch {
                    $warn.Add([ordered]@{ target = $t.Dn; category = (Get-ADSAErrorCategory -ErrorRecord $_); message = "$($_.Exception.Message)" })
                }
            }
            if ($targets.Count -gt $max) { $warn.Add([ordered]@{ target = '*'; category = 'Truncated'; message = "ACL target list truncated to collection.aclMaxObjects = $max." }) }
            if ($records.Count -eq 0 -and $warn.Count -gt 0) { throw "No ACLs could be read: $($warn[0].message)" }
            @{ __data = $records.ToArray(); __warnings = $warn.ToArray() }
        }
    }

    # GPOs: container ACLs, links, and SYSVOL content
    $sections['Gpos'] = Invoke-ADSACollector -Name 'Gpos' -Script {
        $linkMap = @{}
        Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase $dn -Properties 'gPLink' @common -ErrorAction Stop | ForEach-Object {
            $target = "$($_.DistinguishedName)"
            foreach ($l in (ConvertFrom-ADSAGpLink -GpLink "$(Get-ADSAProp -InputObject $_ -Name 'gPLink' -Default '')")) {
                if (-not $linkMap.ContainsKey($l.Guid)) { $linkMap[$l.Guid] = New-Object System.Collections.Generic.List[object] }
                $linkMap[$l.Guid].Add([ordered]@{ Target = $target; Enabled = $l.Enabled; Enforced = $l.Enforced })
            }
        }
        $gpoObjects = Get-ADObject -Filter 'objectClass -eq "groupPolicyContainer"' -SearchBase "CN=Policies,CN=System,$dn" -Properties 'displayName', 'gPCFileSysPath', 'nTSecurityDescriptor' @common -ErrorAction Stop
        foreach ($g in $gpoObjects) {
            $guid = ("$($g.Name)").Trim('{', '}').ToLowerInvariant()
            $rec = [ordered]@{ Id = $guid; DisplayName = "$(Get-ADSAProp -InputObject $g -Name 'displayName' -Default $g.Name)"; DistinguishedName = "$($g.DistinguishedName)"; LinkedTo = $(if ($linkMap.ContainsKey($guid)) { $linkMap[$guid].ToArray() } else { @() }) }
            try { $acl = ConvertTo-ADSAAclRecord -AdObject $g -Role 'GroupPolicyContainer'; $rec.OwnerSid = $acl.OwnerSid; $rec.Aces = $acl.Aces } catch { Write-ADSALog -Level Warning -Message "GPO ACL for $guid unreadable: $($_.Exception.Message)" }
            if ($SkipSysvol -or -not [bool]$Config['collection']['collectSysvol']) { $rec.SysvolStatus = 'Skipped'; $rec.Settings = @{}; $rec.CpasswordFiles = @() }
            else { $sv = Get-ADSAGpoSysvolSettings -Path "$(Get-ADSAProp -InputObject $g -Name 'gPCFileSysPath' -Default '')"; $rec.SysvolStatus = $sv.SysvolStatus; $rec.Settings = $sv.Settings; $rec.CpasswordFiles = $sv.CpasswordFiles }
            $rec
        }
    }

    # Per-DC host settings (requires WinRM and rights on each DC)
    if ($SkipDcHostChecks -or -not [bool]$Config['collection']['collectDcHostSettings']) {
        $sections['DcHosts'] = New-ADSAFailedSection -Status 'NotAssessed' -Category 'Skipped' -Message 'Domain controller host checks were skipped by request or configuration.'
    } elseif ($sections['DomainControllers'].status -ne 'Collected') {
        $sections['DcHosts'] = New-ADSAFailedSection -Status 'Error' -Category $sections['DomainControllers'].errorCategory -Message 'Domain controllers could not be enumerated, so host checks were not attempted.'
    } else {
        $sections['DcHosts'] = Invoke-ADSACollector -Name 'DcHosts' -Script {
            foreach ($d in @($sections['DomainControllers'].data)) {
                $entry = [ordered]@{ Name = $d.Name; HostName = $d.HostName; OperatingSystem = $d.OperatingSystem; Reachable = $true; Error = ''; ErrorCategory = '' }
                try {
                    $h = Get-ADSADcHostData -ComputerName $(if ($d.HostName) { $d.HostName } else { $d.Name }) -Credential $Credential
                    foreach ($k in 'Ldap', 'Spooler', 'AuditPolicy', 'SecurityLog') { $entry[$k] = $h[$k] }
                } catch {
                    $entry.Reachable = $false
                    $entry.ErrorCategory = Get-ADSAErrorCategory -ErrorRecord $_
                    $entry.Error = "$($_.Exception.Message)"
                }
                $entry
            }
        }
    }

    return [ordered]@{
        schemaVersion  = '1.0'
        dataSource     = 'Live'
        collectionTime = $started.ToString('yyyy-MM-ddTHH:mm:ssZ')
        domain         = $domain
        sections       = $sections
        collector      = [ordered]@{ tool = 'ADSecurityAudit'; version = $script:ADSAVersion }
    }
}

function Test-ADSASnapshotData {
    # Structural validation of a snapshot (imported or collected). Returns @{ IsValid; Errors }.
    [CmdletBinding()]
    param([AllowNull()] $Snapshot)
    $errors = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Snapshot) { return [pscustomobject]@{ IsValid = $false; Errors = @('Snapshot is empty.') } }
    $ver = "$(Get-ADSAProp -InputObject $Snapshot -Name 'schemaVersion')"
    if ($ver -notmatch '^1\.\d+$') { $errors.Add("schemaVersion '$ver' is missing or unsupported (expected 1.x).") }
    $src = "$(Get-ADSAProp -InputObject $Snapshot -Name 'dataSource')"
    if ($src -notin 'Live', 'Simulated') { $errors.Add("dataSource '$src' must be 'Live' or 'Simulated'.") }
    if ($null -eq (ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $Snapshot -Name 'collectionTime'))) { $errors.Add('collectionTime is missing or not a valid date.') }
    $domain = Get-ADSAProp -InputObject $Snapshot -Name 'domain'
    if ($null -eq $domain -or -not (Get-ADSAProp -InputObject $domain -Name 'name')) { $errors.Add('domain.name is missing.') }
    $sections = Get-ADSAProp -InputObject $Snapshot -Name 'sections'
    if ($null -eq $sections) { $errors.Add('sections is missing.') }
    else {
        $names = if ($sections -is [System.Collections.IDictionary]) { @($sections.Keys) } else { @($sections.PSObject.Properties.Name) }
        foreach ($n in $names) {
            $sec = Get-ADSAProp -InputObject $sections -Name $n
            $st = "$(Get-ADSAProp -InputObject $sec -Name 'status')"
            if ($st -notin 'Collected', 'Error', 'NotAssessed') { $errors.Add("sections.$n.status '$st' must be Collected, Error or NotAssessed.") }
            if ($st -eq 'Collected' -and -not (Test-ADSAHasProp -InputObject $sec -Name 'data')) { $errors.Add("sections.$n is Collected but has no data.") }
        }
    }
    return [pscustomobject]@{ IsValid = ($errors.Count -eq 0); Errors = $errors.ToArray() }
}
