function Invoke-ADSecurityAudit {
    <#
    .SYNOPSIS
        Runs the read-only Active Directory security audit and returns a report object.
    .DESCRIPTION
        Offline mode (-SnapshotPath or -Snapshot) needs no domain access. Live mode collects a snapshot with the
        ActiveDirectory module. The toolkit never changes directory objects, ACLs, Group Policy or domain controllers.
    .EXAMPLE
        Invoke-ADSecurityAudit -SnapshotPath .\sample-data\contoso-sim.snapshot.json -OutputPath .\output
    .EXAMPLE
        Invoke-ADSecurityAudit -AuthorizedAssessment -Server dc01.lab.example -Credential (Get-Credential) -Module AccountLifecycle,Acl -OutputPath .\output
    #>
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    param(
        [string] $ConfigPath,
        [Parameter(ParameterSetName = 'Offline', Mandatory)] [string] $SnapshotPath,
        [Parameter(ParameterSetName = 'Object', Mandatory)] $Snapshot,
        [Parameter(ParameterSetName = 'Live')] [switch] $AuthorizedAssessment,
        [Parameter(ParameterSetName = 'Live')] [string] $Server,
        [Parameter(ParameterSetName = 'Live')] [pscredential] $Credential,
        [Parameter(ParameterSetName = 'Live')] [switch] $SkipDcHostChecks,
        [Parameter(ParameterSetName = 'Live')] [switch] $SkipSysvol,
        [Parameter(ParameterSetName = 'Live')] [switch] $SkipAcls,
        [Parameter(ParameterSetName = 'Live')] [string] $SaveSnapshotPath,
        [ValidateSet('AccountLifecycle', 'PrivilegedAccess', 'Delegation', 'Acl', 'AuthenticationPolicy', 'GroupPolicy', 'Infrastructure')] [string[]] $Module,
        [string] $OutputPath,
        [ValidateSet('Json', 'Csv', 'Html')] [string[]] $Format = @('Json', 'Csv', 'Html'),
        [string] $BaseName,
        [switch] $Redact,
        [string] $RedactionSalt,
        [switch] $AllowUncOutput,
        [switch] $AllowRepositoryOutput
    )
    if ($PSCmdlet.ParameterSetName -eq 'Live' -and -not $AuthorizedAssessment) {
        throw 'Live collection reads directory data from a real domain. Re-run with -AuthorizedAssessment to confirm you are authorized to assess it, or use -SnapshotPath for offline analysis.'
    }
    $loaded = Import-ADSAConfigData -Path $ConfigPath
    $config = $loaded.Config
    $logPath = $config['logging']['path']
    Initialize-ADSALog -Level $config['logging']['level'] -Path $(if ($logPath) { "$logPath" } else { $null })
    foreach ($w in $loaded.Warnings) { Write-ADSALog -Level Warning -Message $w }
    if ($logPath) { $null = Resolve-ADSAOutputPath -Path (Split-Path -Path ([System.IO.Path]::GetFullPath("$logPath")) -Parent) -AllowUnc:$AllowUncOutput -AllowRepositoryPath:$AllowRepositoryOutput }

    # Validate the output location before spending time on collection
    $outDir = $null
    if ($OutputPath) { $outDir = Resolve-ADSAOutputPath -Path $OutputPath -AllowUnc:$AllowUncOutput -AllowRepositoryPath:$AllowRepositoryOutput }

    $mode = 'OfflineSnapshot'
    switch ($PSCmdlet.ParameterSetName) {
        'Offline' { $snap = Import-ADSASnapshot -Path $SnapshotPath }
        'Object' { $snap = $Snapshot }
        default {
            $mode = 'LiveCollection'
            Write-ADSALog -Message 'Starting read-only live collection.' -Data @{ server = "$Server" }
            $snap = ConvertTo-ADSAObject -InputObject (Get-ADSASnapshotData -Config $config -Server $Server -Credential $Credential -SkipDcHostChecks:$SkipDcHostChecks -SkipSysvol:$SkipSysvol -SkipAcls:$SkipAcls)
            if ($SaveSnapshotPath) { $null = Export-ADSASnapshot -Snapshot $snap -OutputPath $SaveSnapshotPath -AllowUncOutput:$AllowUncOutput -AllowRepositoryOutput:$AllowRepositoryOutput }
        }
    }
    $check = Test-ADSASnapshotData -Snapshot $snap
    if (-not $check.IsValid) { throw ("Snapshot is invalid:`n - " + ($check.Errors -join "`n - ")) }

    $modules = if ($Module) { @($Module) } else { Get-ADSAModuleName }
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($m in $modules) {
        Write-ADSALog -Message "Running module $m"
        foreach ($r in (Invoke-ADSAAuditModule -Module $m -Snapshot $snap -Config $config)) { $results.Add($r) }
    }
    $ref = ConvertTo-ADSADateTime -Value (Get-ADSAProp -InputObject $snap -Name 'collectionTime')
    $unused = Add-ADSAExceptionInfo -Result $results.ToArray() -Config $config -ReferenceTime $ref
    $report = New-ADSAReportObject -Snapshot $snap -Config $config -Result $results.ToArray() -ModulesRun $modules -AnalysisMode $mode -ConfigWarning (@($loaded.Warnings) + @($unused))
    if ($Redact) { $report = Protect-ADSAReportData -Report $report -Salt $RedactionSalt }
    if ($outDir) {
        $files = Export-ADSAReport -Report $report -OutputPath $outDir -Format $Format -BaseName $BaseName -AllowUncOutput:$AllowUncOutput -AllowRepositoryOutput:$AllowRepositoryOutput
        Add-Member -InputObject $report -MemberType NoteProperty -Name OutputFiles -Value @($files | ForEach-Object { $_.FullName }) -Force
    }
    return $report
}
