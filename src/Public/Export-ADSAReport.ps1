function Export-ADSAReport {
    <#
    .SYNOPSIS
        Writes JSON, CSV and/or HTML reports to a validated output directory.
    .DESCRIPTION
        HTML output is escaped and script-free; CSV cells that look like formulas are neutralised.
        Files are restricted to the current user where the platform allows it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Report,
        [Parameter(Mandatory)] [string] $OutputPath,
        [ValidateSet('Json', 'Csv', 'Html')] [string[]] $Format = @('Json', 'Csv', 'Html'),
        [string] $BaseName,
        [switch] $AllowUncOutput,
        [switch] $AllowRepositoryOutput
    )
    $check = Test-ADSAReport -Report $Report
    if (-not $check.IsValid) { throw ("Report failed schema validation:`n - " + ($check.Errors -join "`n - ")) }
    $dir = Resolve-ADSAOutputPath -Path $OutputPath -AllowUnc:$AllowUncOutput -AllowRepositoryPath:$AllowRepositoryOutput
    if (-not $BaseName) {
        $domain = ("$($Report.Metadata.Domain.Name)" -replace '[^A-Za-z0-9.-]', '_')
        if (-not $domain) { $domain = 'domain' }
        $prefix = if ($Report.Metadata.DataSource -eq 'Simulated') { 'SIMULATED-' } else { '' }
        $BaseName = '{0}ADSA-report-{1}-{2}' -f $prefix, $domain, ([datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
    }
    if ($BaseName -match '[\\/]' -or $BaseName.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw "BaseName '$BaseName' must be a plain file name without path separators." }
    $files = @()
    foreach ($fmt in $Format) {
        switch ($fmt) {
            'Json' { $files += Write-ADSAFile -Path (Join-Path $dir "$BaseName.json") -Content (ConvertTo-ADSAJsonReport -Report $Report) }
            'Csv' { $files += Write-ADSAFile -Path (Join-Path $dir "$BaseName.csv") -Content (ConvertTo-ADSACsvReport -Report $Report) -WithBom }
            'Html' { $files += Write-ADSAFile -Path (Join-Path $dir "$BaseName.html") -Content (ConvertTo-ADSAHtmlReport -Report $Report) }
        }
    }
    return $files
}
