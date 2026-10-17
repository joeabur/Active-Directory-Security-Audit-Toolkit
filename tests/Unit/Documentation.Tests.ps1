Describe 'Documentation validation' {
    It 'has no broken links, anchors, diagrams, examples or stale numbers' {
        $pwsh = (Get-Process -Id $PID).Path
        $script = Join-Path $PSScriptRoot '../../scripts/Test-Documentation.ps1'
        $out = & $pwsh -NoProfile -Command "& '$script' -PassThru | ForEach-Object { 'DOC PROBLEM: ' + `$_ }" 2>&1
        $problems = @($out | Where-Object { "$_" -like 'DOC PROBLEM:*' })
        $problems | Should -BeNullOrEmpty -Because ($problems -join "`n")
    }
}
