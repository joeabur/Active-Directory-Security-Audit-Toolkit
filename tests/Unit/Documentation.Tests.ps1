Describe 'Documentation validation' {
    It 'has no broken links, anchors, diagrams, examples or stale numbers' {
        $pwsh = (Get-Process -Id $PID).Path
        $script = Join-Path $PSScriptRoot '../../scripts/Test-Documentation.ps1'
        $out = & $pwsh -NoProfile -Command "& '$script' -PassThru | ForEach-Object { 'DOC PROBLEM: ' + `$_ }" 2>&1
        $problems = @($out | Where-Object { "$_" -like 'DOC PROBLEM:*' })
        $problems | Should -BeNullOrEmpty -Because ($problems -join "`n")
    }
}

Describe 'Repository completeness' {
    It 'does not git-ignore any file the docs, tests or examples rely on' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        if (-not (Test-Path (Join-Path $root '.git'))) { Set-ItResult -Skipped -Because 'not a git checkout'; return }
        $needed = @('sample-data/contoso-sim.snapshot.json', 'config/default.config.json', 'config/schemas/report.schema.json', 'src/Rules/RuleCatalog.psd1', 'examples/custom-config.json',
            'examples/sample-reports/sample-report.json', 'examples/sample-reports/sample-report.csv', 'examples/sample-reports/sample-report.html', 'docs/rule-reference.md')
        foreach ($f in $needed) {
            Push-Location $root
            try { & git check-ignore -q -- $f; $ignored = ($LASTEXITCODE -eq 0) } finally { Pop-Location }
            $ignored | Should -BeFalse -Because "$f is ignored by .gitignore and would be missing from a clean clone"
        }
    }
}
