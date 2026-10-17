# Structured (JSON lines) logging. Logs never contain credentials; sensitive-looking keys are redacted.

$script:ADSALogState = @{
    Level         = 'Information'
    Path          = $null
    CorrelationId = [guid]::NewGuid().ToString()
}

$script:ADSALogLevels = @{ Debug = 0; Information = 1; Warning = 2; Error = 3 }

function Initialize-ADSALog {
    [CmdletBinding()]
    param(
        [ValidateSet('Debug', 'Information', 'Warning', 'Error')] [string] $Level = 'Information',
        [AllowNull()] [string] $Path = $null
    )
    $script:ADSALogState.Level = $Level
    $script:ADSALogState.Path = $Path
    $script:ADSALogState.CorrelationId = [guid]::NewGuid().ToString()
    if ($Path) {
        $dir = Split-Path -Path $Path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
}

function Protect-ADSALogData {
    # Redacts values whose key looks like a secret. Returns a new ordered hashtable.
    [CmdletBinding()]
    param([AllowNull()] [System.Collections.IDictionary] $Data)
    $safe = [ordered]@{}
    if ($null -eq $Data) { return $safe }
    foreach ($key in $Data.Keys) {
        if ("$key" -match '(?i)pass(word|wd)?|secret|credential|token|apikey|cpassword|private') {
            $safe["$key"] = '[REDACTED]'
        } else {
            $safe["$key"] = $Data[$key]
        }
    }
    return $safe
}

function Write-ADSALog {
    [CmdletBinding()]
    param(
        [ValidateSet('Debug', 'Information', 'Warning', 'Error')] [string] $Level = 'Information',
        [Parameter(Mandatory)] [string] $Message,
        [System.Collections.IDictionary] $Data
    )
    if ($script:ADSALogLevels[$Level] -lt $script:ADSALogLevels[$script:ADSALogState.Level]) { return }
    $entry = [ordered]@{
        timestamp     = [datetime]::UtcNow.ToString('o')
        level         = $Level
        correlationId = $script:ADSALogState.CorrelationId
        message       = $Message
        data          = (Protect-ADSALogData -Data $Data)
    }
    switch ($Level) {
        'Warning' { Write-Warning $Message }
        'Error' { Write-Verbose "ERROR: $Message" }
        default { Write-Verbose $Message }
    }
    if ($script:ADSALogState.Path) {
        $line = ($entry | ConvertTo-Json -Compress -Depth 5) + [System.Environment]::NewLine
        try {
            [System.IO.File]::AppendAllText($script:ADSALogState.Path, $line, (New-Object System.Text.UTF8Encoding($false)))
        } catch {
            Write-Warning "Could not write to log file: $($_.Exception.Message)"
        }
    }
}
