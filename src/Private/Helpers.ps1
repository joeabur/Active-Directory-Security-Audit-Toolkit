# Small, dependency-free helpers shared by every audit module.

function Get-ADSAProp {
    # Safe property read: returns $Default when the object or property is absent (never throws under strict mode).
    [CmdletBinding()]
    param(
        [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string] $Name,
        [AllowNull()] $Default = $null
    )
    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $Default
    }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $prop) { return $prop.Value }
    return $Default
}

function Test-ADSAHasProp {
    # True when the property exists at all (even if its value is $null). Distinguishes "not retrieved" from "empty".
    [CmdletBinding()]
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] [string] $Name)
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject.Contains($Name) }
    return ($null -ne $InputObject.PSObject.Properties[$Name])
}

function Get-ADSAList {
    # Returns a (possibly empty) object[] for a property. Always call as: $x = Get-ADSAList ...
    [CmdletBinding()]
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] [string] $Name)
    $value = Get-ADSAProp -InputObject $InputObject -Name $Name
    if ($null -eq $value) { return , @() }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($value)) {
        if ($null -ne $item -and "$item" -ne '') { $items.Add($item) }
    }
    return , $items.ToArray()
}

function ConvertTo-ADSADateTime {
    # Accepts DateTime, ISO-8601 string, or FILETIME (int64 / numeric string). Returns UTC DateTime or $null.
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        switch ($Value.Kind) {
            'Utc' { return $Value }
            'Local' { return $Value.ToUniversalTime() }
            default { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        }
    }
    $text = "$Value".Trim()
    if ($text -eq '') { return $null }
    if ($text -match '^\d+$') {
        $ticks = [int64]0
        if (-not [int64]::TryParse($text, [ref]$ticks)) { return $null }
        if ($ticks -le 0 -or $ticks -ge [int64]::MaxValue) { return $null }
        try { return [datetime]::FromFileTimeUtc($ticks) } catch { return $null }
    }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed
    }
    return $null
}

function Get-ADSAUacFlagMap {
    return @{
        ACCOUNTDISABLE                  = 0x2
        PASSWD_NOTREQD                  = 0x20
        ENCRYPTED_TEXT_PWD_ALLOWED      = 0x80
        WORKSTATION_TRUST_ACCOUNT       = 0x1000
        SERVER_TRUST_ACCOUNT            = 0x2000
        DONT_EXPIRE_PASSWORD            = 0x10000
        SMARTCARD_REQUIRED              = 0x40000
        TRUSTED_FOR_DELEGATION          = 0x80000
        NOT_DELEGATED                   = 0x100000
        USE_DES_KEY_ONLY                = 0x200000
        DONT_REQ_PREAUTH                = 0x400000
        PASSWORD_EXPIRED                = 0x800000
        TRUSTED_TO_AUTH_FOR_DELEGATION  = 0x1000000
    }
}

function Get-ADSAUac {
    # Returns userAccountControl as [int] or $null when unavailable/malformed.
    [CmdletBinding()]
    param([AllowNull()] $InputObject)
    $raw = Get-ADSAProp -InputObject $InputObject -Name 'UserAccountControl'
    if ($null -eq $raw) { return $null }
    $value = 0
    if ([int]::TryParse("$raw", [ref]$value)) { return $value }
    return $null
}

function Test-ADSAUacFlag {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [int] $Uac, [Parameter(Mandatory)] [string] $Flag)
    $map = Get-ADSAUacFlagMap
    if (-not $map.ContainsKey($Flag)) { throw "Unknown userAccountControl flag '$Flag'." }
    return (($Uac -band $map[$Flag]) -ne 0)
}

function Get-ADSAEnabled {
    # Returns $true/$false, or $null when neither Enabled nor userAccountControl is available.
    [CmdletBinding()]
    param([AllowNull()] $InputObject)
    $enabled = Get-ADSAProp -InputObject $InputObject -Name 'Enabled'
    if ($enabled -is [bool]) { return $enabled }
    $uac = Get-ADSAUac -InputObject $InputObject
    if ($null -ne $uac) { return (-not (Test-ADSAUacFlag -Uac $uac -Flag 'ACCOUNTDISABLE')) }
    return $null
}

function Get-ADSADaysBetween {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [datetime] $From, [Parameter(Mandatory)] [datetime] $To)
    return [int][math]::Floor(($To - $From).TotalDays)
}

function Format-ADSAIsoTime {
    [CmdletBinding()]
    param([AllowNull()] $Value)
    $dt = ConvertTo-ADSADateTime -Value $Value
    if ($null -eq $dt) { return $null }
    return $dt.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Test-ADSAWildcardMatch {
    [CmdletBinding()]
    param([AllowNull()] [string] $Value, [Parameter(Mandatory)] [string] $Pattern)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    return ($Value -like $Pattern)
}

function Get-ADSASidRid {
    # Returns the trailing RID of a SID string, or $null.
    [CmdletBinding()]
    param([AllowNull()] [string] $Sid)
    if ([string]::IsNullOrEmpty($Sid)) { return $null }
    if ($Sid -match '-(\d+)$') { return [int64]$Matches[1] }
    return $null
}

function Test-ADSAWindowsPlatform {
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}
