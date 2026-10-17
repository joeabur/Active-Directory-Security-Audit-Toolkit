# Output path validation and file protection. Directory data is sensitive; keep it out of the repository.

function Resolve-ADSAOutputPath {
    <#
    .SYNOPSIS
        Validates and creates an output directory. Throws on unsafe or invalid paths.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Path,
        [switch] $AllowUnc,
        [switch] $AllowRepositoryPath
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'OutputPath must not be empty.' }
    if ($Path.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0) { throw "OutputPath contains invalid characters: '$Path'." }
    if ($Path -match '^\\\\' -and -not $AllowUnc) {
        throw 'OutputPath is a UNC path. Network shares are refused by default because audit output is sensitive; pass -AllowUncOutput to override.'
    }
    $full = [System.IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $full -PathType Leaf) { throw "OutputPath '$full' is an existing file, not a directory." }

    if (-not $AllowRepositoryPath) {
        $comparison = [System.StringComparison]::OrdinalIgnoreCase
        foreach ($tracked in 'src', 'config', 'docs', 'tests', 'sample-data', 'examples', 'scripts', '.github') {
            $trackedFull = [System.IO.Path]::GetFullPath((Join-Path $script:ADSARoot $tracked)).TrimEnd('\', '/')
            if ($full.Equals($trackedFull, $comparison) -or
                $full.StartsWith($trackedFull + [System.IO.Path]::DirectorySeparatorChar, $comparison) -or
                $full.StartsWith($trackedFull + [System.IO.Path]::AltDirectorySeparatorChar, $comparison)) {
                throw "OutputPath '$full' is inside the tracked repository folder '$tracked'. Use an untracked location such as the 'output' folder."
            }
        }
    }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        New-Item -ItemType Directory -Path $full -Force | Out-Null
    }
    return $full
}

function Protect-ADSAOutputFile {
    # Restricts a freshly written output file to the current user (best effort, never throws).
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)
    try {
        if (Test-ADSAWindowsPlatform) {
            $acl = Get-Acl -LiteralPath $Path
            $acl.SetAccessRuleProtection($true, $false)
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
            $acl.SetAccessRule($rule)
            Set-Acl -LiteralPath $Path -AclObject $acl
        } else {
            [System.IO.File]::SetUnixFileMode($Path, ([System.IO.UnixFileMode]'UserRead, UserWrite'))
        }
    } catch {
        Write-ADSALog -Level Warning -Message "Could not restrict permissions on output file: $($_.Exception.Message)"
    }
}

function Write-ADSAFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Content,
        [switch] $WithBom
    )
    $encoding = New-Object System.Text.UTF8Encoding([bool]$WithBom)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
    Protect-ADSAOutputFile -Path $Path
    return Get-Item -LiteralPath $Path
}
