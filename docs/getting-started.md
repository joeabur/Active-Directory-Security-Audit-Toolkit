# Getting started

This guide installs the toolkit and runs the first audit on **synthetic data**. No domain access is needed. For a guided tour with exercises, continue with the [walkthrough](walkthrough.md).

## 1. Prerequisites

| Requirement | Offline analysis, tests, demo | Live collection |
|---|---|---|
| PowerShell | Windows PowerShell 5.1 or PowerShell 7+ (Windows, Linux, macOS) | Windows PowerShell 5.1 or PowerShell 7 on Windows |
| `ActiveDirectory` module (RSAT) | Not needed | Required |
| Pester 5.7.1 | Only to run tests | Only to run tests |
| PSScriptAnalyzer 1.23.0 | Only to run lint | Only to run lint |
| Network access to a domain controller | Not needed | Required (LDAP/ADWS; WinRM for optional DC host checks) |
| Authorization to assess the domain | Not applicable | **Required** |

Check what your host supports:

```powershell
Import-Module ./src/ADSecurityAudit.psd1 -Force
Test-ADSAPrerequisite | Select-Object -ExpandProperty Checks | Format-Table -AutoSize
```

Expected on a non-domain Linux host: `PowerShellVersion` true, `Windows` false, `ActiveDirectoryModule` false, `DomainJoined` false. `OfflineReady` is true when PowerShell is 5.1 or later.

## 2. Install

```powershell
git clone https://github.com/joeabur/Active-Directory-Security-Audit-Toolkit.git
Set-Location Active-Directory-Security-Audit-Toolkit
Import-Module ./src/ADSecurityAudit.psd1 -Force
Get-Command -Module ADSecurityAudit | Select-Object Name
```

The module exports ten commands (see the [command reference](user-guide.md#command-reference)). Nothing is installed system-wide; importing from the clone is enough. To make it available in every session, copy the `src` folder to a directory named `ADSecurityAudit` inside a folder on `$env:PSModulePath`.

Install the development tools only if you want to run tests or lint:

```powershell
./scripts/Install-DevDependencies.ps1
```

This installs pinned versions from the PowerShell Gallery for the current user.

## 3. First run (offline, simulated data)

```powershell
./scripts/Invoke-Demo.ps1
```

Expected output (abridged):

```text
DEMO: offline audit of SYNTHETIC data (no domain access, no network).
SIMULATED DATA: these results come from a synthetic fixture. ...
50 active finding(s) across 41 assessed rule(s); 5 rule(s) could not be fully assessed; 0 finding(s) covered by documented exceptions.
Critical      : 2
High          : 17
Medium        : 20
Low           : 11
Informational : 0
...
Demo self-checks passed.
```

Open `output/demo/sample-report.html` in a browser. The page opens with a banner that states the data source is **Simulated**.

## 4. Audit your own snapshot offline

A snapshot is a JSON file of normalized directory data (see `config/schemas/snapshot.schema.json`). Real snapshots are sensitive directory data; handle them like a password hash dump.

```powershell
$report = Invoke-ADSecurityAudit -SnapshotPath ./sample-data/contoso-sim.snapshot.json -OutputPath ./output/first-run
$report.Summary.Headline
$report.OutputFiles
```

## 5. Live collection (optional, authorized domains only)

Live collection reads from a real domain. It needs Windows, RSAT, and **written authorization**. Start with the least invasive options:

```powershell
$cred = Get-Credential
$report = Invoke-ADSecurityAudit -AuthorizedAssessment -Server dc01.lab.example -Credential $cred -SkipDcHostChecks -OutputPath ./output/live
```

Permissions per module are listed in [security and limitations](security-and-limitations.md#permissions-by-module). A standard authenticated domain user is enough for everything except the optional domain controller host checks.

## Where to go next

- [Walkthrough](walkthrough.md): the guided path with three exercises.
- [Configuration](configuration.md): thresholds, exclusions, documented exceptions.
- [Troubleshooting](troubleshooting.md) if something fails.
