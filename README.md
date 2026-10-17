# Active Directory Security Audit Toolkit

A **read-only** PowerShell toolkit for authorized Active Directory security assessments. It collects selected directory evidence, evaluates 44 documented rules, and produces JSON, CSV and safely escaped HTML reports with an executive summary, technical findings, coverage and collection errors.

> **Scope and honesty.** The toolkit checks selected, well-defined conditions. It does **not** claim to find every Active Directory attack path, it never exploits anything, never attacks credentials, and never changes the directory, ACLs, Group Policy or domain controllers. Results from the bundled mock/simulated data demonstrate the tooling only and **never establish the security of a real domain**. Missing permissions or unreachable servers are reported as `ERROR` or `NOT_ASSESSED`, never as `PASS`.

## Documentation

| Guide | Purpose |
|---|---|
| [Getting started](docs/getting-started.md) | Install, prerequisites, first offline run |
| [Walkthrough](docs/walkthrough.md) | Clone to mock audit to interpreting reports; three progressive exercises |
| [User guide](docs/user-guide.md) | Architecture, audit workflow, command reference, report format |
| [Configuration](docs/configuration.md) | Thresholds, exclusions, documented exceptions, validation |
| [Troubleshooting](docs/troubleshooting.md) | Missing modules, permissions, unreachable DCs, LDAP errors, unsupported attributes |
| [Security and limitations](docs/security-and-limitations.md) | Safety model, per-module permissions, what needs a real test domain |
| [Examples](docs/examples.md) | Copy-paste recipes |
| [Rule reference](docs/rule-reference.md) | All rules: severity, confidence, remediation, limitations |
| [Test results](docs/test-results.md) | Actual test and lint results and what has not been validated |

## Quick start (no domain needed)

```powershell
git clone https://github.com/joeabur/Active-Directory-Security-Audit-Toolkit.git
Set-Location Active-Directory-Security-Audit-Toolkit
./scripts/Invoke-Demo.ps1
```

This audits a **synthetic** snapshot (`sample-data/contoso-sim.snapshot.json`, domain `contoso-sim.test`) and writes reports to `output/demo/`. Sample reports are committed in [`examples/sample-reports/`](examples/sample-reports/).

## Supported platforms

| Mode | Windows PowerShell 5.1 | PowerShell 7 (Windows) | PowerShell 7 (Linux/macOS) |
|---|---|---|---|
| Offline analysis of a snapshot, reports, tests | Supported by design (see [test results](docs/test-results.md) for what was verified) | Supported and tested | Supported and tested |
| Live collection | Supported (needs RSAT `ActiveDirectory` module) | Supported (module via Windows compatibility) | Not supported |

## Repository layout

```text
src/            ADSecurityAudit module (Private helpers, Modules = audit modules, Rules = catalog, Public API)
config/         versioned default configuration and JSON schemas
tests/          Unit (portable, mocked), Integration (offline + Windows test domain), Fixtures (synthetic)
sample-data/    SYNTHETIC snapshot used by the demo and tests
examples/       custom configuration, example scripts, committed sample reports
scripts/        test runner, lint, demo, documentation validator, generators
docs/           guides
.github/        CI (lint, tests, secret scanning, dependency review)
```

## Safety summary

- Read-only: only `Get-AD*` queries, one fixed read-only remote script block per domain controller, and SYSVOL file reads. A static-analysis test fails the build if a state-changing cmdlet appears.
- Live collection requires an explicit `-AuthorizedAssessment` switch.
- Credentials are accepted only as a run-time `[pscredential]`; they are never stored in configuration, logs or reports.
- Output paths are validated; files are restricted to the current user where the platform allows; `-Redact` pseudonymises object names for sharing.
- GPP `cpassword` values are detected but never stored.

## Development

```powershell
./scripts/Install-DevDependencies.ps1   # Pester 5.7.1 and PSScriptAnalyzer 1.23.0, current user
./scripts/Invoke-Lint.ps1
./scripts/Invoke-Tests.ps1 -Suite All
./scripts/Test-Documentation.ps1
```

No license file is included yet; add one before publishing or accepting contributions.
