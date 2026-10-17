# Changelog

All notable changes are recorded here. The format follows Keep a Changelog; versions follow Semantic Versioning.

## [1.0.0] - unreleased

### Added
- ADSecurityAudit PowerShell module (Windows PowerShell 5.1 and PowerShell 7): read-only collection, 44 rules in seven audit modules, JSON/CSV/HTML reports.
- Result model with PASS, FAIL, ERROR, NOT_APPLICABLE and NOT_ASSESSED; missing permissions never produce PASS.
- Versioned configuration with strict validation, documented exclusions and time-boxed exceptions.
- Independent ACL and delegation analysis modules.
- Report redaction (`-Redact`), explicit live-collection authorization gate (`-AuthorizedAssessment`), validated and protected output paths.
- Synthetic sample snapshot, repeatable offline demo, committed sample reports.
- Pester unit and integration suites, PSScriptAnalyzer settings, documentation validator, CI with secret scanning and dependency review.
- Guides: getting started, walkthrough, user guide, configuration, troubleshooting, security and limitations, examples, rule reference.

### Known limitations
See [docs/security-and-limitations.md](docs/security-and-limitations.md). Live collection, Windows PowerShell 5.1 execution and DC host checks have not been validated against a real Windows domain by the author.
