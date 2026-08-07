# Changelog

All notable changes to this version of `Test-MdiReadiness.ps1` are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) with the following meaning:

| Bump | When |
|---|---|
| **MAJOR** | The report JSON changes shape, breaking `-AsJson` consumers or invalidating an existing `-BaselinePath` history; a parameter is removed or renamed |
| **MINOR** | A new check, parameter or report section is added without changing what already exists |
| **PATCH** | A defect is fixed or wording is corrected, with no new data and no change of shape |

The version is defined once, in the `$settings` block of the script, and appears in the HTML report
footer, in the `-AsJson` output and in each baseline history entry, so any report or trend can be
traced back to the build that produced it.

## [1.0.0] - 2026-08-07

First release of this extended version. It keeps everything the original script checks and adds the
following.

### Added

- **Forest-wide scanning** with `-Forest`, testing every domain controller of every domain in one run
  and producing a single consolidated report.
- **Required network port validation** for every documented Defender for Identity port, including the
  four Network Name Resolution methods behind the *Low success rate of active name resolution* health
  issue. Probes run on the sensor server itself so they test the real direction of traffic, and UDP is
  validated with genuine protocol requests rather than a connect attempt.
- **Sensor v3.x upgrade readiness**, reporting per server whether it meets the v3.x prerequisites and
  whether it is eligible for in-place migration, with the specific blocker for each server.
- **Capacity planning** with `-CapacityPlanning`, sampling the packet rate of all domain controllers
  concurrently and mapping the result to the published sizing table.
- **Remediation script generation** with `-RemediationScript`, producing a reviewable script that
  supports `-WhatIf` and is never executed automatically.
- **Trend tracking** with `-BaselinePath`, charting readiness across runs.
- **Automation support**: `-AsJson` for machine-readable output and `-FailOnIssues` for a non-zero
  exit code, so the script can be used as a scheduled compliance gate.
- Additional checks for sensor health, time synchronisation and Directory Service Account permissions
  on the Deleted Objects container.
- A redesigned HTML report with tabbed navigation, charts, filtering, CSV export, a colour-preserving
  print layout and a classic view that reproduces the original single-page layout.

### Changed

- Advanced audit policy comparison now uses language-neutral fields, so it works on non-English
  operating systems.
- Capacity sampling uses WMI performance classes rather than performance counter paths, whose names
  are localised.

### Fixed

- Certificate Authority and Entra Connect discovery no longer raise a parameter binding error in a
  domain that has neither.
- Servers that do not answer WMI no longer cause a failure when the remote temporary folder cannot be
  resolved.
- Port probing no longer reports domain controller ports as blocked on servers that are not domain
  controllers.
- The sensor state no longer suggests activating the v3.x sensor on a server that cannot run it.

[1.0.0]: https://github.com/psim/MDI-Readiness-Extended/releases/tag/v1.0.0
