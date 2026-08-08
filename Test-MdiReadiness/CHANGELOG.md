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

## [1.1.0] - 2026-08-08

Correctness release. Every entry below was found by testing against a real multi-domain forest, and
each one is a case where the script gave a confident answer it had not earned.

### Fixed

- **An unreadable SACL was reported as misconfigured auditing.** Reading a SACL needs
  `SeSecurityPrivilege`. Without it Active Directory returns the security descriptor with the SACL
  silently stripped and raises **no error**, so the comparison found nothing and concluded that object,
  Exchange and AD FS auditing were not configured. The generated remediation script then offered to
  rewrite auditing on the domain naming context on the strength of a read that never happened. All
  three checks now report *not tested* and say why.
- **Domain-level checks ran once and were presented forest-wide.** Object auditing, Exchange auditing,
  AD FS auditing, the Deleted Objects permission and the schema version are configured per domain, but
  `-Forest` evaluated them against the root domain only and displayed the answer under a forest
  heading. A child domain with no auditing configured was reported as audited. Each domain is now
  evaluated and shown separately, and one domain that cannot be read no longer stops the others.
- **A multi-homed server was probed on one address.** Every path that learned an address returned a
  single one: `Get-ADComputer` exposes one `IPv4Address`, and taking the first DNS answer picks an
  arbitrary record - a different one per call when DNS round-robins. Network Name Resolution resolves
  whatever source address the sensor observed, so a domain controller answering on one NIC and
  filtered on another failed resolution for half its traffic while the report showed it fully open.
  Every address is now discovered and probed, and the report keeps them apart.
- **Ports that were never probed were reported as blocked.** A name that could not be resolved, and a
  probe that could not run on the sensor, were both counted as closed ports. When the probe could not
  run at all the script now falls back to testing the reverse direction, labels it as such, and
  reports the required-ports check as *not tested* rather than failed - the sensor's outbound path
  and this computer's inbound path are different questions and a firewall can block one and not the
  other.
- **The forest could silently shrink to one domain.** When Active Directory Web Services was
  unavailable, forest enumeration fell back to the current domain and carried on. There is now an LDAP
  fallback that reads the `crossRef` objects directly, and a run that still cannot enumerate the forest
  is reported as incomplete instead of ready.
- **A domain that produced no servers counted as a pass.** Contributing no servers meant contributing
  no failures, so an unreachable domain could not lower the verdict. Each domain in scope is now
  checked for representation.
- **The console, the report and the exit code disagreed.** The console counted failed checks while the
  report listed findings, and one failed ports check expands into one finding per blocked port. Both
  now read the same list. That list also covers domain-level and forest-level findings, so the report
  can no longer say *action required* and *no issues were found* on the same page.
- **The trend chart compared runs that measured different things.** A script upgrade that added a
  check, or a decommissioned domain controller, moved the ratio for reasons unrelated to readiness and
  the report drew a confident percentage-point arrow over it. Runs are now compared only when the
  check set and the server list match, and are reported as *not comparable* otherwise.
- **A sensor health or capacity result that could not be measured vanished from the score.** Both were
  omitted from the server object rather than recorded as not tested, so the gap was invisible to every
  count. A sensor that is simply not installed is still not counted as a gap.
- **NIC teaming double-counted traffic.** A team exposes both the team interface and its members, and
  every packet traverses both, which inflated the packet rate and could report an adequate server as
  under-sized.
- **The generated remediation script could be broken by a server name.** One server name was written
  into the script without the escaping helper used everywhere else. The generated remote helper also
  reported success for a command that failed, because only a thrown exception was treated as an error.
- **A server that was reached and then failed one check lost all its results.** Both cases left a
  comment, and any comment was read as "never answered", so real measured findings were discarded and
  the server was dropped from the remediation script.

### Changed

- `-Forest` now rejects `-DomainController`, `-CAServer` and `-EntraConnectServer` instead of silently
  ignoring them; they describe a single domain.
- `-SkipNetworkPorts` now warns when it is combined with port-related parameters that it disables.
- `-Path` must be a folder, and its writability is checked before the scan rather than after it. A
  failure to write the report is now an error rather than a silent success.
- A scan that enumerates no servers exits with code 255 even without `-FailOnIssues`. Previously it
  printed *scan incomplete* and exited 0, so a scheduled job checking only the exit code treated a run
  that failed to look as a run that found nothing wrong.

### Added

- Per-domain results in the report (`DomainAuditing`), the forest discovery method and whether it was
  complete (`ForestDiscovery`), every address of each server (`Addresses`), and the domain each server
  belongs to (`Domain`).
- Findings for checks that could not be measured, so an unread check is visible and clearly separated
  from one that failed.

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
