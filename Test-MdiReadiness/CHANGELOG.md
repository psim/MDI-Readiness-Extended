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

## [1.1.0] - 2026-08-09

Correctness release. Every entry below was found by testing against a real multi-domain forest, and
each one is a case where the script gave a confident answer it had not earned.

### Fixed

- **The verdict trusted a summary flag over its own measurements.** Each server carries a
  `RequiredPorts` summary alongside the individual probe records behind it. The verdict and the issue
  list read only the summary, so when the two disagreed the disagreement resolved silently in favour
  of green: the statistics reported a required port as blocked while the report said READY and listed
  no issues at all. Both now decide from the probe records. `AtLeastOne` groups, which Network Name
  Resolution uses, still pass on one success rather than requiring every method.
- **An empty probe plan certified the ports as open.** When no domain controller resolved, no probe
  ran, so no probe failed - and no failures was read as nothing wrong. It reports that nothing was
  measured.
- **A name that did not resolve was reported as a refused connection.** A DNS failure was labelled
  "Closed - connection refused", which sends an administrator to a firewall for a name resolution
  fault. The socket error code decides it now.
- **A probe that could not run was recognised only by its English message.** "Access is denied" and
  "The RPC server is unavailable" stop matching on a localised Windows, where a probe that never ran
  then reads as a blocked port. Those failures are classified by numeric error code where the detail
  is written, so the decision no longer depends on the language of the operating system.
- **The same classifier matched the middle of a sentence.** "could not be" and "unable to" were
  unanchored, so a genuinely failed probe reported as "the server could not be contacted" was
  reclassified as one that never ran: the ports card then read a green "1/1 open" with nothing to fix.
  The script's own phrases are anchored to the front of the detail, which is where it always writes
  them.
- **A probe whose applicability was unknown vanished from the totals.** A record with no applicability
  flag was dropped rather than counted, so a blocked port could disappear and leave the totals at
  zero. It counts as untested, which is what it is.
- **The overview painted cards green over checks it had never read.** A server was counted as fully
  ready while its checks were still unread, and the required-ports card was drawn green from a 0/0
  score when every probe was untested. Unread now reads as unread, and the ports card shows *n/a*.
- **The Deleted Objects section showed only the first domain.** A forest run where a child domain
  failed the permission check displayed a green Pass beside an issue list that reported the failure.
  Every domain is listed.
- **The generated remediation script could be made to run injected code.** Values taken from the
  directory were written into its header comment unescaped, so a domain name containing a comment
  terminator closed the comment and everything after it became live code in a file the operator is
  told to review and run. Comment and code contexts are both escaped now.
- **The remediation script ignored every domain but the first.** In a forest run a child domain with
  failed auditing or Deleted Objects permissions produced "No remediation is required" while the run
  itself was not ready.
- **Report URLs were written into `href` attributes unescaped.**
- **Any parameter could bind by position.** With thirty parameters, a missing switch name put the
  value into whichever parameter happened to sit at that position, so two names given without
  `-DomainController` bound the first to `-Domain` and scanned the wrong scope while reporting
  success. Positional binding is off; `-Path` keeps position 0 so the documented short form still
  works.
- **Two parameter pairs were silently ignored.** `-Forest` with `-Domain`, and `-RemediationScript`
  with `-SkipRemediationScript`, each dropped the second parameter without saying so. Both warn.
- **An unreadable SACL was reported as misconfigured auditing.** Reading a SACL needs
  `SeSecurityPrivilege`. Without it Active Directory returns the security descriptor with the SACL
  silently stripped and raises **no error**, so the comparison found nothing and concluded that object,
  Exchange and AD FS auditing were not configured. The generated remediation script then offered to
  rewrite auditing on the domain naming context on the strength of a read that never happened. All
  three checks now report *not tested* and say why.
- **A domain with no AD FS was reported as unverified, permanently.** The AD FS check read the
  container without first asking whether it exists; the directory answered "no such object" and that
  error was classified as a failure to measure, so a forest with no AD FS - which is most of them -
  could never be reported ready. Existence is established first now, exactly as the Exchange check
  already did.
- **Domain-level checks ran once and were presented forest-wide.** Object auditing, Exchange auditing,
  AD FS auditing, the Deleted Objects permission and the schema version are configured per domain, but
  `-Forest` evaluated them against the root domain only and displayed the answer under a forest
  heading. A child domain with no auditing configured was reported as audited. Each domain is now
  evaluated and shown separately, and one domain that cannot be read no longer stops the others.
- **A server that was reached and then failed part way through was reported READY.** Its remaining
  checks were never run, so they were absent rather than false - and on a small estate the handful
  that had completed were the only results present, a clean sweep of passes over a scan that stopped
  at the first check.
- **A single server holding several roles was counted several times.** Running AD CS and Entra Connect
  on a domain controller is ordinary in a small environment, and the three discovery passes each found
  the same host: it reported as three servers scanned, every shared check counted three times in the
  score, each of its findings listed three times, and the generated script set its power scheme and
  restarted its sensor three times. Servers are now merged by name, keeping the checks that belong to
  only one role.
- **A multi-homed server was probed on one address.** Every path that learned an address returned a
  single one: `Get-ADComputer` exposes one `IPv4Address`, and taking the first DNS answer picks an
  arbitrary record - a different one per call when DNS round-robins. Network Name Resolution resolves
  whatever source address the sensor observed, so a domain controller answering on one NIC and
  filtered on another failed resolution for half its traffic while the report showed it fully open.
  Every address is now discovered and probed, and the report keeps them apart.
- **A port was declared blocked on the strength of one lost packet.** A single 1500 ms timeout was
  reported as "filtered by a firewall" with certainty, and a firewall rule was generated to open it -
  but a domain controller across a slow WAN legitimately exceeds that, and UDP has no retransmission
  at all, so one ordinary lost datagram was enough to report NetBIOS name resolution as blocked on a
  network where it works. Both probes now retry once with a longer budget before concluding, and say
  so in the result.
- **Ports that were never probed were reported as blocked.** A name that could not be resolved, and a
  probe that could not run on the sensor, were both counted as closed. When the probe cannot run the
  script now falls back to testing the reverse direction, labels every result with that fact, and
  reports the required-ports check as *not tested* rather than failed - the sensor's outbound path and
  this computer's inbound path are different questions, and a firewall can block one and not the other.
  The generated script no longer opens a port that was not tested.
- **The Deleted Objects permission never reached the verdict.** A missing Directory Service Account
  permission showed as Fail in the report while the console said READY and the exit code was 0.
- **The forest could silently shrink to one domain.** When Active Directory Web Services was
  unavailable, forest enumeration fell back to the current domain and carried on. There is now an LDAP
  fallback that reads the `crossRef` objects directly, and a run that still cannot enumerate the forest
  is reported as incomplete instead of ready. A domain that produced no servers likewise contributed
  no failures, so it could not lower the verdict.
- **The console, the report and the exit code disagreed.** The console counted failed checks while the
  report listed findings, and one failed ports check expands into one finding per blocked port. Both
  now read the same list, which also covers domain-level and forest-level findings - the report could
  previously say *action required* and *no issues were found* on the same page.
- **The trend chart compared runs that measured different things.** A script upgrade that added a
  check, or a decommissioned domain controller, moved the ratio for reasons unrelated to readiness and
  the report drew a confident percentage-point arrow over it. Runs are now compared only when the
  check set and the server list match, and are reported as *not comparable* otherwise.
- **A sensor health or capacity result that could not be measured vanished from the score.** Both were
  omitted from the server object rather than recorded as not tested, so the gap was invisible to every
  count. A server that could not be queried at all was also rendered as having a sensor installed,
  because `[bool] 'N/A'` is `$true`.
- **NIC teaming double-counted traffic.** A team exposes both the team interface and its members, and
  every packet traverses both, which inflated the packet rate and could report an adequate server as
  under-sized.
- **The generated remediation script could be broken by a server name**, and its remote helper
  reported success for a command that had failed, because only a thrown exception was treated as an
  error. A command that outlives its timeout is now terminated rather than left running on the domain
  controller, and its partial output is discarded rather than parsed.
- **The delegated Managed Service Account audit entry** is decided by looking for the class in the
  schema rather than by comparing a schema version number - the published version for Windows Server
  2025 is quoted as both 90 and 91, and a live 2025 forest reports 91, so any threshold is a guess.
- **A failure to enumerate certification authorities or Entra Connect servers** is now warned about
  rather than being indistinguishable from "this domain has none".
- **PowerShell 7 was accepted and silently degraded the results.** PowerShell 7 removed the WMI
  cmdlets this script depends on, but it does not fail: it forwards those calls to Windows PowerShell
  over implicit remoting, and what comes back is *deserialized* - properties survive, methods do not.
  A probe that outlived its timeout could therefore not be terminated and was left running on a domain
  controller, and every WMI call paid a per-call remoting cost that turns a forest scan into an
  overnight job. The script now refuses to run under PowerShell 7 and names the command to use
  instead, rather than half-working.

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
- A test suite: 397 assertions across 11 suites plus 14 static rules, in `tests/`. See its README for
  what each protects and for the mutation-testing results that shaped it.

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
