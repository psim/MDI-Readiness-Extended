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

## [1.2.0] - 2026-08-21

Correctness release, on one theme: a value the script could not read must never come back looking
like a measurement, and two surfaces reading the same fact must not disagree about it.

A `Requirement` this script cannot read is no longer treated as one it read and found optional. It
now has a third state of its own, and it keeps a run out of READY.

The verdict therefore changes for the estates where it applies: a run that was reported READY over a
refused or never-probed port whose obligation could not be read no longer reaches READY. Measured on
an otherwise healthy estate whose only fault is one such probe, the console prints `READINESS N/A`
and the report's `Readiness` field reads `N/A` rather than `true` - the state is unread, not
measured-and-failed, and the verdict says so. No existing report field changes meaning and one field
is added, so an existing `-BaselinePath` history and any `-AsJson` consumer keep working.

### Added

- `PortsRequirementUnread` in the statistics that drive the report: applicable probes whose
  `Requirement` could not be read and that were not measured open. Counted separately from
  `PortsRequiredFail` and `PortsRequiredUntested`, so neither of those changes meaning. The count is
  a statistic and not a key of the `-AsJson` document; there the same state shows as `ChecksUnread`
  rising and `Readiness` reading `N/A`.
- A `Not verified` finding naming each such probe with its protocol, port and target address, worded
  so it is not mistaken for a probe that failed to run.

### Fixed

- The sampling disclosure could be suppressed by hosts that were never in scope. The count of
  "hosts actually probed" was filtered on `Scope` while the count of "hosts that could have been
  probed" was the domain controllers, so a probe record whose `Scope` was present but unreadable - a
  hashtable, a number, a boolean - is not equal to `NetworkDevice`, satisfied the filter, and entered
  a domain-controller ratio on the strength of a value nobody could read. Two named workstations were
  enough to turn "2 of 4 probed" into "4 of 4" and silence the disclosure entirely. The numerator is
  now drawn from the denominator's own population, so it can no longer exceed it.
- A trend delta was drawn between two different estates when one of them could not be named. An
  unreadable `Domain` or `Forest` normalised to blank and blank was treated as "matches anything", so
  a run whose estate identity could not be read was declared comparable with a baseline from a
  different forest. Such a run is now refused - and the refusal says the identity could not be read,
  rather than claiming a different domain and printing the unreadable value's rendering as its name.
  A blank identity still falls through, because a history written before these fields existed records
  exactly that and every stored baseline must keep working.
- A forest enumeration nobody could confirm was certified as complete. `ForestDiscovery` arriving as
  `Unknown`, a number, a boolean or a list of unreadable entries answered "complete" because it was
  not a record, which is the false green this guard exists to prevent. A value that was recorded and
  cannot be read is now charged incomplete; absence - no field, a null, or a blank - still is not.
- A CSV exported from the report while a filter was typed omitted the rows the filter had hidden and
  said nothing about it, so an export that matched one healthy server was indistinguishable from a
  report of a healthy estate - the reading the on-screen `n of m row(s) shown` counter exists to
  prevent, on the copy that leaves the machine as evidence. The export still follows the screen; it
  now begins with one line naming the filter text and repeating that counter. An unfiltered export is
  unchanged, and classic view - which clears every filter and exports the whole report - carries no
  such line.
- A required port measured REFUSED, and a required port never probed at all, both left the run READY
  when `Requirement` arrived as null, an empty string, the boolean `true`, a number, a hashtable or a
  padded spelling. `Requirement` makes a full JSON round trip, where `"Requirement":true` becomes the
  boolean `true`, and `-MultiForest` promotes LDAPS 636 and LDAPS to Global Catalog 3269 into the
  required set - so in a cross-forest estate the records that decide readiness are exactly the ones
  travelling that path.
- The per-server ports state and the issue list follow the same rule as the verdict, so the Overview
  can no longer report a server's ports in order while the verdict withholds READY over them.
- A domain check the scanner could not read was scored as a measurement and named as a pass. The
  `Measured` companion flag was read with a bare `[bool]` cast in three places, and `[bool] 'False'`
  is `$true`, so a flag that had been through a JSON round trip asserted the opposite of what it
  said: the check left the unread count, the verdict flipped from NOT READY to READY, and the domain
  auditing table claimed `Not applicable` - a definite statement that the role is absent from the
  domain - about a SACL nobody could read. An unreadable flag now counts as unread, which also means
  a bare `1`, the string `Unknown` and a hashtable are no longer treated as measurements.
- A baseline history the script could not parse was overwritten, destroying every run recorded in it.
  A file that cannot be DECODED was already preserved, but one that decodes as valid UTF-8 and fails
  at `ConvertFrom-Json` - a history truncated by a full disk, or half-written by a run that was
  killed - took the other branch and was replaced with the current run alone, behind a warning that
  read as routine (`183 -> 659 bytes` measured). Such a file is now moved aside to
  `mdi-baseline-<domain>.json.damaged-<timestamp>`, the warning says where it went, and a new history
  is started so the trend resumes on the same run instead of being blocked until the file is repaired
  by hand. If it cannot be moved aside it is not overwritten either.
- The domain-scope resolver accepted anything that RENDERED as a domain name. Both directory readers
  cast the answer to a string before the usability rule saw it, so a hashtable was accepted as
  `System.Collections.Hashtable` and `1.5` as `1.5` - both match the DNS name pattern, carry a dot
  and are not IP addresses. The resolved name becomes the run's `$Domain`, which names the JSON
  report, the HTML report and the **baseline file**, and is the host part of every later `LDAP://`
  bind, so a run that resolved to a rendered type name compared its trend against a different file.
  The readers now hand back the directory's answer unrendered and a non-string is refused, which
  falls through to the next reader and finally to keeping the operator's own spelling. No live run is
  known to produce these shapes; this is hardening of a value with an outsized blast radius.
- A row was badged `partial results` for a server that was fully scanned. The DC table read the
  `PartialFailure` flag with a bare `[bool]` cast while `PartialScanCount` read the same flag with
  `-eq $true`, so after a JSON round trip the badge and the count disagreed about the same server on
  the same page. Both now read it through the count's own expression.

### Unchanged, deliberately

- The requirement rank scale. An unreadable value still ranks 0 and is still not mandatory - it is
  never promoted into an obligation, only refused the right to be treated, in silence, as one that
  was read. Nothing is trimmed. `Optional` and `Recommended` behave exactly as before.
- A port measured OPEN with an unreadable `Requirement` is still READY, and an unreadable value is
  never counted as a required failure and never painted as a blocked port.

## [1.1.8] - 2026-08-21

Correctness release. Twenty-six defects fixed, each with a mutation-tested regression test.

No parameter, report section or JSON field changed, so an existing `-BaselinePath` history and any
`-AsJson` consumer keep working.

### Fixed

- Estates that were never examined were certified as covered: a forest the report never enumerated,
  a discovery record held once per forest that hid an unfinished enumeration, an estate nobody could
  name, and a target certified by a different target's success.
- An estate that was only partly sampled reported itself as fully sampled, and a named workstation
  counted as a domain controller erased the sampling disclosure altogether.
- The inventory miscounted machines: one domain named twice enlarged the forest and the estate, a
  domain controller carrying a usable address vanished from it, a multi-homed projection rewrote the
  record it was built from, and a host discovered in a third role could re-merge its own evidence.
- Values nobody could read were published as measurements - probe sources, probe latencies, a probe
  that had in fact been measured, and unmeasured checks left sitting in the failed column.
- A per-user audit policy target nobody could read was elected as the machine's system audit policy.
- An unreadable domain became a DNS suffix and split one machine into two, and unreadable domains
  and NetBIOS suffixes took name-resolution probe slots from a second forest that had them coming.
- One unreadable value could destroy a whole output: a single port could wreck the entire
  remediation script, a baseline the script could not read was one simplification away from being
  overwritten by it, a dictionary shape the accessors had just proved they could read made them
  throw, and a required port measured as refused was lost with an unreadable server name.
- A clock tolerance taken from one row certified an estate that fails the requirement, and identical
  text that names nobody was reported as a verified grant.

## [1.1.7] - 2026-08-19

Correctness release. Nineteen defects fixed, each with a mutation-tested regression test.

No parameter, report section or JSON field changed, so an existing `-BaselinePath` history and any
`-AsJson` consumer keep working.

### Fixed

- A domain left unprobed by the global `-MaxNnrTargets` budget was reported as ready, and a target
  the budget dropped was reported as one whose address could not be resolved.
- A measured failure was published as `Readiness: "N/A"`, which a pipeline gating on that field
  reads as nothing proven wrong.
- A mandatory check that failed was painted as advisory on the prerequisite chart, disagreeing with
  the verdict that had already blocked on it.
- A resolver failure collapsed the self-probe guard and fabricated a pass on required LDAP and
  LDAPS ports.
- Rows arriving as dictionaries lost their checks, their addresses and recorded measurements, and
  gained .NET members as failures.
- A schema version was invented for a domain whose schema was never read.
## [1.1.6] - 2026-08-18

Correctness release. Thirty-one defects fixed, each with a mutation-tested regression test.

No parameter, report section or JSON field changed, so an existing `-BaselinePath` history and any
`-AsJson` consumer keep working.

### Fixed

- An estate named by its NetBIOS name, with a trailing dot or in a different case was treated as
  unreachable rather than as the same estate spelled differently.
- Surfaces that could not be read - a service list, a product type, a DNS question, a schema, a
  certification authority - were reported as failures instead of as unread.
- NNR probe budget and domain-controller scope were decided by sampling or by one domain's share,
  leaving other domains unprobed but still counted.
- A port requirement was ranked against the first match rather than the strongest, and a probe of a
  host against itself counted as an open network path.
- Cross-forest trustees and DACL entries were identified by spelling, so one trustee could read as
  two and a DENY stopped subtracting from its ALLOW.
- Reported artefact paths, remote JSON output and coverage figures disagreed with what the run
  actually wrote.

## [1.1.5] - 2026-08-16

Correctness release, and the end of a known blind spot: every function in the script is now named by
the regression suite.

No parameter, report section or JSON field changed, so an existing `-BaselinePath` history and any
`-AsJson` consumer keep working.

### Fixed

- A domain controller whose name parses as a legacy address form - `2019`, `10.1`, an octal or hex
  octet - was keyed as a fabricated IP address instead of its FQDN, splitting one server into two
  half-populated rows and aiming its port probes at an address nobody owns.
- A schema version the lookup table does not name was rendered as `n/a`, discarding a number the run
  had actually read and making a measured version indistinguishable from an unread one.
- Endpoint merging asserted that addresses had been resolved even when the source said they had not,
  which left the caller's DNS-retry path unreachable.

### Added

- The regression suite now covers every function in the script. Each new test was mutation-tested:
  the defect was reintroduced, the test confirmed red, then restored and confirmed green.

## [1.1.4] - 2026-08-16

Correctness release. The same family as 1.1.1 through 1.1.3: a value the run could not read being
presented as a definite answer.

No parameter, report section or JSON field changed, so an existing `-BaselinePath` history and any
`-AsJson` consumer keep working.

### Fixed

- A run that scanned nothing handed a machine a success signal, and the Windows PowerShell 5.1
  re-launch leaked onto the interfaces a machine reads.
- A service state that could not be determined was reported as stopped, a sensor version read short
  became a measured "upgrade the sensor", and a value whose type could not be read counted as
  passing.
- Migration eligibility that was never established was published as a measured "No".
- A domain controller the directory could not name was dropped from the estate rather than counted.
- A required subcategory listed twice turned a correct audit policy into a measured failure.
- Port probes are sent on the address family they are probing, and a port finding names the address
  that actually failed.
- An unread coverage figure in the trend comparison is no longer reported as a coverage of zero.
- Forest discovery reports a partial enumeration as partial, and domain attribution no longer credits
  coverage nobody measured.

### Added

- The regression suite grew to 215 files. Each new test was mutation-tested: the defect was
  reintroduced, the test confirmed red, then restored and confirmed green.
- The published build is now verified by a real scan against a live multi-domain forest before it is
  promoted, in addition to the unit suite and the linter.

## [1.1.3] - 2026-08-15

Correctness release. Same family as 1.1.1 and 1.1.2: a figure the run did not measure being
presented as one that it did.

No parameter, report section or JSON field changed, so an existing `-BaselinePath` history and any
`-AsJson` consumer keep working.

### Fixed

- A baseline file written in another encoding was silently corrupted, permanently, losing the trend
  history it was meant to preserve.
- A server discovered under two spellings was merged into one machine, but the counters still
  charged it twice, so the score was taken over an estate larger than the one that exists.
- A name-resolution target that was never probed disappeared from the report when another host
  shared its first label, and an NNR issue now names the address that actually failed.
- Sizing thresholds are applied to the measurement rather than to a rounded copy of it.
- A path containing a space, an apostrophe or a quote no longer breaks the remote probe, the
  auditpol call or the sensor version check.
- Clock comparisons must agree with each other before a skew is reported.
- The detail merges are pinned as non-mutating, which is what makes the shallow per-role copy of a
  server's details safe.

### Added

- The regression suite grew to 189 files. Each new test was mutation-tested: the defect was
  reintroduced, the test confirmed red, then restored and confirmed green.

## [1.1.2] - 2026-08-15

Correctness release, continuing 1.1.1. Same families of defect: a value that was never read being
presented as a measurement, and a figure quoted over a population it did not cover.

No parameter, report section or JSON field changed, so an existing `-BaselinePath` history and any
`-AsJson` consumer keep working.

### Fixed

- The generated remediation script no longer weakens a setting that already passes. The NTLM
  auditing values were written without reading the current value first, so a domain controller
  configured more strictly than the minimum would have been downgraded by running it.
- Remediation names the correct servers as the source of the network rules it generates, and the
  one destructive command it emits runs once per container.
- The trend chart no longer joins runs that cannot be compared, and the delta pill no longer prints
  a zero it did not measure.
- Unmeasured name resolution, sensor and capacity results are reported as unmeasured rather than as
  failures or absence, and the KPI strip, score card and issue list agree on the same population.
- A capacity sampling budget too large for a 32-bit counter no longer aborts the run.

### Added

- The regression suite grew to 169 files. Each new test was mutation-tested: the defect was
  reintroduced, the test confirmed red, then restored and confirmed green.

## [1.1.1] - 2026-08-14

Correctness release. Roughly 120 defects were found by an automated hunt against the lab forest and
fixed. No parameter, report section or JSON field changed, so an existing `-BaselinePath` history and
any `-AsJson` consumer keep working.

Almost every fix belongs to one family: **the script stated something it had not measured.** The
recurring shapes were an unread value presented as a measured one, a partial scan presented as a
verdict, and one host counted twice.

### Fixed

- A check that could not be read is never reported as a check that failed, in any KPI, chart, table
  or console line. Unmeasured population is carried in the denominator instead of being dropped.
- A scan that stopped part way, or that enumerated no server at all, no longer prints a readiness
  verdict or scores green. It says the scan did not complete and asks for a re-run.
- An area switched off with a `-Skip*` switch is reported as not examined rather than as a failure
  to evaluate.
- One physical server is counted once however its name was spelled where it was discovered, and a
  server that is not ready always appears in the issue list.
- Audit policy is read from the machine's own system policy; a backup containing only per-user
  policy is reported as unreadable rather than mistaken for it.
- The generated remediation script only covers checks that were actually measured, never weakens a
  setting that already passes, and reports a failing command as failed.
- Numeric and locale hardening: a packet rate too large for a 32-bit counter no longer aborts the
  run, and timestamps and parsing no longer depend on the operator's culture.

### Added

- A behavioural regression test suite: 142 files, 3,699 assertions, run against every change. Each
  test was mutation-tested - the defect was reintroduced, the test confirmed red, then restored.
- The report screenshots in `docs/` were regenerated from a current run.

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
