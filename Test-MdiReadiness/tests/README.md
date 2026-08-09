# Tests

397 assertions across 11 suites, plus 14 static rules. They run in seconds, need no lab and no
network, and they exist because each one caught something real.

## Running them

The suites read the script from the same folder, so copy it in first:

```powershell
cd Test-MdiReadiness\tests
Copy-Item ..\Test-MdiReadiness.ps1 .
Get-ChildItem *.Tests.ps1 | ForEach-Object { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $_.FullName }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-Lint.ps1
```

Each suite prints `N passed / M failed` and exits non-zero on failure.

They run under Windows PowerShell 5.1 deliberately, because that is what a domain controller has.

## How they work

Nothing is mocked at the module level. Each suite parses the script with the PowerShell AST, dot-sources
the function definitions and the script-scoped constants, and then calls the real functions with real
data. That means a suite exercises the code that ships, not a re-implementation of it — and it also
means a suite can be wrong in a way that hides a bug, which has happened and is noted below.

## The suites

| Suite | What it protects |
|---|---|
| `Test-Lint.ps1` | 14 AST rules. Rules 7 to 14 were each written the day a bug of that exact shape shipped. |
| `Test-Resilience.Tests.ps1` | Tri-state integrity end to end: an unread check must never render or score as a failed one. |
| `Test-PortProbes.Tests.ps1` | Probe packets against real listeners, the remote probe contract, and the generated remediation script. |
| `Test-PartialFailure.Tests.ps1` | A server that answered and then failed part way keeps its results; a server that never answered contributes none. |
| `Test-MultiHomed.Tests.ps1` | Every address of a multi-homed host is probed, and NNR results are kept apart per address. |
| `Test-IssueList.Tests.ps1` | The verdict, the console count and the report's issue table can never disagree. |
| `Test-MergeRoles.Tests.ps1` | A server holding several roles is counted once without losing any role's checks — and the merge does not mutate what the report renders. |
| `Test-MutationGaps.Tests.ps1` | The seven mutations the suite failed to catch (see below). |
| `Test-Locale.Tests.ps1` | The report renders on it-IT, de-DE, fr-FR and es-ES, where the decimal separator is a comma. |
| `Test-Capacity.Tests.ps1` | Sizing bands, and the full-window-only sampling rule. |
| `Test-Reachability.Tests.ps1` | ICMP is not the only way to decide a server is reachable. |
| `Test-Colour.Tests.ps1` | Console colour never reaches a redirected stream. |

## Mutation testing

Eighteen realistic bugs were introduced into the script one at a time, and the whole suite was run
against each. Eleven were caught. The seven that were not are the reason `Test-MutationGaps.Tests.ps1`
exists — a mutation the tests do not catch is a bug that reaches the customer.

Two of those seven were not hypothetical. They were live defects in fixes made the same day:

- The trend chart's comparability guard used `@($previous.CheckNames).Count -gt 0` to decide whether a
  baseline entry carried a fingerprint. `@($null).Count` is **1**, not 0, so an entry with no
  fingerprint reported as having one — and the guard drew the confident percentage-point arrow it
  existed to prevent.
- Two functions returned through the comma operator (`, $targets`). That preserves array identity for
  a single result but turns an **empty** result into one element that *is* the empty array, so a caller
  writing `@(Resolve-...)` counted one target where there were none.

`Test-MergeRoles.Tests.ps1` has its own lesson. Its first version built the `Details` fixture as a
`PSCustomObject` and passed — while the merge was completely broken for the type the script actually
uses. `Details` is an ordered hashtable, and on one of those `PSObject.Copy()` returns *the same
object* and `PSObject.Properties` enumerates `Count`, `Keys` and `Values` rather than the entries. A
fixture that does not match reality is not a test.

## Adding a test

Assert on behaviour, not on source text. Several assertions here match the script with a regular
expression, and every one of them is a compromise made because the function is too coupled to WMI or
to a live directory to call in a harness — they are marked as such. A structural assertion passes when
the fix is present and the behaviour is still wrong.

State what the wrong answer would have been. The assertion name should say what a user would have
seen, not which line changed.
