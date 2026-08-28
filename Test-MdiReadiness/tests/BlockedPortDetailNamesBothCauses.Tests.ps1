<#
    [1366] "Blocked" on the double-timeout path named ONE of two equally likely causes.

    Test-mdiTcpPort retries a silent port once with a much longer budget and, if it is still silent,
    reports:

        Blocked - no response within 1500 ms, retried for 5000 ms (consistent with a firewall
        dropping the traffic)

    The comment above that path conditions the reading on "while the host itself is reachable" - but
    the function performs no reachability check, and the port-probe dispatch calls it per target
    without gating on Test-mdiServerReachable. So an unroutable host - a controller across a dead
    site link - produces one "Blocked" row per required port, each naming a firewall.

    Over TCP a DROP rule and an unreachable host are genuinely indistinguishable: silence is all
    either produces. The wording already hedged with "consistent with" rather than asserting, so this
    is not a false measurement - it is an incomplete one, and it points the operator at the expensive
    remedy. A change request to open a port that was never shut is the outcome this file goes to some
    length elsewhere to avoid, and the DNS branch of this same function already names its own
    ambiguity explicitly rather than leaving it implied.

    WHAT IS PINNED:
      * the detail names BOTH causes, not just the firewall;
      * it still says which budgets were spent, which an earlier fix put there deliberately;
      * the leading 'Blocked - ' token is UNCHANGED. The report's filters and the issue wording key
        on it, so a fix to a sentence must not move a real finding out of the reader's view.

    Asserted against the SOURCE rather than by forcing a real double timeout, which would need two
    live socket waits and would be slow and flaky in a suite. The same technique is already used in
    this tree to pin call-site rules.
#>

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path -LiteralPath $target)) {
    $parent = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
    if (Test-Path -LiteralPath $parent) { $target = $parent }
}
if (-not (Test-Path -LiteralPath $target)) {
    $staged = Join-Path (Split-Path (Split-Path $here -Parent) -Parent) 'MDI-Repo\Test-MdiReadiness\Test-MdiReadiness.ps1'
    if (Test-Path -LiteralPath $staged) { $target = $staged }
}
if (-not (Test-Path -LiteralPath $target)) { Write-Host 'FAIL  the product script could not be located'; exit 1 }
$source = Get-Content -LiteralPath $target -Raw

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

# The one line that builds the double-timeout detail in Test-mdiTcpPort. Selected by excluding the
# UDP sibling, which carries its own wording ("filtered by a firewall or no service listening") for a
# different ambiguity, and the comment that quotes the string.
$line = @($source -split "`r?`n" | Where-Object {
        $_ -match "Blocked - no response within" -and
        $_ -notmatch 'no service listening' -and
        $_.Trim() -notmatch '^#'
    })
"`n[1] the TCP blocked-detail line exists exactly once"
Assert-That 'exactly one TCP blocked-detail string in the product' ($line.Count -eq 1) "(found $($line.Count))"
if ($line.Count -ne 1) { "pass=$script:pass fail=$script:fail"; exit 1 }
$detail = $line[0]

"`n[2] THE DEFECT - both causes are named, not just the firewall"
Assert-That 'it still names a firewall dropping the traffic' ($detail -match 'firewall') "($detail)"
Assert-That 'it ALSO names the host not being reachable' `
($detail -match 'unreachable|not being reachable|not reachable') "($detail)"
Assert-That '  ...and says the two are indistinguishable over TCP rather than implying it' `
($detail -match 'identical|indistinguishable') "($detail)"

"`n[3] WHAT MUST NOT MOVE"
Assert-That "the leading 'Blocked - ' token the report's filters key on is unchanged" `
($detail -match "'Blocked - no response within \{0\}") "($detail)"
Assert-That 'both budgets are still disclosed' `
($source -match "retried for \{1\} ms" -and $source -match "\{0\} ms, retried") ''

"`n[4] the sibling paths are untouched"
Assert-That "the closed-port path still says 'Closed - connection refused'" `
($source -match "Closed - connection refused") ''
Assert-That "the slow-but-open path still discloses the first timeout" `
($source -match "Connected on the second attempt") ''
Assert-That "an unresolvable name is still 'Not tested', not blocked" `
($source -match "Not tested - ") ''

""
"pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
