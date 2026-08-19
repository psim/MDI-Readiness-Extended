<#
    THE CLOCK SPREAD MUST BE JUDGED BY THE STRICTEST TOLERANCE RECORDED, NOT THE LOOSEST.

    Get-mdiClockSpread answers the only prerequisite MDI actually states about clocks - that the
    sensor servers be within five minutes OF EACH OTHER - and three surfaces take its answer: the
    time synchronization card (Get-mdiTimeSyncHtml), the issue list (Get-mdiIssueList) and the READY
    verdict (Test-mdiReadinessResult, "so the run cannot be reported as ready").

    It does not restate the tolerance. Get-mdiTimeSync stamps MaxSkewMinutes onto every measurement
    it takes, deliberately, so that "a report read back later is still judged against the tolerance
    it was taken under" - and Get-mdiClockSpread reads it back off the rows. When the rows disagree
    it has to choose one, and it chose with:

        if ($reported.Count -gt 0) { $tolerance = ($reported | Measure-Object -Maximum).Maximum }

    directly underneath a comment stating the opposite rule:

        # The tolerance each measurement was taken under, not a restated constant. The largest is
        # used when they differ, so a stricter run cannot be judged by a looser one's threshold by
        # accident.

    MAXIMUM IS THE LOOSEST THRESHOLD. The comment describes -Minimum; the line implemented -Maximum,
    which is precisely "a stricter run judged by a looser one's threshold" - the thing the comment
    says must not happen. The safe rule was written down and its inverse was shipped.

    Measured on the shipped function, the extended lab's three sites with the clocks 8 minutes apart:
    dc2022 in HQ-Site at -240s, dc3 in EMEA-Site at 0s, and dcfab01 across the fabrikam.local trust
    at +240s. That is a 480 second spread, which FAILS the five-minute requirement:

        every row records 5      tolerance 5      spread 480   IsWithin False   <- correct
        ONE row records 60       tolerance 60     spread 480   IsWithin TRUE    <- FALSE GREEN
        ONE row records 1440     tolerance 1440   spread 480   IsWithin TRUE    <- FALSE GREEN

    and in the other direction, a 160 second spread with one row recording a 1-minute tolerance:

        ONE row records 1        tolerance 5      spread 160   IsWithin TRUE    <- strictest DISCARDED
        ONE row records 2        tolerance 5      spread 160   IsWithin TRUE    <- strictest DISCARDED

    A single unrelated row carrying a looser number therefore certified an estate that violates the
    requirement, and the card rendered the sentence "inside the 60 minute(s) MDI requires between
    sensor servers" - a five-minute requirement restated as sixty by the report whose job is to quote
    it.

    SCOPE, stated no more strongly than it was measured, the same way Get-mdiProbeTargetKey states
    its own: one run stamps a single -MaxClockSkewMinutes on every row through Get-mdiTimeSync, so a
    stock single-run report cannot hold two different tolerances and this was not a live false green
    in that pipeline. It is the rule itself being backwards on the one line that decides it, on a
    field whose entire purpose is to be re-read after the run that produced it.

    WHAT MAKES THIS CLEAR-CUT rather than a judgement call: the code's own comment names the correct
    behaviour, so no interpretation is needed to say which of the two is wrong. And the conservative
    direction is not in doubt anywhere else in this file - an unread check is not a pass, an
    unexamined domain is not an examined one, and a clock spread nobody may judge is returned 'N/A'
    rather than zero eleven lines below.

    These assertions drive the REAL Get-mdiClockSpread, and the last block drives the REAL renderer
    and verdict so that the three surfaces cannot drift apart from the function they share.
#>

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Test-MdiReadiness.ps1 not found from $here" }
$text = Get-Content -LiteralPath $target -Raw

$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main'); if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

function New-Clock {
    param(
        [string] $Fqdn,
        [object] $Skew,
        [object] $Tol = 5,
        [switch] $NoTolerance
    )
    $sync = [ordered]@{
        SkewSeconds  = $Skew
        RemoteUtc    = '2026-08-19 08:00:00'
        ReferenceUtc = '2026-08-19 08:00:00'
        Detail       = 'Compared with the local clock'
    }
    if (-not $NoTolerance) { $sync['MaxSkewMinutes'] = $Tol }
    [PSCustomObject]@{
        FQDN     = $Fqdn
        TimeSync = $true
        Details  = [PSCustomObject]@{ TimeSyncDetails = [PSCustomObject] $sync }
    }
}

# The extended lab: HQ-Site, EMEA-Site and across the fabrikam.local trust. 480 seconds apart, which
# is 8 minutes and therefore OUTSIDE the five-minute requirement. Note that every one of these three
# clocks is within five minutes of the SCANNER - +/-4 minutes - which is the false green
# Get-mdiClockSpread was written to catch in the first place.
function Get-EightMinuteEstate {
    param([object] $FabTol = 5, [object] $HqTol = 5, [object] $EmeaTol = 5)
    @(
        (New-Clock -Fqdn 'dc2022.mdilab.local'    -Skew -240 -Tol $HqTol)
        (New-Clock -Fqdn 'dc3.emea.mdilab.local'  -Skew 0    -Tol $EmeaTol)
        (New-Clock -Fqdn 'dcfab01.fabrikam.local' -Skew 240  -Tol $FabTol)
    )
}

Write-Host 'Clock spread: the strictest recorded tolerance is the one that judges the estate' -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------------
# THE BASELINE. Every row agrees on 5, which is every stock single-run report, and the answer must be
# exactly what it always was. A fix that changed this would have broken the ordinary case.
# ---------------------------------------------------------------------------------------------------
$base = Get-mdiClockSpread -Server (Get-EightMinuteEstate)
Assert-That 'the uniform estate still measures three clocks' ($base.Measured -eq 3) ("measured={0}" -f $base.Measured)
Assert-That 'the uniform estate still spans 480 seconds' ($base.SpreadSeconds -eq 480) ("spread={0}" -f $base.SpreadSeconds)
Assert-That 'the uniform estate is still judged at 5 minutes' ($base.MaxSkewMinutes -eq 5) ("tolerance={0}" -f $base.MaxSkewMinutes)
Assert-That 'the uniform estate is still outside tolerance' ($base.IsWithin -eq $false) ("IsWithin={0}" -f $base.IsWithin)

# ---------------------------------------------------------------------------------------------------
# THE DEFECT. One row carrying a LOOSER tolerance must not certify an estate that fails the strict
# one. Every row position is exercised: the defect was in the aggregate, so it did not matter which
# row carried the loose value, and a test that only ever loosened the last row would pin less than
# it appears to.
# ---------------------------------------------------------------------------------------------------
foreach ($loose in 6, 9, 60, 120, 1440) {
    foreach ($where in 'the cross-forest row', 'the HQ-Site row', 'the EMEA-Site row') {
        $estate = switch ($where) {
            'the cross-forest row' { Get-EightMinuteEstate -FabTol $loose }
            'the HQ-Site row' { Get-EightMinuteEstate -HqTol $loose }
            'the EMEA-Site row' { Get-EightMinuteEstate -EmeaTol $loose }
        }
        $r = Get-mdiClockSpread -Server $estate
        Assert-That ("{0} recording {1} minutes does not raise the tolerance above 5" -f $where, $loose) `
        ($r.MaxSkewMinutes -eq 5) ("tolerance={0}" -f $r.MaxSkewMinutes)
        Assert-That ("{0} recording {1} minutes does not certify an 8-minute spread" -f $where, $loose) `
        ($r.IsWithin -eq $false) ("IsWithin={0} tolerance={1}" -f $r.IsWithin, $r.MaxSkewMinutes)
        # The spread itself is a separate fact and must be untouched by any of this.
        Assert-That ("{0} recording {1} minutes leaves the spread at 480s" -f $where, $loose) `
        ($r.SpreadSeconds -eq 480) ("spread={0}" -f $r.SpreadSeconds)
    }
}

# ---------------------------------------------------------------------------------------------------
# THE OTHER DIRECTION, which is the half the old comment claimed to be protecting. A STRICTER row must
# be honoured. 160 seconds is inside five minutes and outside one and two, so only a tolerance that
# actually took the strictest value can call it a failure.
# ---------------------------------------------------------------------------------------------------
function Get-OneHundredSixtySecondEstate {
    param([object] $FabTol)
    @(
        (New-Clock -Fqdn 'dc2022.mdilab.local'    -Skew -30 -Tol 5)
        (New-Clock -Fqdn 'dc3.emea.mdilab.local'  -Skew 0   -Tol 5)
        (New-Clock -Fqdn 'dcfab01.fabrikam.local' -Skew 130 -Tol $FabTol)
    )
}
foreach ($strict in 1, 2) {
    $r = Get-mdiClockSpread -Server (Get-OneHundredSixtySecondEstate -FabTol $strict)
    Assert-That ("a row recording {0} minute(s) sets the tolerance to {0}" -f $strict) `
    ($r.MaxSkewMinutes -eq $strict) ("tolerance={0}" -f $r.MaxSkewMinutes)
    Assert-That ("a 160s spread fails the {0}-minute tolerance somebody recorded" -f $strict) `
    ($r.IsWithin -eq $false) ("IsWithin={0} tolerance={1}" -f $r.IsWithin, $r.MaxSkewMinutes)
}
# 3 minutes is 180s, which a 160s spread is INSIDE. The strictest-wins rule must not turn into
# "always fail": a genuinely compliant estate stays compliant.
$rOk = Get-mdiClockSpread -Server (Get-OneHundredSixtySecondEstate -FabTol 3)
Assert-That 'a 160s spread passes a 3-minute tolerance' ($rOk.IsWithin -eq $true) ("IsWithin={0}" -f $rOk.IsWithin)
Assert-That 'a 160s spread under 3 minutes reports the 3-minute tolerance' ($rOk.MaxSkewMinutes -eq 3) ("tolerance={0}" -f $rOk.MaxSkewMinutes)

# ---------------------------------------------------------------------------------------------------
# AN UNREADABLE TOLERANCE IS NOT A TOLERANCE. It must neither raise nor lower the threshold: the
# documented default stands, and the shapes below are the ones a JSON round trip, a hand-edited
# report and Get-mdiTimeSync's own catch branch actually produce. This half was already correct and is
# pinned so that a future change to the aggregate cannot quietly let one of them through.
# ---------------------------------------------------------------------------------------------------
foreach ($case in @(
        @{ L = '$null'; V = $null }
        @{ L = 'the empty string'; V = '' }
        @{ L = 'whitespace'; V = '   ' }
        @{ L = 'the word "N/A"'; V = 'N/A' }
        @{ L = 'the word "unknown"'; V = 'unknown' }
        @{ L = 'boolean $true'; V = $true }
        @{ L = 'boolean $false'; V = $false }
        @{ L = 'a hashtable'; V = @{} }
        @{ L = 'an empty array'; V = @() }
        @{ L = 'zero'; V = 0 }
        @{ L = 'a negative number'; V = -5 }
        @{ L = 'a value beyond Int32'; V = 3000000000 }
        @{ L = 'a double 60.9'; V = 60.9 }
    )) {
    $r = Get-mdiClockSpread -Server (Get-EightMinuteEstate -FabTol $case.V)
    Assert-That ("an unreadable tolerance of {0} leaves the documented 5 minutes in force" -f $case.L) `
    ($r.MaxSkewMinutes -eq 5) ("tolerance={0}" -f $r.MaxSkewMinutes)
    Assert-That ("an unreadable tolerance of {0} does not certify an 8-minute spread" -f $case.L) `
    ($r.IsWithin -eq $false) ("IsWithin={0}" -f $r.IsWithin)
}

# A READABLE tolerance written in a shape a round trip produces is still read, in BOTH directions, or
# the fix would have thrown away the operator's own -MaxClockSkewMinutes.
foreach ($case in @(
        @{ L = 'the string "2"'; V = '2'; Expect = 2 }
        @{ L = 'the padded string " 2 "'; V = ' 2 '; Expect = 2 }
        @{ L = 'a one-element array @(2)'; V = @(2); Expect = 2 }
    )) {
    $r = Get-mdiClockSpread -Server (Get-OneHundredSixtySecondEstate -FabTol $case.V)
    Assert-That ("a strict tolerance written as {0} is still read" -f $case.L) `
    ($r.MaxSkewMinutes -eq $case.Expect) ("tolerance={0}" -f $r.MaxSkewMinutes)
}

# ---------------------------------------------------------------------------------------------------
# THE ABSENT FIELD. Get-mdiTimeSync's catch branch emits TimeSyncDetails with no MaxSkewMinutes at
# all, and a server reached across a forest trust - where remote WMI is routinely refused - is
# exactly the row that carries it. A report predating the field carries it on no row. Neither may
# change the threshold the readable rows recorded.
# ---------------------------------------------------------------------------------------------------
$partial = Get-mdiClockSpread -Server @(
    (New-Clock -Fqdn 'dc2022.mdilab.local'    -Skew -30 -Tol 2)
    (New-Clock -Fqdn 'dc3.emea.mdilab.local'  -Skew 0   -Tol 2)
    (New-Clock -Fqdn 'dcfab01.fabrikam.local' -Skew 130 -NoTolerance)
)
Assert-That 'a row with no MaxSkewMinutes does not relax the 2-minute tolerance the others recorded' `
($partial.MaxSkewMinutes -eq 2) ("tolerance={0}" -f $partial.MaxSkewMinutes)
Assert-That 'a row with no MaxSkewMinutes does not certify a 160s spread under 2 minutes' `
($partial.IsWithin -eq $false) ("IsWithin={0}" -f $partial.IsWithin)

$noField = Get-mdiClockSpread -Server @(
    (New-Clock -Fqdn 'dc2022.mdilab.local'    -Skew -240 -NoTolerance)
    (New-Clock -Fqdn 'dc3.emea.mdilab.local'  -Skew 0    -NoTolerance)
    (New-Clock -Fqdn 'dcfab01.fabrikam.local' -Skew 240  -NoTolerance)
)
Assert-That 'a report predating MaxSkewMinutes falls back to the documented 5 minutes' `
($noField.MaxSkewMinutes -eq 5) ("tolerance={0}" -f $noField.MaxSkewMinutes)
Assert-That 'a report predating MaxSkewMinutes still fails an 8-minute spread' `
($noField.IsWithin -eq $false) ("IsWithin={0}" -f $noField.IsWithin)

# Fewer than two measured clocks is still 'N/A', never a zero spread that reads as agreement.
$single = Get-mdiClockSpread -Server @((New-Clock -Fqdn 'dc2022.mdilab.local' -Skew 0 -Tol 60))
Assert-That 'one clock is still unmeasurable rather than a zero spread' `
(([string] $single.IsWithin -eq 'N/A') -and ($null -eq $single.SpreadSeconds)) ("IsWithin={0} spread={1}" -f $single.IsWithin, $single.SpreadSeconds)

# ---------------------------------------------------------------------------------------------------
# THE THREE CONSUMERS. The card, the issue list and the verdict all take this one answer, so the
# defect was never confined to the function - it certified the estate on every surface at once. These
# drive the real renderer and the real verdict.
# ---------------------------------------------------------------------------------------------------
$looseEstate = Get-EightMinuteEstate -FabTol 60
$html = (Get-mdiTimeSyncHtml -Server $looseEstate) -join "`n"
Assert-That 'the card does not tell the reader MDI requires 60 minutes between sensor servers' `
($html -notmatch '60 minute\(s\) MDI requires') $html
Assert-That 'the card reports the 8-minute spread as outside tolerance' `
($html -match 'which is MORE than the 5 minute\(s\) MDI requires')

$report = [PSCustomObject]@{
    Domain              = 'mdilab.local'
    DomainControllers   = $looseEstate
    CAServers           = @()
    EntraConnectServers = @()
}
$stats = Get-mdiReportStatistics -ReportData $report
$issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report)
Assert-That 'the issue list raises the clock spread even though one row recorded 60 minutes' `
(@($issues | Where-Object { [string] $_.Area -eq 'Time sync' -and [string] $_.Issue -match 'span 480 second' }).Count -ge 1) `
    (($issues | ForEach-Object { $_.Issue }) -join ' | ')

Assert-That 'the verdict refuses READY over an 8-minute spread one row tried to excuse' `
((Test-mdiReadinessResult -ReportData @($report)) -ne $true)

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) `
    -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $(if ($script:fail) { 1 } else { 0 })
