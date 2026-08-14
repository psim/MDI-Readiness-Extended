<#
    The trend pill must point the way the estate actually moved.

    Baseline history is APPEND-ordered, which is chronological right up until it is not: a hand merge,
    a restored backup, two hosts writing the same share, or a clock that stepped backwards all produce
    a file whose order is not time order. Get-mdiChronologicalRun exists to repair that - but it
    recognised only the 's' round-trip format that this script itself writes, and discarded everything
    else as undated. When EVERY entry was discarded it fell back to the file's append order, which is
    precisely the order that cannot be trusted.

    Measured on the shipped code, all three of these parse perfectly well as dates and were dropped
    anyway, so an estate that had FALLEN 60 points rendered a green "up 60 pt":
        '10/1/2026 00:00:00'        vs '9/1/2026 00:00:00'
        '2026-10-01'                vs '2026-9-01'          (single-digit month)
        '2026-09-01T12:00:00+02:00' vs '2026-09-01T09:30:00+00:00'

    The charter records that a trend test once stayed green while the pill reported "no change" under a
    line that had fallen 64 points, because the test never called the chart function at all. These
    tests therefore assert the RENDERED pill produced by the real New-mdiTrendChart, not the sort
    order in isolation, and never inspect the script's source text.
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

function New-Run {
    param([string] $Stamp, [int] $Passed, [int] $Total)
    # CheckNames/ServerNames are the comparison fingerprint: without them the pill correctly refuses
    # to draw a delta at all, and the test would prove nothing about direction.
    [PSCustomObject]@{
        Timestamp    = $Stamp
        ChecksPassed = $Passed
        ChecksTotal  = $Total
        ChecksUnread = 0
        CheckNames   = @('Advanced auditing', 'NTLM auditing', 'Time sync')
        ServerNames  = @('dc1.contoso.com', 'dc2.contoso.com')
        ScriptVersion = '1.1.0'
    }
}
# Two runs: an OLDER one scoring 80% and a NEWER one scoring 20%. Whatever order they are recorded
# in, the estate has fallen 60 points and the pill must say so.
function Get-Pill {
    param([string] $NewerStamp, [string] $OlderStamp, [switch] $NewerFirst)
    $newer = New-Run -Stamp $NewerStamp -Passed 20 -Total 100
    $older = New-Run -Stamp $OlderStamp -Passed 80 -Total 100
    $runs = if ($NewerFirst) { @($newer, $older) } else { @($older, $newer) }
    New-mdiTrendChart -History $runs
}

Write-Host 'A fall is rendered as a fall whatever order the file records it in' -ForegroundColor Cyan
# The canonical format is the control: this already worked and must keep working.
$canonical = Get-Pill -NewerStamp '2026-10-01T00:00:00' -OlderStamp '2026-09-01T00:00:00' -NewerFirst
Assert-That 'canonical "s" timestamps recorded newest-first still report a FALL' ($canonical -match '-60 pt') "got: $canonical"
Assert-That '  ...and the pill is styled as bad' ($canonical -match 'class="[^"]*bad') "got: $canonical"

$cases = @(
    @{ Name = 'US-style date and time'; Newer = '10/1/2026 00:00:00'; Older = '9/1/2026 00:00:00' }
    @{ Name = 'single-digit month vs two-digit month'; Newer = '2026-10-01'; Older = '2026-9-01' }
    @{ Name = 'UTC offsets that invert the wall-clock order'; Newer = '2026-09-01T12:00:00+02:00'; Older = '2026-09-01T09:30:00+00:00' }
    @{ Name = 'a date-only value against a full timestamp'; Newer = '2026-10-01'; Older = '2026-09-01T00:00:00' }
    # The DST fall-back hour is the case that proves the timestamps must be normalised to UTC rather
    # than to local wall clock. 00:30Z and 02:30+01:00 (= 01:30Z) are an hour apart, but BOTH render
    # as local 02:30 in a +01:00/+02:00 zone on the changeover day. Compared as local wall clock they
    # tie, the tie-break falls back to position in the file - which is exactly the order this function
    # exists to repair - and the pill reports the fall as a rise.
    @{ Name = 'two instants inside the DST fall-back hour'; Newer = '2026-10-25T02:30:00+01:00'; Older = '2026-10-25T00:30:00+00:00' }
)
foreach ($c in $cases) {
    # Recorded NEWEST FIRST, i.e. the file order is wrong and must be repaired.
    $pill = Get-Pill -NewerStamp $c.Newer -OlderStamp $c.Older -NewerFirst
    Assert-That "$($c.Name): a 60-point fall reports a FALL" ($pill -match '-60 pt') "got: $pill"
    Assert-That "  ...and never reports a rise" ($pill -notmatch '&uarr;') "got: $pill"

    # Recorded oldest first, i.e. the file order is already right. Same answer.
    $pill2 = Get-Pill -NewerStamp $c.Newer -OlderStamp $c.Older
    Assert-That "  ...and the same two runs recorded in time order agree" ($pill2 -match '-60 pt') "got: $pill2"
}

Write-Host 'A rise is still a rise - the fix must not simply invert every delta' -ForegroundColor Cyan
$risingNewer = New-Run -Stamp '10/1/2026 00:00:00' -Passed 90 -Total 100
$risingOlder = New-Run -Stamp '9/1/2026 00:00:00' -Passed 30 -Total 100
$rise = New-mdiTrendChart -History @($risingNewer, $risingOlder)
Assert-That 'a genuine 60-point rise reports a RISE' ($rise -match '60 pt' -and $rise -notmatch '-60 pt') "got: $rise"
Assert-That '  ...and is not styled as bad' ($rise -notmatch 'class="[^"]*bad') "got: $rise"

Write-Host 'Get-mdiRunTimestamp orders by the instant, not by the wall-clock text' -ForegroundColor Cyan
$utcEarly = Get-mdiRunTimestamp '2026-09-01T09:30:00+00:00'
$utcLate = Get-mdiRunTimestamp '2026-09-01T12:00:00+02:00'
Assert-That 'an offset-bearing timestamp parses at all' ($null -ne $utcEarly) 'got $null'
Assert-That '  ...and 09:30Z is earlier than 12:00+02:00 (= 10:00Z)' ($utcEarly -lt $utcLate) "got $utcEarly vs $utcLate"
# Two spellings of the same instant must compare equal, so record order breaks the tie rather than
# the timestamps swapping places on every render.
Assert-That 'the same instant written two ways compares equal' `
((Get-mdiRunTimestamp '2026-09-01T12:00:00+02:00') -eq (Get-mdiRunTimestamp '2026-09-01T10:00:00+00:00')) `
    "got $(Get-mdiRunTimestamp '2026-09-01T12:00:00+02:00') vs $(Get-mdiRunTimestamp '2026-09-01T10:00:00+00:00')"

# Two DISTINCT instants inside the DST fall-back hour share one local wall-clock reading, so they
# must not compare equal. Parsed to local rather than to UTC they do, and the ordering is lost.
$dstEarly = Get-mdiRunTimestamp '2026-10-25T00:30:00+00:00'
$dstLate = Get-mdiRunTimestamp '2026-10-25T02:30:00+01:00'
Assert-That 'two instants in the DST fall-back hour are not equal' ($dstEarly -ne $dstLate) "got $dstEarly vs $dstLate"
Assert-That '  ...and 00:30Z sorts before 01:30Z' ($dstEarly -lt $dstLate) "got $dstEarly vs $dstLate"

Write-Host 'A value that is not a timestamp is still rejected' -ForegroundColor Cyan
foreach ($bad in @($null, '', '   ', 'N/A', 'Unknown', 'not-a-date', 'never')) {
    $shown = if ($null -eq $bad) { '<null>' } else { "'$bad'" }
    Assert-That "  $shown is not a timestamp" ($null -eq (Get-mdiRunTimestamp $bad)) "got '$(Get-mdiRunTimestamp $bad)'"
}

Write-Host 'An undated entry never becomes the run the delta is measured against' -ForegroundColor Cyan
# A junk entry in the middle previously reordered every real run around it.
$mixed = @(
    New-Run -Stamp '2026-10-01T00:00:00' -Passed 20 -Total 100
    New-Run -Stamp $null -Passed 55 -Total 100
    New-Run -Stamp 'N/A' -Passed 55 -Total 100
    New-Run -Stamp '2026-09-01T00:00:00' -Passed 80 -Total 100
)
$mixedPill = New-mdiTrendChart -History $mixed
Assert-That 'two real runs around two junk entries still report the FALL' ($mixedPill -match '-60 pt') "got: $mixedPill"
Assert-That '  ...and the undated entries are not silently counted as plotted' ($mixedPill -match '2 of 4') "got: $mixedPill"

Write-Host 'Chronological ordering is by time, not by position in the file' -ForegroundColor Cyan
$ordered = @(Get-mdiChronologicalRun -Run @(
        New-Run -Stamp '10/1/2026 00:00:00' -Passed 20 -Total 100
        New-Run -Stamp '9/1/2026 00:00:00' -Passed 80 -Total 100
    ))
Assert-That 'the older run is returned first' ($ordered[0].ChecksPassed -eq 80) "got $($ordered[0].ChecksPassed)"
Assert-That '  ...and the newer run last' ($ordered[-1].ChecksPassed -eq 20) "got $($ordered[-1].ChecksPassed)"
Assert-That '  ...and no run is dropped' ($ordered.Count -eq 2) "got $($ordered.Count)"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
