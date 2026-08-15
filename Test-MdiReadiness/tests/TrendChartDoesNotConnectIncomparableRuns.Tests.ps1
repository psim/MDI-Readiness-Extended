<#
    THE CHART DREW A LINE BETWEEN TWO RUNS THE PILL REFUSED TO COMPARE.

    New-mdiTrendChart renders a history of coverage percentages and, underneath it, a pill giving
    the delta between the last two runs. The pill has a careful comparability guard: if the server
    set, the check set, the covered population, the scanner version or the estate itself changed
    between those two runs, it declines to state a delta and says why.

    The chart above it never consulted that guard. Measured on the shipped renderer, an
    incomparable pair and a comparable pair produced byte-for-byte identical geometry:

        incomparable (server set changed) : polyline=1 polygon=1
        comparable                        : polyline=1 polygon=1

    so the line sloped from 20% to 90% directly above a sentence reading "Not comparable with the
    previous run - the set of servers changed". A reader takes the shape of a line as the finding;
    the pill is the small print. That is the "two surfaces of the same fact disagreeing" class, and
    this exact control has produced it before - a pill reading "no change" under a line that had
    fallen 64 points.

    A second, quieter half: the comparability test only ever ran on the LAST TWO points, so an
    estate change earlier in the history was drawn straight through with no guard at all.

    The fix extracts one shared predicate, Test-mdiTrendPointsComparable, consulted by the pill AND
    by every adjacent pair, and breaks the polyline and its fill wherever a pair is not comparable.

    THE DOTS MUST STAY. Every recorded run is a real measurement and belongs on the chart; it is
    only the JOIN between two of them that asserts a movement. A "fix" that dropped the
    incomparable runs from the chart would hide the very discontinuity the operator needs to see,
    so the dot count is asserted as carefully as the line count.

    Behavioural: every assertion calls the shipped New-mdiTrendChart and counts what it actually
    rendered.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

function New-TrendPoint {
    param($Stamp, $Total, $Passed, $Unread = 0, $Ver = '3.0.0',
        $Servers = @('S1'), $Checks = @('C1'), $Dom = 'contoso.com', $Forest = 'contoso.com')
    [PSCustomObject]@{
        Timestamp = $Stamp; ChecksTotal = $Total; ChecksPassed = $Passed; ChecksUnread = $Unread
        ScriptVersion = $Ver; Domain = $Dom; Forest = $Forest
        CheckNames = $Checks; ServerNames = $Servers
    }
}
function Measure-Chart {
    param($History)
    $svg = [string]((New-mdiTrendChart -History $History) -join '')
    $pill = [regex]::Match($svg, '<span class="pill ([^"]*)">(.*?)</span>')
    [PSCustomObject]@{
        Polyline = ([regex]::Matches($svg, '<polyline')).Count
        Polygon  = ([regex]::Matches($svg, '<polygon')).Count
        Circle   = ([regex]::Matches($svg, '<circle')).Count
        PillText = $(if ($pill.Success) { $pill.Groups[2].Value } else { '' })
        Svg      = $svg
    }
}

# Every "incomparable" reason the predicate knows about. Each must break the line, not just the
# server-set one that happened to be found first.
$reasons = @(
    @{ N = 'the server set changed'; P = (New-TrendPoint '2026-08-13T10:00:00Z' 100 20 0 '3.0.0' @('S1'))
        C = (New-TrendPoint '2026-08-14T10:00:00Z' 100 90 0 '3.0.0' @('S1', 'S2')) }
    @{ N = 'the check set changed'; P = (New-TrendPoint '2026-08-13T10:00:00Z' 100 20 0 '3.0.0' @('S1') @('C1'))
        C = (New-TrendPoint '2026-08-14T10:00:00Z' 100 90 0 '3.0.0' @('S1') @('C1', 'C2')) }
    @{ N = 'the scanner version changed'; P = (New-TrendPoint '2026-08-13T10:00:00Z' 100 20 0 '2.1.0')
        C = (New-TrendPoint '2026-08-14T10:00:00Z' 100 90 0 '3.0.0') }
    @{ N = 'the covered population changed'; P = (New-TrendPoint '2026-08-13T10:00:00Z' 100 20 0)
        C = (New-TrendPoint '2026-08-14T10:00:00Z' 50 45 0) }
    @{ N = 'the estate changed (different forest)'
        P = (New-TrendPoint '2026-08-13T10:00:00Z' 100 20 0 '3.0.0' @('S1') @('C1') 'contoso.com' 'contoso.com')
        C = (New-TrendPoint '2026-08-14T10:00:00Z' 100 90 0 '3.0.0' @('S1') @('C1') 'contoso.com' 'fabrikam.com') }
)

Write-Host 'An incomparable pair must not be joined by a line' -ForegroundColor Cyan
foreach ($r in $reasons) {
    $m = Measure-Chart @($r.P, $r.C)
    Assert-That "$($r.N): the pill refuses to compare" (
        $m.PillText -like 'Not comparable*') "pill='$($m.PillText)'"
    Assert-That "$($r.N): no connecting line is drawn" ($m.Polyline -eq 0) "polyline=$($m.Polyline)"
    Assert-That "$($r.N): no filled area is drawn either" ($m.Polygon -eq 0) "polygon=$($m.Polygon)"
    # The runs themselves are real measurements and must remain visible.
    Assert-That "$($r.N): both runs are still plotted as points" ($m.Circle -eq 2) "circle=$($m.Circle)"
}

Write-Host ''
Write-Host 'CONTROL - a comparable pair must still be joined exactly as before' -ForegroundColor Cyan
$ok = Measure-Chart @(
    (New-TrendPoint '2026-08-13T10:00:00Z' 100 20),
    (New-TrendPoint '2026-08-14T10:00:00Z' 100 90)
)
Assert-That 'CONTROL: the pill states a delta' ($ok.PillText -like '*pt vs previous run*') "pill='$($ok.PillText)'"
Assert-That 'CONTROL: the line is drawn' ($ok.Polyline -eq 1) "polyline=$($ok.Polyline)"
Assert-That 'CONTROL: the fill is drawn' ($ok.Polygon -eq 1) "polygon=$($ok.Polygon)"
Assert-That 'CONTROL: both runs are plotted' ($ok.Circle -eq 2) "circle=$($ok.Circle)"

Write-Host ''
Write-Host 'Comparability must be judged for EVERY adjacent pair, not only the last two' -ForegroundColor Cyan
# Three runs. The break is between the FIRST and SECOND - the pair the old code never looked at.
# The last pair IS comparable, so the pill states a delta while the chart must still show the gap.
$midBreak = Measure-Chart @(
    (New-TrendPoint '2026-08-12T10:00:00Z' 100 20 0 '2.1.0'),
    (New-TrendPoint '2026-08-13T10:00:00Z' 100 60 0 '3.0.0'),
    (New-TrendPoint '2026-08-14T10:00:00Z' 100 90 0 '3.0.0')
)
Assert-That 'the last pair is comparable, so a delta is stated' (
    $midBreak.PillText -like '*pt vs previous run*') "pill='$($midBreak.PillText)'"
Assert-That 'all three runs are plotted' ($midBreak.Circle -eq 3) "circle=$($midBreak.Circle)"
# Only the comparable 2-point tail may be joined; the isolated first run must not be connected.
Assert-That 'the line is broken at the incomparable pair' ($midBreak.Polyline -eq 1) "polyline=$($midBreak.Polyline)"
Assert-That 'the fill is broken with it' ($midBreak.Polygon -eq 1) "polygon=$($midBreak.Polygon)"

# CONTROL for the same shape: three comparable runs must be ONE continuous line.
$threeOk = Measure-Chart @(
    (New-TrendPoint '2026-08-12T10:00:00Z' 100 20),
    (New-TrendPoint '2026-08-13T10:00:00Z' 100 60),
    (New-TrendPoint '2026-08-14T10:00:00Z' 100 90)
)
Assert-That 'CONTROL: three comparable runs draw ONE line' ($threeOk.Polyline -eq 1) "polyline=$($threeOk.Polyline)"
Assert-That 'CONTROL: three comparable runs are all plotted' ($threeOk.Circle -eq 3) "circle=$($threeOk.Circle)"
# The single line must span all three, so it carries three coordinate pairs.
$pts = [regex]::Match($threeOk.Svg, '<polyline class="trend-line" points="([^"]*)"')
Assert-That 'CONTROL: the single line joins all three points' (
    $pts.Success -and @($pts.Groups[1].Value -split '\s+' | Where-Object { $_ }).Count -eq 3) (
    "points='$($pts.Groups[1].Value)'")

Write-Host ''
Write-Host 'Two separate comparable stretches either side of a break draw two lines' -ForegroundColor Cyan
$twoRuns = Measure-Chart @(
    (New-TrendPoint '2026-08-11T10:00:00Z' 100 10 0 '2.1.0'),
    (New-TrendPoint '2026-08-12T10:00:00Z' 100 20 0 '2.1.0'),
    (New-TrendPoint '2026-08-13T10:00:00Z' 100 60 0 '3.0.0'),
    (New-TrendPoint '2026-08-14T10:00:00Z' 100 90 0 '3.0.0')
)
Assert-That 'all four runs are plotted' ($twoRuns.Circle -eq 4) "circle=$($twoRuns.Circle)"
Assert-That 'the version change splits the line in two' ($twoRuns.Polyline -eq 2) "polyline=$($twoRuns.Polyline)"
Assert-That 'and splits the fill in two' ($twoRuns.Polygon -eq 2) "polygon=$($twoRuns.Polygon)"

Write-Host ''
Write-Host 'The shared predicate itself agrees with what the chart drew' -ForegroundColor Cyan
$a = New-TrendPoint '2026-08-13T10:00:00Z' 100 20 0 '3.0.0' @('S1')
$b = New-TrendPoint '2026-08-14T10:00:00Z' 100 90 0 '3.0.0' @('S1', 'S2')
$cmp = Test-mdiTrendPointsComparable -Previous $a -Current $b
Assert-That 'an incomparable pair is reported incomparable' ($cmp.IsComparable -eq $false)
Assert-That 'and it names the reason' ([string] $cmp.Reason -like '*servers*') "reason=$($cmp.Reason)"
$cmpOk = Test-mdiTrendPointsComparable -Previous $a -Current (New-TrendPoint '2026-08-14T10:00:00Z' 100 90 0 '3.0.0' @('S1'))
Assert-That 'CONTROL: a comparable pair is reported comparable' ($cmpOk.IsComparable -eq $true) "reason=$($cmpOk.Reason)"
Assert-That 'CONTROL: and carries no reason' ($null -eq $cmpOk.Reason) "reason=$($cmpOk.Reason)"
# A missing run is not silently comparable.
$cmpNull = Test-mdiTrendPointsComparable -Previous $null -Current $b
Assert-That 'a missing run is not comparable' ($cmpNull.IsComparable -eq $false)

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
