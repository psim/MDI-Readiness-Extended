<#
    A REAL MOVEMENT WAS PRINTED AS "0 pt" ON A LARGE ESTATE.

    The trend pill carries an explicit guard whose comment reads "A real movement must never be
    printed as '0 pt' - that is the one number a reader takes as 'nothing changed'". It was added
    after 1000/2000 -> 1001/2000 rendered "-> 0 pt", and it worked by falling back to a second
    decimal when the first rounded away.

    A second decimal is only enough for a SMALL estate. The smallest movement a run can produce is
    one check out of the covered population, so the delta shrinks as the estate grows:

        one check of  2,000  ->  0.05     printed fine
        one check of 25,000  ->  0.004    printed "0 pt"
        one check of 40,000  ->  0.0025   printed "0 pt"

    Two separate things had to be fixed, and the second is the one that hid the first: the guard
    rounded to two decimals (0.004 -> 0), and the format string was '0.##', which truncates to two
    decimals as well. Widening only one of them leaves the lie in place - a fix that rounds to four
    decimals and then formats two still prints "0".

    The precision is now chosen from the number: enough decimals are taken to make the movement
    visible, and the format string is widened to match.

    What must NOT change is the dead band. The arrow and the tone deliberately treat anything within
    half a point as "no meaningful movement" - that is a separate, intentional decision made once and
    judged on the rounded value so the arrow, the tone and the number cannot disagree. This defect is
    only about the NUMBER printing zero when it is not zero. A fix that made 0.004 render a green
    up-arrow would be a worse bug than the one being fixed, so the tone and arrow are pinned here too.

    Behavioural: every assertion calls the shipped New-mdiTrendChart and reads the rendered pill.
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
    param($Stamp, $Total, $Passed, $Unread = 0)
    [PSCustomObject]@{
        Timestamp = $Stamp; ChecksTotal = $Total; ChecksPassed = $Passed; ChecksUnread = $Unread
        ScriptVersion = '3.0.0'; Domain = 'contoso.com'; Forest = 'contoso.com'
        CheckNames = @('C1'); ServerNames = @('S1')
    }
}

# The rendered pill, as an operator reads it - not an intermediate variable.
function Get-Pill {
    param($Total, $From, $To)
    $svg = [string]((New-mdiTrendChart -History @(
                (New-TrendPoint '2026-08-13T10:00:00Z' $Total $From),
                (New-TrendPoint '2026-08-14T10:00:00Z' $Total $To)
            )) -join '')
    $m = [regex]::Match($svg, '<span class="pill ([^"]*)">(.*?)</span>')
    if (-not $m.Success) { throw 'no pill was rendered' }
    [PSCustomObject]@{ Tone = $m.Groups[1].Value; Text = $m.Groups[2].Value }
}
function Get-TrueDelta {
    param($Total, $From, $To)
    (Get-mdiCoveragePercent -Passed $To -Measured $Total -Unread 0) -
    (Get-mdiCoveragePercent -Passed $From -Measured $Total -Unread 0)
}

Write-Host 'A movement too small for two decimals must still be printed' -ForegroundColor Cyan
foreach ($case in @(
        @{ N = '25,000 checks, one check gained'; T = 25000; A = 12500; B = 12501 },
        @{ N = '40,000 checks, one check gained'; T = 40000; A = 20000; B = 20001 },
        @{ N = '25,000 checks, one check LOST'; T = 25000; A = 12501; B = 12500 },
        @{ N = '100,000 checks, one check gained'; T = 100000; A = 50000; B = 50001 })) {
    $pill = Get-Pill -Total $case.T -From $case.A -To $case.B
    $realDelta = Get-TrueDelta -Total $case.T -From $case.A -To $case.B
    Assert-That "$($case.N): the movement is real" ($realDelta -ne 0) "delta=$realDelta"
    Assert-That "$($case.N): the pill does not print 0 pt" (
        $pill.Text -notmatch '(^|\s)0 pt\b') "pill='$($pill.Text)' delta=$realDelta"
    # Printing a number is not enough - it must be the RIGHT number, not a widened zero.
    Assert-That "$($case.N): the printed number is non-zero" (
        [regex]::IsMatch($pill.Text, '[-+]?0?\.0*[1-9]')) "pill='$($pill.Text)'"
    Assert-That "$($case.N): the sign matches the direction of travel" (
        ($realDelta -lt 0) -eq ($pill.Text -match '-\d')) "pill='$($pill.Text)' delta=$realDelta"
}

Write-Host ''
Write-Host 'The dead band must be untouched: a tiny movement is still neither up nor down' -ForegroundColor Cyan
foreach ($case in @(
        @{ N = '25,000 checks, one gained'; T = 25000; A = 12500; B = 12501 },
        @{ N = '25,000 checks, one lost'; T = 25000; A = 12501; B = 12500 })) {
    $pill = Get-Pill -Total $case.T -From $case.A -To $case.B
    Assert-That "$($case.N): tone stays neutral" ($pill.Tone -eq 'na') "tone=$($pill.Tone)"
    Assert-That "$($case.N): arrow stays sideways" ($pill.Text -like '*rarr*') "pill='$($pill.Text)'"
    Assert-That "$($case.N): it is not painted as an improvement" ($pill.Tone -ne 'ok') "tone=$($pill.Tone)"
}

Write-Host ''
Write-Host 'CONTROLS - the cases that already worked must be unchanged' -ForegroundColor Cyan
$c1 = Get-Pill -Total 2000 -From 1000 -To 1001
Assert-That 'CONTROL: the case the guard was written for still prints 0.05' (
    $c1.Text -like '*0.05 pt*') "pill='$($c1.Text)'"
Assert-That 'CONTROL: and stays in the dead band' ($c1.Tone -eq 'na') "tone=$($c1.Tone)"

$c2 = Get-Pill -Total 200 -From 100 -To 110
Assert-That 'CONTROL: a clear gain still prints 5 pt' ($c2.Text -like '*5 pt*') "pill='$($c2.Text)'"
Assert-That 'CONTROL: a clear gain is still green' ($c2.Tone -eq 'ok') "tone=$($c2.Tone)"
Assert-That 'CONTROL: a clear gain still points up' ($c2.Text -like '*uarr*') "pill='$($c2.Text)'"

$c3 = Get-Pill -Total 200 -From 110 -To 100
Assert-That 'CONTROL: a clear loss is still red' ($c3.Tone -eq 'bad') "tone=$($c3.Tone)"
Assert-That 'CONTROL: a clear loss still points down' ($c3.Text -like '*darr*') "pill='$($c3.Text)'"

# The one case where "0 pt" is the honest answer.
$c4 = Get-Pill -Total 200 -From 100 -To 100
Assert-That 'CONTROL: a genuine no-change still prints 0 pt' (
    $c4.Text -match '(^|\s)0 pt\b') "pill='$($c4.Text)'"
Assert-That 'CONTROL: a genuine no-change is neutral' ($c4.Tone -eq 'na') "tone=$($c4.Tone)"

Write-Host ''
Write-Host 'The number must stay culture-invariant however many decimals it grows' -ForegroundColor Cyan
$culture = [Threading.Thread]::CurrentThread.CurrentCulture
try {
    [Threading.Thread]::CurrentThread.CurrentCulture = [cultureinfo]::GetCultureInfo('de-DE')
    $deDe = Get-Pill -Total 25000 -From 12500 -To 12501
    Assert-That 'a small delta uses a decimal POINT under de-DE' (
        $deDe.Text -notmatch ',\d') "pill='$($deDe.Text)'"
    Assert-That 'and still shows the movement under de-DE' (
        $deDe.Text -notmatch '(^|\s)0 pt\b') "pill='$($deDe.Text)'"
    $deDeBig = Get-Pill -Total 200 -From 100 -To 110
    Assert-That 'CONTROL: a whole-number delta is unaffected by de-DE' (
        $deDeBig.Text -like '*5 pt*') "pill='$($deDeBig.Text)'"
} finally {
    [Threading.Thread]::CurrentThread.CurrentCulture = $culture
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
