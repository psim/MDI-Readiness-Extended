<#
    The trend pill states how much of the baseline it could not read.

    New-mdiTrendChart deliberately drops history entries that cannot be plotted - no parseable score, a
    score outside its own population, no timestamp - because a corrupted entry that is plotted anyway
    fabricates a delta, and that pill is what gets pasted into a change ticket to close a remediation.
    Dropping them is right. Reporting the survivors as the history was not.

    The pill read "(3 run(s) recorded)". On a nine-entry baseline whose middle six entries were
    unreadable it produced markup byte-for-byte identical to a genuine three-run history - measured -
    while the verbose surface printed nine for the same file. The reader could not distinguish a young
    baseline from a corrupted one, which is the difference between "keep scanning" and "your history
    file is broken".

    These assertions drive the real New-mdiTrendChart and read the pill back out of the emitted HTML.
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

$checkNames = @('a', 'b', 'c', 'd', 'e')
$serverNames = @('dc1.contoso.com')

# A run the chart can plot.
function New-GoodRun {
    param([string] $Stamp, [int] $Passed, [int] $Total = 5)
    [PSCustomObject]@{
        Timestamp     = $Stamp
        ChecksPassed  = $Passed
        ChecksTotal   = $Total
        ChecksUnread  = 0
        CheckNames    = $checkNames
        ServerNames   = $serverNames
        ScriptVersion = '1.0.0'
    }
}

# Stored, but unreadable: the score is not a number, so it is dropped rather than plotted as 0%.
function New-UnreadableRun {
    param([string] $Stamp)
    [PSCustomObject]@{
        Timestamp     = $Stamp
        ChecksPassed  = 'n/a'
        ChecksTotal   = 5
        ChecksUnread  = 0
        CheckNames    = $checkNames
        ServerNames   = $serverNames
        ScriptVersion = '1.0.0'
    }
}

function Get-Pill {
    param([object[]] $History)
    $html = (New-mdiTrendChart -History $History) -join "`n"
    $m = [regex]::Match($html, '<span class="pill [^"]*">([^<]*)</span>')
    if (-not $m.Success) { return '' }
    return $m.Groups[1].Value
}

function Get-PlottedDot {
    param([object[]] $History)
    $html = (New-mdiTrendChart -History $History) -join "`n"
    return [regex]::Matches($html, '<circle').Count
}

Write-Host 'Trend pill: unreadable history entries are disclosed' -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------------
# Nine stored runs, six of them unreadable. The pill must not read like a three-run history.
# ---------------------------------------------------------------------------------------------------
$mixed = @(
    New-GoodRun '2026-08-01T09:00:00' 3
    New-UnreadableRun '2026-08-02T09:00:00'
    New-UnreadableRun '2026-08-03T09:00:00'
    New-UnreadableRun '2026-08-04T09:00:00'
    New-UnreadableRun '2026-08-05T09:00:00'
    New-UnreadableRun '2026-08-06T09:00:00'
    New-UnreadableRun '2026-08-07T09:00:00'
    New-GoodRun '2026-08-11T09:00:00' 4
    New-GoodRun '2026-08-12T09:00:00' 5
)
$young = @(
    New-GoodRun '2026-08-01T09:00:00' 3
    New-GoodRun '2026-08-11T09:00:00' 4
    New-GoodRun '2026-08-12T09:00:00' 5
)

$mixedPill = Get-Pill -History $mixed
$youngPill = Get-Pill -History $young
$mixedDots = Get-PlottedDot -History $mixed

Assert-That 'unreadable entries are still excluded from the plot' ($mixedDots -eq 3) "(dots=$mixedDots)"

Assert-That 'a corrupted baseline does not render as a young one' ($mixedPill -ne $youngPill) `
    "(both read '$mixedPill')"

Assert-That 'the pill names how many runs are stored' ($mixedPill -match '\b9\b') "(pill='$mixedPill')"
Assert-That 'the pill names how many runs were plotted' ($mixedPill -match '\b3\b') "(pill='$mixedPill')"
Assert-That 'the pill says the rest could not be used' ($mixedPill -match 'no usable score or timestamp') `
    "(pill='$mixedPill')"

# The delta itself is unaffected - only the disclosure was wrong, and a fix that changed the arrow
# would be a different defect.
Assert-That 'the delta is still measured from the plotted runs' ($mixedPill -match '20 pt vs previous run') `
    "(pill='$mixedPill')"

# ---------------------------------------------------------------------------------------------------
# A genuinely complete history must NOT gain a disclosure it does not need.
# ---------------------------------------------------------------------------------------------------
Assert-That 'a clean history reports its run count plainly' ($youngPill -match '3 run\(s\) recorded') `
    "(pill='$youngPill')"
Assert-That 'a clean history invents no shortfall' `
    (($youngPill -notmatch 'no usable score') -and ($youngPill -notmatch ' of \d+ recorded runs plotted')) `
    "(pill='$youngPill')"

# ---------------------------------------------------------------------------------------------------
# Same fact on the not-comparable pill, which is a separate code path and must not drift.
# ---------------------------------------------------------------------------------------------------
$versionChanged = @(
    New-GoodRun '2026-08-01T09:00:00' 3
    New-UnreadableRun '2026-08-02T09:00:00'
    New-UnreadableRun '2026-08-03T09:00:00'
    New-GoodRun '2026-08-11T09:00:00' 4
    New-GoodRun '2026-08-12T09:00:00' 5
)
$versionChanged[-1].ScriptVersion = '1.1.0'
$ncPill = Get-Pill -History $versionChanged
Assert-That 'the not-comparable pill still explains itself' ($ncPill -match 'Not comparable with the previous run') `
    "(pill='$ncPill')"
Assert-That 'the not-comparable pill discloses the shortfall too' `
    (($ncPill -match '\b3\b') -and ($ncPill -match '\b5\b') -and ($ncPill -match 'no usable score or timestamp')) `
    "(pill='$ncPill')"

# ---------------------------------------------------------------------------------------------------
# Too few plottable runs to draw anything. "At least two runs are needed" on an eight-entry baseline
# reads as a young history when seven entries are actually broken.
# ---------------------------------------------------------------------------------------------------
$mostlyBroken = @(
    New-GoodRun '2026-08-01T09:00:00' 3
    New-UnreadableRun '2026-08-02T09:00:00'
    New-UnreadableRun '2026-08-03T09:00:00'
    New-UnreadableRun '2026-08-04T09:00:00'
    New-UnreadableRun '2026-08-05T09:00:00'
    New-UnreadableRun '2026-08-06T09:00:00'
    New-UnreadableRun '2026-08-07T09:00:00'
    New-UnreadableRun '2026-08-08T09:00:00'
)
$tooFew = (New-mdiTrendChart -History $mostlyBroken) -join "`n"
Assert-That 'a mostly-broken baseline still declines to draw a trend' ($tooFew -match 'At least two runs are needed')
Assert-That '  ...and says how many entries it could not read' `
    (($tooFew -match '\b7\b') -and ($tooFew -match '\b8\b') -and ($tooFew -match 'no usable score or timestamp')) `
    "(html='$tooFew')"

$genuinelyYoung = @(New-GoodRun '2026-08-12T09:00:00' 5)
$oneRun = (New-mdiTrendChart -History $genuinelyYoung) -join "`n"
Assert-That 'a genuinely single-run baseline says only that' `
    (($oneRun -match 'At least two runs are needed') -and ($oneRun -notmatch 'no usable score or timestamp')) `
    "(html='$oneRun')"

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) `
    -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $(if ($script:fail) { 1 } else { 0 })
