<#
    The trend pill may not claim a fuller history than it actually plotted.

    Get-mdiTrendRunCountText is the single place that decides what the trend pill says about history
    depth, and both pills - the "not comparable" one and the delta one - render its output. The pill
    used to print "(3 run(s) recorded)" using the count of runs it PLOTTED. Points are dropped by
    New-mdiTrendChart whenever an entry carries no usable score or timestamp, which is deliberate so
    that a corrupted entry cannot fabricate a delta, but the pill then reported the survivors as if
    they were the whole history. A nine-entry baseline with six unreadable entries produced a pill
    byte-for-byte identical to a genuine three-run history, while the verbose surface printed nine
    for the same file: a reader could not tell a young baseline from a corrupted one, and the two
    surfaces of one fact disagreed.

    No defect was found in the current implementation. It is pinned because nothing named it before,
    and because the disclosure it produces is the only thing standing between a corrupted baseline
    and a pill that looks healthy.

    Pinned here:

    1. When runs were recorded but could not be plotted, the shortfall is DISCLOSED, and both
       numbers appear: how many were plotted and how many exist. Dropping either number, or falling
       back to the plain "N run(s) recorded" wording, turns this red.
    2. The two numbers are in the right ORDER and mean the right things - the first is the PLOTTED
       count and the second is the RECORDED total. This is the specific inversion that matters,
       because the neighbouring verbose surface reports the same fact the other way round, as
       "{unplottable} of {recorded} recorded run(s) could not be plotted". Swapping plotted for
       unplottable here would still read as a sensible English sentence while stating a different
       number, which is exactly how the original defect survived review.
    3. When nothing was dropped, the pill uses the plain wording and does NOT invent a shortfall
       disclosure for a healthy baseline.
    4. The boundary cases behave: exactly one run, a single dropped run, and a baseline where NOTHING
       could be plotted at all. The last is the important one - zero plotted out of nine recorded must
       still announce the nine, because that is the case where the chart is empty and the pill is the
       only thing left that can say the history exists.

    Deliberately NOT pinned: Plotted greater than Recorded, and non-integer Recorded values such as
    $null, '' or a decimal. None can occur. Both arguments are supplied by the same caller from the
    same source - $recordedRuns is @($History | Where-Object { $null -ne $_ }).Count and $points is
    that same $History put through further filters - so Plotted is always a subset count of Recorded
    and neither can be null, negative or non-numeric. Asserting those shapes would freeze behaviour
    that has no caller and invite a "fix" for a defect that cannot happen.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
if (-not (Test-Path $target)) { throw "Could not locate Test-MdiReadiness.ps1 from $here" }
$text = Get-Content -LiteralPath $target -Raw
if ($text -notmatch '(?m)^function Get-mdiTrendRunCountText') { throw "The file loaded from $target is not the Test-MdiReadiness product script." }
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}
function Pill { param([int] $Plotted, [int] $Recorded) Get-mdiTrendRunCountText -Plotted $Plotted -Recorded $Recorded }

'1. A shortfall is disclosed, with both numbers'
$t = Pill 3 9
Assert-That 'a 3-of-9 history does not use the plain wording' ($t -notmatch '^\d+ run\(s\) recorded$') "got [$t]"
Assert-That 'it says the runs could not be plotted' ($t -match 'no usable score or timestamp') "got [$t]"
Assert-That 'it names the plotted count 3' ($t -match '\b3\b') "got [$t]"
Assert-That 'it names the recorded total 9' ($t -match '\b9\b') "got [$t]"

'2. The numbers are in the right order and mean the right things'
# 3 plotted of 9 recorded. The plotted count must come FIRST; the recorded total SECOND. If the
# first number were the unplottable count it would read 6, which is why 6 must not appear here.
Assert-That 'the plotted count is stated before the recorded total' `
    ($t -match '3\D+9') "got [$t]"
Assert-That 'the unplottable count (6) is NOT what the pill reports as plotted' `
    ($t -notmatch '^6\b') "got [$t]"
$t2 = Pill 2 7
Assert-That 'a 2-of-7 history states 2 then 7' ($t2 -match '2\D+7') "got [$t2]"
Assert-That 'a 2-of-7 history does not state the unplottable 5 first' ($t2 -notmatch '^5\b') "got [$t2]"

'3. A healthy baseline uses the plain wording'
foreach ($n in 1, 3, 9) {
    $h = Pill $n $n
    Assert-That "$n of $n plotted reads '$n run(s) recorded'" ($h -eq "$n run(s) recorded") "got [$h]"
    Assert-That "$n of $n plotted invents no shortfall" ($h -notmatch 'no usable score') "got [$h]"
}

'4. Boundaries'
$one = Pill 2 3
Assert-That 'a single dropped run is still disclosed' ($one -match 'no usable score or timestamp') "got [$one]"
Assert-That 'a single dropped run names 2 and 3' ($one -match '2\D+3') "got [$one]"
$none = Pill 0 9
Assert-That 'nothing plotted out of nine is disclosed' ($none -match 'no usable score or timestamp') "got [$none]"
Assert-That 'nothing plotted still announces the nine recorded runs' ($none -match '\b9\b') "got [$none]"
$empty = Pill 0 0
Assert-That 'an empty baseline reads 0 run(s) recorded' ($empty -eq '0 run(s) recorded') "got [$empty]"
Assert-That 'an empty baseline invents no shortfall' ($empty -notmatch 'no usable score') "got [$empty]"
Assert-That 'the result is always a single string' ((Pill 3 9) -is [string])

''
"PASS: $script:pass  FAIL: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
