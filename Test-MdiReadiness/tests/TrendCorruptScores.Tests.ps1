<#
    A corrupt history entry must not become a fabricated improvement.

    The trend pill is what gets pasted into a change ticket to close a remediation. "+50 pt vs
    previous run" is an assertion that the estate got better, and if the tool can produce it from a
    corrupt history entry rather than from an improvement, it is manufacturing evidence for a
    decision somebody is about to make.

    The guard that drops an unusable entry checked the TYPE of ChecksPassed and not its VALUE. A
    native NaN, Infinity or negative double IS a [double], so it sailed past the type test - while
    the STRING forms of the same values were correctly rejected by TryParse. The guard's strictness
    therefore depended on whether the history had been round-tripped through JSON as text. Measured
    before the fix: an entry whose ChecksPassed was NaN or -5 was floored to zero by
    Get-mdiCoverageCount and PLOTTED as a legitimate 0%, and the next genuine run at 50% rendered
    "up 50 pt vs previous run" over an estate that had not changed at all.

    Reachability: the script never writes such an entry itself. It arrives from a history that was
    hand-merged from two collectors, restored from a backup, edited, or written by a different tool -
    which is precisely the threat model the comments around this code already claim to defend
    against, and the reason the sibling guards exist.
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

$checkNames = @('NtlmAuditing', 'AdvancedAuditing')
$serverNames = @('dc1.contoso.com')
function New-Entry {
    param($Stamp, $Passed, $Total = 10, $Unread = 0)
    [PSCustomObject]@{
        Timestamp = $Stamp; ChecksPassed = $Passed; ChecksTotal = $Total; ChecksUnread = $Unread
        CheckNames = $checkNames; ServerNames = $serverNames; ScriptVersion = '1.1.0'
    }
}
function Get-Pill { param($Svg) [regex]::Match($Svg, '<span class="pill[^"]*">([^<]*)</span>').Groups[1].Value }
function Get-Delta {
    param($Svg)
    $m = [regex]::Match((Get-Pill $Svg), '(-?\d+)\s*pt')
    if ($m.Success) { return [int] $m.Groups[1].Value }
    $null
}
function Get-PlottedCount { param($Svg) ([regex]::Matches($Svg, '<circle')).Count }

Write-Host 'An unusable score is dropped, not plotted as zero' -ForegroundColor Cyan
# Each of these, followed by a genuine 5/10 run, must NOT produce an upward delta.
foreach ($case in @(
        @{ Label = 'NaN'; Value = [double]::NaN }
        @{ Label = 'positive infinity'; Value = [double]::PositiveInfinity }
        @{ Label = 'negative infinity'; Value = [double]::NegativeInfinity }
        @{ Label = 'a negative count'; Value = -5 }
        @{ Label = 'a negative double'; Value = [double] -0.5 }
        @{ Label = "the string 'NaN'"; Value = 'NaN' }
        @{ Label = "the string '-5'"; Value = '-5' }
    )) {
    $svg = New-mdiTrendChart -History @(
        (New-Entry '2026-08-01T00:00:00' $case.Value)
        (New-Entry '2026-08-08T00:00:00' 5)
    )
    $delta = Get-Delta $svg
    Assert-That ('{0} does not fabricate an improvement' -f $case.Label) (
        $null -eq $delta -or $delta -le 0) "(pill '$(Get-Pill $svg)')"
    Assert-That ('  ...and {0} is not plotted as a data point' -f $case.Label) (
        (Get-PlottedCount $svg) -le 1) "(plotted $(Get-PlottedCount $svg))"
}

Write-Host 'A genuine score of zero is still a data point' -ForegroundColor Cyan
# The whole risk of this fix is over-rejecting: a real 0% run is meaningful and must still plot,
# and the improvement away from it must still be shown.
$realZero = New-mdiTrendChart -History @(
    (New-Entry '2026-08-01T00:00:00' 0)
    (New-Entry '2026-08-08T00:00:00' 10)
)
Assert-That 'a measured 0 of 10 is plotted' ((Get-PlottedCount $realZero) -eq 2) "(plotted $(Get-PlottedCount $realZero))"
Assert-That '  ...and the real improvement is reported' ((Get-Delta $realZero) -eq 100) "(pill '$(Get-Pill $realZero)')"

Write-Host 'Ordinary histories are unaffected' -ForegroundColor Cyan
$flat = New-mdiTrendChart -History @((New-Entry '2026-08-01T00:00:00' 5), (New-Entry '2026-08-08T00:00:00' 5))
Assert-That 'two identical runs still read zero' ((Get-Delta $flat) -eq 0) "(pill '$(Get-Pill $flat)')"
$better = New-mdiTrendChart -History @((New-Entry '2026-08-01T00:00:00' 3), (New-Entry '2026-08-08T00:00:00' 8))
Assert-That 'a genuine improvement is still reported' ((Get-Delta $better) -eq 50) "(pill '$(Get-Pill $better)')"
$worse = New-mdiTrendChart -History @((New-Entry '2026-08-01T00:00:00' 8), (New-Entry '2026-08-08T00:00:00' 3))
Assert-That 'a genuine regression is still reported' ((Get-Delta $worse) -eq -50) "(pill '$(Get-Pill $worse)')"
# A numeric string is a legitimate JSON round-trip and must survive.
$stringy = New-mdiTrendChart -History @((New-Entry '2026-08-01T00:00:00' '3'), (New-Entry '2026-08-08T00:00:00' '8'))
Assert-That 'a numeric string score still plots' ((Get-Delta $stringy) -eq 50) "(pill '$(Get-Pill $stringy)')"

Write-Host 'Nothing throws on a hostile history' -ForegroundColor Cyan
foreach ($hostile in @(
        @{ Label = 'every entry unusable'; History = @((New-Entry '2026-08-01T00:00:00' ([double]::NaN)), (New-Entry '2026-08-08T00:00:00' -1)) }
        @{ Label = 'a single unusable entry'; History = @((New-Entry '2026-08-01T00:00:00' ([double]::NaN))) }
    )) {
    $threw = $false
    try { $null = New-mdiTrendChart -History $hostile.History } catch { $threw = $true }
    Assert-That ('{0} does not throw' -f $hostile.Label) (-not $threw)
}

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
