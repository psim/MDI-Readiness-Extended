<#
    The trend pill is what gets pasted into a change ticket to close a remediation.

    "+30 pt vs previous run" is an assertion that the estate got better. If the tool can produce that
    from a corrupt history entry rather than from an improvement, it is manufacturing evidence for a
    decision somebody is about to make.

    The defect: Get-mdiCoverageCount returns 0 for anything it cannot parse - absent, $null, '',
    'n/a'. That is right for a COUNT and wrong for a DATA POINT. An entry whose ChecksPassed had been
    lost was plotted as a legitimate 0%, every comparability guard passed because the check and
    server names still matched, and the NEXT run rendered a green upward arrow on an estate where
    nothing had changed. Measured: two identical 5/5 runs read "0 pt"; delete ChecksPassed from the
    first and the same pair reads "up 100 pt".

    ChecksTotal was already validated. ChecksPassed was not, and it is the more dangerous of the two.
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

$script:pass = 0; $script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

$checkNames = @('Power settings', 'Advanced auditing', 'NTLM auditing', 'Sensor health', 'Time sync')
$serverNames = @('dc1.contoso.com')
function New-Entry {
    param($Stamp, $Passed, $Total = 5, $Unread = 0, [string] $Omit)
    $h = [ordered]@{
        Timestamp = $Stamp; ChecksPassed = $Passed; ChecksTotal = $Total; ChecksUnread = $Unread
        CheckNames = $checkNames; ServerNames = $serverNames; ScriptVersion = '1.1.0'
    }
    if ($Omit) { $h.Remove($Omit) }
    [PSCustomObject]$h
}
function Get-Pill($svg) { [regex]::Match($svg, '<span class="pill[^"]*">([^<]*)</span>').Groups[1].Value }
function Get-Dots($svg) { ([regex]::Matches($svg, '<circle')).Count }
function Get-Delta($svg) {
    $m = [regex]::Match((Get-Pill $svg), '(\d+)\s*pt')
    if ($m.Success) { [int]$m.Groups[1].Value } else { $null }
}

Write-Host 'Two identical runs are not an improvement' -ForegroundColor Cyan
# The control. If this ever stops reading zero, everything below is meaningless.
$identical = New-mdiTrendChart -History @((New-Entry '2026-08-01T09:00:00' 5), (New-Entry '2026-08-08T09:00:00' 5))
Assert-That 'two identical runs show a delta of zero' ((Get-Delta $identical) -eq 0) "(pill='$(Get-Pill $identical)')"
Assert-That '  and both are plotted' ((Get-Dots $identical) -eq 2)
$better = New-mdiTrendChart -History @((New-Entry '2026-08-01T09:00:00' 3), (New-Entry '2026-08-08T09:00:00' 5))
Assert-That 'a genuine improvement is still shown as one' ((Get-Delta $better) -gt 0) "(pill='$(Get-Pill $better)')"
Assert-That '  with an upward arrow' ((Get-Pill $better) -match '&uarr;')
$worse = New-mdiTrendChart -History @((New-Entry '2026-08-01T09:00:00' 5), (New-Entry '2026-08-08T09:00:00' 3))
Assert-That 'a genuine decline is still shown as one' ((Get-Pill $worse) -match '&darr;') "(pill='$(Get-Pill $worse)')"

Write-Host 'An entry that cannot state its score is not a data point' -ForegroundColor Cyan
# THE defect. Each of these was plotted as 0%, manufacturing an upward delta for the next run.
foreach ($case in @(
        @{ N = 'ChecksPassed absent'; E = (New-Entry '2026-08-01T09:00:00' 5 -Omit 'ChecksPassed') }
        @{ N = "ChecksPassed = 'n/a'"; E = (New-Entry '2026-08-01T09:00:00' 'n/a') }
        @{ N = 'ChecksPassed = null'; E = (New-Entry '2026-08-01T09:00:00' $null) }
        @{ N = "ChecksPassed = ''"; E = (New-Entry '2026-08-01T09:00:00' '') }
        @{ N = 'ChecksPassed = array'; E = (New-Entry '2026-08-01T09:00:00' @(1, 2)) }
        @{ N = 'ChecksPassed = $true'; E = (New-Entry '2026-08-01T09:00:00' $true) }
    )) {
    $svg = New-mdiTrendChart -History @($case.E, (New-Entry '2026-08-08T09:00:00' 5))
    $delta = Get-Delta $svg
    Assert-That ("{0} does not fabricate an improvement" -f $case.N) (
        (Get-Dots $svg) -lt 2 -or $null -eq $delta -or $delta -eq 0) `
        "(dots=$(Get-Dots $svg) pill='$(Get-Pill $svg)')"
}

# The other direction: a NUMBER that arrived as a string is a real score and must survive, because
# JSON round-trips widen integers to strings.
$asString = New-mdiTrendChart -History @((New-Entry '2026-08-01T09:00:00' '3'), (New-Entry '2026-08-08T09:00:00' 5))
Assert-That "a numeric string score is still plotted" ((Get-Dots $asString) -eq 2) `
    "(dots=$(Get-Dots $asString))"
Assert-That '  and produces the correct delta' ((Get-Delta $asString) -eq (Get-Delta $better)) `
    "(string='$(Get-Pill $asString)' int='$(Get-Pill $better)')"
# A legitimate zero score is a measurement and must NOT be dropped.
$zero = New-mdiTrendChart -History @((New-Entry '2026-08-01T09:00:00' 0), (New-Entry '2026-08-08T09:00:00' 5))
Assert-That 'a genuine score of zero is still plotted' ((Get-Dots $zero) -eq 2) "(dots=$(Get-Dots $zero))"
Assert-That '  and shows the real improvement' ((Get-Delta $zero) -eq 100) "(pill='$(Get-Pill $zero)')"

Write-Host 'Passed and Total are validated to the same standard' -ForegroundColor Cyan
# The asymmetry that allowed this: ChecksTotal was checked, ChecksPassed was not.
foreach ($field in 'ChecksPassed', 'ChecksTotal') {
    $svg = New-mdiTrendChart -History @(
        (New-Entry '2026-08-01T09:00:00' 5 -Omit $field), (New-Entry '2026-08-08T09:00:00' 5))
    Assert-That ("an entry missing {0} is discarded" -f $field) ((Get-Dots $svg) -lt 2) "(dots=$(Get-Dots $svg))"
}
# A score exceeding its own denominator is impossible and must not plot above the chart.
$impossible = New-mdiTrendChart -History @((New-Entry '2026-08-01T09:00:00' 99 5 0), (New-Entry '2026-08-08T09:00:00' 5))
Assert-That 'a score larger than the population is discarded' ((Get-Dots $impossible) -lt 2)

Write-Host 'A chart with nothing to plot renders nothing, and does not throw' -ForegroundColor Cyan
foreach ($h in @(@(), @($null), @((New-Entry '2026-08-01T09:00:00' 'x')))) {
    $threw = $false
    try { $null = New-mdiTrendChart -History $h } catch { $threw = $true }
    Assert-That 'an unusable history does not throw' (-not $threw)
}
$single = New-mdiTrendChart -History @((New-Entry '2026-08-01T09:00:00' 5))
Assert-That 'a single run does not claim a delta' ((Get-Pill $single) -notmatch 'vs previous run') `
    "(pill='$(Get-Pill $single)')"

Write-Host 'Runs that measured different things are not compared' -ForegroundColor Cyan
# Already correct; pinned so a future change to the filter cannot quietly remove it.
$fewerChecks = New-mdiTrendChart -History @(
    (New-Entry '2026-08-01T09:00:00' 3 10 0)
    [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00'; ChecksPassed = 5; ChecksTotal = 5; ChecksUnread = 0
        CheckNames = @('Power settings', 'Advanced auditing'); ServerNames = $serverNames; ScriptVersion = '1.1.0' })
Assert-That 'a run that measured fewer checks is flagged, not delta-ed' (
    (Get-Pill $fewerChecks) -match '(?i)not comparable') "(pill='$(Get-Pill $fewerChecks)')"
$fewerServers = New-mdiTrendChart -History @(
    (New-Entry '2026-08-01T09:00:00' 5)
    [PSCustomObject]@{ Timestamp = '2026-08-08T09:00:00'; ChecksPassed = 5; ChecksTotal = 5; ChecksUnread = 0
        CheckNames = $checkNames; ServerNames = @('dc1.contoso.com', 'dc2.contoso.com'); ScriptVersion = '1.1.0' })
Assert-That 'a run over a different server set is flagged' (
    (Get-Pill $fewerServers) -match '(?i)not comparable') "(pill='$(Get-Pill $fewerServers)')"

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
