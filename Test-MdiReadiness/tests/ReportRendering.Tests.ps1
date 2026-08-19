<#
    Report-rendering regression: unread checks must be visible in every summary that claims to
    describe readiness, and an unmeasured thing must never render as either a pass or a failure.

    The defects these pin were all the same shape: a summary computed over MEASURED results only,
    presented as if it described the whole estate. Each is asserted in both directions, because the
    obvious correction - counting unread as failed - trades a false green for a false red.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Write-Host 'Bar chart: unread checks belong in the denominator' -ForegroundColor Cyan
function New-Bar($value, $total, $unread) {
    $o = [PSCustomObject]@{ Label = 'srv'; Value = $value; Total = $total; Hint = 'h' }
    if ($null -ne $unread) { $o | Add-Member -NotePropertyName Unread -NotePropertyValue $unread }
    New-mdiBarChart -Bar @($o)
}

# One check readable and passing, four unreadable. This rendered "1/1 (100%)" solid green next to a
# score card reading 20% - the single most reassuring row on the page, describing a server nobody
# managed to examine.
$h = New-Bar 1 1 4
Assert-That 'a server with 4 unread checks is not shown at 100%' ($h -notmatch '\(100%\)')
Assert-That '  ...the fraction is out of measured + unread' ($h -match '1/5')
Assert-That '  ...the unread count is stated' ($h -match '4 not read')
Assert-That '  ...and the bar is not toned green' ($h -notmatch 'bar-fill ok')
Assert-That '  ...but a neutral segment is drawn for them' ($h -match 'bar-fill na')

# The other direction: a real clean sweep must still look like one, or the fix has just moved the lie.
$clean = New-Bar 5 5 0
Assert-That 'a genuine 5/5 is still green at 100%' (($clean -match '\(100%\)') -and ($clean -match 'bar-fill ok'))
Assert-That '  ...with no unread annotation' ($clean -notmatch 'not read')

# Nothing measured is neither a pass nor a failure. Toning this red would invent a finding from an
# absence of evidence - which is the same defect class, pointing the other way.
$blank = New-Bar 0 0 6
Assert-That 'a fully unread bar is neutral' ($blank -match 'bar-fill na')
Assert-That '  ...and is NOT red' ($blank -notmatch 'bar-fill bad')
# A zero that WAS measured must stay red.
$zero = New-Bar 0 4 0
Assert-That 'a measured 0/4 is still red' ($zero -match 'bar-fill bad')
# Callers that predate the Unread property must be unaffected.
$legacy = New-Bar 3 4 $null
Assert-That 'a bar with no Unread property is unchanged' ($legacy -match '3/4')
Assert-That 'an empty bar set still returns the empty message' ((New-mdiBarChart -Bar @() -EmptyMessage 'nothing') -match 'nothing')
# Percentages floor, never round up to a clean sweep that did not happen.
$almost = New-Bar 996 1000 0
Assert-That '996/1000 floors to 99%, never 100%' ($almost -match '\(99%\)')

Write-Host 'Readiness donut and trend share the score card denominator' -ForegroundColor Cyan
# Behavioural. The previous assertion searched the source for the segment literal and was proven
# vacuous by mutation: the real segment was changed to "Measured only, Value 0" with a decoy comment
# left behind, and the suite still reported 37/0. The donut is rendered here and the arcs are counted.
$donutStats = [PSCustomObject]@{ ChecksPassed = 2; ChecksTotal = 4; ChecksUnread = 6 }
$donutHtml = New-mdiDonutChart -Segment @(
    [PSCustomObject]@{ Label = 'Passed'; Value = $donutStats.ChecksPassed; Color = 'var(--ok)' }
    [PSCustomObject]@{ Label = 'Failed'; Value = ($donutStats.ChecksTotal - $donutStats.ChecksPassed); Color = 'var(--bad)' }
    [PSCustomObject]@{ Label = 'Not read'; Value = $donutStats.ChecksUnread; Color = 'var(--na)' }
) -CenterValue '20%' -CenterLabel 'ready'
Assert-That 'the donut renders three arcs, not two' (([regex]::Matches($donutHtml, '<circle|<path')).Count -ge 3) `
    "(found $(([regex]::Matches($donutHtml,'<circle|<path')).Count))"
Assert-That '  ...and names the unread segment' ($donutHtml -match 'Not read')
Assert-That '  ...with the unread count in it' ($donutHtml -match '6')
# The real caller must feed ChecksUnread into that third segment. Asserted against the DONUT SECTION
# only: matching the whole overview page for "not read" was proven vacuous by mutation, because the
# bar charts annotate their own unread counts with the same words, so the page matched whatever the
# donut did. The donut is extracted by its heading and examined on its own.
$donutEstate = [PSCustomObject]@{
    DomainControllers = @(
        [PSCustomObject]@{ FQDN = 'dc1'; Unreachable = $false; PartialFailure = $false; OSVersion = $true; TimeSync = 'N/A'; Details = [PSCustomObject]@{} }
        [PSCustomObject]@{ FQDN = 'dc2'; Unreachable = $false; PartialFailure = $false; OSVersion = $false; TimeSync = 'N/A'; Details = [PSCustomObject]@{} })
    CAServers = @(); EntraConnectServers = @()
    DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'; Forest = 'contoso.com'
}
$donutStatsLive = Get-mdiReportStatistics -ReportData $donutEstate
$donutOverview = Get-mdiOverviewHtml -ReportData $donutEstate -Statistics $donutStatsLive
$donutSection = [regex]::Match($donutOverview, '(?s)<h3>Overall readiness</h3>(.*?)</section>').Groups[1].Value
Assert-That 'the overview actually renders a readiness donut' ($donutSection.Length -gt 0)
Assert-That '  ...carrying an unread arc' ($donutSection -match 'Not read') "(section length $($donutSection.Length))"
Assert-That '  ...whose value is the statistics unread count' ($donutSection -match [regex]::Escape([string] $donutStatsLive.ChecksUnread)) `
    "(ChecksUnread = $($donutStatsLive.ChecksUnread))"
Assert-That 'the baseline still stores ChecksUnread' ($text -match 'ChecksUnread  = \[int\] \$Statistics\.ChecksUnread')

# Behavioural, and it actually CALLS the chart. The previous version of this block asserted on source
# text only - it never invoked New-mdiTrendChart at all - so it passed while the delta pill still
# divided by ChecksTotal alone and reported "no change" under a line that had fallen 64 points. An
# adversarial review proved it by reverting the fix and watching the suite stay green.
$trendChecks = @(1..10 | ForEach-Object { "Check$_" })
$trendServers = @('dc1.contoso.com', 'dc2.contoso.com')
function New-TrendPoint($stamp, $passed, $total, $unread) {
    [PSCustomObject]@{ Timestamp = $stamp; ChecksPassed = $passed; ChecksTotal = $total; ChecksUnread = $unread
        CheckNames = $trendChecks; ServerNames = $trendServers }
}
function Get-TrendPill($svg) { [regex]::Match($svg, '<span class="pill[^"]*">([^<]*)</span>').Groups[1].Value }

# Coverage collapse: same measured counts, but 40 checks became unreadable. The plot must fall, and
# the pill must NOT claim no change.
$collapse = New-mdiTrendChart -History @(
    (New-TrendPoint '2026-08-01T09:00:00' 8 10 0), (New-TrendPoint '2026-08-08T09:00:00' 8 10 40))
$collapsePill = Get-TrendPill $collapse
Assert-That 'a coverage collapse is never reported as no change' ($collapsePill -notmatch '&rarr; 0 pt') "($collapsePill)"
Assert-That '  ...it is reported as not comparable' ($collapsePill -match 'Not comparable') "($collapsePill)"
Assert-That '  ...and the plot itself falls to 16%' ($collapse -match '16%')
Assert-That '  ...with a tooltip stating the same fraction' ($collapse -match '8/50') "(tooltip must not say 8/10)"

# A genuine improvement over identical coverage must still produce a real delta.
$better = New-mdiTrendChart -History @(
    (New-TrendPoint '2026-08-01T09:00:00' 6 10 0), (New-TrendPoint '2026-08-08T09:00:00' 9 10 0))
Assert-That 'a genuine improvement still shows an upward delta' ((Get-TrendPill $better) -match '&uarr; 30 pt')

# A genuine regression, with unread held constant on both sides, must still show a fall.
$worse = New-mdiTrendChart -History @(
    (New-TrendPoint '2026-08-01T09:00:00' 9 10 5), (New-TrendPoint '2026-08-08T09:00:00' 6 10 5))
Assert-That 'a genuine regression still shows a downward delta' ((Get-TrendPill $worse) -match '&darr;')

# The plot, the tooltip and the pill must all be derived from the same denominator.
$same = New-mdiTrendChart -History @(
    (New-TrendPoint '2026-08-01T09:00:00' 5 10 10), (New-TrendPoint '2026-08-08T09:00:00' 5 10 10))
Assert-That 'a flat run over equal coverage reports no change' ((Get-TrendPill $same) -match '0 pt')
Assert-That '  ...and plots 25%, not 50%' ($same -match '25%') "(5 of 10+10 is 25%)"

Write-Host 'Tri-state values are compared, never tested for truthiness' -ForegroundColor Cyan
# 'False' and 'N/A' are both non-empty strings and therefore truthy - the trap that made a server
# nobody evaluated render a green "Yes, eligible for in-place migration".
Assert-That "the string 'False' is truthy (the trap this guards)" ([bool] 'False')
Assert-That "the string 'N/A' is truthy (the trap this guards)" ([bool] 'N/A')
Assert-That 'the migration KPI compares against $true' ($text -match 'MigrationEligible -eq \$true \}\)\.Count')
Assert-That 'the migration cell renders a third state' ($text -match 'Not determined</td>')

Write-Host 'Nothing is dropped from the port matrix' -ForegroundColor Cyan
# The ids are read off the RECORDS, so a probe whose id is absent, renamed or unrecognised still has
# a row to land in. This used to pin the literal `Select-Object -ExpandProperty Id -Unique`, which
# was replaced because -ExpandProperty RAISES on a record that has no Id property at all and took the
# whole table down with it; the intent - ids come from the results, not only from the settings - is
# unchanged and is what is pinned here.
Assert-That 'probe ids come from the results, not only the settings' (
    $text -match '\$recordProbeId = @\(\$records \| ForEach-Object \{')
Assert-That '  ...read off each record rather than expanded' (
    $text -match '\$recordId = \[string\] \$_\.Id')
Assert-That '  ...and an unreadable id keys as a stated marker, so the record is not dropped' (
    $text -match "\`$unidentifiedProbeId = '\(unidentified probe\)'" -and
    $text -match 'if \(\[string\]::IsNullOrWhiteSpace\(\$recordId\)\) \{ \$unidentifiedProbeId \} else \{ \$recordId \}')
Assert-That '  ...orphans are appended rather than skipped' (
    $text -match '\$orphanProbeId = @\(\$recordProbeId \| Where-Object \{ \$_ -notin \$knownProbeId \}\)')
Assert-That '  ...and an orphan still gets a description' ($text -match 'has no entry in the shipped port list')

Write-Host 'NNR: untested is not unresolvable' -ForegroundColor Cyan
# A target whose every method was never probed rendered a red "0/1" captioned "Lowers the name
# resolution rate" - an assertion about observed traffic, made about traffic never observed - while
# the issue table on the same page correctly said it could not be tested.
Assert-That 'statistics expose an untested NNR count' ($text -match 'NnrUntested       = \$nnrUntested\.Count')
Assert-That '  ...derived with the shared not-tested pattern' ($text -match '\$nnrMeasuredIn = \{')
Assert-That '  ...and untested alone tones the card amber, not red' ($text -match "elseif \(\`$nnrUnmeasured2 -gt 0\) \{ 'warn' \}")
Assert-That '  ...while a measured failure still tones it red' ($text -match "elseif \(\`$nnrFailed2 -gt 0\) \{ 'bad' \}")

Write-Host 'Counting collections' -ForegroundColor Cyan
Assert-That '@($null).Count is 1 (the trap this guards)' (@($null).Count -eq 1)
Assert-That 'the DC badge filters out empty entries' ($text -match "DomainControllers \| Where-Object \{ \`$_ \}\)\.Count")
Assert-That '  ...so an all-null collection counts zero' ((@($null, $null) | Where-Object { $_ }).Count -eq 0)

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
