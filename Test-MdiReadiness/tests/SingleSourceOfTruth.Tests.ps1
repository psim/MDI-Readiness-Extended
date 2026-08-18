<#
    Structural guarantees, not individual defects.

    Roughly half of every defect in this project's history had one shape: a fact computed independently
    in two or three places, which then drifted apart. Fixing an instance leaves the shape intact, and
    the next instance appears somewhere else - that is exactly what happened when the trend plot was
    corrected and the trend delta beside it was not.

    These tests pin the structure rather than the instances: each fact has ONE definition, every
    surface reads it from there, and the duplicated forms cannot come back.
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

Write-Host 'One denominator rule for every readiness percentage' -ForegroundColor Cyan
# Unread checks belong in the denominator. Leaving them out answers "of what I managed to look at,
# how many passed" and presents it as though it described the estate.
Assert-That '8 passed of 10 measured with no unread is 80%' ((Get-mdiCoveragePercent -Passed 8 -Measured 10 -Unread 0) -eq 80)
Assert-That '8 passed of 10 measured with 40 unread is 16%' ((Get-mdiCoveragePercent -Passed 8 -Measured 10 -Unread 40) -eq 16)
Assert-That 'a fully unread population is 0%, not a divide by zero' ((Get-mdiCoveragePercent -Passed 0 -Measured 0 -Unread 5) -eq 0)
Assert-That 'an empty population is 0%, not an exception' ((Get-mdiCoveragePercent -Passed 0 -Measured 0 -Unread 0) -eq 0)
Assert-That 'nulls are treated as zero, not as an error' ((Get-mdiCoveragePercent -Passed $null -Measured $null -Unread $null) -eq 0)
Assert-That 'a negative unread cannot inflate the score' ((Get-mdiCoveragePercent -Passed 5 -Measured 10 -Unread -100) -eq 50)
Assert-That 'strings from a JSON round-trip still compute' ((Get-mdiCoveragePercent -Passed '8' -Measured '10' -Unread '40') -eq 16)
Assert-That 'the denominator helper agrees with the percentage' (
    (Get-mdiCoverageDenominator -Measured 10 -Unread 40) -eq 50)
Assert-That '  ...and floors negatives to zero' ((Get-mdiCoverageDenominator -Measured 10 -Unread -5) -eq 10)

# The formula must exist in ONE place. It was duplicated six times; five were corrected in one pass
# and the sixth was missed, which is how "-> 0 pt" came to sit under a line that had fallen 64 points.
$inlineDenominator = [regex]::Matches($text, '\$total \+ \$unread|ChecksTotal \+ \$stats\.ChecksUnread')
Assert-That 'no inline "measured + unread" survives' ($inlineDenominator.Count -eq 0) "(found $($inlineDenominator.Count))"
$percentSites = [regex]::Matches($text, '\* 100')
Assert-That 'percentage arithmetic is concentrated' ($percentSites.Count -le 4) "(found $($percentSites.Count))"

Write-Host 'One definition of a ready server' -ForegroundColor Cyan
function New-Score($total, $failed, $unread) { [PSCustomObject]@{ Total = $total; Failed = $failed; Unread = $unread } }
Assert-That 'all measured and all passing is ready' (Test-mdiServerIsReady -Score (New-Score 5 0 0))
Assert-That 'a measured failure is not ready' (-not (Test-mdiServerIsReady -Score (New-Score 5 1 0)))
Assert-That 'an unread check is not ready' (-not (Test-mdiServerIsReady -Score (New-Score 5 0 1)))
Assert-That 'a server with nothing measured is not ready' (-not (Test-mdiServerIsReady -Score (New-Score 0 0 5)))
Assert-That 'a null score is not ready, and does not throw' (-not (Test-mdiServerIsReady -Score $null))
$inlineReady = [regex]::Matches($text, '\.Total -gt 0 -and \$_\.Failed -eq 0 -and \$_\.Unread -eq 0')
Assert-That 'no inline ready predicate survives' ($inlineReady.Count -eq 0) "(found $($inlineReady.Count))"

Write-Host 'One definition of an unmeasured mandatory probe' -ForegroundColor Cyan
# The score, the findings table and the exit code are the three surfaces an operator acts on. This
# filter was written three times, which is three chances for them to disagree.
# Success is carried explicitly, as every REAL record does. Verified against a live 1 MB lab report:
# 202 of 220 records held a boolean Success, and all 18 that did not were already not-applicable
# "Not tested" rows. A synthetic record omitting Success is not a shape the scan can produce, and
# testing with one asserted the wrong thing - Test-mdiProbeWasMeasured requires a real boolean
# precisely because a Success normalised to $null was counted as a MEASURED BLOCKED PORT, sending an
# operator to open a firewall port on a probe that had produced no result.
$measured = [PSCustomObject]@{ Requirement = 'Required'; Applicable = $true; Success = $false; Detail = 'Connection refused' }
$notRun = [PSCustomObject]@{ Requirement = 'Required'; Applicable = $true; Success = $null; Detail = 'Not tested - access denied' }
$notApplicable = [PSCustomObject]@{ Requirement = 'Required'; Applicable = $false; Success = $null; Detail = 'Not applicable' }
$optional = [PSCustomObject]@{ Requirement = 'Recommended'; Applicable = $true; Success = $null; Detail = 'Not tested - access denied' }
# Applied, no not-tested marker, but no boolean result either: unmeasured, not a measured failure.
$noResult = [PSCustomObject]@{ Requirement = 'Required'; Applicable = $true; Success = $null; Detail = 'Connection refused' }
Assert-That 'a probe that never ran is unmeasured' (@(Get-mdiUnmeasuredRequiredProbe -Record @($notRun)).Count -eq 1)
Assert-That 'a measured failure is NOT unmeasured' (@(Get-mdiUnmeasuredRequiredProbe -Record @($measured)).Count -eq 0)
Assert-That 'a not-applicable probe is not counted' (@(Get-mdiUnmeasuredRequiredProbe -Record @($notApplicable)).Count -eq 0)
Assert-That 'an optional probe is not counted' (@(Get-mdiUnmeasuredRequiredProbe -Record @($optional)).Count -eq 0)
Assert-That 'an empty record set yields nothing' (@(Get-mdiUnmeasuredRequiredProbe -Record @()).Count -eq 0)
# The case the tightened predicate exists for: applied, no not-tested marker, but no boolean result.
# Counting it as a measured failure reported a blocked port that nobody had observed shut.
Assert-That 'a probe with no boolean result is unmeasured, not a measured failure' (@(Get-mdiUnmeasuredRequiredProbe -Record @($noResult)).Count -eq 1)
Assert-That 'a null record set yields nothing and does not throw' (@(Get-mdiUnmeasuredRequiredProbe -Record $null).Count -eq 0)
$helperCalls = [regex]::Matches($text, 'Get-mdiUnmeasuredRequiredProbe -Record')
Assert-That 'every consumer routes through the helper' ($helperCalls.Count -ge 3) "(found $($helperCalls.Count))"

Write-Host 'Facts survive the surfaces that display them' -ForegroundColor Cyan
# End to end: the score card, the bar chart and the trend must all describe the same estate the same
# way. This is the assertion that would have caught the "1/1 (100%)" bar beside a "20%" score card.
$scores = @(New-Score 1 0 4)
$barSeries = @([PSCustomObject]@{ Label = 'dc1'; Value = 1; Total = 1; Unread = 4; Hint = 'h' })
$barHtml = New-mdiBarChart -Bar $barSeries
$scorePct = [int] [math]::Floor((Get-mdiCoveragePercent -Passed 1 -Measured 1 -Unread 4))
Assert-That 'the score card and the bar agree on the same server' (
    $barHtml -match ("\({0}%\)" -f $scorePct)) "(score card says $scorePct%)"
Assert-That '  ...and neither of them says 100%' ($barHtml -notmatch '100%' -and $scorePct -ne 100)
Assert-That '  ...and the server is not counted as ready' (-not (Test-mdiServerIsReady -Score $scores[0]))

Write-Host 'The trend cannot compare runs that measured different things' -ForegroundColor Cyan
$cn = @(1..5 | ForEach-Object { "Check$_" }); $sn = @('dc1')
function New-Point($stamp, $passed, $total, $unread, $version) {
    [PSCustomObject]@{ Timestamp = $stamp; ChecksPassed = $passed; ChecksTotal = $total; ChecksUnread = $unread
        CheckNames = $cn; ServerNames = $sn; ScriptVersion = $version }
}
function Get-Pill($svg) { [regex]::Match($svg, '<span class="pill[^"]*">([^<]*)</span>').Groups[1].Value }
# A change in this tool's own strictness must never render as the customer's estate improving.
$versionChange = Get-Pill (New-mdiTrendChart -History @(
        (New-Point '2026-08-01T09:00:00' 3 5 0 '2.1.0'), (New-Point '2026-08-08T09:00:00' 5 5 0 '3.0.0')))
Assert-That 'a scanner version change is not an improvement' ($versionChange -match 'Not comparable') "($versionChange)"
Assert-That '  ...and it says which versions' ($versionChange -match '2\.1\.0.*3\.0\.0')
# A history written before ScriptVersion existed must still compare on the other guards.
$noVersion = Get-Pill (New-mdiTrendChart -History @(
        (New-Point '2026-08-01T09:00:00' 3 5 0 $null), (New-Point '2026-08-08T09:00:00' 5 5 0 $null)))
Assert-That 'a history with no version still produces a delta' ($noVersion -match 'pt vs previous run') "($noVersion)"
# Same version, same coverage: a real delta.
$realDelta = Get-Pill (New-mdiTrendChart -History @(
        (New-Point '2026-08-01T09:00:00' 3 5 0 '3.0.0'), (New-Point '2026-08-08T09:00:00' 5 5 0 '3.0.0')))
Assert-That 'a genuine improvement under one version is reported' ($realDelta -match '&uarr; 40 pt') "($realDelta)"

Write-Host 'A blocked required port never disappears' -ForegroundColor Cyan
# @($null).Count is 1, so a report with no Results property counted as HAVING results: the legacy
# path was skipped, the measurement path had nothing to work with, and the port vanished from both.
function New-PortReport($details) {
    $s = [PSCustomObject]@{ FQDN = 'dc1.contoso.com'; Unreachable = $false; PartialFailure = $false; RequiredPorts = $false
        Details = [PSCustomObject]@{ RequiredPortsDetails = $details } }
    [PSCustomObject]@{ DomainControllers = @($s); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'; Forest = 'contoso.com' }
}
function Get-NetworkIssue($report) {
    @(Get-mdiIssueList -Statistics (Get-mdiReportStatistics -ReportData $report) -ReportData $report |
        Where-Object { $_.Area -eq 'Network' })
}
$rec = [PSCustomObject]@{ Id = 'LdapTcp'; Name = 'LDAP'; Group = 'LDAP'; Scope = 'DomainController'
    Protocol = 'TCP'; Port = 389; Target = 'dc1.contoso.com'; TargetIP = '10.0.0.1'
    Requirement = 'Required'; Success = $false; Applicable = $true; Detail = 'Connection refused' }

$modern = @(Get-NetworkIssue (New-PortReport ([PSCustomObject]@{
            FailedRequired = @('TCP 389 to dc1.contoso.com'); NnrFailedTargets = @(); Results = @($rec) })))
Assert-That 'a current report reports the port exactly once' ($modern.Count -eq 1) "(got $($modern.Count))"
Assert-That '  ...with text an operator can act on' (-not [string]::IsNullOrWhiteSpace([string] $modern[0].Issue))

$legacy = @(Get-NetworkIssue (New-PortReport ([PSCustomObject]@{
            FailedRequired = @('TCP 389 to dc1.contoso.com'); NnrFailedTargets = @() })))
Assert-That 'a report with no Results still reports the port' ($legacy.Count -eq 1) "(got $($legacy.Count))"

$nullResults = @(Get-NetworkIssue (New-PortReport ([PSCustomObject]@{
            FailedRequired = @('TCP 389 to dc1.contoso.com'); NnrFailedTargets = @(); Results = $null })))
Assert-That 'an explicitly null Results still reports the port' ($nullResults.Count -eq 1) "(got $($nullResults.Count))"

Write-Host 'Degenerate inputs never throw and never flatter' -ForegroundColor Cyan
# These helpers are read while assembling the report and while drawing the trend. A throw here loses
# the WHOLE report, not one row, so every malformed shape must degrade to a conservative number.
Assert-That 'a count beyond Int32 does not throw' ((Get-mdiCoverageCount -Value 3000000000) -eq 3000000000)
Assert-That 'a non-numeric string counts as zero' ((Get-mdiCoverageCount -Value 'N/A') -eq 0)
Assert-That 'a null counts as zero' ((Get-mdiCoverageCount -Value $null) -eq 0)
Assert-That 'a negative counts as zero' ((Get-mdiCoverageCount -Value -50) -eq 0)
Assert-That 'a numeric string parses' ((Get-mdiCoverageCount -Value '42') -eq 42)
# A huge unread count used to overflow [int] to zero and report a perfect score.
Assert-That 'a huge unread count does not report 100%' ((Get-mdiCoveragePercent -Passed 5 -Measured 5 -Unread 3000000000) -lt 1)
Assert-That 'passed cannot exceed the covered population' ((Get-mdiCoveragePercent -Passed 20 -Measured 10 -Unread 0) -eq 100)

# Test-mdiServerIsReady decides, for one server, the yes-or-no the whole report reduces to.
Assert-That "a score with 'N/A' fields is not ready, and does not throw" (
    -not (Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = 'N/A'; Failed = 'N/A'; Unread = 'N/A' })))
# $null -eq 0 is TRUE in PowerShell, so a score missing Failed/Unread used to report READY - a server
# whose failures were unknown, presented as fully compliant.
Assert-That 'a score missing Failed and Unread is NOT ready' (
    -not (Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = 5 })))
Assert-That 'a score with a null Failed is NOT ready' (
    -not (Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = 5; Failed = $null; Unread = 0 })))
Assert-That '  ...but a complete passing score still is' (
    Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = 5; Failed = 0; Unread = 0 }))

# A corrupted count must never certify a server as compliant. Get-mdiCoverageCount floors a nonsense
# value to zero, which is right for a PERCENTAGE - it contributes nothing - but catastrophic here,
# because zero failures is exactly the condition that makes a server ready. Measured: Failed = -1 and
# Failed = 'NaN' both reported READY before these guards were added.
Assert-That 'a negative failure count is NOT ready' (
    -not (Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = 5; Failed = -1; Unread = 0 })))
Assert-That "a 'NaN' failure count is NOT ready" (
    -not (Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = 5; Failed = 'NaN'; Unread = 0 })))
Assert-That 'a negative unread count is NOT ready' (
    -not (Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = 5; Failed = 0; Unread = -3 })))
Assert-That 'an infinite count is NOT ready' (
    -not (Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = 'Infinity'; Failed = 0; Unread = 0 })))
Assert-That 'a boolean masquerading as a count is NOT ready' (
    -not (Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = 5; Failed = $false; Unread = 0 })))
# String-typed counts from a JSON round-trip must still work.
Assert-That 'string counts from a JSON round-trip still resolve' (
    Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = '5'; Failed = '0'; Unread = '0' }))
Assert-That '  ...and a string failure count is still a failure' (
    -not (Test-mdiServerIsReady -Score ([PSCustomObject]@{ Total = '5'; Failed = '2'; Unread = '0' })))

Write-Host 'The trend keeps the runs that measured nothing' -ForegroundColor Cyan
# Local helpers: this file must not depend on definitions in a sibling test file.
$trendChecks = @(1..5 | ForEach-Object { "Check$_" })
$trendServers = @('dc1')
function New-TrendPoint($stamp, $passed, $total, $unread) {
    [PSCustomObject]@{ Timestamp = $stamp; ChecksPassed = $passed; ChecksTotal = $total; ChecksUnread = $unread
        CheckNames = $trendChecks; ServerNames = $trendServers; ScriptVersion = '1.1.0' }
}
function Get-TrendPill($svg) { [regex]::Match($svg, '<span class="pill[^"]*">([^<]*)</span>').Groups[1].Value }

# A run where the estate became unreadable has a well-defined 0% coverage and IS written to the
# baseline. Gating the chart on ChecksTotal deleted it: a three-run history plotted two points, the
# x-axis jumped over the blind week, and the pill read "up 20 pt" straight across it.
$blindSvg = New-mdiTrendChart -History @(
    (New-TrendPoint '2026-08-04T09:00:00' 4 5 0)
    (New-TrendPoint '2026-08-11T09:00:00' 0 0 5)
    (New-TrendPoint '2026-08-18T09:00:00' 5 5 0))
Assert-That 'a blind run is still plotted' (([regex]::Matches($blindSvg, '<circle class="trend-dot')).Count -eq 3)
Assert-That '  ...and the delta is not drawn across it' ((Get-TrendPill $blindSvg) -notmatch '20 pt')
$twoRunBlind = New-mdiTrendChart -History @(
    (New-TrendPoint '2026-08-04T09:00:00' 4 5 0), (New-TrendPoint '2026-08-11T09:00:00' 0 0 5))
Assert-That 'two runs including a blind one still chart' ($twoRunBlind -notmatch 'At least two runs are needed')
Assert-That 'an entry with no counts at all is discarded' (
    (New-mdiTrendChart -History @((New-TrendPoint '2026-08-04T09:00:00' 4 5 0), [PSCustomObject]@{ Timestamp = 'x' })) -match 'At least two runs')

Write-Host 'The console and the HTML report the same fraction' -ForegroundColor Cyan
# Behavioural. The previous version asserted on source shape and was proven vacuous by mutation: the
# console denominator was reverted to ChecksTotal on its own line, with a decoy comment left in
# place, and the suite still reported 62/0. A source-shape assertion only pins the shape it happened
# to be written against.
#
# The console line is built from $stats, so the honest check is that the SAME statistics produce the
# same fraction on both surfaces.
$consoleEstate = [PSCustomObject]@{
    DomainControllers = @(
        [PSCustomObject]@{ FQDN = 'dc1'; Unreachable = $false; PartialFailure = $false; OSVersion = $true; AdvancedAuditing = $true; Details = [PSCustomObject]@{} }
        [PSCustomObject]@{ FQDN = 'dc2'; Unreachable = $false; PartialFailure = $false; OSVersion = $true; AdvancedAuditing = 'N/A'; Details = [PSCustomObject]@{} }
        [PSCustomObject]@{ FQDN = 'dc3'; Unreachable = $false; PartialFailure = $false; OSVersion = $true; AdvancedAuditing = 'N/A'; Details = [PSCustomObject]@{} }
        [PSCustomObject]@{ FQDN = 'dc4'; Unreachable = $false; PartialFailure = $false; OSVersion = $true; AdvancedAuditing = 'N/A'; Details = [PSCustomObject]@{} })
    CAServers = @(); EntraConnectServers = @()
    DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'; Forest = 'contoso.com'
}
$consoleStats = Get-mdiReportStatistics -ReportData $consoleEstate
$consoleDenominator = Get-mdiCoverageDenominator -Measured $consoleStats.ChecksTotal -Unread $consoleStats.ChecksUnread
Assert-That 'the shared denominator counts unread checks' ($consoleDenominator -gt $consoleStats.ChecksTotal) `
    "(denominator $consoleDenominator vs measured $($consoleStats.ChecksTotal))"
Assert-That '  ...so the console fraction is not measured-only' ($consoleDenominator -eq ($consoleStats.ChecksTotal + $consoleStats.ChecksUnread))
# And the HTML score card must state the very same fraction.
$consoleHtml = Get-mdiOverviewHtml -ReportData $consoleEstate -Statistics $consoleStats
$cardFraction = [regex]::Match($consoleHtml, '(\d+) of (\d+) checks passed')
Assert-That 'the score card states the shared denominator' (
    $cardFraction.Success -and ([int] $cardFraction.Groups[2].Value) -eq [int] $consoleDenominator) `
    "(card says $($cardFraction.Groups[2].Value), shared denominator is $([int]$consoleDenominator))"

# The console line itself, executed. Get-mdiVerdictQualifier and the format string are exercised the
# way Main uses them, so a call site reverted to ChecksTotal produces a visibly different fraction.
$consoleLine = '  {0} issue(s) found: {1}/{2} checks passed across {3} server(s).' -f
    3, $consoleStats.ChecksPassed,
    (Get-mdiCoverageDenominator -Measured $consoleStats.ChecksTotal -Unread $consoleStats.ChecksUnread),
    $consoleStats.TotalServers
"    console line would read: $consoleLine"
Assert-That 'the console line quotes the covered population' ($consoleLine -match "/$([int]$consoleDenominator) checks passed")
Assert-That '  ...not the measured-only total' (
    ($consoleStats.ChecksTotal -eq $consoleDenominator) -or ($consoleLine -notmatch "/$([int]$consoleStats.ChecksTotal) checks passed"))
# And Main must be wired to that denominator, not to ChecksTotal - checked on the parsed command
# rather than on raw source text, so a decoy comment cannot satisfy it.
$mainRegion = $text.Substring($text.IndexOf('#region Main'))
$mainAst = [System.Management.Automation.Language.Parser]::ParseInput($mainRegion, [ref]$null, [ref]$null)
$consoleCalls = $mainAst.FindAll({
        param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
        $n.GetCommandName() -eq 'Write-mdiConsole' -and $n.Extent.Text -match 'checks passed'
    }, $true)
Assert-That 'both console verdict lines exist' ($consoleCalls.Count -ge 2) "(found $($consoleCalls.Count))"

# A call site may reach the shared denominator EITHER by calling Get-mdiCoverageDenominator inline or
# by using a variable that Main assigned from exactly that call. Demanding the inline call made this
# assertion fail on a refactor that IMPROVED the code - the three verdict lines were changed to share
# one $coverageDenominator computed once, which is the very rule this file exists to enforce, and the
# test called it "still on ChecksTotal" when none of them mentions ChecksTotal at all.
#
# So the variables are resolved first, from assignments whose right-hand side really is that call, and
# a call site passes if it uses one of them. The thing that must NOT appear is a raw ChecksTotal.
$sharedVars = @($mainAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Right.Extent.Text -match 'Get-mdiCoverageDenominator' -and
            $n.Left -is [System.Management.Automation.Language.VariableExpressionAst]
        }, $true) | ForEach-Object { $_.Left.VariablePath.UserPath } | Select-Object -Unique)
Assert-That '  the shared denominator is computed once into a variable' ($sharedVars.Count -ge 1) `
    "(assignments found: $($sharedVars -join ', '))"
$badConsole = @($consoleCalls | Where-Object {
        $callText = $_.Extent.Text
        $usesShared = ($callText -match 'Get-mdiCoverageDenominator') -or
            @($sharedVars | Where-Object { $callText -match ('\$' + [regex]::Escape($_) + '\b') }).Count -gt 0
        -not $usesShared
    })
Assert-That '  ...and every one uses the shared denominator' ($badConsole.Count -eq 0) `
    "($($badConsole.Count) reach it by neither the call nor a shared variable)"
$rawTotal = @($consoleCalls | Where-Object { $_.Extent.Text -match 'ChecksTotal' })
Assert-That '  ...and none quotes the measured-only total directly' ($rawTotal.Count -eq 0) `
    "($($rawTotal.Count) still on ChecksTotal)"

Write-Host 'Every template substitution is encoded' -ForegroundColor Cyan
Assert-That 'the verdict text is HTML-encoded' ($text -match "Replace\('@@VERDICTTEXT@@', \(ConvertTo-mdiHtmlEncoded")

Write-Host 'The version guard is tolerant of formatting, strict on content' -ForegroundColor Cyan
function New-VersionPoint($stamp, $version) {
    [PSCustomObject]@{ Timestamp = $stamp; ChecksPassed = 3; ChecksTotal = 5; ChecksUnread = 0
        CheckNames = $trendChecks; ServerNames = $trendServers; ScriptVersion = $version }
}
$wsPill = Get-TrendPill (New-mdiTrendChart -History @(
        (New-VersionPoint '2026-08-01T09:00:00' ' 1.1.0 '), (New-VersionPoint '2026-08-08T09:00:00' '1.1.0')))
Assert-That 'whitespace is not a version change' ($wsPill -match 'pt vs previous run') "($wsPill)"
$casePill = Get-TrendPill (New-mdiTrendChart -History @(
        (New-VersionPoint '2026-08-01T09:00:00' '2.0.0-RC'), (New-VersionPoint '2026-08-08T09:00:00' '2.0.0-rc')))
Assert-That 'case is not a version change' ($casePill -match 'pt vs previous run') "($casePill)"
$realPill = Get-TrendPill (New-mdiTrendChart -History @(
        (New-VersionPoint '2026-08-01T09:00:00' '1.1.0'), (New-VersionPoint '2026-08-08T09:00:00' '2.0.0')))
Assert-That 'a real version change still blocks the delta' ($realPill -match 'Not comparable') "($realPill)"

Write-Host 'A check absent from a server counts as unread, not as silence' -ForegroundColor Cyan
# Get-mdiCheckProperty drops any value that does not parse to a boolean, so an 'N/A' check is not
# merely non-boolean - it is ABSENT from that server's property list entirely. Counting only what
# each server reports made Total the number of servers the check could be READ on: a prerequisite
# readable on one server out of four rendered a full-width green "1/1 (100%)" bar while the score
# card on the same page counted three unread checks.
function New-CheckServer($name, $auditing) {
    [PSCustomObject]@{ FQDN = $name; Unreachable = $false; PartialFailure = $false
        OSVersion = $true; AdvancedAuditing = $auditing; Details = [PSCustomObject]@{} }
}
$mixedEstate = [PSCustomObject]@{
    DomainControllers = @((New-CheckServer 'dc1' $true), (New-CheckServer 'dc2' 'N/A'),
        (New-CheckServer 'dc3' 'N/A'), (New-CheckServer 'dc4' 'N/A'))
    CAServers = @(); EntraConnectServers = @()
    DomainsInScope = @('contoso.com'); Domains = @(); Domain = 'contoso.com'; Forest = 'contoso.com'
}
$mixedStats = Get-mdiReportStatistics -ReportData $mixedEstate
$auditTotals = $mixedStats.CheckTotals['AdvancedAuditing']
Assert-That 'a check read on 1 of 4 servers counts 3 unread' ($auditTotals.Unread -eq 3) "(got $($auditTotals.Unread))"
Assert-That '  ...and does not inflate its measured total' ($auditTotals.Total -eq 1) "(got $($auditTotals.Total))"
Assert-That '  ...so its bar is not 100%' (
    (New-mdiBarChart -Bar @([PSCustomObject]@{ Label = 'a'; Value = $auditTotals.Pass; Total = $auditTotals.Total
                Unread = $auditTotals.Unread; Hint = 'h' })) -notmatch '\(100%\)')
Assert-That '  ...and it agrees with the score card' ($auditTotals.Unread -eq $mixedStats.ChecksUnread)
# A check every server reported must be unaffected.
Assert-That 'a fully measured check still counts zero unread' ($mixedStats.CheckTotals['OSVersion'].Unread -eq 0)
Assert-That '  ...with every server in its total' ($mixedStats.CheckTotals['OSVersion'].Total -eq 4)

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
