<#
    EVERY CLOCK WAS COMPARED WITH THE SCANNER, AND NOTHING COMPARED THEM WITH EACH OTHER.

    The prerequisite this script quotes, and prints at the top of its own time synchronization card,
    is that the sensor servers must have their clocks synchronized to within five minutes OF EACH
    OTHER. Get-mdiTimeSync only ever compares one clock with the computer running the script.

    Those are not the same rule, and the gap is exactly a factor of two. A scanner sitting between
    two sensors that are eight minutes apart measures +4 and -4. Both are inside the tolerance, so:

        dc-east.contoso.com   Within tolerance: Yes    240 s
        dc-west.contoso.com   Within tolerance: Yes   -240 s
        VERDICT: All prerequisites met

    over an estate that fails the documented requirement by three minutes. No issue was raised, and
    the JSON recorded TimeSync=True for both. The permitted spread was twice the stated tolerance.

    This is reached by the ordinary case it was designed for: an administration workstation that is
    correctly synchronized, one sensor running slow and another running fast.

    The check is a RELATIONSHIP between servers, so it cannot live in the per-server function. It is
    stated once in Get-mdiClockSpread and read by both surfaces that need it - the card and the issue
    list - because two surfaces computing one fact separately is how they come to disagree.
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
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

function New-ClockServer {
    param([string] $Fqdn, $SkewSeconds, $TimeSync = $true, $MaxSkewMinutes = 5)
    $details = if ($null -eq $SkewSeconds) {
        [PSCustomObject]@{ Detail = 'Not tested - the remote clock could not be read'; MaxSkewMinutes = $MaxSkewMinutes }
    } else {
        [PSCustomObject]@{
            RemoteUtc = '2026-08-15 08:00:00'; ReferenceUtc = '2026-08-15 08:00:00'
            SkewSeconds = $SkewSeconds; MaxSkewMinutes = $MaxSkewMinutes
            Detail = ('Clock is within {0} second(s) of this computer' -f [math]::Abs($SkewSeconds))
        }
    }
    [PSCustomObject]@{
        FQDN = $Fqdn; TimeSync = $TimeSync
        Details = [PSCustomObject]@{ TimeSyncDetails = $details }
    }
}

Write-Host 'Two servers inside tolerance of the scanner can still be outside it of each other' -ForegroundColor Cyan
# +240 and -240: each is four minutes from the scanner, so each passes its own check, but they are
# eight minutes apart - three minutes past what MDI requires between them.
$split = @(
    (New-ClockServer -Fqdn 'dc-east.contoso.com' -SkewSeconds 240),
    (New-ClockServer -Fqdn 'dc-west.contoso.com' -SkewSeconds -240)
)
$spread = Get-mdiClockSpread -Server $split
Assert-That 'both servers were counted as measured' ($spread.Measured -eq 2) "measured=$($spread.Measured)"
Assert-That 'the spread is the full 480 seconds, not either half' (
    $spread.SpreadSeconds -eq 480) "spread=$($spread.SpreadSeconds)"
Assert-That 'and it is reported as OUTSIDE the requirement' (
    $spread.IsWithin -eq $false) "isWithin=$($spread.IsWithin)"
Assert-That 'the furthest behind is named' ($spread.Earliest -eq 'dc-west.contoso.com') "earliest=$($spread.Earliest)"
Assert-That 'the furthest ahead is named' ($spread.Latest -eq 'dc-east.contoso.com') "latest=$($spread.Latest)"

Write-Host ''
Write-Host 'The HTML card must say so, not show two green rows and stop' -ForegroundColor Cyan
$html = Get-mdiTimeSyncHtml -Server $split
Assert-That 'the per-server rows are still green, because each IS within tolerance of the scanner' (
    ([regex]::Matches($html, '<td class="green">Yes</td>')).Count -eq 2) $html
Assert-That 'the card states the spread between the servers' (
    $html -match 'span 480 second\(s\)') $html
Assert-That 'and says it exceeds the requirement' (
    $html -match 'MORE than the 5 minute\(s\)') $html
Assert-That 'and explains why every row can still read Yes' (
    $html -match 'compares one server with the computer that ran this script') $html
Assert-That 'the warning is not styled as a benign note' ($html -match '<p class="bad">') $html

Write-Host ''
Write-Host 'And an issue must be raised, so the verdict cannot read "all prerequisites met"' -ForegroundColor Cyan
$statistics = [PSCustomObject]@{ ReachableList = $split; UnreachableList = @() }
$issues = @(Get-mdiIssueList -Statistics $statistics)
$clockIssue = @($issues | Where-Object { $_.Area -eq 'Time sync' -and $_.Issue -match 'span 480 second' })
Assert-That 'a time sync issue is raised for the estate' ($clockIssue.Count -eq 1) (
    "issues: " + (($issues | ForEach-Object { $_.Issue }) -join ' | '))
Assert-That 'it is High severity' (
    $clockIssue.Count -eq 1 -and $clockIssue[0].Severity -eq 'High') "severity=$($clockIssue.Severity)"
Assert-That 'it is raised ONCE for the estate, not once per server' (
    @($issues | Where-Object { $_.Area -eq 'Time sync' }).Count -eq 1) (
    "count=$(@($issues | Where-Object { $_.Area -eq 'Time sync' }).Count)")

Write-Host ''
Write-Host 'And the VERDICT must read it - an issue nobody acts on is not a finding' -ForegroundColor Cyan
$tight = @(
    (New-ClockServer -Fqdn 'dc-a.contoso.com' -SkewSeconds 30),
    (New-ClockServer -Fqdn 'dc-b.contoso.com' -SkewSeconds -30),
    (New-ClockServer -Fqdn 'dc-c.contoso.com' -SkewSeconds 0)
) 
# Raising the issue is not enough. The verdict is what the console prints, what the HTML headline
# says, and what -FailOnIssues gates on, so a High finding that leaves the verdict READY is a finding
# the run tells the operator to ignore. Measured before this was wired in: ISSUE_COUNT=1,
# VERDICT_READY=True, HTML_VERDICT='All prerequisites met', PROCESS_EXIT=0.
function New-ReportData {
    param([object[]] $Server)
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = $Server; CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @([PSCustomObject]@{
                Domain = 'contoso.com'
                AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
                ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
                ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
                DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
            })
    }
}
# Each server carries one passing boolean check so the verdict has something measured to judge; the
# clock spread must be the ONLY thing standing between this run and READY.
foreach ($srv in $split) { $srv | Add-Member -NotePropertyName 'OSVersionOk' -NotePropertyValue $true -Force }
foreach ($srv in $tight) { $srv | Add-Member -NotePropertyName 'OSVersionOk' -NotePropertyValue $true -Force }

$splitVerdict = Test-mdiReadinessResult -ReportData @(New-ReportData -Server $split) 3>$null
Assert-That 'a run whose clocks disagree is NOT ready' (
    $splitVerdict -eq $false) "verdict=$splitVerdict"

# CONTROL: the identical fixture with clocks 60 seconds apart must still be READY, or the assertion
# above is just "the verdict is always false" and proves nothing.
$tightVerdict = Test-mdiReadinessResult -ReportData @(New-ReportData -Server $tight) 3>$null
Assert-That 'CONTROL: the same run with agreeing clocks IS ready' (
    $tightVerdict -eq $true) "verdict=$tightVerdict"

# CONTROL: a spread that could not be measured must not fail the run by itself. IsWithin is 'N/A'
# there, and 'N/A' is a truthy string - the trap this codebase rejects everywhere else.
$singleServer = @((New-ClockServer -Fqdn 'dc-only.contoso.com' -SkewSeconds 10))
$singleServer[0] | Add-Member -NotePropertyName 'OSVersionOk' -NotePropertyValue $true -Force
$singleVerdict = Test-mdiReadinessResult -ReportData @(New-ReportData -Server $singleServer) 3>$null
Assert-That 'CONTROL: one clock - an unmeasurable spread - does not fail the run' (
    $singleVerdict -eq $true) "verdict=$singleVerdict"

Write-Host ''
Write-Host 'The inverse: a wrong SCANNER clock must not fail an estate that agrees with itself' -ForegroundColor Cyan
# The mirror image of the defect above, and the one an operator hits far more often - an
# administration workstation with a wrong clock is much commoner than a split estate. Both sensors
# read the same instant, so the MDI prerequisite is satisfied with a zero-second spread, but each is
# ten minutes from the scanner. Measured before this was fixed: spread=0, IsWithin=True, and TWO High
# rows both saying "MDI requires all sensor servers to be within 5 minutes of each other" - the very
# rule the spread had just proved satisfied - plus a NOT READY verdict and a non-zero exit.
$scannerOff = @(
    (New-ClockServer -Fqdn 'sensor1.contoso.com' -SkewSeconds 600 -TimeSync $false),
    (New-ClockServer -Fqdn 'sensor2.contoso.com' -SkewSeconds 600 -TimeSync $false)
)
foreach ($srv in $scannerOff) {
    $srv | Add-Member -NotePropertyName 'OSVersionOk' -NotePropertyValue $true -Force
    $srv.Details.TimeSyncDetails | Add-Member -NotePropertyName 'Detail' `
        -NotePropertyValue 'Clock differs by 10 minute(s) - MDI requires all sensor servers to be within 5 minutes of each other' -Force
}

$offSpread = Get-mdiClockSpread -Server $scannerOff
Assert-That 'the estate itself agrees - a zero second spread' (
    $offSpread.SpreadSeconds -eq 0 -and $offSpread.IsWithin -eq $true) (
    "spread=$($offSpread.SpreadSeconds) isWithin=$($offSpread.IsWithin)")

$offIssues = @(Get-mdiIssueList -Statistics ([PSCustomObject]@{ ReachableList = $scannerOff; UnreachableList = @() }))
$offClock = @($offIssues | Where-Object { $_.Area -eq 'Time sync' })
Assert-That 'no High time-sync row is raised against the servers' (
    @($offClock | Where-Object { $_.Severity -eq 'High' }).Count -eq 0) (
    'rows: ' + (($offClock | ForEach-Object { $_.Severity + '/' + $_.Issue }) -join ' | '))
Assert-That 'the scanner clock is reported once, not once per server' (
    $offClock.Count -eq 1) "count=$($offClock.Count)"
Assert-That 'and it is Medium, because nothing about the estate is wrong' (
    $offClock.Count -eq 1 -and $offClock[0].Severity -eq 'Medium') "severity=$($offClock.Severity)"
Assert-That 'it says the requirement IS met' (
    $offClock.Count -eq 1 -and $offClock[0].Issue -match 'requirement is met') "issue=$($offClock.Issue)"
Assert-That 'and it points at the scanning computer, not the estate' (
    $offClock.Count -eq 1 -and $offClock[0].Issue -match 'scanning computer') "issue=$($offClock.Issue)"
# The decisive one: a correct estate must not be failed by a wrong wristwatch.
$offVerdict = Test-mdiReadinessResult -ReportData @(New-ReportData -Server $scannerOff) 3>$null
Assert-That 'the run is READY - the prerequisite is satisfied' (
    $offVerdict -eq $true) "verdict=$offVerdict"

Write-Host ''
Write-Host 'CONTROL - a genuinely split estate is still failed, even though it also fails against the scanner' -ForegroundColor Cyan
# Both servers ten minutes from the scanner AND twenty minutes from each other. The spread is the
# real failure and must still be caught; the exclusion above must not swallow it.
$reallySplit = @(
    (New-ClockServer -Fqdn 'sensor1.contoso.com' -SkewSeconds 600 -TimeSync $false),
    (New-ClockServer -Fqdn 'sensor2.contoso.com' -SkewSeconds -600 -TimeSync $false)
)
foreach ($srv in $reallySplit) { $srv | Add-Member -NotePropertyName 'OSVersionOk' -NotePropertyValue $true -Force }
$splitSpread = Get-mdiClockSpread -Server $reallySplit
Assert-That 'CONTROL: the spread is measured as outside tolerance' (
    $splitSpread.IsWithin -eq $false) "spread=$($splitSpread.SpreadSeconds)"
$splitIssues = @(Get-mdiIssueList -Statistics ([PSCustomObject]@{ ReachableList = $reallySplit; UnreachableList = @() }))
Assert-That 'CONTROL: High time-sync rows are still raised' (
    @($splitIssues | Where-Object { $_.Area -eq 'Time sync' -and $_.Severity -eq 'High' }).Count -ge 1) (
    'rows: ' + (($splitIssues | Where-Object { $_.Area -eq 'Time sync' } | ForEach-Object { $_.Severity }) -join ', '))
Assert-That 'CONTROL: and the run is NOT ready' (
    (Test-mdiReadinessResult -ReportData @(New-ReportData -Server $reallySplit) 3>$null) -eq $false)

# The spread row must not claim something this run measured as FALSE. Both these servers also failed
# their own scanner-relative check, so the "each is individually within tolerance" clause - which is
# the right thing to say when the scanner sits between two drifting sensors - would be a lie here.
$splitSpreadRow = @($splitIssues | Where-Object { $_.Issue -match 'span \d+ second' })
Assert-That 'CONTROL: the spread row exists' ($splitSpreadRow.Count -eq 1) "count=$($splitSpreadRow.Count)"
Assert-That 'CONTROL: and does NOT claim each server was within scanner tolerance' (
    $splitSpreadRow.Count -eq 1 -and
    $splitSpreadRow[0].Issue -notmatch 'individually within tolerance') "issue=$($splitSpreadRow.Issue)"
Assert-That 'CONTROL: it says how many also failed against the scanner' (
    $splitSpreadRow.Count -eq 1 -and
    $splitSpreadRow[0].Issue -match 'also outside tolerance') "issue=$($splitSpreadRow.Issue)"

# And the inverse: when every server IS within scanner tolerance, the clause is TRUE and explains why
# the per-server rows all look fine. $split is the morning's case - +240 and -240, both compliant.
$originalSpreadRow = @($issues | Where-Object { $_.Issue -match 'span 480 second' })
Assert-That 'CONTROL: with all servers scanner-compliant the clause IS stated' (
    $originalSpreadRow.Count -eq 1 -and
    $originalSpreadRow[0].Issue -match 'individually within tolerance') "issue=$($originalSpreadRow.Issue)"

# A single server has no estate to appeal to, so its scanner-relative failure must still count.
$loneBadClock = @((New-ClockServer -Fqdn 'sensor1.contoso.com' -SkewSeconds 600 -TimeSync $false))
$loneBadClock[0] | Add-Member -NotePropertyName 'OSVersionOk' -NotePropertyValue $true -Force
$loneIssues = @(Get-mdiIssueList -Statistics ([PSCustomObject]@{ ReachableList = $loneBadClock; UnreachableList = @() }))
Assert-That 'CONTROL: one server with a bad clock is still a High finding' (
    @($loneIssues | Where-Object { $_.Area -eq 'Time sync' -and $_.Severity -eq 'High' }).Count -eq 1) (
    'rows: ' + (($loneIssues | Where-Object { $_.Area -eq 'Time sync' } | ForEach-Object { $_.Severity + '/' + $_.Issue }) -join ' | '))
Assert-That 'CONTROL: and it is NOT ready, since there is no estate to appeal to' (
    (Test-mdiReadinessResult -ReportData @(New-ReportData -Server $loneBadClock) 3>$null) -eq $false)

Write-Host ''
Write-Host 'CONTROLS - a healthy estate must not be accused of drift' -ForegroundColor Cyan
$tightSpread = Get-mdiClockSpread -Server $tight
Assert-That 'CONTROL: a 60 second spread is within tolerance' (
    $tightSpread.IsWithin -eq $true) "spread=$($tightSpread.SpreadSeconds) isWithin=$($tightSpread.IsWithin)"
Assert-That 'CONTROL: no issue is raised for it' (
    @(@(Get-mdiIssueList -Statistics ([PSCustomObject]@{ ReachableList = $tight; UnreachableList = @() })) |
            Where-Object { $_.Area -eq 'Time sync' }).Count -eq 0)
Assert-That 'CONTROL: the card reports the spread as inside the requirement' (
    (Get-mdiTimeSyncHtml -Server $tight) -match 'span 60 second\(s\), inside the 5 minute\(s\)')

# A single server has nothing to be spread against. Zero would read as "they agree", which is the
# same false green this file exists to remove, so it must come back unmeasured instead.
$single = @((New-ClockServer -Fqdn 'dc-only.contoso.com' -SkewSeconds 10))
$singleSpread = Get-mdiClockSpread -Server $single
Assert-That 'CONTROL: one clock is not a spread of zero, it is unmeasured' (
    $null -eq $singleSpread.SpreadSeconds -and [string] $singleSpread.IsWithin -eq 'N/A') (
    "spread=$($singleSpread.SpreadSeconds) isWithin=$($singleSpread.IsWithin)")
Assert-That 'CONTROL: and the card says the spread was not measured' (
    (Get-mdiTimeSyncHtml -Server $single) -match 'Fewer than two clocks were read')

# A clock that could not be read carries no skew and must not be treated as skew 0 - that would drag
# the spread down and hide a real one.
$withUnread = @(
    (New-ClockServer -Fqdn 'dc-east.contoso.com' -SkewSeconds 240),
    (New-ClockServer -Fqdn 'dc-west.contoso.com' -SkewSeconds -240),
    (New-ClockServer -Fqdn 'dc-dead.contoso.com' -SkewSeconds $null -TimeSync 'N/A')
)
$unreadSpread = Get-mdiClockSpread -Server $withUnread
Assert-That 'CONTROL: an unreadable clock is excluded rather than counted as zero' (
    $unreadSpread.Measured -eq 2 -and $unreadSpread.SpreadSeconds -eq 480) (
    "measured=$($unreadSpread.Measured) spread=$($unreadSpread.SpreadSeconds)")

# The tolerance travels with the measurement, so a run made with a custom -MaxClockSkewMinutes is
# judged by the value it was taken under rather than by the default.
$loose = @(
    (New-ClockServer -Fqdn 'dc-east.contoso.com' -SkewSeconds 240 -MaxSkewMinutes 10),
    (New-ClockServer -Fqdn 'dc-west.contoso.com' -SkewSeconds -240 -MaxSkewMinutes 10)
)
$looseSpread = Get-mdiClockSpread -Server $loose
Assert-That 'CONTROL: a 10 minute tolerance accepts the same 480 second spread' (
    $looseSpread.IsWithin -eq $true -and $looseSpread.MaxSkewMinutes -eq 10) (
    "isWithin=$($looseSpread.IsWithin) tolerance=$($looseSpread.MaxSkewMinutes)")

Write-Host ''
Write-Host 'The SCORE must follow the verdict, not contradict it' -ForegroundColor Cyan
# The verdict and the issue list already refuse a split estate. The headline numbers did not: a run
# whose clocks were 480 seconds apart rendered "Overall check score 100% - 8 of 8 checks passed" in
# green, a "Servers fully ready 2/2 - All checks passed" tile and a solid-green donut, directly
# beside a hero verdict of "Action required" and a High finding. One estate, described two ways on
# one page - which is the defect class this codebase spends most of its guards on.
#
# $split is the fixture that isolates it: +240 and -240, so EVERY per-server check passes and the
# ONLY thing wrong is the relationship between them. Using a fixture whose servers also fail their
# own TimeSync check would charge the score by that route instead, and the assertion would pass
# whether or not the estate charge exists - which is exactly what happened on the first attempt, and
# the mutation test caught it by not going red.
$splitStats = Get-mdiReportStatistics -ReportData (New-ReportData -Server $split)
Assert-That 'the clock failure is charged to the score' (
    [int] $splitStats.ChecksPassed -lt [int] $splitStats.ChecksTotal) (
    "passed=$($splitStats.ChecksPassed) total=$($splitStats.ChecksTotal)")
Assert-That 'so the coverage percentage is not a perfect 100' (
    (Get-mdiCoveragePercent -Passed $splitStats.ChecksPassed -Measured $splitStats.ChecksTotal -Unread $splitStats.ChecksUnread) -lt 100) (
    "percent=$(Get-mdiCoveragePercent -Passed $splitStats.ChecksPassed -Measured $splitStats.ChecksTotal -Unread $splitStats.ChecksUnread)")
# It is charged as a measured FAILURE, not as an unread check - two clocks were read and their
# difference is known.
Assert-That 'and it is charged as a failure, not as unread' (
    [int] $splitStats.ChecksUnread -eq 0) "unread=$($splitStats.ChecksUnread)"

# CONTROL: a healthy estate must still score a clean 100, or the assertion above is just "the score
# is never 100".
$tightStats = Get-mdiReportStatistics -ReportData (New-ReportData -Server $tight)
Assert-That 'CONTROL: an estate whose clocks agree still scores every check passed' (
    [int] $tightStats.ChecksPassed -eq [int] $tightStats.ChecksTotal) (
    "passed=$($tightStats.ChecksPassed) total=$($tightStats.ChecksTotal)")
# CONTROL: an unmeasurable spread must not be charged either.
$singleStats = Get-mdiReportStatistics -ReportData (New-ReportData -Server $singleServer)
Assert-That 'CONTROL: one clock - an unmeasurable spread - is not charged as a failure' (
    [int] $singleStats.ChecksPassed -eq [int] $singleStats.ChecksTotal) (
    "passed=$($singleStats.ChecksPassed) total=$($singleStats.ChecksTotal)")

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
