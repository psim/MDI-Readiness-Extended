# Two KPI cards on one overview strip disagreed about the same run.
#
# "Servers fully ready" describes SERVERS, and every count feeding its sub-label ($readyServers,
# $needAttention, $trulyUnmeasured, $notReady) is derived from real server rows. A per-domain
# directory check belongs to no single server, so when one of them FAILED every one of those counts
# was legitimately zero - and the failure is not unread, so the estate-level branch that already
# existed for unread gaps did not catch it either. The tile fell through to a green
# "1/1 - All checks passed".
#
# Measured on the shipped functions, with a failed domain object-auditing check:
#
#     score : 88% [warn] 8 of 9 checks passed
#     ready : 1/1 [ok]  All checks passed          <-- green, beside an 88% score
#     donut = 88%   verdict = NOT READY   issues = 1 High "Object auditing is not configured"
#
# The asymmetry is what makes it clearly an oversight rather than a decision: the SAME domain check
# that could not be READ correctly rendered "1 check(s) not measured" in warn, and a failing SERVER
# check correctly rendered "1 need attention" in bad. Only a domain check that measured a FAILURE -
# the most serious of the three - produced the reassuring green.
#
# A reader who glances at the KPI strip is told the estate is clean by a run whose verdict is
# "Action required".
#
# The assertions below are differential and cover all four populations, so the tile cannot be made to
# pass by hard-coding one of them.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

function New-Dc {
    param($TimeSync = $true)
    [PSCustomObject]@{
        FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
        Unreachable = $false; PartialFailure = $false
        OSVersion = $true; AdvancedAuditing = $true; PowerSettings = $true; NtlmAuditing = $true
        TimeSync = $TimeSync
        Details = [PSCustomObject]@{ TimeSyncDetails = [PSCustomObject]@{ Detail = 'clock is 12 minutes behind' } }
    }
}

# The domain-auditing shape the scanner itself writes: a per-domain record whose four directory
# checks each carry an is*Ok value that is $true, $false or 'N/A'.
function New-DomainAudit {
    param($ObjectAuditing = $true, $DeletedObjects = $true)
    [PSCustomObject]@{
        Domain = 'contoso.com'; Measured = $true
        ObjectAuditing   = [PSCustomObject]@{ isObjectAuditingOk = $ObjectAuditing }
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
        AdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DeletedObjects   = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $DeletedObjects }
    }
}

function Measure-Strip {
    param($Dc, $Audit)
    $report = [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
        DomainsInScope = @('contoso.com'); DomainControllers = @($Dc)
        CAServers = @(); EntraConnectServers = @(); DomainAuditing = @($Audit)
        LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
        MaxNnrTargets = 0; SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report 3>$null
    $html = Get-mdiOverviewHtml -ReportData $report -Statistics $stats 3>$null | Out-String

    # Pull the two cards out of the rendered strip rather than recomputing anything.
    $readyCard = ''
    $scoreCard = ''
    foreach ($m in [regex]::Matches($html, '<div class="kpi (?<tone>\w+)"><span class="kpi-label">(?<label>[^<]*)</span><span class="kpi-value">(?<value>[^<]*)</span><span class="kpi-sub">(?<sub>[^<]*)</span></div>')) {
        if ($m.Groups['label'].Value -eq 'Servers fully ready') { $readyCard = $m.Value }
        if ($m.Groups['label'].Value -eq 'Overall check score') { $scoreCard = $m.Value }
    }
    $readyTone = ''; $readySub = ''
    $rm = [regex]::Match($readyCard, 'kpi (?<tone>\w+)".*kpi-sub">(?<sub>[^<]*)<')
    if ($rm.Success) { $readyTone = $rm.Groups['tone'].Value; $readySub = $rm.Groups['sub'].Value }
    $scoreTone = ''
    $sm = [regex]::Match($scoreCard, 'kpi (?<tone>\w+)"')
    if ($sm.Success) { $scoreTone = $sm.Groups['tone'].Value }

    [PSCustomObject]@{
        ReadyTone = $readyTone; ReadySub = $readySub; ScoreTone = $scoreTone
        Passed = [int] $stats.ChecksPassed; Total = [int] $stats.ChecksTotal; Unread = [int] $stats.ChecksUnread
        Verdict = (Test-mdiReadinessResult -ReportData $report)
        Issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report).Count
    }
}

'[kpi agreement] a clean estate is the only thing that says "All checks passed"'
$clean = Measure-Strip (New-Dc) (New-DomainAudit)
Assert-That 'clean: the ready tile says all checks passed' ($clean.ReadySub -eq 'All checks passed') "(got '$($clean.ReadySub)')"
Assert-That 'clean: the ready tile is green' ($clean.ReadyTone -eq 'ok') "(got '$($clean.ReadyTone)')"
Assert-That 'clean: nothing failed and nothing is unread' (($clean.Passed -eq $clean.Total) -and ($clean.Unread -eq 0)) "(P/T/U $($clean.Passed)/$($clean.Total)/$($clean.Unread))"
Assert-That 'clean: the verdict is READY' $clean.Verdict

''
'[kpi agreement] a FAILED domain check must not read as "All checks passed"'
$domainFail = Measure-Strip (New-Dc) (New-DomainAudit -ObjectAuditing $false)
Assert-That 'the score card shows a measured failure' ($domainFail.Passed -lt $domainFail.Total) "(P/T $($domainFail.Passed)/$($domainFail.Total))"
Assert-That 'the verdict is NOT READY' (-not $domainFail.Verdict)
Assert-That 'a finding is raised' ($domainFail.Issues -gt 0) "(got $($domainFail.Issues))"
# THE DEFECT.
Assert-That 'the ready tile does NOT claim all checks passed' ($domainFail.ReadySub -ne 'All checks passed') "(got '$($domainFail.ReadySub)')"
Assert-That 'the ready tile is not green' ($domainFail.ReadyTone -ne 'ok') "(got '$($domainFail.ReadyTone)')"
# A measured FAILURE is 'bad', not merely 'warn' - the distinction the score card already draws.
Assert-That 'the ready tile is bad, not warn' ($domainFail.ReadyTone -eq 'bad') "(got '$($domainFail.ReadyTone)')"
# The sub-label names its unit, because the headline of this card counts SERVERS.
Assert-That 'the sub-label names the unit as checks' ($domainFail.ReadySub -match 'check') "(got '$($domainFail.ReadySub)')"
Assert-That 'the sub-label does not invent a server that needs attention' ($domainFail.ReadySub -notmatch '^\d+ need attention$') "(got '$($domainFail.ReadySub)')"

# The same defect through the other domain check, so the fix cannot be keyed to one property.
$deletedFail = Measure-Strip (New-Dc) (New-DomainAudit -DeletedObjects $false)
Assert-That 'a failed Deleted Objects permission behaves the same' ($deletedFail.ReadySub -ne 'All checks passed') "(got '$($deletedFail.ReadySub)')"
Assert-That '  ...and is not green' ($deletedFail.ReadyTone -eq 'bad') "(got '$($deletedFail.ReadyTone)')"

''
'[kpi agreement] the neighbouring populations still behave as before'
# These two already worked. They are pinned so the new branch cannot swallow them, and because the
# CONTRAST between them is what proved the defect: the same domain check unread said "not measured",
# while measured-as-failed said "All checks passed".
$domainUnread = Measure-Strip (New-Dc) (New-DomainAudit -ObjectAuditing 'N/A')
Assert-That 'an UNREAD domain check still says not measured' ($domainUnread.ReadySub -match 'not measured') "(got '$($domainUnread.ReadySub)')"
Assert-That '  ...and is warn, not bad - it was not looked at, it did not fail' ($domainUnread.ReadyTone -eq 'warn') "(got '$($domainUnread.ReadyTone)')"

$serverFail = Measure-Strip (New-Dc -TimeSync $false) (New-DomainAudit)
Assert-That 'a failing SERVER still says need attention' ($serverFail.ReadySub -match 'need attention') "(got '$($serverFail.ReadySub)')"
Assert-That '  ...and is bad' ($serverFail.ReadyTone -eq 'bad') "(got '$($serverFail.ReadyTone)')"

''
'[kpi agreement] the invariant, stated once'
# Whatever the population, the two cards must not contradict each other: the ready tile may only say
# "All checks passed" when the score really is every check passed.
foreach ($case in @(
        @{ Name = 'clean'; R = $clean }
        @{ Name = 'domain check failed'; R = $domainFail }
        @{ Name = 'Deleted Objects failed'; R = $deletedFail }
        @{ Name = 'domain check unread'; R = $domainUnread }
        @{ Name = 'server check failed'; R = $serverFail }
    )) {
    $r = $case.R
    $claimsAllPassed = ($r.ReadySub -eq 'All checks passed')
    $everythingPassed = (($r.Passed -eq $r.Total) -and ($r.Unread -eq 0))
    Assert-That ("{0}: 'All checks passed' only when everything passed" -f $case.Name) (
        $claimsAllPassed -eq $everythingPassed
    ) "(sub '$($r.ReadySub)', P/T/U $($r.Passed)/$($r.Total)/$($r.Unread))"
    Assert-That ("{0}: the ready tile is not green while the score card is not" -f $case.Name) (
        -not (($r.ReadyTone -eq 'ok') -and ($r.ScoreTone -ne 'ok'))
    ) "(ready '$($r.ReadyTone)', score '$($r.ScoreTone)')"
}

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
