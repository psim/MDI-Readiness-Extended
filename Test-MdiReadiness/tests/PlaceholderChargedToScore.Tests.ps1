# [w84] A discovery placeholder must be charged to the score, not rendered as a perfect estate.
#
# A placeholder is emitted when a role - AD CS, Entra Connect - could not be enumerated. A placeholder
# row that carries NO check properties at all scores Passed 0, Total 0, Unread 0: a row on NEITHER
# side of the ratio. That produces the false green this codebase has already fixed three times for
# other causes (unexamined domain, unreachable server, incomplete forest discovery): "Overall check
# score 100%" with an 'ok' GREEN badge, beside a High finding saying the role could not be enumerated,
# under a verdict of NOT READY.
#
# HONEST SCOPE, measured rather than assumed: the REAL producers do NOT emit such a row.
# DiscoveryPlaceholderNotAServer.Tests.ps1 asserts "the produced placeholder is still charged as
# unread", and that assertion passes with this guard removed - so the live scan path was already
# correct. This file therefore guards a REACHABILITY BOUNDARY rather than a defect observed in a real
# run: any placeholder that reaches the scoring loop having measured nothing is charged, however it
# was constructed - including one rehydrated from an older JSON report or baseline that predates the
# current placeholder shape.
#
# The guard also makes the row's own comment true. It claimed "its unread check is unaffected, so the
# check score still charges the gap" while nothing in the code guaranteed it.
#
# These assertions drive the REAL Get-mdiReportStatistics, Test-mdiReadinessResult and
# Get-mdiOverviewHtml.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$full = Get-Content -LiteralPath $target -Raw
$text = $full -replace '(?m)^\s*#Requires.*$', ''
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

function New-Outcome {
    param([switch] $WithPlaceholder)
    $servers = @([PSCustomObject]@{ FQDN = 'dc.local'; Domain = 'local'; Unreachable = $false; PartialFailure = $false; CheckA = $true })
    if ($WithPlaceholder) {
        $servers += [PSCustomObject]@{ FQDN = 'placeholder'; Domain = 'local'; Unreachable = $false; PartialFailure = $false; IsPlaceholder = $true }
    }
    $report = [PSCustomObject]@{
        DomainsInScope = @('local'); DomainControllers = $servers; CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    $verdict = [bool] (Test-mdiReadinessResult -ReportData $report 3>$null 4>$null)
    $html = Get-mdiOverviewHtml -Statistics $stats -ReportData $report
    $tone = if ($html -match '<div class="kpi (ok|warn|bad|na)"><span class="kpi-label">Overall check score') { $Matches[1] } else { 'none' }
    $pct = if ($html -match '<span class="kpi-label">Overall check score</span><span class="kpi-value">(\d+)%') { [int] $Matches[1] } else { -1 }
    $issues = @(Get-mdiIssueList -Statistics $stats -ReportData $report)
    [PSCustomObject]@{ Ready = $verdict; Tone = $tone; Pct = $pct; Issues = $issues.Count; Stats = $stats }
}

'[w84] the control: a clean one-server estate is 100% GREEN and READY'
# Without this, charging every run an unread would satisfy everything below.
$clean = New-Outcome
Assert-That 'a clean estate is READY' ($clean.Ready) "(issues $($clean.Issues))"
Assert-That 'a clean estate scores 100%' ($clean.Pct -eq 100) "(got $($clean.Pct)%)"
Assert-That 'a clean estate is GREEN' ($clean.Tone -eq 'ok') "(tone '$($clean.Tone)')"
Assert-That 'a clean estate raises no issue' ($clean.Issues -eq 0) "(got $($clean.Issues))"

'[w84] a role that could not be enumerated is charged to the score'
$ph = New-Outcome -WithPlaceholder
Assert-That 'the run is NOT ready' (-not $ph.Ready)
Assert-That 'the run raises an issue' ($ph.Issues -gt 0) "(got $($ph.Issues))"
Assert-That 'the score is NOT 100%' ($ph.Pct -lt 100) "(got $($ph.Pct)%)"
Assert-That 'the badge is NOT green' ($ph.Tone -ne 'ok') "(tone '$($ph.Tone)')"

'[w84] the headline number never contradicts the verdict'
# The invariant the whole page rests on: of the verdict and the percentage, the percentage is what
# gets screenshotted, so it must not say the opposite.
foreach ($case in @(
        @{ Name = 'clean'; O = $clean },
        @{ Name = 'placeholder'; O = $ph }
    )) {
    $o = $case.O
    $contradiction = ($o.Pct -eq 100 -and $o.Tone -eq 'ok' -and -not $o.Ready)
    Assert-That "  no 100%-green headline over a NOT READY verdict ($($case.Name))" (-not $contradiction) `
        "(pct=$($o.Pct) tone=$($o.Tone) ready=$($o.Ready))"
}

'[w84] the placeholder is counted as unmeasured population, not as a server'
# NOTE: the Kind='Unmeasured' doctrine is owned by DiscoveryPlaceholderNotAServer.Tests.ps1, which
# does kill a mutant that reclassifies it. It is deliberately NOT re-asserted here: TotalServers is
# not derived from Kind, so the obvious assertion passes under that mutant and would be a test that
# cannot fail.
Assert-That 'the placeholder did not inflate the server count' ($ph.Stats.TotalServers -eq $clean.Stats.TotalServers) `
    "(clean $($clean.Stats.TotalServers) vs placeholder $($ph.Stats.TotalServers))"

'[w84] the unread count actually moved'
$cleanUnread = [int] $clean.Stats.ChecksUnread
$phUnread = [int] $ph.Stats.ChecksUnread
Assert-That 'the placeholder added exactly one unread check' ($phUnread -eq $cleanUnread + 1) `
    "(clean $cleanUnread vs placeholder $phUnread)"

'[w84] two placeholders are charged twice'
$servers = @(
    [PSCustomObject]@{ FQDN = 'dc.local'; Domain = 'local'; Unreachable = $false; PartialFailure = $false; CheckA = $true },
    [PSCustomObject]@{ FQDN = 'ph1'; Domain = 'local'; Unreachable = $false; PartialFailure = $false; IsPlaceholder = $true },
    [PSCustomObject]@{ FQDN = 'ph2'; Domain = 'local'; Unreachable = $false; PartialFailure = $false; IsPlaceholder = $true }
)
$two = Get-mdiReportStatistics -ReportData ([PSCustomObject]@{
        DomainsInScope = @('local'); DomainControllers = $servers; CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    })
Assert-That 'two placeholders add two unread checks' ([int] $two.ChecksUnread -eq $cleanUnread + 2) `
    "(got $([int] $two.ChecksUnread), expected $($cleanUnread + 2))"

'[w84] a placeholder that DID carry a readable check is not charged twice'
# The guard on the fix. A placeholder carrying a measured check is already represented in the ratio;
# adding a synthetic unread on top would double-count the same gap.
$withCheck = @(
    [PSCustomObject]@{ FQDN = 'dc.local'; Domain = 'local'; Unreachable = $false; PartialFailure = $false; CheckA = $true },
    [PSCustomObject]@{ FQDN = 'ph3'; Domain = 'local'; Unreachable = $false; PartialFailure = $false; IsPlaceholder = $true; CheckA = $true }
)
$measured = Get-mdiReportStatistics -ReportData ([PSCustomObject]@{
        DomainsInScope = @('local'); DomainControllers = $withCheck; CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    })
Assert-That 'a placeholder with a measured check adds no synthetic unread' ([int] $measured.ChecksUnread -eq $cleanUnread) `
    "(got $([int] $measured.ChecksUnread), expected $cleanUnread)"

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
