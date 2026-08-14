# [w93] The "Pass rate by prerequisite" chart must not make an estate look BETTER as servers are lost.
#
# The chart's first pass iterated the REACHABLE servers only, so an unreachable server left both the
# numerator and the denominator of every bar and vanished from the chart completely. Measured on the
# shipped functions with 49 of 50 domain controllers unreachable: every bar rendered a solid green
# "1/1 (100%)" beside a score card on the same page reading "12%, 7 of 56 checks passed, 49 not
# measured". The identical estate with those 49 servers REACHABLE but unreadable rendered
# "1/50 (2%), 49 not read" in warn - so one fact, "one server measured out of fifty", was drawn two
# completely different ways depending only on WHY the other forty-nine were not measured, and the
# more serious case was the one that looked perfect. Losing more servers made the chart greener.
#
# The fix keeps the rule that ABSENCE is not unread - a certification authority legitimately carries
# fewer checks than a domain controller, and charging it for checks that do not apply would invent a
# gap on every CA in the estate - so an unreachable server is not charged against each individual
# prerequisite. It is instead named explicitly, exactly as a partial scan already was, so the loss is
# visible on the chart instead of silently absent from it.
#
# What this file pins:
#   * unreachable servers are part of the chart population at all;
#   * the chart discloses them rather than rendering only full-width green bars;
#   * the disclosure scales with the number of servers lost;
#   * a partial scan is still disclosed (the pre-existing behaviour this shares a branch with);
#   * a clean estate is unaffected, and a CA is still not charged for domain-controller checks.

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

function New-MeasuredDc {
    param([string] $Fqdn, [string] $Domain = 'contoso.com')
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = $Domain
        Unreachable = $false; PartialFailure = $false
        OperatingSystem = 'Windows Server 2022'
        NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true
        SensorHealth = $true; TimeSync = $true
        Details = [ordered]@{}
    }
}

# An unreachable server as the SHIPPED discovery builds one: a Comment and the flag, and NOT ONE
# check property, because nothing was ever run on it. Adding checks here would test a server shape
# that never occurs and would hide the defect.
function New-UnreachableDc {
    param([string] $Fqdn, [string] $Domain = 'contoso.com')
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = $Domain
        Unreachable = $true; PartialFailure = $false
        Comment = 'Server is not available: ICMP'
        Details = [ordered]@{}
    }
}

function Get-Chart {
    param([object[]] $DomainControllers, [object[]] $CAServers = @())
    $report = [PSCustomObject]@{
        DomainsInScope = @('contoso.com')
        DomainControllers = $DomainControllers
        CAServers = $CAServers
        EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    $html = Get-mdiOverviewHtml -Statistics $stats -ReportData $report
    # The row is captured up to and including its VALUE span. A non-greedy match that stops at the
    # first "</div></div>" ends inside bar-track - the inner fill div plus the track div - and cuts
    # off "1/50 (2%) 49 not read" entirely, so every assertion about the disclosure silently reads an
    # empty string and this file would fail against a correct script.
    $rows = @([regex]::Matches($html, '<div class="bar-row">.*?<div class="bar-value">.*?</div></div>') | ForEach-Object { $_.Value })
    [PSCustomObject]@{ Stats = $stats; Html = $html; Rows = $rows }
}

# ---------------------------------------------------------------------------------------------
'[w93] one measured server, 49 unreachable'
$measured = @(New-MeasuredDc -Fqdn 'dc1.contoso.com')
$lost = @(1..49 | ForEach-Object { New-UnreachableDc -Fqdn ("dc{0}.contoso.com" -f ($_ + 1)) })
$chart = Get-Chart -DomainControllers ($measured + $lost)

Assert-That 'the fixture really is 1 reachable of 50' `
    (([int] $chart.Stats.TotalServers -eq 50) -and ([int] $chart.Stats.UnreachableCount -eq 49)) `
    "(TotalServers $($chart.Stats.TotalServers), Unreachable $($chart.Stats.UnreachableCount))"

# The core invariant. Before the fix EVERY row was a full-width green bar and nothing on the chart
# referred to the 49 servers at all.
$disclosingRows = @($chart.Rows | Where-Object { $_ -match 'not read' })
Assert-That 'the chart discloses the servers that were never read' ($disclosingRows.Count -ge 1) `
    "($($chart.Rows.Count) row(s), none mentioning 'not read')"
Assert-That 'and the disclosure names all 49 of them' `
    (($disclosingRows -join ' ') -match '49 not read') "($($disclosingRows -join ' | '))"
Assert-That 'the chart is not made up exclusively of 100% bars' `
    (@($chart.Rows | Where-Object { $_ -notmatch '\(100%\)' }).Count -ge 1) `
    "(every one of $($chart.Rows.Count) rows reads 100%)"

# The chart must not contradict the score card standing beside it on the same page.
Assert-That 'the score card still reports the loss' `
    ($chart.Html -match 'not measured') '(score card sub-label does not mention unmeasured checks)'

# ---------------------------------------------------------------------------------------------
'[w93] the disclosure scales with the loss'
$smallLoss = Get-Chart -DomainControllers (@(New-MeasuredDc -Fqdn 'dc1.contoso.com') + @(New-UnreachableDc -Fqdn 'dc2.contoso.com'))
$smallRows = @($smallLoss.Rows | Where-Object { $_ -match 'not read' })
Assert-That 'losing one server discloses one server' (($smallRows -join ' ') -match '1 not read') `
    "($($smallRows -join ' | '))"

# ---------------------------------------------------------------------------------------------
'[w93] control: a partial scan is still disclosed (same branch)'
$partial = New-MeasuredDc -Fqdn 'dc9.contoso.com'
$partial.PartialFailure = $true
foreach ($p in 'NtlmAuditing', 'AdvancedAuditing', 'PowerSettings', 'SensorHealth', 'TimeSync') {
    $partial.PSObject.Properties.Remove($p)
}
$partialChart = Get-Chart -DomainControllers (@(New-MeasuredDc -Fqdn 'dc1.contoso.com') + @($partial))
Assert-That 'a partial scan is named on the chart' `
    (@($partialChart.Rows | Where-Object { $_ -match 'not read' }).Count -ge 1) `
    "($($partialChart.Rows -join ' | '))"

# ---------------------------------------------------------------------------------------------
'[w93] control: a fully measured estate is unchanged'
$clean = Get-Chart -DomainControllers @((New-MeasuredDc -Fqdn 'dc1.contoso.com'), (New-MeasuredDc -Fqdn 'dc2.contoso.com'))
Assert-That 'a clean estate discloses nothing as unread' `
    (@($clean.Rows | Where-Object { $_ -match 'not read' }).Count -eq 0) "($($clean.Rows -join ' | '))"
Assert-That 'and its bars read 2/2' ((($clean.Rows -join ' ') -match '2/2')) "($($clean.Rows -join ' | '))"

# ---------------------------------------------------------------------------------------------
'[w93] control: a CA is not charged for domain-controller checks'
# The rule the fix had to preserve: ABSENCE is not unread. A CA carries fewer checks by design, and
# charging it for the ones it does not have would invent a gap on every CA in the estate.
$ca = [PSCustomObject]@{
    FQDN = 'ca1.contoso.com'; Domain = 'contoso.com'
    Unreachable = $false; PartialFailure = $false
    CertificateRootStoreOk = $true
    Details = [ordered]@{}
}
$withCa = Get-Chart -DomainControllers @(New-MeasuredDc -Fqdn 'dc1.contoso.com') -CAServers @($ca)
$dcCheckRows = @($withCa.Rows | Where-Object { $_ -match 'NTLM Auditing|Time Sync|Power Settings' })
Assert-That 'a reachable CA does not turn domain-controller checks into gaps' `
    (@($dcCheckRows | Where-Object { $_ -match 'not read' }).Count -eq 0) "($($dcCheckRows -join ' | '))"

''
"UnreachableInPrerequisiteChart: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
