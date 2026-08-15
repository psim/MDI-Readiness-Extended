# A domain whose LDAP probe plan could not be built was charged NOTHING on the score surface.
#
# Get-mdiReportStatistics charges one unread for each of three "we did not measure this" gaps, with
# the same comment on each: not looked at is not passed.
#   - a domain in scope that was never examined
#   - a server that was never reached
#   - a forest whose domains could not be enumerated
#
# LdapPlanGapDomains is the FOURTH gap of exactly that kind - the domain's controllers failed the
# first discovery pass, so no sensor was ever asked whether it can reach that domain - and it was the
# only one the statistics function never read. The issue list raises it, the verdict fails on it, and
# Main's own warning says "it will be reported as unverified rather than ready". The score surface
# said the opposite.
#
# Measured before the fix: two reports differing ONLY in LdapPlanGapDomains produced a BYTE-IDENTICAL
# "Overall check score 100% - 14 of 14 checks passed" in green, an identical "Servers fully ready
# 2/2 - All checks passed" card and an identical solid-green donut, directly beside a NOT READY
# verdict and a High "Not measured" finding naming the domain. The two surfaces a reader screenshots
# were the two that were wrong.
#
# The assertions below are differential: they compare the SAME report with and without the gap, so
# they cannot pass by accident on a hard-coded number.

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
    param($Fqdn, $Domain)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = $Domain; IP = '10.0.0.1'; Addresses = @('10.0.0.1')
        Unreachable = $false; PartialFailure = $false
        OSVersion = $true; AdvancedAuditing = $true; PowerSettings = $true
        Details = [PSCustomObject]@{}
    }
}

function New-DomainAudit {
    param($Domain)
    [PSCustomObject]@{
        Domain = $Domain; Measured = $true
        ObjectAuditing   = [PSCustomObject]@{ isObjectAuditingOk = $true }
        ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
        AdfsAuditing     = [PSCustomObject]@{ isAdfsAuditingOk = $true }
        DeletedObjects   = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true }
    }
}

function New-Report {
    param([string[]] $Gap = @())
    [PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
        DomainsInScope = @('contoso.com', 'child.contoso.com')
        DomainControllers = @((New-Dc 'dc-contoso.com' 'contoso.com'), (New-Dc 'dc-child.contoso.com' 'child.contoso.com'))
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @((New-DomainAudit 'contoso.com'), (New-DomainAudit 'child.contoso.com'))
        LdapPlanGapDomains = @($Gap)
        NnrUnresolvedTargets = @(); NnrTargetComputer = @(); MaxNnrTargets = 0; SkippedAreas = @()
    }
}

function Measure-Report {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report 3>$null
    [PSCustomObject]@{
        Stats   = $stats
        Unread  = [int] $stats.ChecksUnread
        Total   = [int] $stats.ChecksTotal
        Passed  = [int] $stats.ChecksPassed
        Rows    = @($stats.ServerScores | ForEach-Object { [string] $_.FQDN })
        Verdict = (Test-mdiReadinessResult -ReportData $Report)
        Issues  = @(Get-mdiIssueList -Statistics $stats -ReportData $Report)
    }
}

$control = Measure-Report (New-Report)
$subject = Measure-Report (New-Report @('child.contoso.com'))

'[ldap plan gap] a domain that was never probed is charged on the score surface'
Assert-That 'the control run is clean' ($control.Unread -eq 0 -and $control.Verdict) "(unread $($control.Unread) verdict $($control.Verdict))"
Assert-That 'the gap run fails the verdict' (-not $subject.Verdict)
Assert-That 'the gap run raises a finding' ($subject.Issues.Count -gt $control.Issues.Count) "(control $($control.Issues.Count), subject $($subject.Issues.Count))"
# THE DEFECT: the score surface must not describe the gap run identically to the clean run.
Assert-That 'the unread count is higher than the control' ($subject.Unread -gt $control.Unread) "(control $($control.Unread), subject $($subject.Unread))"
Assert-That 'the effective denominator grows, so the percentage cannot stay 100' (
    ($subject.Total + $subject.Unread) -gt ($control.Total + $control.Unread)
) "(control $($control.Total)+$($control.Unread), subject $($subject.Total)+$($subject.Unread))"
Assert-That 'the passed count does NOT grow - nothing new passed' ($subject.Passed -eq $control.Passed) "(control $($control.Passed), subject $($subject.Passed))"
Assert-That 'a synthetic unmeasured row names the domain' (
    @($subject.Rows | Where-Object { $_ -match 'child\.contoso\.com' -and $_ -match 'not probed' }).Count -eq 1
) "(rows: $($subject.Rows -join ' | '))"
Assert-That 'the row is classified Unmeasured, not Server' (
    @($subject.Stats.ServerScores | Where-Object { [string] $_.FQDN -match 'not probed' -and [string] $_.Kind -eq 'Unmeasured' }).Count -eq 1
) "(kinds: $(($subject.Stats.ServerScores | ForEach-Object { '{0}={1}' -f $_.FQDN, $_.Kind }) -join ' | '))"

''
'[ldap plan gap] it is charged the SAME way as its three sibling gaps'
# The point is consistency: four gaps of one kind must not be treated three ways.
$unexamined = Measure-Report ([PSCustomObject]@{
        ScriptVersion = 'test'; Domain = 'contoso.com'; Forest = 'contoso.com'
        ForestDiscovery = [PSCustomObject]@{ Name = 'contoso.com'; Complete = $true }
        DomainsInScope = @('contoso.com', 'child.contoso.com')
        DomainControllers = @((New-Dc 'dc-contoso.com' 'contoso.com'))
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @((New-DomainAudit 'contoso.com'))
        LdapPlanGapDomains = @()
        NnrUnresolvedTargets = @(); NnrTargetComputer = @(); MaxNnrTargets = 0; SkippedAreas = @()
    })
Assert-That 'an unexamined domain is charged one unread' ($unexamined.Unread -ge 1) "(got $($unexamined.Unread))"
Assert-That 'the LDAP plan gap is charged the same one unread' ($subject.Unread -eq 1) "(got $($subject.Unread))"

''
'[ldap plan gap] duplicates and blanks do not inflate the charge'
$dupes = Measure-Report (New-Report @('child.contoso.com', 'child.contoso.com', '', '   '))
Assert-That 'the same domain twice is charged once' ($dupes.Unread -eq 1) "(got $($dupes.Unread))"
Assert-That 'blank entries are not charged' (
    @($dupes.Rows | Where-Object { $_ -match 'not probed' }).Count -eq 1
) "(rows: $($dupes.Rows -join ' | '))"

''
'[ldap plan gap] two distinct gap domains are charged twice'
$two = Measure-Report (New-Report @('child.contoso.com', 'other.contoso.com'))
Assert-That 'two gap domains produce two unread' ($two.Unread -eq 2) "(got $($two.Unread))"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
