# [w94] Losing a server outright must not disclose LESS than losing it half way.
#
# Both sensor KPI cards built their populations from the REACHABLE list only, so an unreachable
# server left both sides of the ratio and the card rendered exactly as though that server was not in
# the estate at all. Measured on the shipped functions, one healthy server plus one second server:
#
#   second server healthy      -> "Sensors healthy 1/1" ok   "All sensor services running"
#   second server UNREACHABLE  -> "Sensors healthy 1/1" ok   "All sensor services running"   <- identical
#   second server PARTIAL      -> "Sensors healthy 1/1" warn "All read sensor services running, 1 could not be read"
#
# and the same three-way split on "Sensor v3.x ready". So the estate where a machine was never
# reached at all rendered greener than the one where it was reached and failed part way - and
# identical to one where nothing was wrong. This is the same shape already fixed for the overall
# check score and for the pass-rate chart: the server is UNEVALUATED, not absent.
#
# Placeholders stay excluded on both cards: they are discovery records, not machines, and are already
# counted as unmeasured population in their own right.

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

function New-HealthyDc {
    param([string] $Fqdn)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false
        SensorHealth = $true; SensorV3Ready = $true
        Details = [PSCustomObject]@{
            SensorHealthDetails = [PSCustomObject]@{ Installed = $true; Version = '2.240.0.0' }
            SensorV3ReadyDetails = [PSCustomObject]@{ SensorState = 'Running'; MigrationEligible = $true }
        }
    }
}

# As the SHIPPED discovery builds one: the flag and a Comment, and NO details at all, because nothing
# was ever run on it. Giving it detail here would test a shape that never occurs.
function New-UnreachableDc {
    param([string] $Fqdn)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'
        Unreachable = $true; PartialFailure = $false
        Comment = 'Server is not available: ICMP'
        Details = [PSCustomObject]@{ }
    }
}

function New-PartialDc {
    param([string] $Fqdn)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $true
        Comment = 'Testing stopped early'
        Details = [PSCustomObject]@{ }
    }
}

function Get-SensorKpis {
    param([object[]] $DomainControllers)
    $report = [PSCustomObject]@{
        DomainsInScope = @('contoso.com')
        DomainControllers = $DomainControllers
        CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    $html = Get-mdiOverviewHtml -Statistics $stats -ReportData $report
    $read = {
        param([string] $Label)
        $pattern = '<div class="kpi (ok|warn|bad|na)"><span class="kpi-label">' + [regex]::Escape($Label) +
        '</span><span class="kpi-value">([^<]*)</span><span class="kpi-sub">([^<]*)</span>'
        if ($html -match $pattern) { [PSCustomObject]@{ Tone = $Matches[1]; Value = $Matches[2]; Sub = $Matches[3] } }
        else { [PSCustomObject]@{ Tone = 'none'; Value = '?'; Sub = '?' } }
    }
    [PSCustomObject]@{ Health = (& $read 'Sensors healthy'); V3 = (& $read 'Sensor v3.x ready'); Stats = $stats }
}

$clean = Get-SensorKpis -DomainControllers @((New-HealthyDc 'dc1.contoso.com'))
$withUnreachable = Get-SensorKpis -DomainControllers @((New-HealthyDc 'dc1.contoso.com'), (New-UnreachableDc 'dc2.contoso.com'))
$withPartial = Get-SensorKpis -DomainControllers @((New-HealthyDc 'dc1.contoso.com'), (New-PartialDc 'dc2.contoso.com'))

'[w94] the fixtures are what they claim to be'
Assert-That 'the unreachable fixture really has an unreachable server' `
    ([int] $withUnreachable.Stats.UnreachableCount -eq 1) "(UnreachableCount $($withUnreachable.Stats.UnreachableCount))"
Assert-That 'the partial fixture has no unreachable server' `
    ([int] $withPartial.Stats.UnreachableCount -eq 0) "(UnreachableCount $($withPartial.Stats.UnreachableCount))"
Assert-That 'both two-server fixtures carry two servers' `
    (([int] $withUnreachable.Stats.TotalServers -eq 2) -and ([int] $withPartial.Stats.TotalServers -eq 2)) `
    "($($withUnreachable.Stats.TotalServers) / $($withPartial.Stats.TotalServers))"

'[w94] Sensors healthy'
Assert-That 'an unreachable server does NOT render identically to a clean estate' `
    ($withUnreachable.Health.Sub -ne $clean.Health.Sub) "(both read '$($clean.Health.Sub)')"
Assert-That 'the card stops claiming every sensor service is running' `
    ($withUnreachable.Health.Sub -notmatch '^All sensor services running$') "(sub '$($withUnreachable.Health.Sub)')"
Assert-That 'it discloses that a server could not be read' `
    ($withUnreachable.Health.Sub -match 'could not be read') "(sub '$($withUnreachable.Health.Sub)')"
Assert-That 'and it is not green' ($withUnreachable.Health.Tone -ne 'ok') "(tone '$($withUnreachable.Health.Tone)')"
Assert-That 'losing a server outright discloses no less than losing it half way' `
    ($withUnreachable.Health.Sub -eq $withPartial.Health.Sub) `
    "(unreachable '$($withUnreachable.Health.Sub)' vs partial '$($withPartial.Health.Sub)')"

'[w94] Sensor v3.x ready - boundary owned by SensorCardsLostServerNotHidden.Tests.ps1'
# That file pins the opposite rule for THIS card: an unreachable server is deliberately not charged
# to it, because it is already reported by the unreachable KPI, the issue list and the verdict, and
# charging it here as well would report one gap on two surfaces. Asserting disclosure here would put
# two test files in direct contradiction, so this file only pins that the v3 card keeps saying
# something truthful about the servers it DID evaluate, and leaves the boundary to its owner.
Assert-That 'the v3 card still reports the server it did evaluate' `
    ($withUnreachable.V3.Value -eq '1/1') "(value '$($withUnreachable.V3.Value)')"

'[w94] controls: a clean estate is untouched'
Assert-That 'a clean estate still reports every sensor service running' `
    ($clean.Health.Sub -match 'All sensor services running') "(sub '$($clean.Health.Sub)')"
Assert-That 'and stays green' ($clean.Health.Tone -eq 'ok') "(tone '$($clean.Health.Tone)')"
Assert-That 'the v3 card stays green on a clean estate' ($clean.V3.Tone -eq 'ok') "(tone '$($clean.V3.Tone)')"
Assert-That 'and claims no unevaluated servers' ($clean.V3.Sub -notmatch 'could not be evaluated') "(sub '$($clean.V3.Sub)')"

'[w94] control: a discovery placeholder is not counted as an unread machine'
$placeholder = [PSCustomObject]@{
    FQDN = 'Domain controller (not named) 1 of 1 - contoso.com'; Domain = 'contoso.com'
    Unreachable = $false; PartialFailure = $false; IsPlaceholder = $true
    SensorHealth = 'N/A'; Details = [PSCustomObject]@{ }
}
$withPlaceholder = Get-SensorKpis -DomainControllers @((New-HealthyDc 'dc1.contoso.com'), $placeholder)
Assert-That 'a placeholder does not make the sensor card claim an unread machine' `
    ($withPlaceholder.Health.Sub -eq $clean.Health.Sub) `
    "(placeholder '$($withPlaceholder.Health.Sub)' vs clean '$($clean.Health.Sub)')"

''
"UnreachableInSensorKpis: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
