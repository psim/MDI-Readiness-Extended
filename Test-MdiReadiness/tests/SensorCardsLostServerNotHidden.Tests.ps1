# [w86] Losing a server EARLIER must not make the sensor cards look better.
#
# Both sensor KPIs scoped themselves to servers that already carried a detail blob:
#   $v3Servers     = @($reachable | Where-Object { $_.Details.SensorV3ReadyDetails })
#   $sensorServers = @($stats.ReachableList | Where-Object { $_.Details.SensorHealthDetails })
#
# A REACHABLE server that produced no blob at all - the shipped partial-failure path stops before the
# sensor and v3 reads - was therefore absent from BOTH sides of each ratio and vanished from the card
# entirely. Measured, side by side, on identical two-server estates whose second server was not
# assessed either way:
#
#   blob present, unevaluated : warn  1/1  "1 eligible for in-place migration, 1 could not be evaluated"
#   blob absent  (lost early) : ok    1/1  "1 eligible for in-place migration"      <- GREEN
#
# Losing the server earlier turned the amber card green, and made a two-server estate render exactly
# like a clean one-server estate. That is the same "losing a server improves the headline" shape the
# codebase already fixed for the overall check score.
#
# SCOPE NOTE: an UNREACHABLE server is deliberately NOT counted here. It is already reported by the
# unreachable KPI, the issue list and the verdict, and the codebase has an explicit doctrine against
# charging it twice (see the port-candidate comment: "An unreachable DC is already reported as
# unreachable and must not also be counted as a host the ports probe declined to visit"). This file
# pins that boundary too, so a future well-meaning widening of the fix turns it red.
#
# Assertions drive the REAL Get-mdiReportStatistics and the REAL Get-mdiOverviewHtml.

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

# A server that was fully assessed and is v3 ready.
function New-ReadyServer {
    param([string] $Fqdn)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false
        NtlmAuditing = $true
        SensorHealth = $true; SensorV3Ready = $true
        Details = [PSCustomObject]@{
            SensorHealthDetails   = [PSCustomObject]@{ Installed = 'True'; Running = 'True' }
            SensorV3ReadyDetails  = [PSCustomObject]@{ MigrationEligible = $true }
            RequiredPortsDetails  = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() }
        }
    }
}

# Same server, assessed but the readings could not be interpreted: the blob EXISTS and discloses it.
function New-DisclosedServer {
    param([string] $Fqdn)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false
        NtlmAuditing = $true
        SensorHealth = 'N/A'; SensorV3Ready = 'N/A'
        Details = [PSCustomObject]@{
            SensorHealthDetails   = [PSCustomObject]@{ Installed = 'N/A'; Running = 'N/A' }
            SensorV3ReadyDetails  = [PSCustomObject]@{ MigrationEligible = 'N/A' }
            RequiredPortsDetails  = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() }
        }
    }
}

# Reachable, but testing stopped before the sensor reads: NO blob at all.
function New-LostEarlyServer {
    param([string] $Fqdn)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $true; Comment = 'Access denied reading WMI'
        NtlmAuditing = $true
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
    }
}

function New-UnreachableServer {
    param([string] $Fqdn)
    [PSCustomObject]@{
        FQDN = $Fqdn; Domain = 'contoso.com'
        Unreachable = $true; PartialFailure = $false
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
    }
}

function Get-Cards {
    param([object[]] $Servers)
    $report = [PSCustomObject]@{
        DomainsInScope = @('contoso.com'); DomainControllers = $Servers; CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @(); LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); SkippedAreas = @()
    }
    $stats = Get-mdiReportStatistics -ReportData $report
    $html = Get-mdiOverviewHtml -Statistics $stats -ReportData $report
    function Get-Card { param([string] $Label)
        $rx = '<div class="kpi (ok|warn|bad|na|info)"><span class="kpi-label">' + [regex]::Escape($Label) +
              '</span><span class="kpi-value">([^<]*)</span><span class="kpi-sub">([^<]*)</span>'
        if ($html -match $rx) { [PSCustomObject]@{ Tone = $Matches[1]; Value = $Matches[2]; Sub = $Matches[3] } }
        else { [PSCustomObject]@{ Tone = 'none'; Value = '?'; Sub = '?' } }
    }
    [PSCustomObject]@{ V3 = (Get-Card 'Sensor v3.x ready'); Health = (Get-Card 'Sensors healthy'); Stats = $stats }
}

$oneServer = Get-Cards -Servers @(New-ReadyServer 'dc1.contoso.com')
$disclosed = Get-Cards -Servers @((New-ReadyServer 'dc1.contoso.com'), (New-DisclosedServer 'dc2.contoso.com'))
$lostEarly = Get-Cards -Servers @((New-ReadyServer 'dc1.contoso.com'), (New-LostEarlyServer 'dc2.contoso.com'))
$unreachable = Get-Cards -Servers @((New-ReadyServer 'dc1.contoso.com'), (New-UnreachableServer 'dc2.contoso.com'))

'[w86] control: a clean one-server estate is green on both cards'
Assert-That 'v3 card is green' ($oneServer.V3.Tone -eq 'ok') "(tone '$($oneServer.V3.Tone)' sub '$($oneServer.V3.Sub)')"
Assert-That 'sensor health card is green' ($oneServer.Health.Tone -eq 'ok') "(tone '$($oneServer.Health.Tone)' sub '$($oneServer.Health.Sub)')"

'[w86] control: a second server that disclosed its own unreadability downgrades both cards'
Assert-That 'v3 card is amber when disclosed' ($disclosed.V3.Tone -eq 'warn') "(tone '$($disclosed.V3.Tone)' sub '$($disclosed.V3.Sub)')"
Assert-That 'sensor health card is amber when disclosed' ($disclosed.Health.Tone -eq 'warn') "(tone '$($disclosed.Health.Tone)' sub '$($disclosed.Health.Sub)')"

'[w86] the defect: the same server lost EARLIER must not look better'
Assert-That 'v3 card is not green when the server was lost early' ($lostEarly.V3.Tone -ne 'ok') `
    "(tone '$($lostEarly.V3.Tone)' sub '$($lostEarly.V3.Sub)')"
Assert-That 'sensor health card is not green when the server was lost early' ($lostEarly.Health.Tone -ne 'ok') `
    "(tone '$($lostEarly.Health.Tone)' sub '$($lostEarly.Health.Sub)')"
Assert-That 'v3 card renders the same as the disclosed case' ($lostEarly.V3.Tone -eq $disclosed.V3.Tone) `
    "(lost '$($lostEarly.V3.Tone)' vs disclosed '$($disclosed.V3.Tone)')"
Assert-That 'the lost server is counted as unevaluated' ([int] $lostEarly.Stats.V3Unevaluated -ge 1) `
    "(V3Unevaluated $($lostEarly.Stats.V3Unevaluated))"

'[w86] a two-server estate never renders identically to a one-server estate'
foreach ($case in @(@{ N = 'disclosed'; C = $disclosed }, @{ N = 'lost early'; C = $lostEarly })) {
    $c = $case.C
    $sameAsOne = ($c.V3.Tone -eq $oneServer.V3.Tone -and $c.V3.Sub -eq $oneServer.V3.Sub)
    Assert-That "  v3 card distinguishes two servers from one ($($case.N))" (-not $sameAsOne) `
        "(both '$($c.V3.Tone)' / '$($c.V3.Sub)')"
}

'[w86] boundary: an UNREACHABLE server is not charged to these cards'
# It is already reported by the unreachable KPI, the issue list and the verdict. Charging it here too
# would report one gap twice, which the codebase explicitly refuses to do elsewhere.
Assert-That 'an unreachable server does not appear as unevaluated v3' `
    ([int] $unreachable.Stats.V3Unevaluated -eq [int] $oneServer.Stats.V3Unevaluated) `
    "(one-server $($oneServer.Stats.V3Unevaluated) vs unreachable-added $($unreachable.Stats.V3Unevaluated))"
Assert-That 'but the estate is still not READY, so the gap is not lost' `
    ([int] $unreachable.Stats.UnreachableCount -ge 1) "(UnreachableCount $($unreachable.Stats.UnreachableCount))"

'[w86] boundary: a discovery PLACEHOLDER is not charged to these cards either'
# A placeholder is a role that could not be enumerated. It is already unmeasured population in its
# own right - counted in the check score and named in the issue list - so charging it to the sensor
# cards as well would report the same gap on two surfaces. Without this case the placeholder
# exclusion in the fix could be deleted and nothing would notice.
$placeholder = Get-Cards -Servers @(
    (New-ReadyServer 'dc1.contoso.com'),
    [PSCustomObject]@{
        FQDN = 'ca-role-not-enumerated'; Domain = 'contoso.com'
        Unreachable = $false; PartialFailure = $false; IsPlaceholder = $true
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{ FailedRequired = @(); NnrFailedTargets = @(); Results = @() } }
    })
Assert-That 'the fixture really is a placeholder' (Test-mdiServerIsPlaceholder -Server ([PSCustomObject]@{ FQDN = 'x'; IsPlaceholder = $true }))
Assert-That 'a placeholder does not appear as unevaluated v3' `
    ([int] $placeholder.Stats.V3Unevaluated -eq [int] $oneServer.Stats.V3Unevaluated) `
    "(one-server $($oneServer.Stats.V3Unevaluated) vs placeholder-added $($placeholder.Stats.V3Unevaluated))"
Assert-That 'and the v3 card stays green - the placeholder is disclosed elsewhere' `
    ($placeholder.V3.Tone -eq 'ok') "(tone '$($placeholder.V3.Tone)' sub '$($placeholder.V3.Sub)')"
Assert-That 'a placeholder does not turn the sensor health card amber either' `
    ($placeholder.Health.Tone -eq 'ok') "(tone '$($placeholder.Health.Tone)' sub '$($placeholder.Health.Sub)')"

''
"PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 }
