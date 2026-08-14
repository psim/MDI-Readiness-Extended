<#
    Unmeasured population may never be dropped from a headline KPI.

    Every defect these tests pin had one shape: a population that could NOT be measured was removed
    from a summary card's numerator AND denominator together, so losing coverage IMPROVED the
    headline. Four cards did it at once, each contradicted by another surface on its own page:

      - "Overall check score" read a green 100% ("3 of 3 checks passed") over a scan that reached
        one domain controller in four, beside a red "3 not reachable" card and under a NOT READY
        verdict. The readiness donut, built from the same numbers, drew a solid green ring.
      - "Servers fully ready" counted the synthetic "Domain not examined" rows as servers, so 2
        reachable servers rendered "2/2" with the sub-label "1 not measured" - the overview's own
        stated invariant, ready + attention + unmeasured = reachable, giving 2 + 0 + 1 = 3.
      - "Sensors healthy" asserted "No v2.x sensor installed yet" - a definite claim about the
        estate - for servers whose WMI never answered, while the table below said "Not tested".
      - "Sensor v3.x ready" showed a green 1/1 over a v3 tab reading "Not determined" three times.

    These assert on the RENDERED CARDS - tone, value and sub-label parsed back out of the HTML the
    script actually emits - not on the source text. A test that greps the script passes happily
    while the defect is reintroduced, which has already happened on this project.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

function New-TestServer {
    param($Fqdn, [hashtable] $Checks = @{}, $Unreachable = $false, $Domain = 'contoso.com')
    $o = [PSCustomObject]@{
        FQDN        = $Fqdn
        Domain      = $Domain
        Unreachable = $Unreachable
        Comment     = $null
        Details     = [PSCustomObject]@{}
    }
    foreach ($k in $Checks.Keys) { $o | Add-Member -NotePropertyName $k -NotePropertyValue $Checks[$k] -Force }
    $o
}

function New-TestReport {
    param([object[]] $Dc, [string[]] $Scope = @('contoso.com'))
    [PSCustomObject]@{
        DomainControllers   = @($Dc)
        CAServers           = @()
        EntraConnectServers = @()
        DomainsInScope      = $Scope
        Domain              = $Scope[0]
        Forest              = $Scope[0]
    }
}

# The rendered card, read back out of the HTML: tone, value and sub-label as an operator sees them.
function Get-RenderedKpi {
    param($Statistics, $ReportData)
    $html = (Get-mdiOverviewHtml -Statistics $Statistics -ReportData $ReportData) -join "`n"
    $map = @{}
    foreach ($m in [regex]::Matches($html, '<div class="kpi (\w+)"><span class="kpi-label">(.*?)</span><span class="kpi-value">(.*?)</span><span class="kpi-sub">(.*?)</span></div>')) {
        $map[$m.Groups[2].Value] = [PSCustomObject]@{
            Tone = $m.Groups[1].Value; Value = $m.Groups[3].Value; Sub = $m.Groups[4].Value
        }
    }
    $map
}

$checks = @{ NtlmAuditing = $true; AdvancedAuditing = $true; PowerSettings = $true }

Write-Host 'An unreached server is unmeasured population, not a pass' -ForegroundColor Cyan
# One DC reachable and passing all three checks; three DCs that never answered.
$repA = New-TestReport -Dc @(
    (New-TestServer 'dc1.contoso.com' $checks)
    (New-TestServer 'dc2.contoso.com' @{} $true)
    (New-TestServer 'dc3.contoso.com' @{} $true)
    (New-TestServer 'dc4.contoso.com' @{} $true)
)
$stA = Get-mdiReportStatistics -ReportData $repA
$kpiA = Get-RenderedKpi -Statistics $stA -ReportData $repA
$scoreA = $kpiA['Overall check score']

Assert-That 'three unreached servers are charged to the score denominator' (
    $stA.ChecksUnread -eq 3) "(ChecksUnread=$($stA.ChecksUnread), expected 3)"
Assert-That 'the score card is NOT 100% when 3 of 4 servers never answered' (
    $scoreA.Value -ne '100%') "(rendered '$($scoreA.Value)')"
Assert-That '  ...it reads 50%: 3 passed of 6 attempted' ($scoreA.Value -eq '50%') "(rendered '$($scoreA.Value)')"
Assert-That '  ...and is not toned ok' ($scoreA.Tone -ne 'ok') "(tone '$($scoreA.Tone)')"
Assert-That '  ...and discloses the unmeasured checks in its sub-label' (
    $scoreA.Sub -match 'not measured') "(sub '$($scoreA.Sub)')"
# The card and the verdict are two surfaces of one fact and may never disagree.
$verdictA = Test-mdiReadinessResult -ReportData $repA 3>$null
Assert-That 'the score card agrees with the verdict that the run is not ready' (
    $verdictA -eq $false -and $scoreA.Tone -ne 'ok')
# The donut is built from the same three numbers and is what actually gets screenshotted.
$donutA = (Get-mdiOverviewHtml -Statistics $stA -ReportData $repA) -join "`n"
Assert-That 'the readiness donut carries a "not read" arc for the unreached servers' (
    $donutA -match 'Not read: 3')
Assert-That '  ...and its centre value is not 100%' ($donutA -notmatch '>100%<')

# Losing a measurement must never raise the headline. This is the property the whole class violates.
$repAllUp = New-TestReport -Dc @(
    (New-TestServer 'dc1.contoso.com' $checks)
    (New-TestServer 'dc2.contoso.com' $checks)
    (New-TestServer 'dc3.contoso.com' $checks)
    (New-TestServer 'dc4.contoso.com' $checks)
)
$stAllUp = Get-mdiReportStatistics -ReportData $repAllUp
$pctAllUp = [math]::Floor((Get-mdiCoveragePercent -Passed $stAllUp.ChecksPassed -Measured $stAllUp.ChecksTotal -Unread $stAllUp.ChecksUnread))
$pctA = [math]::Floor((Get-mdiCoveragePercent -Passed $stA.ChecksPassed -Measured $stA.ChecksTotal -Unread $stA.ChecksUnread))
Assert-That 'losing three servers LOWERS the score rather than raising it' (
    $pctA -lt $pctAllUp) "(1-of-4 scored $pctA, 4-of-4 scored $pctAllUp)"

Write-Host 'Synthetic unmeasured rows are not servers' -ForegroundColor Cyan
# Two reachable servers in a.com; b.com is in scope but produced nothing.
$repB = New-TestReport -Dc @(
    (New-TestServer 'dc1.a.com' $checks $false 'a.com')
    (New-TestServer 'dc2.a.com' $checks $false 'a.com')
) -Scope @('a.com', 'b.com')
$stB = Get-mdiReportStatistics -ReportData $repB
$kpiB = Get-RenderedKpi -Statistics $stB -ReportData $repB
$readyB = $kpiB['Servers fully ready']

Assert-That 'the unexamined domain still charges the score denominator' ($stB.ChecksUnread -eq 1)
Assert-That '  ...and the score card discloses it' (
    $kpiB['Overall check score'].Sub -match '1 not measured')
# ready + attention + unmeasured must account for exactly the reachable servers.
Assert-That 'the servers card counts 2 of 2 reachable servers' (
    $readyB.Value -eq '2/2') "(rendered '$($readyB.Value)')"
Assert-That '  ...and does not describe a third server that does not exist' (
    $readyB.Sub -notmatch '(?<!check\(s\) )\bnot measured\b') "(sub '$($readyB.Sub)')"
# The invariant is about the UNIT, not about the phrase. An estate-level gap - an unexamined domain,
# a discovery placeholder, an unreadable directory check - is charged to the score and must keep this
# tile from claiming "All checks passed", so the tile is allowed to disclose it; what it must never do
# is state it in SERVERS, because there is no third server. "1 check(s) not measured" is the
# disclosure; "1 not measured" under a headline of 2/2 servers is the phantom.
Assert-That '  ...and any disclosure it does make names checks, not servers' (
    ($readyB.Sub -notmatch 'not measured') -or ($readyB.Sub -match 'check')) "(sub '$($readyB.Sub)')"
# The placeholder rows must be distinguishable from real servers by construction.
$placeholders = @($stB.ServerScores | Where-Object { $_.Kind -eq 'Unmeasured' })
$realRows = @($stB.ServerScores | Where-Object { $_.Kind -ne 'Unmeasured' })
Assert-That 'the unexamined-domain row is marked as unmeasured, not as a server' (
    $placeholders.Count -eq 1 -and $realRows.Count -eq 2) "(placeholders=$($placeholders.Count) real=$($realRows.Count))"
Assert-That '  ...and the real rows equal the reachable count' ($realRows.Count -eq $stB.ReachableServers)
# Same invariant on the unreachable-server placeholders from case A.
$realA = @($stA.ServerScores | Where-Object { $_.Kind -ne 'Unmeasured' })
Assert-That 'unreachable servers are not counted twice as servers' (
    $realA.Count -eq $stA.ReachableServers) "(real=$($realA.Count) reachable=$($stA.ReachableServers))"
Assert-That '  ...and the servers card still names them as unreachable' (
    $kpiA['Servers fully ready'].Sub -match '3 not reachable')

Write-Host 'Unreadable sensor state is not an absent sensor' -ForegroundColor Cyan
function New-SensorServer {
    param($Fqdn, $Installed, $Healthy)
    $o = New-TestServer $Fqdn @{ NtlmAuditing = $true }
    $o.Details | Add-Member -NotePropertyName SensorHealthDetails -NotePropertyValue ([PSCustomObject]@{
            Installed = $Installed; ServiceRunning = $Healthy; Version = 'N/A'
        }) -Force
    $o | Add-Member -NotePropertyName SensorHealth -NotePropertyValue $Healthy -Force
    $o
}
# Nothing readable anywhere: the card must not assert that no sensor is installed.
$repS1 = New-TestReport -Dc @(
    (New-SensorServer 'dc1.contoso.com' 'N/A' 'N/A')
    (New-SensorServer 'dc2.contoso.com' 'N/A' 'N/A')
)
$stS1 = Get-mdiReportStatistics -ReportData $repS1
$sensorS1 = (Get-RenderedKpi -Statistics $stS1 -ReportData $repS1)['Sensors healthy']
Assert-That 'an unreadable estate is not reported as having no sensor installed' (
    $sensorS1.Sub -notmatch 'No v2\.x sensor installed yet') "(sub '$($sensorS1.Sub)')"
Assert-That '  ...it says the servers could not be read' ($sensorS1.Sub -match 'could not be read') "(sub '$($sensorS1.Sub)')"
Assert-That '  ...and is toned warn, not na' ($sensorS1.Tone -eq 'warn') "(tone '$($sensorS1.Tone)')"

# One genuinely healthy sensor, two servers nobody could read: 1/1 must not render as a clean green.
$repS2 = New-TestReport -Dc @(
    (New-SensorServer 'dc1.contoso.com' 'True' $true)
    (New-SensorServer 'dc2.contoso.com' 'N/A' 'N/A')
    (New-SensorServer 'dc3.contoso.com' 'N/A' 'N/A')
)
$stS2 = Get-mdiReportStatistics -ReportData $repS2
$sensorS2 = (Get-RenderedKpi -Statistics $stS2 -ReportData $repS2)['Sensors healthy']
Assert-That 'two unreadable servers are disclosed beside the healthy count' (
    $sensorS2.Sub -match '2 could not be read') "(sub '$($sensorS2.Sub)')"
Assert-That '  ...and the card is not toned ok' ($sensorS2.Tone -ne 'ok') "(tone '$($sensorS2.Tone)')"
# A genuinely complete estate must still read green, or the tone carries no information.
$repS3 = New-TestReport -Dc @(
    (New-SensorServer 'dc1.contoso.com' 'True' $true)
    (New-SensorServer 'dc2.contoso.com' 'True' $true)
)
$stS3 = Get-mdiReportStatistics -ReportData $repS3
$sensorS3 = (Get-RenderedKpi -Statistics $stS3 -ReportData $repS3)['Sensors healthy']
Assert-That 'a fully read, fully healthy estate is still green' (
    $sensorS3.Tone -eq 'ok' -and $sensorS3.Sub -eq 'All sensor services running') "(tone '$($sensorS3.Tone)' sub '$($sensorS3.Sub)')"
# And a genuine observed absence must still be sayable.
$repS4 = New-TestReport -Dc @((New-SensorServer 'dc1.contoso.com' 'False' $false))
$stS4 = Get-mdiReportStatistics -ReportData $repS4
$sensorS4 = (Get-RenderedKpi -Statistics $stS4 -ReportData $repS4)['Sensors healthy']
Assert-That 'an OBSERVED absence of sensors is still reported as such' (
    $sensorS4.Sub -match 'No v2\.x sensor installed yet') "(sub '$($sensorS4.Sub)')"

Write-Host 'Undetermined v3 readiness is disclosed, not dropped' -ForegroundColor Cyan
function New-V3Server {
    param($Fqdn, $Ready, $Eligible)
    $o = New-TestServer $Fqdn @{ NtlmAuditing = $true }
    $o | Add-Member -NotePropertyName SensorV3Ready -NotePropertyValue $Ready -Force
    $o.Details | Add-Member -NotePropertyName SensorV3ReadyDetails -NotePropertyValue ([PSCustomObject]@{
            MigrationEligible = $Eligible; Blockers = @()
        }) -Force
    $o
}
$repV = New-TestReport -Dc @(
    (New-V3Server 'dc1.contoso.com' $true $true)
    (New-V3Server 'dc2.contoso.com' 'N/A' 'N/A')
    (New-V3Server 'dc3.contoso.com' 'N/A' 'N/A')
)
$stV = Get-mdiReportStatistics -ReportData $repV
$v3 = (Get-RenderedKpi -Statistics $stV -ReportData $repV)['Sensor v3.x ready']
Assert-That 'servers whose v3 readiness could not be determined are counted' (
    $stV.V3Unevaluated -eq 2) "(V3Unevaluated=$($stV.V3Unevaluated))"
Assert-That '  ...and named on the card' ($v3.Sub -match '2 could not be evaluated') "(sub '$($v3.Sub)')"
Assert-That '  ...so the card is not toned ok' ($v3.Tone -ne 'ok') "(tone '$($v3.Tone)')"
# A fully evaluated, fully ready estate must still read green.
$repV2 = New-TestReport -Dc @(
    (New-V3Server 'dc1.contoso.com' $true $true)
    (New-V3Server 'dc2.contoso.com' $true $true)
)
$stV2 = Get-mdiReportStatistics -ReportData $repV2
$v3b = (Get-RenderedKpi -Statistics $stV2 -ReportData $repV2)['Sensor v3.x ready']
Assert-That 'a fully evaluated, fully ready estate is still green' (
    $v3b.Tone -eq 'ok' -and $v3b.Sub -notmatch 'could not be evaluated') "(tone '$($v3b.Tone)' sub '$($v3b.Sub)')"

Write-Host 'The persisted history keeps the unmeasured population' -ForegroundColor Cyan
# The history is written permanently and is what gets reported upward over time, so a headline that
# overstates coverage there outlives the run that produced it. Storing V3Ready and V3Evaluated alone
# preserved "1 of 1 ready" for a run that could assess one server in three, and no consumer of the
# file could recover that the real coverage was 33%.
#
# Asserted against the entry actually written to and read back from disk, not against a shape built
# in the test - the file is the artefact that survives the run.
$histDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi-w30-hist-{0}' -f [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $histDir -Force
try {
    $written = Get-mdiBaselineHistory -BaselinePath $histDir -Domain 'contoso.com' -Statistics $stV
    $histEntry = @($written.History)[-1]

    $hasV3Unevaluated = $null -ne $histEntry.PSObject.Properties['V3Unevaluated']
    Assert-That 'the history entry carries the unevaluated v3 population' $hasV3Unevaluated
    if ($hasV3Unevaluated) {
        Assert-That '  ...with the same value the report showed' (
            [int] $histEntry.V3Unevaluated -eq 2) "(stored $($histEntry.V3Unevaluated), expected 2)"
        # The stored triple must not imply a perfect score. 1/1 does; 1 of (1+2) does not.
        $storedApparent = if ([int] $histEntry.V3Evaluated -gt 0) { [math]::Floor(([int] $histEntry.V3Ready / [int] $histEntry.V3Evaluated) * 100) } else { 0 }
        $storedCovered = [math]::Floor((Get-mdiCoveragePercent -Passed $histEntry.V3Ready -Measured $histEntry.V3Evaluated -Unread $histEntry.V3Unevaluated))
        Assert-That '  ...so coverage is recoverable from the file, not just an apparent 100%' (
            $storedApparent -eq 100 -and $storedCovered -eq 33) "(apparent $storedApparent%, recoverable $storedCovered%)"
    }

    # It must survive the JSON round-trip too: the file is what a later run actually reads.
    $onDisk = Get-ChildItem -Path $histDir -Filter 'mdi-baseline-*.json' | Select-Object -First 1
    Assert-That 'the history file was written' ($null -ne $onDisk)
    if ($onDisk) {
        $reread = @((Get-Content -LiteralPath $onDisk.FullName -Raw | ConvertFrom-Json))[-1]
        Assert-That '  ...and the unevaluated count survives the round-trip to disk' (
            [int] $reread.V3Unevaluated -eq 2) "(read back $($reread.V3Unevaluated))"
    }
} finally {
    Remove-Item -LiteralPath $histDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
exit 0
