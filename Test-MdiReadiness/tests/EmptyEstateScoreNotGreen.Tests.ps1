<#
    An empty scan must not render a green readiness score.

    Main declares a run that enumerated no server SCAN INCOMPLETE and exits 255 precisely so that no
    readiness conclusion is drawn from it. The "Overall check score" card did not consult
    TotalServers at all - it took its verdict from the DENOMINATOR alone - and the four domain-level
    checks (object auditing, Exchange, ADFS, deleted objects) are measured BEFORE any server is
    reached, so they survive an estate that enumerated nothing. Measured on the shipped functions:
    zero servers with four passing domain checks rendered

        Overall check score   100%   "4 of 4 checks passed"   in the ok (green) tone
        donut                 100%   "ready"                  a solid green ring

    beside a red hero banner, a console reading SCAN INCOMPLETE, and exit 255. The score is the
    number a reader screenshots, so this was the most dangerous false green on the page.

    The chart is pinned together with the card deliberately. Fixing only the score would leave the
    donut painting a solid green 100% ring, and the two surfaces would disagree - which is the exact
    defect class this campaign exists to remove. The ring is the worse half: a reader takes the
    picture, not the caption.

    Asserted on the RENDERED MARKUP rather than by recomputing the card's own expression. A test that
    reimplements the branch it checks keeps passing while the defect is reintroduced.

    The healthy control carries equal weight. Blanking the score unconditionally would also "fix"
    this defect and would be a false amber on every real estate, so a genuinely clean run must still
    render a green 100% card and a "100% ready" donut.
#>

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

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$cleanDomainAuditing = [PSCustomObject]@{
    Domain = 'contoso.com'
    ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = $true }
    ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = $true }
    DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
    ObjectAuditingMeasured = $true; ExchangeAuditingMeasured = $true
    AdfsAuditingMeasured = $true; DeletedObjectsMeasured = $true
}
$readyDc = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'
    Unreachable = $false; PartialFailure = $false; Comment = ''
    Details = [PSCustomObject]@{}
    AdvancedAuditing = $true; NtlmAuditing = $true; PowerSettings = $true
    RequiredPorts = $true; TimeSync = $true; SensorHealth = $true
}
function New-Report {
    param($Dcs)
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @($Dcs); CAServers = @(); EntraConnectServers = @()
        DomainAuditing = @($cleanDomainAuditing)
        ForestDiscovery = $null
        DomainSchemaVersion = [PSCustomObject]@{ details = 'x'; schemaVersion = 1 }
        LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
    }
}

function Get-ScoreSurfaces {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    $html = (Get-mdiOverviewHtml -Statistics $stats -ReportData $Report) -join ''
    $tone = if ($html -match '<div class="kpi (ok|warn|bad|na)"><span class="kpi-label">Overall check score') { $Matches[1] } else { 'none' }
    $value = 'none'; $sub = 'none'
    if ($html -match 'Overall check score</span><span class="kpi-value">([^<]*)</span><span class="kpi-sub">([^<]*)') {
        $value = $Matches[1]; $sub = $Matches[2]
    }
    $donutValue = 'none'; $donutLabel = 'none'
    if ($html -match '<text class="donut-value"[^>]*>([^<]*)</text><text class="donut-label"[^>]*>([^<]*)</text>') {
        $donutValue = $Matches[1]; $donutLabel = $Matches[2]
    }
    [PSCustomObject]@{
        Tone = $tone; Value = $value; Sub = $sub
        DonutValue = $donutValue; DonutLabel = $donutLabel
        TotalServers = [int] $stats.TotalServers; ChecksPassed = [int] $stats.ChecksPassed
    }
}

'[empty scan] the readiness score must not render green over an estate nobody looked at'
$empty = Get-ScoreSurfaces (New-Report @())
Assert-That 'the estate really is empty' ($empty.TotalServers -eq 0) "(servers=$($empty.TotalServers))"
Assert-That 'domain-level checks still passed, so the denominator is non-zero' ($empty.ChecksPassed -gt 0) "(passed=$($empty.ChecksPassed))"
Assert-That 'the score card is not painted ok' ($empty.Tone -ne 'ok') "(tone='$($empty.Tone)')"
Assert-That 'the score card does not claim a percentage' ($empty.Value -notmatch '^\d+%$') "(value='$($empty.Value)')"
Assert-That 'the score card does not claim checks passed' ($empty.Sub -notmatch 'checks passed') "(sub='$($empty.Sub)')"
Assert-That 'the score card says nothing was examined' ($empty.Sub -match 'No server was examined') "(sub='$($empty.Sub)')"

'[empty scan] the donut must move with the card, not paint a solid green ring'
Assert-That 'the donut does not claim a percentage' ($empty.DonutValue -notmatch '^\d+%$') "(donut='$($empty.DonutValue)')"
Assert-That 'the donut is not captioned ready' ($empty.DonutLabel -ne 'ready') "(label='$($empty.DonutLabel)')"

'[healthy control] a genuinely clean estate still reads a green 100%'
$clean = Get-ScoreSurfaces (New-Report $readyDc)
Assert-That 'the control has servers' ($clean.TotalServers -gt 0) "(servers=$($clean.TotalServers))"
Assert-That 'the control score card is still ok' ($clean.Tone -eq 'ok') "(tone='$($clean.Tone)')"
Assert-That 'the control score card still reads 100%' ($clean.Value -eq '100%') "(value='$($clean.Value)')"
Assert-That 'the control score card still counts its checks' ($clean.Sub -match 'checks passed') "(sub='$($clean.Sub)')"
Assert-That 'the control donut still reads 100%' ($clean.DonutValue -eq '100%') "(donut='$($clean.DonutValue)')"
Assert-That 'the control donut is still captioned ready' ($clean.DonutLabel -eq 'ready') "(label='$($clean.DonutLabel)')"

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
