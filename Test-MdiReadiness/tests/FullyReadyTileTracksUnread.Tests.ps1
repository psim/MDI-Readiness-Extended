<#
    The "Servers fully ready" KPI tile must not paint green over an estate-level gap.

    $readyServers, $needAttention, $trulyUnmeasured and $notReady are all derived from the REAL
    server scores. An estate-level gap - an incomplete forest discovery, a discovery placeholder for
    a role that could not be enumerated, or a domain whose directory checks could not be read - is
    charged to $stats.ChecksUnread but belongs to no single server, so every one of those counts is
    legitimately zero and the tile fell through to a green "1/1 - All checks passed". Measured on
    the shipped functions: that green tile rendered directly beside its own score card reading
    "10 of 11 checks passed, 1 not measured", one High finding, and a hero verdict of "Action
    required" - four parts of one page disagreeing about whether anything needed doing.

    The empty-scan case (TotalServers -eq 0) had already been special-cased for exactly this
    reason, which closed the instance where NOTHING was examined and left the three where the
    estate is only partly examined - the harder ones to spot, because the rest of the page looks
    healthy.

    Asserted on the RENDERED MARKUP, not by recomputing the tile's own expression. A test that
    reimplements the branch it is checking passes while the defect is reintroduced: the probe that
    originally found this defect did exactly that, and its verdict lines went on reporting DEFECT
    after the fix had demonstrably corrected the HTML.

    The clean-estate control matters as much as the gap cases. Suppressing the green tile
    unconditionally would also "fix" this defect, and would be a false amber on every healthy
    estate - so a genuinely clean run must still say "All checks passed" in ok.
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

$readyDc = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; Domain = 'contoso.com'
    Unreachable = $false; PartialFailure = $false; Comment = ''
    Details = [PSCustomObject]@{}
    AdvancedAuditing = $true; NtlmAuditing = $true; PowerSettings = $true
    RequiredPorts = $true; TimeSync = $true; SensorHealth = $true
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
function New-BaseReport {
    param($DomainAuditing, $ForestDiscovery = $null, $CaServers = @())
    [PSCustomObject]@{
        Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @($readyDc); CAServers = @($CaServers); EntraConnectServers = @()
        DomainAuditing = @($DomainAuditing)
        ForestDiscovery = $ForestDiscovery
        DomainSchemaVersion = [PSCustomObject]@{ details = 'x'; schemaVersion = 1 }
        LdapPlanGapDomains = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
    }
}

$unmeasuredDomainAuditing = [PSCustomObject]@{
    Domain = 'contoso.com'
    ObjectAuditing = [PSCustomObject]@{ isObjectAuditingOk = 'N/A' }
    ExchangeAuditing = [PSCustomObject]@{ isExchangeAuditingOk = 'N/A' }
    AdfsAuditing = [PSCustomObject]@{ isAdfsAuditingOk = 'N/A' }
    DeletedObjects = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
    ObjectAuditingMeasured = $false; ExchangeAuditingMeasured = $true
    AdfsAuditingMeasured = $true; DeletedObjectsMeasured = $true
}
$placeholderCa = [PSCustomObject]@{
    FQDN = 'AD CS (not enumerated) - contoso.com'; Domain = 'contoso.com'
    Unreachable = $false; PartialFailure = $false; IsPlaceholder = $true
    Comment = 'AD CS role could not be enumerated'; Details = [PSCustomObject]@{}
}

function Get-TileFromHtml {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    $html = (Get-mdiOverviewHtml -Statistics $stats -ReportData $Report) -join ''
    $tone = if ($html -match 'class="kpi (ok|bad|warn)"><span class="kpi-label">Servers fully ready') { $Matches[1] } else { '?' }
    $sub = if ($html -match 'Servers fully ready</span><span class="kpi-value">([^<]+)</span><span class="kpi-sub">([^<]+)') { $Matches[2] } else { '?' }
    [PSCustomObject]@{ Tone = $tone; Sub = $sub; Unread = [int] $stats.ChecksUnread }
}

'[fully-ready tile] an estate-level gap must not render a green "All checks passed"'
foreach ($case in @(
        @{ Name = 'incomplete forest discovery'
           Report = (New-BaseReport $cleanDomainAuditing ([PSCustomObject]@{ Complete = $false; Error = 'access denied' })) }
        @{ Name = 'role that could not be enumerated'
           Report = (New-BaseReport $cleanDomainAuditing $null $placeholderCa) }
        @{ Name = 'domain directory check unmeasured'
           Report = (New-BaseReport $unmeasuredDomainAuditing) }
    )) {
    $t = Get-TileFromHtml $case.Report
    Assert-That ("{0}: the gap is charged as unread" -f $case.Name) ($t.Unread -gt 0) "(unread=$($t.Unread))"
    Assert-That ("{0}: the tile does not claim all checks passed" -f $case.Name) ($t.Sub -ne 'All checks passed') "(sub='$($t.Sub)')"
    Assert-That ("{0}: the tile is not painted ok" -f $case.Name) ($t.Tone -ne 'ok') "(tone='$($t.Tone)')"
    Assert-That ("{0}: the tile says what was not measured" -f $case.Name) ($t.Sub -match 'not measured') "(sub='$($t.Sub)')"
}

'[fully-ready tile] a genuinely clean estate still reads green'
$clean = Get-TileFromHtml (New-BaseReport $cleanDomainAuditing)
Assert-That 'the clean control has nothing unread' ($clean.Unread -eq 0) "(unread=$($clean.Unread))"
Assert-That 'the clean control still says all checks passed' ($clean.Sub -eq 'All checks passed') "(sub='$($clean.Sub)')"
Assert-That 'the clean control is still painted ok' ($clean.Tone -eq 'ok') "(tone='$($clean.Tone)')"

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
