<#
    A trend delta must be drawn between two runs of the SAME estate, and never between two estates.

    The history file is named after the domain, but the name of a file is not proof of what is inside
    it. The comparability guard checked the check set, the server set, the covered population and the
    scanner version - and never the estate itself. So a baseline copied between customers, restored
    from the wrong backup, or a domain name that lives in two forests (contoso.com in a lab and in
    production is the ordinary case) was compared against the current run as though it were the same
    estate. Measured on the shipped renderer, BOTH of these rendered:

        &uarr; 20 pt vs previous run (2 run(s) recorded)

    a confident improvement figure computed from a stranger's estate. A percentage-point number is
    exactly what gets copied into a status report, and the renderer already knew how to say "Not
    comparable" - it just never asked this question.

    Asserted on the RENDERED PILL MARKUP produced by the real New-mdiTrendChart, from history entries
    produced by the real Get-mdiBaselineHistory. A test that recomputed the guard would keep passing
    while the defect was reintroduced.

    The controls carry equal weight, because refusing every comparison would also "fix" this and would
    destroy the feature:
      - a genuine same-estate pair must still draw its delta
      - 'CONTOSO.COM.' vs 'contoso.com' is ONE estate (DNS rules: case-insensitive, trailing dot
        ignored) and must still draw its delta
      - a LEGACY history written before these fields existed must still compare, or every baseline in
        the field silently stops producing a trend
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
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

$domainAuditing = [PSCustomObject]@{
    Domain                 = 'contoso.com'
    ObjectAuditing         = [PSCustomObject]@{ isObjectAuditingOk = $true }
    ExchangeAuditing       = [PSCustomObject]@{ isExchangeAuditingOk = $true }
    AdfsAuditing           = [PSCustomObject]@{ isAdfsAuditingOk = $true }
    DeletedObjects         = [PSCustomObject]@{ isDeletedObjectsPermissionOk = $true; details = [PSCustomObject]@{ Detail = 'ok' } }
    ObjectAuditingMeasured = $true; ExchangeAuditingMeasured = $true
    AdfsAuditingMeasured   = $true; DeletedObjectsMeasured = $true
}
$dc = [PSCustomObject]@{
    FQDN             = 'dc1.contoso.com'; Domain = 'contoso.com'
    Unreachable      = $false; PartialFailure = $false; Comment = ''
    Details          = [PSCustomObject]@{}
    AdvancedAuditing = $true; NtlmAuditing = $true; PowerSettings = $true
    RequiredPorts    = $true; TimeSync = $true; SensorHealth = $true
}
$report = [PSCustomObject]@{
    Domain              = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers   = @($dc); CAServers = @(); EntraConnectServers = @()
    DomainAuditing      = @($domainAuditing)
    ForestDiscovery     = $null
    DomainSchemaVersion = [PSCustomObject]@{ details = 'x'; schemaVersion = 1 }
    LdapPlanGapDomains  = @(); NnrUnresolvedTargets = @(); NnrTargetComputer = @()
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('mdi-estateid-' + [guid]::NewGuid().ToString('N'))
[void] (New-Item -ItemType Directory -Path $tmp -Force)

try {
    $stats = Get-mdiReportStatistics -ReportData $report
    # The fixture is the REAL writer's output, so the test cannot drift from the shape actually stored.
    $written = Get-mdiBaselineHistory -BaselinePath $tmp -Domain 'contoso.com' -Forest 'contoso.com' -Statistics $stats
    $entry = $written.Current

    '[the writer] the history must record which estate the run measured'
    Assert-That 'the entry carries a Domain' ([string] $entry.Domain -eq 'contoso.com') "(got '$($entry.Domain)')"
    Assert-That 'the entry carries a Forest' ([string] $entry.Forest -eq 'contoso.com') "(got '$($entry.Forest)')"

    function New-Point {
        param($From, [string] $Stamp, [int] $Passed, $Domain = '__keep__', $Forest = '__keep__')
        $p = $From.PSObject.Copy()
        $p.Timestamp = $Stamp
        $p.ChecksPassed = $Passed
        if ($Domain -ne '__keep__') { $p.Domain = $Domain }
        if ($Forest -ne '__keep__') { $p.Forest = $Forest }
        $p
    }
    function Get-Pill {
        param($Previous, $Current)
        $html = (New-mdiTrendChart -History @($Previous, $Current)) -join ''
        $m = [regex]::Match($html, '<span class="pill[^"]*">([^<]*)</span>')
        $raw = if ($m.Success) { $m.Groups[1].Value } else { '<none>' }
        [PSCustomObject]@{
            Text           = [Net.WebUtility]::HtmlDecode($raw)
            NotComparable  = ($raw -match 'Not comparable')
            HasArrow       = ($html.Contains('&uarr;') -or $html.Contains('&darr;'))
            HasPercentages = ($raw -match '\d+(\.\d+)?\s*pt')
        }
    }

    # One fewer passing check in the baseline, so a delta MUST be drawn whenever the estate matches.
    $lowPassed = [int] $entry.ChecksPassed - 1

    '[different domain] a baseline from another domain must not produce a delta'
    $d = Get-Pill (New-Point $entry '2026-08-14T09:00:00' $lowPassed -Domain 'fabrikam.com') (New-Point $entry '2026-08-14T10:00:00' ([int] $entry.ChecksPassed))
    Assert-That 'the comparison is refused' ($d.NotComparable) "(pill='$($d.Text)')"
    Assert-That 'the reason names the domain mismatch' ($d.Text -match 'different domain') "(pill='$($d.Text)')"
    Assert-That 'no improvement arrow is drawn' (-not $d.HasArrow) "(pill='$($d.Text)')"
    Assert-That 'no percentage-point figure is offered' (-not $d.HasPercentages) "(pill='$($d.Text)')"

    '[different forest] the same domain name in another forest is another estate'
    $f = Get-Pill (New-Point $entry '2026-08-14T09:00:00' $lowPassed -Forest 'fabrikam.net') (New-Point $entry '2026-08-14T10:00:00' ([int] $entry.ChecksPassed))
    Assert-That 'the comparison is refused' ($f.NotComparable) "(pill='$($f.Text)')"
    Assert-That 'the reason names the forest mismatch' ($f.Text -match 'different forest') "(pill='$($f.Text)')"
    Assert-That 'no improvement arrow is drawn' (-not $f.HasArrow) "(pill='$($f.Text)')"

    '[same estate control] a genuine comparison must still draw its delta'
    $same = Get-Pill (New-Point $entry '2026-08-14T09:00:00' $lowPassed) (New-Point $entry '2026-08-14T10:00:00' ([int] $entry.ChecksPassed))
    Assert-That 'the comparison is allowed' (-not $same.NotComparable) "(pill='$($same.Text)')"
    Assert-That 'an arrow is drawn' ($same.HasArrow) "(pill='$($same.Text)')"
    Assert-That 'a percentage-point figure is offered' ($same.HasPercentages) "(pill='$($same.Text)')"

    '[dns normalisation control] case and a trailing dot are the same estate'
    $norm = Get-Pill (New-Point $entry '2026-08-14T09:00:00' $lowPassed -Domain 'CONTOSO.COM.' -Forest 'CONTOSO.COM.') (New-Point $entry '2026-08-14T10:00:00' ([int] $entry.ChecksPassed))
    Assert-That 'the comparison is still allowed' (-not $norm.NotComparable) "(pill='$($norm.Text)')"
    Assert-That 'an arrow is still drawn' ($norm.HasArrow) "(pill='$($norm.Text)')"

    '[legacy history control] baselines written before these fields existed must keep working'
    $legacyPrev = New-Point $entry '2026-08-14T09:00:00' $lowPassed -Domain '' -Forest ''
    $legacyCurr = New-Point $entry '2026-08-14T10:00:00' ([int] $entry.ChecksPassed)
    $legacy = Get-Pill $legacyPrev $legacyCurr
    Assert-That 'a delta is still drawn against a legacy entry' (-not $legacy.NotComparable) "(pill='$($legacy.Text)')"
    Assert-That 'an arrow is still drawn against a legacy entry' ($legacy.HasArrow) "(pill='$($legacy.Text)')"
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

''
"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
