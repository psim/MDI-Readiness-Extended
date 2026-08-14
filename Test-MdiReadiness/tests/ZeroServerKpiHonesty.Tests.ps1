<#
    The "Servers fully ready" KPI must never read a green "All checks passed" for a scan that examined
    nothing.

    Every branch of that tile's sub-label counts servers that FAILED - need attention, not measured,
    not reachable. With no servers at all each of those counts is legitimately zero, so the tile fell
    through to its final `else` and rendered a green "All checks passed"... beside a red 0% score card,
    two High findings in the issues table, and a NOT READY verdict from Test-mdiReadinessResult.

    The KPI strip is the first thing a reader looks at. A run that enumerated nothing - no rights, no
    reachable domain controller, a wrong -Domain - would tell them the estate was clean.

    These tests assert the rendered tile against the other surfaces describing the same scan. They do
    not inspect the script's source text.
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

function New-Report {
    param($Servers)
    [PSCustomObject]@{
        Domain              = 'contoso.com'
        DomainsInScope      = @('contoso.com')
        DomainControllers   = @($Servers)
        CAServers           = @()
        EntraConnectServers = @()
        Domains             = @()
    }
}
function New-Server {
    param([string] $Fqdn, [object] $Ntlm = $true, [bool] $Unreachable = $false)
    [PSCustomObject]@{
        FQDN            = $Fqdn
        OperatingSystem = 'Windows Server 2022'
        Unreachable     = $Unreachable
        IsPlaceholder   = $false
        PartialFailure  = $false
        NtlmAuditing    = $Ntlm
        Details         = [PSCustomObject]@{}
    }
}
# The tile is parsed back out of the rendered overview so the assertion is on what is actually shown.
function Get-ReadyTile {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    $html = Get-mdiOverviewHtml -Statistics $stats -ReportData $Report
    # The exact shape the report emits: tone, label, value and sub are sibling spans in one kpi div.
    $cards = [regex]::Matches($html, '<div class="kpi (\w+)"><span class="kpi-label">([^<]+)</span><span class="kpi-value">([^<]+)</span><span class="kpi-sub">([^<]*)</span></div>')
    foreach ($c in $cards) {
        if ($c.Groups[2].Value -eq 'Servers fully ready') {
            return [PSCustomObject]@{
                Tone  = $c.Groups[1].Value
                Value = $c.Groups[3].Value
                Sub   = $c.Groups[4].Value
            }
        }
    }
    throw 'The "Servers fully ready" KPI card was not found in the rendered overview'
}

Write-Host 'A scan that examined nothing never claims every check passed' -ForegroundColor Cyan
$empty = New-Report @()
$emptyStats = Get-mdiReportStatistics -ReportData $empty
$emptyTile = Get-ReadyTile -Report $empty
Assert-That 'the estate really is empty in the statistics' ($emptyStats.TotalServers -eq 0) "got $($emptyStats.TotalServers)"
Assert-That 'the ready tile does NOT say "All checks passed"' ($emptyTile.Sub -notlike '*All checks passed*') "got '$($emptyTile.Sub)'"
Assert-That '  ...and is not toned green/ok' ($emptyTile.Tone -ne 'ok') "got tone '$($emptyTile.Tone)'"
Assert-That '  ...and says nothing was examined' ($emptyTile.Sub -match 'No server was examined') "got '$($emptyTile.Sub)'"

# The tile must agree with every other surface describing the same scan.
$emptyVerdict = Test-mdiReadinessResult -ReportData $empty
$emptyIssues = @(Get-mdiIssueList -ReportData $empty -Statistics $emptyStats)
Assert-That 'the verdict for the same scan is NOT READY' ($emptyVerdict -eq $false) "got '$emptyVerdict'"
Assert-That '  ...and the issue list is not empty' ($emptyIssues.Count -gt 0) "got $($emptyIssues.Count)"
Assert-That '  ...so a green "all passed" tile would contradict them' `
($emptyTile.Tone -ne 'ok' -and $emptyTile.Sub -notlike '*All checks passed*') "tone=$($emptyTile.Tone) sub=$($emptyTile.Sub)"

Write-Host 'A genuinely clean estate still gets the green tile' -ForegroundColor Cyan
# If this breaks, the fix has made the tile useless rather than honest.
$clean = New-Report @((New-Server -Fqdn 'dc1.contoso.com' -Ntlm $true))
$cleanTile = Get-ReadyTile -Report $clean
Assert-That 'a passing single-server estate says All checks passed' ($cleanTile.Sub -like '*All checks passed*') "got '$($cleanTile.Sub)'"
Assert-That '  ...and is toned ok' ($cleanTile.Tone -eq 'ok') "got tone '$($cleanTile.Tone)'"

Write-Host 'A failing estate is still reported as failing' -ForegroundColor Cyan
$bad = New-Report @((New-Server -Fqdn 'dc1.contoso.com' -Ntlm $false))
$badTile = Get-ReadyTile -Report $bad
Assert-That 'a failing server is not "All checks passed"' ($badTile.Sub -notlike '*All checks passed*') "got '$($badTile.Sub)'"
Assert-That '  ...and is toned bad' ($badTile.Tone -eq 'bad') "got tone '$($badTile.Tone)'"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
