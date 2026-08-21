<#
    A ROW WAS BADGED "partial results" FOR A SERVER THAT WAS FULLY SCANNED.

    The server table marks two kinds of row so a reader can tell them apart: a server that was never
    reached, and one that was reached and then failed part way through. The second badge matters
    because it tells the reader how much of that row to trust.

    UNREACHABLE is read through a shared predicate, Test-mdiServerIsUnreachable, and that predicate's
    header states exactly why it has to be: "the flag survives a JSON round trip as the STRING
    'False', and every non-empty string is truthy in PowerShell". Set-MdiReadinessReport honoured that
    for Unreachable and then read its SIBLING flag, on the very next line, with a bare cast:

        $partial = (-not $unreachable) -and [bool] $srv.PartialFailure

    [bool] 'False' is TRUE. So a PartialFailure that came back from a JSON round trip as the string
    'False' badged the row "partial results" and put the server's Comment in the row tooltip - telling
    the operator that a fully scanned server had only been partly measured.

    THE SAME PAGE DISAGREED WITH ITSELF, which is the failure this codebase keeps finding. The KPI
    reads the same flag correctly, in Get-mdiReportStatistics:

        PartialScanCount = @($realServers | Where-Object { $_.PartialFailure -eq $true }).Count

    and 'False' -eq $true is FALSE, because PowerShell coerces the right operand to the LEFT operand's
    type and compares 'False' with 'True'. Measured on the shipped renderer, one reachable server,
    nothing differing but the spelling of the flag:

        PartialFailure          PartialScanCount   row badge
        $true                   1                  partial results
        $false                  0                  none
        'True'  (round trip)    1                  partial results
        'False' (round trip)    0                  PARTIAL RESULTS   <- the defect

    The flag is now routed through ConvertTo-mdiBoolean, the reader the rest of the script already
    uses, and compared with -eq $true rather than tested for truthiness - so an UNREADABLE flag, one
    that normalises to $null, leaves the row unbadged rather than inventing a partial scan.

    WHAT MUST NOT REGRESS, pinned below:
      * the two surfaces AGREE on every shape: a row is badged "partial results" if and only if
        PartialScanCount counts it
      * a genuine partial failure - $true, or 'True' from a round trip - is still badged
      * an absent flag, an empty string and a zero leave the row unbadged
      * an UNREACHABLE server is still badged "not reachable" and not "partial results"
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
    param($PartialFailure, $Unreachable = $false, [switch] $OmitPartial)
    $dc = [PSCustomObject]@{
        FQDN = 'dcfab01.fabrikam.local'; Domain = 'fabrikam.local'; Unreachable = $Unreachable
        Comment = 'Some roles could not be read'
        isAdvancedAuditingOk = $true; isPowerSchemeOk = $true
    }
    if (-not $OmitPartial) { $dc | Add-Member -NotePropertyName PartialFailure -NotePropertyValue $PartialFailure -Force }
    [PSCustomObject]@{
        Domain = 'fabrikam.local'
        Domains = @('fabrikam.local')
        DomainsInScope = @('fabrikam.local')
        DomainControllers = @($dc)
        CAServers = @(); EntraConnectServers = @()
    }
}

# Renders the REAL report and reports what the row actually says, so the badge is read from the
# rendered page rather than inferred from the expression that produces it.
function Measure-Row {
    param($Report)
    $stats = Get-mdiReportStatistics -ReportData $Report
    $outDir = Join-Path ([IO.Path]::GetTempPath()) ('mdi-partial-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    try {
        Set-MdiReadinessReport -Domain 'fabrikam.local' -Path $outDir -ReportData $Report -Statistics $stats -SkipTrend | Out-Null
        $htmlFile = @(Get-ChildItem $outDir -Filter '*.html' -ErrorAction SilentlyContinue) | Select-Object -First 1
        $html = if ($htmlFile) { [IO.File]::ReadAllText($htmlFile.FullName) } else { '' }
        [PSCustomObject]@{
            PartialCount   = [int] $stats.PartialScanCount
            BadgedPartial  = [bool] ($html -match 'partial results')
            BadgedUnreach  = [bool] ($html -match 'not reachable')
        }
    } finally {
        if (Test-Path $outDir) { Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host 'A row is badged partial only when the count agrees that it is' -ForegroundColor Cyan

foreach ($case in @(
        @{ L = 'a real $true'; V = $true; Expect = $true }
        @{ L = 'a real $false'; V = $false; Expect = $false }
        @{ L = "the string 'True' from a JSON round trip"; V = 'True'; Expect = $true }
        @{ L = "the string 'False' from a JSON round trip"; V = 'False'; Expect = $false }
        @{ L = 'an empty string'; V = ''; Expect = $false }
        @{ L = 'a zero'; V = 0; Expect = $false }
        @{ L = 'a one'; V = 1; Expect = $true }
    )) {
    $m = Measure-Row (New-Report -PartialFailure $case.V)
    Assert-That ('{0}: the row badge and the count AGREE' -f $case.L) (
        $m.BadgedPartial -eq ($m.PartialCount -gt 0)) ("(badge=$($m.BadgedPartial) count=$($m.PartialCount))")
    Assert-That ('{0}: badged partial = {1}' -f $case.L, $case.Expect) (
        $m.BadgedPartial -eq $case.Expect) ("(badge=$($m.BadgedPartial))")
}

$m = Measure-Row (New-Report -OmitPartial)
Assert-That 'an ABSENT flag leaves the row unbadged' (-not $m.BadgedPartial) "(badge=$($m.BadgedPartial))"
Assert-That '  ...and counts no partial scan' ($m.PartialCount -eq 0) "(count=$($m.PartialCount))"

# An unreachable server must keep its own badge. 'partial results' would tell the reader its findings
# are real measurements, which is the opposite of what an unreachable row means.
$m = Measure-Row (New-Report -PartialFailure $true -Unreachable $true)
Assert-That 'an UNREACHABLE server is badged not reachable' $m.BadgedUnreach "(unreach=$($m.BadgedUnreach))"
Assert-That '  ...and is NOT badged partial results' (-not $m.BadgedPartial) "(badge=$($m.BadgedPartial))"

''
"RESULT pass=$script:pass fail=$script:fail"
if ($script:fail -gt 0) { exit 1 }
