<#
    A finding the operator cannot act on is worse than no finding, because it still fails the run.

    Get-mdiCAReadiness and Get-mdiEntraConnectReadiness emit a DISCOVERY PLACEHOLDER row when they
    cannot enumerate a role, so the role is reported as not-measured rather than rendering as "nothing
    to check here". Get-mdiIssueList raises one High finding for that row and then `continue`s,
    deliberately suppressing the generic per-property lines - because those describe a placeholder as
    though it were a machine ("Sensor Health could not be read on this server").

    The text of that one finding was `[string] $srv.Comment` with no fallback. Comment is not
    guaranteed: a producer with nothing to say, or a report that has been through a JSON round trip,
    leaves it empty. The issues table then rendered a HIGH severity row with a server name and a
    COMPLETELY BLANK description, and because the generic lines were suppressed, nothing anywhere else
    in the report described the gap either.

    This file also pins down the placeholder invariants that were CHECKED AND FOUND CORRECT while
    investigating, so a future change cannot quietly break them: a placeholder is not counted as a
    server, but its gap still reaches the score and the verdict. Both directions matter - counting it
    as a server produced "across 2 server(s)" for a one-server estate, and dropping its gap would let
    an unenumerated role pass silently.
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

$dc = [PSCustomObject]@{
    FQDN = 'dc1.contoso.com'; OperatingSystem = 'Windows Server 2022'
    Unreachable = $false; IsPlaceholder = $false; PartialFailure = $false
    NtlmAuditing = $true; Details = [PSCustomObject]@{}
}
function New-Placeholder {
    param($Comment)
    $o = [PSCustomObject]@{
        FQDN = 'AD CS (not enumerated) - contoso.com'
        Unreachable = $false; IsPlaceholder = $true; PartialFailure = $false
        CAAuditing = 'N/A'; Details = [PSCustomObject]@{}
    }
    if ($null -ne $Comment) { $o | Add-Member -NotePropertyName 'Comment' -NotePropertyValue $Comment }
    $o
}
function Get-Report {
    param($Placeholder)
    [PSCustomObject]@{
        Domain = 'contoso.com'; DomainsInScope = @('contoso.com')
        DomainControllers = @($dc)
        CAServers = @(if ($null -ne $Placeholder) { $Placeholder } else { @() })
        EntraConnectServers = @(); Domains = @()
    }
}
function Get-PlaceholderIssue {
    param($Placeholder)
    $rd = Get-Report -Placeholder $Placeholder
    $stats = Get-mdiReportStatistics -ReportData $rd
    @(Get-mdiIssueList -ReportData $rd -Statistics $stats | Where-Object { $_.Area -eq 'Discovery' })
}

Write-Host 'A placeholder finding always carries actionable text' -ForegroundColor Cyan
foreach ($c in @(
        @{ Name = 'no Comment property at all'; Value = $null }
        @{ Name = 'an empty Comment'; Value = '' }
        @{ Name = 'a whitespace-only Comment'; Value = '   ' }
    )) {
    $issues = @(Get-PlaceholderIssue -Placeholder (New-Placeholder -Comment $c.Value))
    Assert-That "$($c.Name): exactly one Discovery finding is raised" ($issues.Count -eq 1) "got $($issues.Count)"
    if ($issues.Count -eq 1) {
        # The defect: a High severity row with nothing in the description column.
        Assert-That "  ...and its text is not blank" (-not [string]::IsNullOrWhiteSpace([string] $issues[0].Issue)) "got '$($issues[0].Issue)'"
        Assert-That "  ...and it tells the operator what to do" ([string] $issues[0].Issue -match '-CAServer|-EntraConnectServer|could not be enumerated') "got '$($issues[0].Issue)'"
        Assert-That "  ...and it is still High severity" ($issues[0].Severity -eq 'High') "got '$($issues[0].Severity)'"
    }
}

Write-Host 'A real Comment is still used verbatim' -ForegroundColor Cyan
$realComment = 'The certification authorities of contoso.com could not be listed: access denied.'
$withComment = @(Get-PlaceholderIssue -Placeholder (New-Placeholder -Comment $realComment))
Assert-That 'the producer''s own explanation wins' ($withComment.Count -eq 1 -and [string] $withComment[0].Issue -eq $realComment) "got '$($withComment[0].Issue)'"

Write-Host 'A placeholder is not a server, but its gap still reaches the score' -ForegroundColor Cyan
# Counting it as a server produced "across 2 server(s)" for a one-server estate.
$rdPh = Get-Report -Placeholder (New-Placeholder -Comment $realComment)
$statsPh = Get-mdiReportStatistics -ReportData $rdPh
Assert-That 'the placeholder is not counted as a server' ($statsPh.TotalServers -eq 1) "got $($statsPh.TotalServers)"
Assert-That '  ...nor as an unreachable server' ($statsPh.UnreachableCount -eq 0) "got $($statsPh.UnreachableCount)"
# ...and dropping its gap would let an unenumerated role pass silently.
Assert-That 'its gap is charged as an unread check' ($statsPh.ChecksUnread -ge 1) "got $($statsPh.ChecksUnread)"

$rdNone = Get-Report -Placeholder $null
$statsNone = Get-mdiReportStatistics -ReportData $rdNone
$pctPh = Get-mdiCoveragePercent -Passed $statsPh.ChecksPassed -Measured $statsPh.ChecksTotal -Unread $statsPh.ChecksUnread
$pctNone = Get-mdiCoveragePercent -Passed $statsNone.ChecksPassed -Measured $statsNone.ChecksTotal -Unread $statsNone.ChecksUnread
Assert-That '  ...so the score drops when a role could not be enumerated' ($pctPh -lt $pctNone) "with=$pctPh without=$pctNone"
Assert-That '  ...and the verdict fails' ((Test-mdiReadinessResult -ReportData $rdPh) -eq $false) 'verdict was ready'
Assert-That '  ...while the same estate without it is ready' ((Test-mdiReadinessResult -ReportData $rdNone) -eq $true) 'control estate was not ready'

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
