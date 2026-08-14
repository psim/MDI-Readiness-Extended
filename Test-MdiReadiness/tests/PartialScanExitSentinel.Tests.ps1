<#
    The exit code must distinguish "the estate has problems" from "the scan did not finish".

    -FailOnIssues is what a CI or compliance gate reads, and the documented contract is:

        0        the scan ran and found nothing to fix
        1..254   that many readiness issues were found
        255      the scan did not run, OR DID NOT COMPLETE - re-run it, do not read the result

    The second half of 255 was never reachable. A server whose scan aborted part way is recorded with
    PartialFailure = $true; its remaining checks were never run, so they are absent rather than false.
    The verdict already refused READY on that, and the console already printed "Testing stopped early
    on N server(s)" - but the exit path only spent 255 when NO server at all could be enumerated, and
    otherwise fell through to the issue count.

    So one interrupted server exited 1, which is exactly what a COMPLETE scan that found one genuine
    High issue exits. A pipeline could not tell the two apart, and on a small estate the checks that
    did complete before the abort can be a clean sweep of passes - so "the scan gave up after the
    first check" could look like a nearly-healthy estate.

    These tests assert the statistic the exit path reads and the population it is computed over. They
    do not grep the script.
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

function New-Server {
    param([string] $Fqdn, [bool] $Partial, [object] $Ntlm = $true)
    [PSCustomObject]@{
        FQDN           = $Fqdn
        OperatingSystem = 'Windows Server 2022'
        PartialFailure = $Partial
        Unreachable    = $false
        IsPlaceholder  = $false
        NtlmAuditing   = $Ntlm
        Details        = [PSCustomObject]@{}
    }
}
function Get-Stats {
    param($Servers)
    Get-mdiReportStatistics -ReportData ([PSCustomObject]@{
            Domain              = 'contoso.com'
            DomainsInScope      = @('contoso.com')
            DomainControllers   = @($Servers)
            CAServers           = @()
            EntraConnectServers = @()
            Domains             = @()
        })
}

Write-Host 'The statistics carry the number of servers whose scan did not finish' -ForegroundColor Cyan
$clean = Get-Stats @((New-Server -Fqdn 'dc1.contoso.com' -Partial $false))
Assert-That 'a completed scan reports zero partial servers' ($clean.PartialScanCount -eq 0) "got $($clean.PartialScanCount)"
Assert-That '  ...and still counts the server' ($clean.TotalServers -eq 1) "got $($clean.TotalServers)"

$partial = Get-Stats @((New-Server -Fqdn 'dc1.contoso.com' -Partial $true))
Assert-That 'an interrupted scan reports one partial server' ($partial.PartialScanCount -eq 1) "got $($partial.PartialScanCount)"
Assert-That '  ...and the server is still counted in the estate' ($partial.TotalServers -eq 1) "got $($partial.TotalServers)"

$mixed = Get-Stats @(
    (New-Server -Fqdn 'dc1.contoso.com' -Partial $false)
    (New-Server -Fqdn 'dc2.contoso.com' -Partial $true)
    (New-Server -Fqdn 'dc3.contoso.com' -Partial $true)
)
Assert-That 'a mixed estate counts only the interrupted servers' ($mixed.PartialScanCount -eq 2) "got $($mixed.PartialScanCount)"
Assert-That '  ...out of the full estate' ($mixed.TotalServers -eq 3) "got $($mixed.TotalServers)"

Write-Host 'A partial scan is never a READY verdict, however healthy the checks that did run look' -ForegroundColor Cyan
# This is the shape that makes the defect dangerous: everything measured PASSED, because the scan
# stopped before it could measure anything else.
$looksClean = @(New-Server -Fqdn 'dc1.contoso.com' -Partial $true -Ntlm $true)
$verdict = Test-mdiReadinessResult -ReportData ([PSCustomObject]@{
        Domain              = 'contoso.com'
        DomainsInScope      = @('contoso.com')
        DomainControllers   = $looksClean
        CAServers           = @()
        EntraConnectServers = @()
        Domains             = @()
    })
Assert-That 'an all-passing partial scan is still NOT ready' ($verdict -eq $false) "got '$verdict'"
$looksCleanStats = Get-Stats $looksClean
Assert-That '  ...and the statistic the exit path reads is non-zero' ($looksCleanStats.PartialScanCount -gt 0) "got $($looksCleanStats.PartialScanCount)"

Write-Host 'The count is taken over real servers, not placeholders' -ForegroundColor Cyan
$placeholder = New-Server -Fqdn 'dc9.contoso.com' -Partial $true
$placeholder.IsPlaceholder = $true
$withPlaceholder = Get-Stats @((New-Server -Fqdn 'dc1.contoso.com' -Partial $false), $placeholder)
Assert-That 'a placeholder does not inflate the partial count' ($withPlaceholder.PartialScanCount -eq 0) "got $($withPlaceholder.PartialScanCount)"
Assert-That '  ...nor the estate total' ($withPlaceholder.TotalServers -eq 1) "got $($withPlaceholder.TotalServers)"

Write-Host 'A missing PartialFailure property is not a partial scan' -ForegroundColor Cyan
# A legacy or hand-built report may not carry the flag at all. Absent must mean "not interrupted",
# never "interrupted" - otherwise every older report would exit 255.
$legacy = [PSCustomObject]@{
    FQDN            = 'dc1.contoso.com'
    OperatingSystem = 'Windows Server 2022'
    NtlmAuditing    = $true
    Details         = [PSCustomObject]@{}
}
$legacyStats = Get-Stats @($legacy)
Assert-That 'a report with no PartialFailure property reports zero' ($legacyStats.PartialScanCount -eq 0) "got $($legacyStats.PartialScanCount)"

Write-Host ''
Write-Host "$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
