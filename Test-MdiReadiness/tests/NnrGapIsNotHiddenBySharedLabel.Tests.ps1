<#
    A HOST THAT WAS NEVER PROBED DISAPPEARED BECAUSE A DIFFERENT HOST SHARED ITS FIRST LABEL.

    A computer named with -NnrTargetComputer that resolves to no address is dropped from the probe
    plan by Resolve-mdiNnrTarget with only a warning. That gap has to reach the verdict, the issue
    list and the exit code, or the run answers "can my sensors resolve these workstations?" without
    having tried.

    The comparison that decides which requested names survived matched on the leftmost DNS label. That
    fallback is needed for exactly one case - a SHORT request like 'SRV1' comes back resolved as
    'srv1.contoso.com' - but it was applied to every request, including names the operator had already
    qualified. A label is not an identity across domains.

    Measured on the shipped Main path with -NnrTargetComputer host.alpha.contoso.com,
    host.beta.contoso.com where only alpha resolves:

        RESOLVED_IN_PLAN=host.alpha.contoso.com
        UNRESOLVED_COUNT=0
        HTML_VERDICT=All prerequisites met
        PROCESS_EXIT=0

    while the console had already printed "Unable to resolve the NNR target computer
    host.beta.contoso.com". The only named host that was never probed was erased from the JSON gap
    list, the HTML issues, the verdict and the exit code by a DIFFERENT machine that happens to share
    its leftmost label. Identically named hosts in sibling domains are the ordinary shape of a
    multi-domain forest.

    The comparison lived inline in the main body, below the region marker every test harness truncates
    at, so no test could reach it - which is why a wrong comparison survived. It is now
    Get-mdiUnresolvedNnrTarget, and these assertions drive it directly.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Write-Host 'A qualified request is only satisfied by that exact host' -ForegroundColor Cyan
# The defect, stated directly: alpha resolved, beta did not, and they share the label 'host'.
$gap = @(Get-mdiUnresolvedNnrTarget `
        -Requested @('host.alpha.contoso.com', 'host.beta.contoso.com') `
        -Resolved  @('host.alpha.contoso.com'))
Assert-That 'the unresolved sibling is still reported as a gap' (
    $gap.Count -eq 1) "gap=$($gap -join ', ')"
Assert-That 'and it is the one that did not resolve' (
    $gap.Count -eq 1 -and $gap[0] -eq 'host.beta.contoso.com') "gap=$($gap -join ', ')"

# Three domains, one resolved: the other two must both be reported, not just one.
$manyGap = @(Get-mdiUnresolvedNnrTarget `
        -Requested @('host.alpha.contoso.com', 'host.beta.contoso.com', 'host.gamma.contoso.com') `
        -Resolved  @('host.alpha.contoso.com'))
Assert-That 'every unresolved sibling is reported, not just the first' (
    $manyGap.Count -eq 2) "gap=$($manyGap -join ', ')"

Write-Host ''
Write-Host 'CONTROLS - a host that DID resolve must never be reported as a gap' -ForegroundColor Cyan
$none = @(Get-mdiUnresolvedNnrTarget `
        -Requested @('host.alpha.contoso.com', 'host.beta.contoso.com') `
        -Resolved  @('host.alpha.contoso.com', 'host.beta.contoso.com'))
Assert-That 'CONTROL: both resolved means no gap' ($none.Count -eq 0) "gap=$($none -join ', ')"

# The short-name case the label fallback exists for. Losing this would report every successfully
# resolved short name as a gap - a false failure on an ordinary invocation.
$short = @(Get-mdiUnresolvedNnrTarget -Requested @('SRV1') -Resolved @('srv1.contoso.com'))
Assert-That 'CONTROL: a short name resolved to its FQDN is not a gap' (
    $short.Count -eq 0) "gap=$($short -join ', ')"
$shortMissing = @(Get-mdiUnresolvedNnrTarget -Requested @('SRV2') -Resolved @('srv1.contoso.com'))
Assert-That 'CONTROL: a short name that resolved to nothing IS a gap' (
    $shortMissing.Count -eq 1) "gap=$($shortMissing -join ', ')"

# DNS spelling variants are the same host and must not be reported as missing.
Assert-That 'CONTROL: case differences are not a gap' (
    @(Get-mdiUnresolvedNnrTarget -Requested @('HOST.ALPHA.CONTOSO.COM') -Resolved @('host.alpha.contoso.com')).Count -eq 0)
Assert-That 'CONTROL: a trailing dot is not a gap' (
    @(Get-mdiUnresolvedNnrTarget -Requested @('host.alpha.contoso.com.') -Resolved @('host.alpha.contoso.com')).Count -eq 0)
Assert-That 'CONTROL: a trailing dot on the RESOLVED name is not a gap either' (
    @(Get-mdiUnresolvedNnrTarget -Requested @('host.alpha.contoso.com') -Resolved @('host.alpha.contoso.com.')).Count -eq 0)
Assert-That 'CONTROL: surrounding whitespace is not a gap' (
    @(Get-mdiUnresolvedNnrTarget -Requested @('  host.alpha.contoso.com  ') -Resolved @('host.alpha.contoso.com')).Count -eq 0)

Write-Host ''
Write-Host 'CONTROLS - the empty and malformed cases' -ForegroundColor Cyan
Assert-That 'CONTROL: nothing requested is no gap' (
    @(Get-mdiUnresolvedNnrTarget -Requested @() -Resolved @('host.alpha.contoso.com')).Count -eq 0)
Assert-That 'CONTROL: a null request list is no gap' (
    @(Get-mdiUnresolvedNnrTarget -Requested $null -Resolved @('host.alpha.contoso.com')).Count -eq 0)
# Nothing resolved at all: every named host is a gap, which is the most important case to get right.
$allGap = @(Get-mdiUnresolvedNnrTarget -Requested @('a.contoso.com', 'b.contoso.com') -Resolved @())
Assert-That 'CONTROL: nothing resolved means every request is a gap' (
    $allGap.Count -eq 2) "gap=$($allGap -join ', ')"
Assert-That 'CONTROL: a null resolved list means every request is a gap' (
    @(Get-mdiUnresolvedNnrTarget -Requested @('a.contoso.com') -Resolved $null).Count -eq 1)
# A blank entry is not a request and must not be reported as an unresolvable host.
Assert-That 'CONTROL: blank entries are ignored rather than reported' (
    @(Get-mdiUnresolvedNnrTarget -Requested @('', '   ', 'host.alpha.contoso.com') -Resolved @('host.alpha.contoso.com')).Count -eq 0)

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
