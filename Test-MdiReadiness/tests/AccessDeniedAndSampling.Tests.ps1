<#
    Access denied is not a measurement.

    The worst thing this tool can do is turn a permission failure into a result. There are two ways
    to do it and both shipped:

      - denial rendered as a definite FAILURE, sending an administrator to fix something that is not
        broken ("the Sense service is not installed - onboard the server");
      - denial rendered as an EMPTY LIST, which the report phrases as the reassuring "No CA servers
        found" and the verdict scores as READY - a false green over servers nobody enumerated.

    The correct answer in both cases is the third state: not measured. These tests hold that line,
    and equally hold the opposite line - a genuine absence must still be reported as an absence, or
    the fix is just a different kind of lie.
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

$script:pass = 0; $script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

Write-Host 'An unreadable service list is not "the service is missing"' -ForegroundColor Cyan
# Get-mdiServiceState returns only the service and discards whether the query succeeded, so an
# Access Denied arrived as $null - identical to "genuinely absent". The v2.x sibling check read the
# same list through the Result variant and correctly said N/A, so two checks on one server disagreed
# about one unreadable query. Both now read the Result variant.
#
# Get-WmiObject is shadowed rather than Get-mdiServiceStateResult, so the REAL readability plumbing
# is exercised: a stub of the result helper would prove only that the stub was consulted.
$script:svcReadable = $true
$script:svcPresent = $false
function global:Get-WmiObject {
    param($ComputerName, $Namespace, $Class, $Property, $Filter, $Query, $ErrorAction)
    if ($Class -eq 'Win32_OperatingSystem') {
        return [PSCustomObject]@{ Version = '10.0.20348'; Caption = 'Windows Server 2022 Datacenter'
            ProductType = 2; BuildNumber = '20348' }
    }
    if ($Class -eq 'Win32_Service') {
        if (-not $script:svcReadable) { throw [System.UnauthorizedAccessException]::new('Access is denied.') }
        if (-not $script:svcPresent) { return $null }
        return [PSCustomObject]@{ Name = 'Sense'; State = 'Running'; StartMode = 'Auto' }
    }
    $null
}
function Get-SenseCheck {
    $r = Get-mdiSensorV3Readiness -ComputerName 'dc1.contoso.com' 3>$null
    @($r.details.Checks | Where-Object { [string] $_.Name -like '*Sense*service is running*' })[0]
}

$script:svcReadable = $false
$denied = Get-SenseCheck
Assert-That 'the check is still emitted when the query is denied' ($null -ne $denied)
if ($denied) {
    Assert-That '  denial reads as N/A, not as a measured failure' ([string] $denied.Status -eq 'N/A') "(got '$($denied.Status)')"
    Assert-That '  it does not claim the service is not installed' ($denied.Detail -notmatch 'not installed')
    Assert-That '  and it names the reason' ($denied.Detail -match 'Access is denied')
}

# The other half of the tri-state. A fix that maps every absence to N/A hides real findings, so the
# genuine "queried successfully, service absent" case must still be a measured failure.
$script:svcReadable = $true; $script:svcPresent = $false
$absent = Get-SenseCheck
Assert-That 'a genuinely absent service is still a measured failure' (
    $absent -and $absent.Status -is [bool] -and $absent.Status -eq $false) "(got '$($absent.Status)')"
Assert-That '  and still tells the operator to onboard' ($absent.Detail -match 'not installed')

$script:svcReadable = $true; $script:svcPresent = $true
$running = Get-SenseCheck
Assert-That 'a running service still passes' ($running -and $running.Status -eq $true)
Remove-Item Function:\global:Get-WmiObject -ErrorAction SilentlyContinue

Write-Host 'A discovery that was DENIED is not a domain with nothing to find' -ForegroundColor Cyan
# Enumerating the Cert Publishers group can fail on permissions. That produced an empty list, the
# report said "No CA servers found", and the verdict stayed READY.
function global:Get-ADDomain { param($Server) [PSCustomObject]@{ DomainSID = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3' } } }
function global:Get-ADGroupMember { param($Server, $Identity, $ErrorAction) throw [System.UnauthorizedAccessException]::new('Access is denied.') }

$caDenied = @(Get-mdiCAReadiness -Domain 'child.contoso.com' 3>$null)
Assert-That 'a denied CA enumeration does not return an empty collection' ($caDenied.Count -gt 0) "(got $($caDenied.Count))"
if ($caDenied.Count -gt 0) {
    Assert-That '  the placeholder row is marked not-measured' ([string] $caDenied[0].SensorHealth -eq 'N/A')
    Assert-That '  it states AD CS was NOT checked' ($caDenied[0].Comment -match 'NOT checked')
    Assert-That '  and it names the cause' ($caDenied[0].Comment -match 'Access is denied')
}

# The row has to change the VERDICT, otherwise it is decoration an operator can scroll past.
$report = [PSCustomObject]@{
    DomainControllers = @([PSCustomObject]@{ FQDN = 'dc1'; Domain = 'contoso.com'; 'Power scheme' = $true })
    CAServers = $caDenied; EntraConnectServers = @()
    DomainsInScope = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
}
Assert-That '  and the run is NOT reported ready' ((Test-mdiReadinessResult -ReportData $report 3>$null).Ready -ne $true)

# A domain that genuinely runs no AD CS must stay silent: no row, no warning, no lost readiness.
function global:Get-ADGroupMember { param($Server, $Identity, $ErrorAction) @() }
Assert-That 'a domain with genuinely no CA produces no placeholder row' (
    @(Get-mdiCAReadiness -Domain 'child.contoso.com' 3>$null).Count -eq 0)
Remove-Item Function:\global:Get-ADGroupMember, Function:\global:Get-ADDomain -ErrorAction SilentlyContinue

Write-Host 'A domain nobody examined is not a domain that passed' -ForegroundColor Cyan
# A domain in scope that produced no servers contributed nothing to the numerator AND nothing to the
# denominator, so the headline read a confident 100% over a domain that was never reached - directly
# contradicting the verdict, which already refused to call the run ready.
function New-Forest($scoped, $withServers) {
    [PSCustomObject]@{
        DomainControllers = @($withServers | ForEach-Object {
                [PSCustomObject]@{ FQDN = "dc1.$_"; Domain = $_; Unreachable = $false; 'Power scheme' = $true } })
        CAServers = @(); EntraConnectServers = @()
        DomainsInScope = $scoped; Domain = @($scoped)[0]; Forest = @($scoped)[0]
    }
}
function Get-Pct($stats) {
    [math]::Floor((Get-mdiCoveragePercent -Passed $stats.ChecksPassed -Measured $stats.ChecksTotal -Unread $stats.ChecksUnread))
}

$partial = Get-mdiReportStatistics -ReportData (New-Forest @('a.com', 'b.com') @('a.com'))
Assert-That 'the unexamined domain is charged as an unread check' ($partial.ChecksUnread -ge 1) "(unread=$($partial.ChecksUnread))"
Assert-That '  so coverage can no longer read 100%' ((Get-Pct $partial) -lt 100) "(got $(Get-Pct $partial)%)"

# The matching false-red guard: when every domain WAS examined the number must still reach 100%.
$full = Get-mdiReportStatistics -ReportData (New-Forest @('a.com', 'b.com') @('a.com', 'b.com'))
Assert-That 'a fully examined forest still reads 100%' ((Get-Pct $full) -eq 100) "(got $(Get-Pct $full)%, unread=$($full.ChecksUnread))"
Assert-That '  and charges no phantom unread' ($full.ChecksUnread -eq 0) "(unread=$($full.ChecksUnread))"

# Three unexamined domains must cost more than one, or the charge is a token.
$one = Get-mdiReportStatistics -ReportData (New-Forest @('a.com', 'b.com') @('a.com'))
$three = Get-mdiReportStatistics -ReportData (New-Forest @('a.com', 'b.com', 'c.com', 'd.com') @('a.com'))
Assert-That 'each unexamined domain is charged separately' ($three.ChecksUnread -gt $one.ChecksUnread) `
    "(1 missing=$($one.ChecksUnread), 3 missing=$($three.ChecksUnread))"

# A scan that found NO servers anywhere is a different and more serious failure, already reported as
# an empty scan. Charging every domain here would bury it under per-domain noise.
$empty = Get-mdiReportStatistics -ReportData (New-Forest @('a.com', 'b.com') @())
Assert-That 'a scan with no servers at all is not charged per domain' ($empty.ChecksUnread -eq 0) "(unread=$($empty.ChecksUnread))"

Write-Host 'A probe of five out of five hundred says so' -ForegroundColor Cyan
# Name resolution is deliberately probed against a bounded sample - probing every DC from every DC
# grows with the SQUARE of the estate - but the card read "5/5, every target resolvable" on a 500-DC
# forest where 1% had been probed. Correct engineering, wrong reporting.
$estate = @(1..50 | ForEach-Object {
        [PSCustomObject]@{ FQDN = ("dc{0:D3}.contoso.com" -f $_); Domain = 'contoso.com'
            Unreachable = $false; 'Power scheme' = $true } })
function New-Estate($nnrChosen) {
    [PSCustomObject]@{ DomainControllers = $estate; CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com'); Domain = 'contoso.com'; Forest = 'contoso.com'
        NnrTargetComputer = $nnrChosen; MaxNnrTargets = 5 }
}
$sampled = Get-mdiReportStatistics -ReportData (New-Estate @())
Assert-That 'the statistics record the size of the population sampled from' (
    $sampled.NnrCandidateCount -eq 50) "(got $($sampled.NnrCandidateCount))"
Assert-That '  which exceeds the number of targets probed' ($sampled.NnrCandidateCount -gt $sampled.NnrTargetCount)

# When the operator NAMED the hosts there is no sample, and claiming one would be false.
$chosen = Get-mdiReportStatistics -ReportData (New-Estate @('WKS001', 'SRV042'))
Assert-That 'an operator-chosen target list claims no sample' (
    $chosen.NnrCandidateCount -eq $chosen.NnrTargetCount) `
    "(candidates=$($chosen.NnrCandidateCount) targets=$($chosen.NnrTargetCount))"

# Unreachable domain controllers are not candidates - a host that could not be reached at all was
# never a possible NNR target, and counting it would overstate what the sample was drawn from.
$withDead = New-Estate @()
$withDead.DomainControllers = @($estate) + @([PSCustomObject]@{ FQDN = 'dead.contoso.com'; Domain = 'contoso.com'; Unreachable = $true })
Assert-That 'an unreachable DC is not counted as a candidate' (
    (Get-mdiReportStatistics -ReportData $withDead).NnrCandidateCount -eq 50) `
    "(got $((Get-mdiReportStatistics -ReportData $withDead).NnrCandidateCount))"

# And the disclosure has to reach the RENDERED card, not merely the statistics object. That needs
# real NNR records: with no records at all the card correctly reads "Not evaluated", and a test that
# accepted that would prove nothing.
$nnrRecords = @(1..5 | ForEach-Object {
        [PSCustomObject]@{ Server = 'dc001.contoso.com'; Target = ("dc{0:D3}.contoso.com" -f $_)
            TargetIP = "10.0.0.$_"; Group = 'NNR'; Method = 'NNR-NetBIOS'; Port = 137
            Success = $true; Detail = 'resolved'; Requirement = 'Required'; Applicable = $true }
    })
$withNnr = New-Estate @()
$withNnr.DomainControllers = @($estate | ForEach-Object {
        $s = $_.PSObject.Copy()
        $s | Add-Member -NotePropertyName Details -NotePropertyValue ([PSCustomObject]@{
                RequiredPortsDetails = [PSCustomObject]@{ Results = $nnrRecords } }) -Force
        $s
    })
$statsNnr = Get-mdiReportStatistics -ReportData $withNnr
$card = Get-mdiOverviewHtml -Statistics $statsNnr -ReportData $withNnr
$plainCard = ($card -replace '<[^>]+>', ' ') -replace '\s+', ' '
Assert-That 'the NNR card actually evaluated some targets' ($statsNnr.NnrTargetCount -gt 0) `
    "(targets=$($statsNnr.NnrTargetCount))"
Assert-That 'the rendered overview discloses the sample' ($plainCard -match '(?i)\d+ of \d+ hosts in scope were probed') `
    "(card did not mention the sample)"
Assert-That '  and points at the parameter that widens it' ($plainCard -match 'MaxNnrTargets')
Assert-That '  and does not claim EVERY target resolvable without qualification' (
    $plainCard -notmatch 'Every target resolvable')

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
