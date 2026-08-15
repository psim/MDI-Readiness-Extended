<#
    TWO UNMEASURED PROBES ON TWO NICS PRODUCED TWO IDENTICAL ROWS, NEITHER SAYING WHICH OR WHY.

    A multi-homed host is discovered once per address and probed per address. When the probe does not
    RUN against two of a host's addresses, the issue list emitted two rows for the same protocol,
    port and host - byte for byte the same string. Measured on the shipped issue list:

        UNMEASURED_PORT_ISSUE_COUNT=2
        DISTINCT_UNMEASURED_PORT_TEXT_COUNT=1
        UNMEASURED_PORT_ISSUES_CONTAIN_FIRST_IP=False
        UNMEASURED_PORT_ISSUES_CONTAIN_SECOND_IP=False

    An operator working that table sees what looks like it repeating itself, cannot tell which NIC
    each row is about, and cannot tell whether one of them has already been dealt with.

    The untested-NNR row had the same fault plus one more - it dropped the record's own Detail:

        NNR_ISSUE_CONTAINS_UNTESTED_IP=False
        NNR_ISSUE_CONTAINS_REASON=False

    The reason is the actionable half. "No route to the target network" and "the remote probe timed
    out before this check ran" call for completely different responses, and neither was shown.

    Both producers carried TargetIP the whole time; only the consumers discarded it. The naming rule
    now lives in Get-mdiTargetLabel and is shared by every surface that names a probe target, because
    the wording has already drifted apart once in this file.
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
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }

Write-Host 'The shared naming rule' -ForegroundColor Cyan
Assert-That 'a multi-homed target is named by host AND address' (
    (Get-mdiTargetLabel -Target 'dc.contoso.com' -TargetIP '10.0.0.11') -eq 'dc.contoso.com (10.0.0.11)')
Assert-That 'CONTROL: no address keeps the plain name' (
    (Get-mdiTargetLabel -Target 'dc.contoso.com') -eq 'dc.contoso.com')
Assert-That 'CONTROL: an empty address keeps the plain name' (
    (Get-mdiTargetLabel -Target 'dc.contoso.com' -TargetIP '') -eq 'dc.contoso.com')
# A target discovered BY address holds the same value in both fields; repeating it is noise.
Assert-That 'CONTROL: an address equal to the name is not repeated' (
    (Get-mdiTargetLabel -Target '10.0.0.5' -TargetIP '10.0.0.5') -eq '10.0.0.5')
Assert-That 'CONTROL: an unnamed target falls back to its address' (
    (Get-mdiTargetLabel -Target '' -TargetIP '10.0.0.11') -eq '10.0.0.11')
Assert-That 'CONTROL: nothing at all yields an empty label rather than throwing' (
    (Get-mdiTargetLabel -Target $null -TargetIP $null) -eq '')

Write-Host ''
Write-Host 'The unmeasured wording carries the target AND the reason' -ForegroundColor Cyan
$withReason = Get-mdiUnmeasuredProbeText -Prefix 'Name resolution could not be tested for' `
    -Target 'dc.contoso.com' -TargetIP '10.0.0.11' -Detail 'Not tested - no route to the target network'
Assert-That 'the address is named' ($withReason -match '10\.0\.0\.11') "text=$withReason"
Assert-That 'and the reason is given' ($withReason -match 'no route to the target network') "text=$withReason"
# An absent reason must not leave a dangling colon - that reads as a truncated message.
$noReason = Get-mdiUnmeasuredProbeText -Prefix 'Name resolution could not be tested for' -Target 'dc.contoso.com'
Assert-That 'CONTROL: no reason produces no trailing colon' (
    $noReason -eq 'Name resolution could not be tested for dc.contoso.com') "text=$noReason"
Assert-That 'CONTROL: an unnamed target still yields a sentence' (
    (Get-mdiUnmeasuredProbeText -Prefix 'Probe skipped for' -Target '' -TargetIP '') -match 'an unnamed target')

Write-Host ''
Write-Host 'The issue list: two untested NICs must be two DISTINGUISHABLE rows' -ForegroundColor Cyan
function New-PortRecord {
    param([string] $Target, [string] $TargetIP, [int] $Port, [string] $Name, [string] $Group,
        [string] $Requirement, $Success, [string] $Detail, [string] $Protocol = 'TCP')
    [PSCustomObject]@{
        Id = "$Name$Port"; Name = $Name; Protocol = $Protocol; Port = $Port
        Scope = 'DomainController'; Group = $Group; Requirement = $Requirement
        Target = $Target; TargetIP = $TargetIP; Applicable = $true
        Success = $Success; Detail = $Detail
    }
}

# One host, two addresses, the required LDAP probe never run against either.
$untestedDetail = 'Not tested - no route to the target network'
$server = [PSCustomObject]@{
    FQDN = 'sensor.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
    Details = [PSCustomObject]@{
        RequiredPortsDetails = [PSCustomObject]@{
            Results = @(
                (New-PortRecord -Target 'dual-dc.contoso.com' -TargetIP '10.0.0.30' -Port 389 -Name 'LDAP' -Group 'LDAP' -Requirement 'Required' -Success $null -Detail $untestedDetail),
                (New-PortRecord -Target 'dual-dc.contoso.com' -TargetIP '10.0.0.31' -Port 389 -Name 'LDAP' -Group 'LDAP' -Requirement 'Required' -Success $null -Detail $untestedDetail))
        }
    }
}
$reportData = [PSCustomObject]@{
    Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers = @($server); CAServers = @(); EntraConnectServers = @(); DomainAuditing = @()
}
$issues = @(Get-mdiIssueList -Statistics (Get-mdiReportStatistics -ReportData $reportData) -ReportData $reportData)
$unmeasured = @($issues | Where-Object { $_.Issue -match 'could not be measured' })

if ($unmeasured.Count -eq 0) {
    throw ('no unmeasured-probe row was raised - the fixture does not reach the path under test. issues: ' +
        (($issues | ForEach-Object { $_.Area + '/' + $_.Issue }) -join ' | '))
}
Assert-That 'one row per untested address' ($unmeasured.Count -eq 2) "count=$($unmeasured.Count)"
# The point of the fix: the rows must be TELLABLE APART.
$distinct = @($unmeasured | ForEach-Object { [string] $_.Issue } | Select-Object -Unique)
Assert-That 'and the rows are distinguishable from each other' (
    $distinct.Count -eq $unmeasured.Count) "distinct=$($distinct.Count) of $($unmeasured.Count)"
Assert-That 'the first address is named' (
    @($unmeasured | Where-Object { $_.Issue -match '10\.0\.0\.30' }).Count -eq 1) (
    'rows: ' + (($unmeasured | ForEach-Object { $_.Issue }) -join ' | '))
Assert-That 'the second address is named' (
    @($unmeasured | Where-Object { $_.Issue -match '10\.0\.0\.31' }).Count -eq 1) (
    'rows: ' + (($unmeasured | ForEach-Object { $_.Issue }) -join ' | '))
Assert-That 'the host, protocol and port are still stated' (
    $unmeasured[0].Issue -match 'dual-dc\.contoso\.com' -and $unmeasured[0].Issue -match 'TCP/389') (
    "row=$($unmeasured[0].Issue)")

Write-Host ''
Write-Host 'The untested NNR row names the address and says why' -ForegroundColor Cyan
$nnrServer = [PSCustomObject]@{
    FQDN = 'sensor.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
    Details = [PSCustomObject]@{
        RequiredPortsDetails = [PSCustomObject]@{
            Results = @(
                (New-PortRecord -Target 'dual-client.contoso.com' -TargetIP '10.0.0.10' -Port 135 -Name 'NNR - RPC' -Group 'NNR' -Requirement 'AtLeastOne' -Success $true -Detail 'Connected'),
                (New-PortRecord -Target 'dual-client.contoso.com' -TargetIP '10.0.0.11' -Port 135 -Name 'NNR - RPC' -Group 'NNR' -Requirement 'AtLeastOne' -Success $null -Detail $untestedDetail),
                (New-PortRecord -Target 'dual-client.contoso.com' -TargetIP '10.0.0.11' -Port 3389 -Name 'NNR - RDP' -Group 'NNR' -Requirement 'AtLeastOne' -Success $null -Detail $untestedDetail))
        }
    }
}
$nnrData = [PSCustomObject]@{
    Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers = @($nnrServer); CAServers = @(); EntraConnectServers = @(); DomainAuditing = @()
}
$nnrIssues = @(Get-mdiIssueList -Statistics (Get-mdiReportStatistics -ReportData $nnrData) -ReportData $nnrData)
$nnrUntested = @($nnrIssues | Where-Object { $_.Issue -match 'Name resolution could not be tested' })

if ($nnrUntested.Count -eq 0) {
    throw ('no untested-NNR row was raised - the fixture does not reach the path under test. issues: ' +
        (($nnrIssues | ForEach-Object { $_.Area + '/' + $_.Issue }) -join ' | '))
}
Assert-That 'the untested NNR row names the address that was not probed' (
    $nnrUntested[0].Issue -match '10\.0\.0\.11') "row=$($nnrUntested[0].Issue)"
Assert-That 'and it gives the reason' (
    $nnrUntested[0].Issue -match 'no route to the target network') "row=$($nnrUntested[0].Issue)"
Assert-That 'and it is filed as Not measured, never as a blocked port' (
    $nnrUntested[0].Area -eq 'Not measured') "area=$($nnrUntested[0].Area)"

Write-Host ''
Write-Host 'CONTROL - a healthy estate raises nothing' -ForegroundColor Cyan
$healthyServer = [PSCustomObject]@{
    FQDN = 'sensor.contoso.com'; Domain = 'contoso.com'; Unreachable = $false; PartialFailure = $false
    Details = [PSCustomObject]@{
        RequiredPortsDetails = [PSCustomObject]@{
            Results = @(
                (New-PortRecord -Target 'dual-dc.contoso.com' -TargetIP '10.0.0.30' -Port 389 -Name 'LDAP' -Group 'LDAP' -Requirement 'Required' -Success $true -Detail 'Connected'),
                (New-PortRecord -Target 'dual-dc.contoso.com' -TargetIP '10.0.0.31' -Port 389 -Name 'LDAP' -Group 'LDAP' -Requirement 'Required' -Success $true -Detail 'Connected'))
        }
    }
}
$healthyData = [PSCustomObject]@{
    Domain = 'contoso.com'; Forest = 'contoso.com'; DomainsInScope = @('contoso.com')
    DomainControllers = @($healthyServer); CAServers = @(); EntraConnectServers = @(); DomainAuditing = @()
}
$healthyIssues = @(Get-mdiIssueList -Statistics (Get-mdiReportStatistics -ReportData $healthyData) -ReportData $healthyData)
Assert-That 'CONTROL: no unmeasured row when both addresses were probed' (
    @($healthyIssues | Where-Object { $_.Issue -match 'could not be measured|could not be tested' }).Count -eq 0) (
    'issues: ' + (($healthyIssues | ForEach-Object { $_.Issue }) -join ' | '))

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
