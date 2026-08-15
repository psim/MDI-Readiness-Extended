<#
    A TIMED-OUT PORT PROBE DELETED FOUR REQUIRED PROBES FROM THE POPULATION.

    Get-mdiRequiredPorts runs the port probes ON the sensor server, outbound. When that remote
    execution times out, Invoke-mdiRemoteCommand returns $null and the function falls back to
    probing the server INBOUND from the machine running the script.

    That fallback narrows the plan to the scopes the reverse direction can actually carry:

        $fallbackPlan.Probes = @($Plan.Probes | Where-Object { $_.Scope -in $fallbackScopes })

    Narrowing is correct - measuring LDAP inbound to a certification authority, or "localhost to
    localhost" on someone else's machine, would be measuring the wrong thing. What was wrong is
    what happened to the probes it dropped: they produced NO RECORD AT ALL. Not a failed record,
    not a "not tested" record - nothing.

    A fact with no record cannot be counted as missing by anything downstream, so the entire
    reporting stack agreed on a complete pass over a population that had quietly lost four of its
    seven required members. Measured on a domain controller whose outbound probe timed out:

        required probes            7  ->  3     (CloudSsl, UpdaterSsl, DnsTcp, DnsUdp gone)
        PortsRequiredUntested      0            (nothing knew they were missing)
        Get-mdiUnmeasuredRequiredProbe  0
        ports KPI                  [ok]  3/3 - No required port blocked

    The KPI is the damning part. It is not merely wrong about four probes; its DENOMINATOR shrank
    to fit the evidence that survived, so it reads as a clean sweep. This is the "unmeasured
    treated as measured" class in its most complete form - the unmeasured items were not even
    present to be classified.

    The ladder guard written for exactly this vanishing-population case never fires, because it
    keys on PartialScanCount, and only a THROWN error sets that. A timeout does not throw.

    The fix records the narrowed-away probes as unmeasured (Applicable $true, Success $null, a
    leading "Not tested" detail) - the same shape the DnsServer scope already uses when the DNS
    server list cannot be read, whose comment states the rule this site was breaking.

    These assertions are behavioural: they call the shipped Get-mdiRequiredPorts with the remote
    execution forced to time out and inspect the records, the statistics and the KPI it produces.
    Nothing greps the source.
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

$server = 'dc1.contoso.com'
$serverIp = '10.0.0.10'

# Every socket-level primitive is stubbed IDENTICALLY for both runs, so the only difference
# between the control and the timeout is whether the remote execution answered.
Set-Item -Path function:script:Test-mdiTcpPort -Value {
    param($ComputerName, $Port, $TimeoutMs)
    [PSCustomObject]@{ Success = $true; LatencyMs = 1; Detail = 'Connected' }
}
Set-Item -Path function:script:Test-mdiUdpPort -Value {
    param($ComputerName, $Port, $TimeoutMs, $Payload, $ExpectedTransactionId, $ResponseValidator)
    [PSCustomObject]@{ Success = $true; LatencyMs = 1; Detail = 'Answered' }
}
Set-Item -Path function:script:Test-mdiNnrNetBios -Value {
    param($ComputerName, $TimeoutMs) [PSCustomObject]@{ Success = $true; LatencyMs = 1; Detail = 'Answered' }
}
Set-Item -Path function:script:Test-mdiReverseDns -Value {
    param($IPAddress, $TimeoutMs) [PSCustomObject]@{ Success = $true; LatencyMs = 1; Detail = 'Resolved' }
}
Set-Item -Path function:script:Test-mdiCloudConnectivity -Value {
    param($Url, $TimeoutMs) [PSCustomObject]@{ Success = $true; LatencyMs = 1; Detail = 'Reachable' }
}
Set-Item -Path function:script:Test-mdiLocalTcpListener -Value { param($Port) @('listening') }
Set-Item -Path function:script:Get-mdiComputerAddress -Value { param($ComputerName) @($script:fakeIp) }
Set-Item -Path function:script:Get-mdiConfiguredDnsServer -Value {
    [PSCustomObject]@{ Measured = $true; Servers = @('10.0.0.53'); Detail = 'ok' }
}
Set-Item -Path function:script:New-mdiRemoteScriptFile -Value { param($ComputerName, $ScriptText, $Folder) $null }
$script:fakeIp = $serverIp

# The stubs must be in force, or every conclusion below is drawn from the real network.
if ((Test-mdiTcpPort -ComputerName 'x' -Port 1 -TimeoutMs 1).Detail -ne 'Connected') { throw 'TCP stub did not take effect' }
if ((Test-mdiCloudConnectivity -Url 'https://x' -TimeoutMs 1).Detail -ne 'Reachable') { throw 'cloud stub did not take effect' }

$plan = New-mdiPortProbePlan -Domain 'contoso.com' -WorkspaceName 'ws' `
    -DomainController @([PSCustomObject]@{ Name = $server; IP = $serverIp }) `
    -NnrTarget @([PSCustomObject]@{ Name = $server; IP = $serverIp })

function Invoke-Ports {
    param([bool] $TimeOut)
    if ($TimeOut) {
        # EXACTLY what canonical Invoke-mdiRemoteCommand returns when $timedOut is true.
        Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
            param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds) $null
        }
    } else {
        Set-Item -Path function:script:Invoke-mdiRemoteCommand -Value {
            param($ComputerName, $CommandLine, $LocalFile, $TimeoutSeconds)
            @((Invoke-mdiPortProbePlan -Plan $script:controlPlan) | ConvertTo-Json -Depth 6 -Compress)
        }
    }
    Get-mdiRequiredPorts -ComputerName $script:serverName -Plan $script:controlPlan
}
$script:controlPlan = $plan
$script:serverName = $server

$control = Invoke-Ports -TimeOut $false
$timeout = Invoke-Ports -TimeOut $true

$controlRecords = @($control.details.Results)
$timeoutRecords = @($timeout.details.Results)

function Get-RequiredIds($records) {
    @($records | Where-Object { $_.Requirement -eq 'Required' } | Select-Object -ExpandProperty Id -Unique | Sort-Object)
}
$controlRequired = Get-RequiredIds $controlRecords
$timeoutRequired = Get-RequiredIds $timeoutRecords

Write-Host 'The probe population must not shrink when the remote execution times out' -ForegroundColor Cyan
Assert-That 'the control measured the outbound direction' (
    [string] $control.details.ProbedFrom -like '*outbound*') "probedFrom=$($control.details.ProbedFrom)"
Assert-That 'the timeout fell back to the inbound direction' (
    [string] $timeout.details.ProbedFrom -like '*inbound*') "probedFrom=$($timeout.details.ProbedFrom)"
Assert-That 'the control found required probes at all' ($controlRequired.Count -gt 0) "ids=$($controlRequired -join ',')"

$vanished = @($controlRequired | Where-Object { $_ -notin $timeoutRequired })
Assert-That 'NO required probe disappears from the result set' ($vanished.Count -eq 0) (
    "vanished=$($vanished -join ',')")
Assert-That 'the required population is the same size either way' (
    $timeoutRequired.Count -eq $controlRequired.Count) (
    "control=$($controlRequired.Count) timeout=$($timeoutRequired.Count)")

# The specific probes the reverse direction cannot carry. Named explicitly: they are the ones the
# scope filter removes, and a regression would remove exactly these again.
foreach ($id in @('CloudSsl', 'UpdaterSsl', 'DnsTcp', 'DnsUdp')) {
    Assert-That "$id still has a record after the timeout" (
        @($timeoutRecords | Where-Object { $_.Id -eq $id }).Count -gt 0)
}

Write-Host ''
Write-Host 'The restored probes must count as UNMEASURED, not as measured, and not as failures' -ForegroundColor Cyan
$unmeasured = @(Get-mdiUnmeasuredRequiredProbe -Record $timeoutRecords)
Assert-That 'the unmeasured-required classifier can see them' ($unmeasured.Count -ge 4) (
    "count=$($unmeasured.Count)")
foreach ($id in @('CloudSsl', 'UpdaterSsl', 'DnsTcp', 'DnsUdp')) {
    $rec = @($timeoutRecords | Where-Object { $_.Id -eq $id })[0]
    if ($null -eq $rec) { Assert-That "$id record exists to classify" $false; continue }
    Assert-That "$id is not counted as measured" ((Test-mdiProbeWasMeasured -Record $rec) -eq $false) (
        "success=$($rec.Success) detail=$($rec.Detail)")
    Assert-That "$id stays applicable, so it keeps its place in the denominator" (
        $rec.Applicable -eq $true) "applicable=$($rec.Applicable)"
}

# The most expensive wrong answer this tool can give is a red "blocked" for a port nobody probed:
# it sends an operator to open a firewall port. An untested probe must never be worded as a failure.
$failedText = @($timeout.details.FailedRequired) -join ' | '
foreach ($id in @('CloudSsl', 'UpdaterSsl', 'DnsTcp', 'DnsUdp')) {
    $rec = @($timeoutRecords | Where-Object { $_.Id -eq $id })[0]
    if ($null -eq $rec) { continue }
    Assert-That "$id is absent from the actionable FailedRequired list" (
        $failedText -notlike ('*' + [string] $rec.Port + ' to *' + $id + '*') -and
        $failedText -notmatch [regex]::Escape([string] $rec.Detail)
    ) "failedRequired=$failedText"
}
$blocking = @(Get-mdiBlockingPortFailure -Record $timeoutRecords)
$blockingIds = @($blocking | Select-Object -ExpandProperty Id -Unique)
foreach ($id in @('CloudSsl', 'UpdaterSsl', 'DnsTcp', 'DnsUdp')) {
    Assert-That "$id is not treated as a blocking failure" ($id -notin $blockingIds) (
        "blocking=$($blockingIds -join ',')")
}

Write-Host ''
Write-Host 'The detail must say it was not tested, and must not invent a source it never had' -ForegroundColor Cyan
foreach ($id in @('CloudSsl', 'UpdaterSsl', 'DnsTcp', 'DnsUdp')) {
    $rec = @($timeoutRecords | Where-Object { $_.Id -eq $id })[0]
    if ($null -eq $rec) { continue }
    $d = [string] $rec.Detail
    Assert-That "$id detail carries the project's not-tested marker" (
        $d -match $script:mdiPortNotTestedPattern) "detail=$d"
    Assert-That "$id detail does not claim the port is blocked" ($d -notmatch '(?i)\bblocked\b') "detail=$d"
    # The fallback rewrite says "measured inbound from this computer instead". For a probe that was
    # never issued in ANY direction that is a false claim, so it must not have been applied.
    Assert-That "$id does not claim it was measured inbound" (
        $d -notmatch '(?i)measured inbound from this computer') "detail=$d"
}

Write-Host ''
Write-Host 'The statistics and the KPI must report the gap instead of a clean sweep' -ForegroundColor Cyan
function New-ReportDataFrom($result) {
    [PSCustomObject]@{
        DomainControllers = @([PSCustomObject]@{
                FQDN = $server; Domain = 'contoso.com'; RequiredPorts = $result.isRequiredPortsOk
                Unreachable = $false; PartialFailure = $false
                Details = [ordered]@{ RequiredPortsDetails = $result.details }
            })
        CAServers = @()
        EntraConnectServers = @()
    }
}
$statsControl = Get-mdiReportStatistics -ReportData (New-ReportDataFrom $control)
$statsTimeout = Get-mdiReportStatistics -ReportData (New-ReportDataFrom $timeout)

Assert-That 'CONTROL: nothing is untested when the outbound probe ran' (
    [int] $statsControl.PortsRequiredUntested -eq 0) "untested=$($statsControl.PortsRequiredUntested)"
Assert-That 'the timeout reports the untested required probes' (
    [int] $statsTimeout.PortsRequiredUntested -ge 4) "untested=$($statsTimeout.PortsRequiredUntested)"
# The denominator is the point of the whole finding: it must not shrink to fit the survivors.
Assert-That 'the total probe population does not shrink on the timeout path' (
    [int] $statsTimeout.PortsTotal -eq [int] $statsControl.PortsTotal) (
    "control=$($statsControl.PortsTotal) timeout=$($statsTimeout.PortsTotal)")

Write-Host ''
Write-Host 'CONTROL - the measured outbound path must be completely unchanged' -ForegroundColor Cyan
Assert-That 'CONTROL: the required ports check passes' ($control.isRequiredPortsOk -eq $true) (
    "value=$($control.isRequiredPortsOk)")
Assert-That 'CONTROL: no probe is left unmeasured' (
    @(Get-mdiUnmeasuredRequiredProbe -Record $controlRecords).Count -eq 0)
Assert-That 'CONTROL: nothing is reported as a failure' (
    @($control.details.FailedRequired).Count -eq 0) "failed=$(@($control.details.FailedRequired) -join '|')"
Assert-That 'CONTROL: no APPLICABLE record claims it was not tested' (
    @($controlRecords | Where-Object { $_.Applicable -eq $true -and [string] $_.Detail -match $script:mdiPortNotTestedPattern }).Count -eq 0) (
    "records=$(@($controlRecords | Where-Object { $_.Applicable -eq $true -and [string] $_.Detail -match $script:mdiPortNotTestedPattern } | Select-Object -ExpandProperty Id) -join ',')")

# A probe that does not apply to this run - RADIUS without the VPN integration - must stay
# non-applicable on the timeout path too. Emitting it as an unmeasured required gap would
# manufacture a permanent phantom on every estate that does not use the feature.
Write-Host ''
Write-Host 'CONTROL: applicability must not be invented by the fallback' -ForegroundColor Cyan
foreach ($rec in $controlRecords) {
    $mirror = @($timeoutRecords | Where-Object { $_.Id -eq $rec.Id })[0]
    if ($null -eq $mirror) { continue }
    if ($rec.Applicable -eq $false) {
        Assert-That "$($rec.Id) stays non-applicable after the timeout" (
            $mirror.Applicable -eq $false) "control=$($rec.Applicable) timeout=$($mirror.Applicable)"
    }
}

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
