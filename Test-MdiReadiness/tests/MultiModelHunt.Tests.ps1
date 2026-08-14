<#
    Regression tests for the defects found in the multi-model bug hunt of 2026-08-09.

    Each test names the defect it locks down. They are written against the individual functions rather
    than a full run, because a full run needs a live forest.
#>

$ErrorActionPreference = 'Stop'
$script:pass = 0
$script:fail = 0

function Assert-Equal {
    param($Name, $Expected, $Actual)
    if ("$Expected" -eq "$Actual") {
        $script:pass++
        Write-Host ('  PASS {0}' -f $Name)
    } else {
        $script:fail++
        Write-Host ('  FAIL {0} -- expected [{1}] got [{2}]' -f $Name, $Expected, $Actual) -ForegroundColor Red
    }
}

$scriptPath = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $scriptPath)) { $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content $scriptPath -Raw
$text = $text -replace '(?m)^#Requires.*$', ''
$text = $text -replace '\[CmdletBinding\([^)]*\)\]', ''
$mainIndex = $text.IndexOf('#region Main')
if ($mainIndex -gt 0) { $text = $text.Substring(0, $mainIndex) }
Invoke-Expression $text

function New-PortRecord {
    param($Group, $Proto, $Port, $Target, $TargetIP, $Req, $Success, $Detail, $Applicable = $true)
    [PSCustomObject]@{
        Group = $Group; Protocol = $Proto; Port = $Port; Target = $Target; TargetIP = $TargetIP
        Requirement = $Req; Success = $Success; Detail = $Detail; Applicable = $Applicable
    }
}

function New-ServerWithPorts {
    param($Fqdn, $Summary, [object[]] $Results, $Failed = @(), $Nnr = @())
    [PSCustomObject]@{
        FQDN = $Fqdn; Unreachable = $false; OSVersion = $true; RequiredPorts = $Summary
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{
                FailedRequired = $Failed; NnrFailedTargets = $Nnr; Results = $Results } }
    }
}

Write-Host 'Overview must never count a server ready while the measurement says a port is blocked'
$srv = New-ServerWithPorts 'dc1.contoso.com' $true @(
    (New-PortRecord 'LDAP' 'TCP' 389 'dc1.contoso.com' '10.0.0.1' 'Required' $false 'Connection timed out')
    (New-PortRecord 'RPC' 'TCP' 135 'dc1.contoso.com' '10.0.0.1' 'Required' $true 'Open')
)
$rd = [PSCustomObject]@{ DomainControllers = @($srv); CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com') }
$stats = Get-mdiReportStatistics -ReportData $rd
$score = @($stats.ServerScores)[0]
Assert-Equal 'blocked required port counts as Failed on the score' 1 $score.Failed
Assert-Equal 'server is not counted ready' 0 @($stats.ServerScores | Where-Object { $_.Total -gt 0 -and $_.Failed -eq 0 -and $_.Unread -eq 0 }).Count

Write-Host 'An all-untested NNR target must read as unread, never as passed and never as failed'
$srv2 = New-ServerWithPorts 'dc2.contoso.com' $true @(
    (New-PortRecord 'NNR' 'TCP' 3389 'wks1.contoso.com' '10.0.0.9' 'AtLeastOne' $false 'Not tested')
    (New-PortRecord 'NNR' 'UDP' 137 'wks1.contoso.com' '10.0.0.9' 'AtLeastOne' $false 'Not tested')
)
$rd2 = [PSCustomObject]@{ DomainControllers = @($srv2); CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com') }
$score2 = @((Get-mdiReportStatistics -ReportData $rd2).ServerScores)[0]
Assert-Equal 'untested NNR is not a failure' 0 $score2.Failed
Assert-Equal 'untested NNR is counted unread' 1 $score2.Unread

Write-Host 'A False summary must still surface probes the legacy string list never mentioned'
$srv3 = New-ServerWithPorts 'dc3.contoso.com' $false @(
    (New-PortRecord 'LDAP' 'TCP' 389 'dc3.contoso.com' '10.0.0.3' 'Required' $false 'Connection timed out')
    (New-PortRecord 'RPC' 'TCP' 135 'dc3.contoso.com' '10.0.0.3' 'Required' $false 'Not tested')
    (New-PortRecord 'NNR' 'UDP' 137 'wks9.contoso.com' '10.0.0.99' 'AtLeastOne' $false 'Not tested')
) @('TCP/389 to dc3.contoso.com: Connection timed out')
$rd3 = [PSCustomObject]@{ DomainControllers = @($srv3); CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com') }
$issues3 = @(Get-mdiIssueList -Statistics (Get-mdiReportStatistics -ReportData $rd3) -ReportData $rd3)
Assert-Equal 'the blocked port is reported exactly once' 1 @($issues3 | Where-Object { $_.Issue -match '389' }).Count
Assert-Equal 'the unmeasured required probe is reported' 1 @($issues3 | Where-Object { $_.Issue -match '135' }).Count
Assert-Equal 'the untested NNR target is reported' 1 @($issues3 | Where-Object { $_.Issue -match 'wks9' }).Count

Write-Host 'A legacy report with no Results still produces exactly one finding'
$legacy = New-ServerWithPorts 'dc4.contoso.com' $false @() @('TCP/389 to dc4.contoso.com: Connection timed out')
$rd4 = [PSCustomObject]@{ DomainControllers = @($legacy); CAServers = @(); EntraConnectServers = @(); DomainsInScope = @('contoso.com') }
$issues4 = @(Get-mdiIssueList -Statistics (Get-mdiReportStatistics -ReportData $rd4) -ReportData $rd4)
Assert-Equal 'legacy FailedRequired still emits one finding' 1 @($issues4 | Where-Object { $_.Issue -match '389' }).Count

Write-Host 'The trend arrow follows chronology, not the order the entries happen to sit in the file'
$older = [PSCustomObject]@{ Timestamp = '2026-08-08T18:00:00'; CheckNames = @('A'); ServerNames = @('dc1'); ChecksPassed = 8; ChecksTotal = 10 }
$newer = [PSCustomObject]@{ Timestamp = '2026-08-09T18:00:00'; CheckNames = @('A'); ServerNames = @('dc1'); ChecksPassed = 9; ChecksTotal = 10 }
$forward = New-mdiTrendChart -History @($older, $newer)
$reversed = New-mdiTrendChart -History @($newer, $older)
Assert-Equal 'in-order history reports an improvement' $true ($forward -match '&uarr;')
Assert-Equal 'reversed history reports the same improvement' $true ($reversed -match '&uarr;')
Assert-Equal 'reversed history does not report a regression' $false ($reversed -match '&darr;')

Write-Host 'Percentages floor, so only a genuine clean sweep may display as 100%'
$bar = New-mdiBarChart -Bar @([PSCustomObject]@{ Label = 'Estate'; Value = 996; Total = 1000; Hint = 'four failed' })
Assert-Equal '996 of 1000 is not shown as 100%' $false ($bar -match '\(100%\)')
Assert-Equal '996 of 1000 is shown as 99%' $true ($bar -match '\(99%\)')
$barFull = New-mdiBarChart -Bar @([PSCustomObject]@{ Label = 'Estate'; Value = 1000; Total = 1000; Hint = 'all passed' })
Assert-Equal 'a genuine 1000 of 1000 is still 100%' $true ($barFull -match '\(100%\)')
$trendPct = New-mdiTrendChart -History @(
    [PSCustomObject]@{ Timestamp = '2026-08-08T18:00:00'; CheckNames = @('A'); ServerNames = @('dc1'); ChecksPassed = 995; ChecksTotal = 1000 }
    [PSCustomObject]@{ Timestamp = '2026-08-09T18:00:00'; CheckNames = @('A'); ServerNames = @('dc1'); ChecksPassed = 996; ChecksTotal = 1000 }
)
Assert-Equal 'the trend tooltip does not round up to 100%' $false ($trendPct -match '>100% \(99')

Write-Host 'An identity that could not be confirmed by SID is not proof of a grant'
$m = @(Get-mdiMatchingTrustee -Trustee @('CONTOSO\svc-mdi') -Account 'FABRIKAM\svc-mdi')
Assert-Equal 'a same-named account in another domain is Ambiguous, not Verified' 'Ambiguous' (($m | ForEach-Object { $_.Confidence }) -join ',')
$m = @(Get-mdiMatchingTrustee -Trustee @('CONTOSO\svc-mdi') -Account 'CONTOSO\svc-mdi')
Assert-Equal 'an identical name is Verified' 'Verified' (($m | ForEach-Object { $_.Confidence }) -join ',')
$m = @(Get-mdiMatchingTrustee -Trustee @('CONTOSO\svc-mdi-old') -Account 'svc-mdi')
Assert-Equal 'svc-mdi is not satisfied by svc-mdi-old' 0 $m.Count
$m = @(Get-mdiMatchingTrustee -Trustee @('BUILTIN\Users') -Account 'BUILTIN\Users')
Assert-Equal 'a resolvable principal matching itself is Verified' 'Verified' (($m | ForEach-Object { $_.Confidence }) -join ',')
$m = @(Get-mdiMatchingTrustee -Trustee @('BUILTIN\Administrators') -Account 'BUILTIN\Users')
Assert-Equal 'two resolvable different principals do not match' 0 $m.Count
$m = @(Get-mdiMatchingTrustee -Trustee @('CONTOSO\svc[mdi]') -Account 'CONTOSO\svc[mdi]')
Assert-Equal 'a bracketed name matches itself literally' 'Verified' (($m | ForEach-Object { $_.Confidence }) -join ',')

Write-Host 'A NetBIOS reply that carries no name has not resolved anything'
function Test-mdiUdpPort {
    param([string] $ComputerName, [int] $Port, [byte[]] $Payload, [int] $TimeoutMs, [int] $ExpectedTransactionId, [switch] $IsRetry)
    $response = New-Object byte[] 57
    $response[0] = $Payload[0]; $response[1] = $Payload[1]
    $response[56] = $script:mockNameCount
    [PSCustomObject]@{ Success = $true; Detail = 'Replied with 57 bytes'; Response = $response; LatencyMs = 4 }
}
$script:mockNameCount = 0
$nb = Test-mdiNnrNetBios -ComputerName '10.0.0.9' -TimeoutMs 1
Assert-Equal 'a zero-name NBSTAT reply is not a success' $false $nb.Success
$script:mockNameCount = 2
$nb = Test-mdiNnrNetBios -ComputerName '10.0.0.9' -TimeoutMs 1
Assert-Equal 'a truncated NBSTAT reply is not a success' $false $nb.Success

Write-Host ''
Write-Host ('{0} passed, {1} failed' -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
