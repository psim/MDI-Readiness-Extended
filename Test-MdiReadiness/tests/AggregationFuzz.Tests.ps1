<#
    Regression tests for defects found by fuzzing the aggregation layer.

    The common thread is that a stored value is not always the type the code assumes, and PowerShell's
    truthiness rules turn that into a false green rather than an error.
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

function New-Rec {
    param($Req, $Success, $Detail, $Applicable = $true, $Group = 'LDAP', $Target = 'dc1.contoso.com')
    [PSCustomObject]@{ Group = $Group; Protocol = 'TCP'; Port = 389; Target = $Target; TargetIP = '10.0.0.1'
        Requirement = $Req; Success = $Success; Detail = $Detail; Applicable = $Applicable }
}
function New-Report {
    param($Servers)
    [PSCustomObject]@{ DomainControllers = @($Servers); CAServers = @(); EntraConnectServers = @()
        DomainsInScope = @('contoso.com') }
}
function Get-ReadyCount {
    param($Stats)
    @($Stats.ServerScores | Where-Object { $_.Total -gt 0 -and $_.Failed -eq 0 -and $_.Unread -eq 0 }).Count
}
function New-PortServer {
    param($Fqdn, [object[]] $Results, $Extra = @{})
    $o = [ordered]@{ FQDN = $Fqdn; Unreachable = $false; OSVersion = $true
        Details = [PSCustomObject]@{ RequiredPortsDetails = [PSCustomObject]@{
                FailedRequired = @(); NnrFailedTargets = @(); Results = $Results } } }
    foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
    [PSCustomObject] $o
}

Write-Host 'A blocked required port keeps a server out of ready even with no summary flag at all'
$s = New-PortServer 'dc1.contoso.com' @((New-Rec 'Required' $false 'Connection timed out'))
$stats = Get-mdiReportStatistics -ReportData (New-Report $s)
Assert-Equal 'the measurement is read as a failure' 'Failed' (Get-mdiEffectivePortState -Server $s)
Assert-Equal 'the server is not counted ready' 0 (Get-ReadyCount $stats)
Assert-Equal 'the failure is counted on the score' 1 @($stats.ServerScores)[0].Failed
Assert-Equal 'the per-check pass rate agrees with the score' 0 $stats.CheckTotals.RequiredPorts.Pass
Assert-Equal 'the per-check total counts the check once' 1 $stats.CheckTotals.RequiredPorts.Total

Write-Host 'An unmeasured required port is unread, not failed, and still not ready'
$s = New-PortServer 'dc2.contoso.com' @((New-Rec 'Required' $false 'Not tested'))
$stats = Get-mdiReportStatistics -ReportData (New-Report $s)
Assert-Equal 'the measurement is read as unread' 'Unread' (Get-mdiEffectivePortState -Server $s)
Assert-Equal 'the server is not counted ready' 0 (Get-ReadyCount $stats)
Assert-Equal 'it is not reported as a failure' 0 @($stats.ServerScores)[0].Failed
Assert-Equal 'it is counted as unread' 1 @($stats.ServerScores)[0].Unread

Write-Host 'A summary of N/A that the measurement resolves is not counted twice'
$s = New-PortServer 'dc3.contoso.com' @((New-Rec 'Required' $false 'Not tested')) @{ RequiredPorts = 'N/A' }
$stats = Get-mdiReportStatistics -ReportData (New-Report $s)
Assert-Equal 'the unread count is one, not two' 1 @($stats.ServerScores)[0].Unread

Write-Host 'Success stored as the string False is a failure, not a success'
Assert-Equal 'ConvertTo-mdiBoolean parses the string False' $false (ConvertTo-mdiBoolean 'False')
Assert-Equal 'ConvertTo-mdiBoolean parses the string True' $true (ConvertTo-mdiBoolean 'True')
Assert-Equal 'ConvertTo-mdiBoolean treats N/A as no measurement' $true ($null -eq (ConvertTo-mdiBoolean 'N/A'))
Assert-Equal 'ConvertTo-mdiBoolean passes a real boolean through' $false (ConvertTo-mdiBoolean $false)
$s = New-PortServer 'dc4.contoso.com' @((New-Rec 'Required' 'False' 'Connection timed out')) @{ RequiredPorts = $true }
$stats = Get-mdiReportStatistics -ReportData (New-Report $s)
Assert-Equal 'the port is not counted open' 0 $stats.PortsOpen
Assert-Equal 'the port is counted blocked' 1 $stats.PortsBlocked
Assert-Equal 'a blocking record is raised' 1 @(Get-mdiBlockingPortFailure -Record @(Get-mdiPortResultRecord -Server @($s))).Count
Assert-Equal 'the verdict is not ready' $false (Test-mdiReadinessResult -ReportData (New-Report $s) 3>$null)

Write-Host 'A check merged from a value stored as the string False stays failed'
Assert-Equal 'merging the string False with True gives False' $false (Merge-mdiCheckValue -First 'False' -Second $true)
Assert-Equal 'merging real booleans is unchanged' $false (Merge-mdiCheckValue -First $false -Second $true)
Assert-Equal 'merging two passes is still a pass' $true (Merge-mdiCheckValue -First $true -Second $true)
Assert-Equal 'an unmeasured value still dominates a pass' 'N/A' (Merge-mdiCheckValue -First 'N/A' -Second $true)

Write-Host 'The same host written with and without a trailing dot is one server'
$a = [PSCustomObject]@{ FQDN = 'dc9.contoso.com'; Unreachable = $false; OSVersion = $true }
$b = [PSCustomObject]@{ FQDN = 'dc9.contoso.com.'; Unreachable = $false; OSVersion = $false }
$stats = Get-mdiReportStatistics -ReportData (New-Report @($a, $b))
Assert-Equal 'the two rows merge into one server' 1 $stats.TotalServers
Assert-Equal 'the failing half is not lost' 0 (Get-ReadyCount $stats)

Write-Host 'Degenerate chart inputs do not take the whole report down'
$threw = $false
try { $null = New-mdiTrendChart -History $null } catch { $threw = $true }
Assert-Equal 'a null history returns a message rather than throwing' $false $threw
$threw = $false
try { $null = New-mdiBarChart -Bar @([PSCustomObject]@{ Label = 'x'; Value = 0; Total = 0; Hint = '' }) } catch { $threw = $true }
Assert-Equal 'a zero total does not divide by zero' $false $threw

Write-Host ''
Write-Host ('{0} passed, {1} failed' -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
