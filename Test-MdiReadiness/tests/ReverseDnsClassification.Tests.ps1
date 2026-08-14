<#
    A DNS failure is not the same as a missing PTR record.

    Observed on a live scan: a DNS server that did not answer produced "No PTR record - ... the local
    server did not receive a response from an authoritative server", which reads as "create the PTR
    record" for a record that may well already exist. Classification is by SocketErrorCode, which is
    language-neutral - the exception MESSAGE is localised, and a text match on it is a bug this project
    has already shipped twice.

    The lookup is shadowed BY FUNCTION NAME rather than by patching the call text. The previous version
    of this test replaced the literal [System.Net.Dns]::GetHostEntry call with a throw, and stopped
    applying the moment that call was rewritten to the asynchronous form - the tests still passed while
    exercising nothing at all.
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
Write-Host ('target LastWriteTime: {0}' -f (Get-Item $scriptPath).LastWriteTime)
$text = Get-Content $scriptPath -Raw
$text = $text -replace '(?m)^#Requires.*$', ''
$text = $text -replace '\[CmdletBinding\([^)]*\)\]', ''
$mainIndex = $text.IndexOf('#region Main')
if ($mainIndex -gt 0) { $text = $text.Substring(0, $mainIndex) }
Invoke-Expression $text

# Shadowed by name. Whatever the real implementation does, the classification under test sees the
# exception this raises.
function Get-mdiPtrHostEntry {
    param([string] $IPAddress, [int] $TimeoutMs = 3000)
    if ($script:timeOut) { return [PSCustomObject]@{ TimedOut = $true; HostEntry = $null } }
    throw (New-Object System.Net.Sockets.SocketException([int] $script:throwError))
}

Write-Host 'An authoritative "no such record" is a measured failure'
foreach ($case in @(
        @{ Err = [System.Net.Sockets.SocketError]::HostNotFound; N = 'HostNotFound' }
        @{ Err = [System.Net.Sockets.SocketError]::NoData; N = 'NoData' }
    )) {
    $script:timeOut = $false
    $script:throwError = $case.Err
    $r = Test-mdiReverseDns -IPAddress '10.0.0.1'
    Assert-Equal ("{0} names the reverse lookup zone" -f $case.N) $true ([string] $r.Detail -match 'Reverse Lookup Zone')
    Assert-Equal ("{0} is not reported as untested" -f $case.N) $false ([string] $r.Detail -match $script:mdiPortNotTestedPattern)
    Assert-Equal ("{0} is never a success" -f $case.N) $false $r.Success
}

Write-Host 'Any other resolver failure means the record was never checked'
foreach ($case in @(
        @{ Err = [System.Net.Sockets.SocketError]::TryAgain; N = 'TryAgain (the server did not answer)' }
        @{ Err = [System.Net.Sockets.SocketError]::NoRecovery; N = 'NoRecovery' }
        @{ Err = [System.Net.Sockets.SocketError]::TimedOut; N = 'TimedOut' }
        @{ Err = [System.Net.Sockets.SocketError]::NetworkUnreachable; N = 'NetworkUnreachable' }
    )) {
    $script:timeOut = $false
    $script:throwError = $case.Err
    $r = Test-mdiReverseDns -IPAddress '10.0.0.1'
    Assert-Equal ("{0} is reported as not tested" -f $case.N) $true ([string] $r.Detail -match $script:mdiPortNotTestedPattern)
    Assert-Equal ("{0} does not claim the record is missing" -f $case.N) $false ([string] $r.Detail -match '^No PTR record')
    Assert-Equal ("{0} is never a success" -f $case.N) $false $r.Success
}

Write-Host 'A lookup that never answers is bounded and reported as not tested'
$script:timeOut = $true
$r = Test-mdiReverseDns -IPAddress '10.0.0.1' -TimeoutMs 250
Assert-Equal 'a timed-out lookup is reported as not tested' $true ([string] $r.Detail -match $script:mdiPortNotTestedPattern)
Assert-Equal 'a timed-out lookup is never a success' $false $r.Success
Assert-Equal 'a timed-out lookup does not claim the record is missing' $false ([string] $r.Detail -match '^No PTR record')

Write-Host 'The real lookup honours its timeout'
Remove-Item function:Get-mdiPtrHostEntry -ErrorAction SilentlyContinue
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$null = Test-mdiReverseDns -IPAddress '192.0.2.123' -TimeoutMs 1500
$sw.Stop()
# Generous headroom: the point is that it is BOUNDED, not that it is exact.
Assert-Equal 'an unroutable address does not take the resolver full retry schedule' $true ($sw.ElapsedMilliseconds -lt 4000)

Write-Host ''
Write-Host ('{0} passed, {1} failed' -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
