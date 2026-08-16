<#
    A port probe must use a transport that matches the address family, or report that it did not measure.

    The probes assumed IPv4. Against an IPv6 target the TCP and UDP checks did not measure the port they
    claimed to, and NBNS - which has no IPv6 form at all - sent a meaningless datagram and reported the
    port as blocked. A method that cannot run against a target has not found that target closed; saying
    so turns an unmeasured probe into a definite negative finding, and the operator investigates a
    firewall that is not there.

    Pinned here: IPv6 TCP and UDP are measured open rather than reported as untested gaps, the reply
    from the IPv6 listener is returned, and NBNS neither sends a meaningless IPv6 datagram nor reports a
    blocked port - it reports an unmeasured method.
#>

$ErrorActionPreference = 'Stop'
$canonical = $(if ($env:MDI_CANONICAL) { $env:MDI_CANONICAL } else { $c = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1'; if (Test-Path -LiteralPath $c) { $c } else { Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1' } })
$loaded = Join-Path $PSScriptRoot 'Test-MdiReadiness.ps1'
if (-not (Test-Path $loaded)) { $loaded = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-MdiReadiness.ps1' }
$loadedHash = (Get-FileHash -LiteralPath $loaded -Algorithm SHA256).Hash
$canonicalHash = $(if (Test-Path -LiteralPath $canonical) { (Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash } else { '<canonical not found>' })
"LOADED_PATH=$loaded"
"LOADED_SHA256=$loadedHash"
"CANONICAL_SHA256=$canonicalHash"
"HASH_MATCH=$($loadedHash -eq $canonicalHash)"
# NOT fatal when the hashes differ. Run-Suite.ps1 deliberately runs every test against an ISOLATED
# SNAPSHOT of the tree, so the canonical file legitimately moves on while the suite is running - and
# throwing here killed the file before a single assertion ran. Five tests reported "no assertions"
# in a suite where they passed standalone, which reads as a quiet file rather than as a dead one.
# The disclosure above is what actually guards against loading a stale copy; the hard guard below
# proves the loaded file is the product script rather than proving it is byte-current.
if ($loadedHash -ne $canonicalHash) {
    "NOTE=loaded copy differs from the canonical file (expected inside an isolated suite copy)"
}
$text = [IO.File]::ReadAllText($loaded) -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
# The guard that actually matters: the file loaded must BE the product script. A stale or truncated
# copy sitting next to a test has silently satisfied a whole test file here before.
if ($text -notmatch '(?m)^function ConvertTo-mdiBoolean') { throw "The file loaded from $loaded is not the Test-MdiReadiness product script." }
$main = $text.IndexOf('#region Main'); if ($main -gt 0) { $text = $text.Substring(0, $main) }
Invoke-Expression $text
Set-Item -Path function:script:Write-mdiVerbose -Value { param($Message) }
Set-Item -Path function:script:Write-mdiWarning -Value { param($Message) }
$script:pass = 0; $script:fail = 0
function Assert-That([string] $Name, [bool] $Condition, [string] $Detail = '') {
    if ($Condition) { $script:pass++; "  PASS  $Name" }
    else { $script:fail++; "  FAIL  $Name $Detail" }
}
'[TCP] the real probe connects to a real IPv6 listener'
$listener = New-Object Net.Sockets.TcpListener ([Net.IPAddress]::IPv6Loopback), 0
$listener.Start()
try {
    $port = ([Net.IPEndPoint] $listener.LocalEndpoint).Port
    $tcp = Test-mdiTcpPort -ComputerName '::1' -Port $port -TimeoutMs 2000
    Assert-That 'IPv6 TCP is measured open' ($tcp.Success -eq $true) "detail=[$($tcp.Detail)]"
    Assert-That 'the TCP result is not an untested gap' ([string] $tcp.Detail -notlike 'Not tested*') "detail=[$($tcp.Detail)]"
} finally { $listener.Stop() }

'[UDP] the real probe exchanges a datagram with a real IPv6 listener'
$job = Start-Job -ScriptBlock {
    $udp = New-Object Net.Sockets.UdpClient ([Net.Sockets.AddressFamily]::InterNetworkV6)
    try {
        $udp.Client.Bind((New-Object Net.IPEndPoint ([Net.IPAddress]::IPv6Loopback), 0))
        [int] ([Net.IPEndPoint] $udp.Client.LocalEndPoint).Port
        $remote = New-Object Net.IPEndPoint ([Net.IPAddress]::IPv6Any), 0
        $request = $udp.Receive([ref] $remote)
        [void] $udp.Send([byte[]] @(1, 2, 3, 4), 4, $remote)
    } finally { $udp.Close() }
}
try {
    $udpPort = $null
    foreach ($attempt in 1..100) {
        $values = @(Receive-Job -Job $job -Keep)
        $udpPort = @($values | Where-Object { $_ -is [int] } | Select-Object -First 1)[0]
        if ($null -ne $udpPort) { break }
        Start-Sleep -Milliseconds 50
    }
    if ($null -eq $udpPort) { throw 'The IPv6 UDP fixture did not publish its port.' }
    $udpResult = Test-mdiUdpPort -ComputerName '::1' -Port $udpPort -Payload ([byte[]] @(9, 8, 7, 6)) -TimeoutMs 2000
    Assert-That 'IPv6 UDP is measured open' ($udpResult.Success -eq $true) "detail=[$($udpResult.Detail)]"
    Assert-That 'the reply from the IPv6 listener is returned' (
        @($udpResult.Response).Count -eq 4 -and $udpResult.Response[0] -eq 1) "response=[$($udpResult.Response -join ',')]"
} finally {
    if ($job.State -eq 'Running') { Stop-Job -Job $job }
    Remove-Job -Job $job -Force
}

'[NetBIOS] an IPv6 target is explicitly unmeasured because NBNS is IPv4-only'
$script:udpWasCalled = $false
Set-Item -Path function:script:Test-mdiUdpPort -Value {
    param($ComputerName, $Port, $Payload, $TimeoutMs, $ExpectedTransactionId, $ResponseValidator)
    $script:udpWasCalled = $true
    [PSCustomObject]@{ Success = $true; Detail = 'fixture'; Response = [byte[]] @(1, 2, 3, 4); LatencyMs = 1 }
}
$nbns = Test-mdiNnrNetBios -ComputerName '2001:db8::20'
Assert-That 'NBNS does not send a meaningless IPv6 datagram' (-not $script:udpWasCalled)
Assert-That 'NBNS reports an unmeasured method, not a blocked port' (
    $nbns.Success -eq $false -and [string] $nbns.Detail -like 'Not tested*') "detail=[$($nbns.Detail)]"

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail) { exit 1 }
