<#
    A RETRIED PORT PROBE MUST REPORT THE BUDGET THE OPERATOR SET, NOT ONLY THE ONE IT CHOSE ITSELF.

    THE DEFECT THIS PINS. Both port probes retry a silent probe once before calling anything blocked,
    and both implement the retry by RECURSING with a longer budget:

        Test-mdiTcpPort   $retryMs = [Math]::Max($TimeoutMs * 3, 5000)
        Test-mdiUdpPort   $retryMs = [Math]::Max($TimeoutMs * 2, 3000)

    Inside the retry frame $TimeoutMs IS the retry budget, and both functions built their "Blocked"
    message from $TimeoutMs. The budget the operator actually set therefore vanished from the report
    and the only number shown was the one the function picked for itself.

    Measured on the shipped functions against a blackholed RFC 5737 address before the fix:

        Test-mdiTcpPort -TimeoutMs 1500  ->  "Blocked - no response within 5000 ms, retried ..."
        Test-mdiTcpPort -TimeoutMs 800   ->  "Blocked - no response within 5000 ms, retried ..."
        Test-mdiTcpPort -TimeoutMs 4000  ->  "Blocked - no response within 12000 ms, retried ..."
        Test-mdiUdpPort -TimeoutMs 1500  ->  "Blocked - no response within 3000 ms, retried ..."
        Test-mdiUdpPort -TimeoutMs 2500  ->  "Blocked - no response within 5000 ms, retried ..."
        Test-mdiUdpPort -TimeoutMs 800   ->  "Blocked - no response within 3000 ms, retried ..."

    In every case the number the operator chose is absent. An operator who ran with
    -PortProbeTimeoutMs 800 is told "no response within 3000 ms" - a wait they never configured -
    and cannot tell from the report how long the first attempt was actually given.

    Both functions already contradict themselves on this: their SUCCESS paths name BOTH budgets
    ("Connected on the second attempt after N ms - the first M ms probe timed out"; "Replied on the
    second attempt after N ms - the first datagram went unanswered within M ms"). Succeed and you
    learn both; fail and you learn only the one you did not choose.

    The comment sitting directly above the TCP line asserted the opposite - "BOTH budgets are named"
    - so the code had drifted from its own stated contract, which is why nothing caught it.

    WHY IT MATTERS NOW. Until 17 August every domain controller sat in Default-First-Site-Name, so
    every probe was same-site and effectively instant and the retry path barely ran. The lab now has
    THREE sites - HQ-Site, EMEA-Site, Branch-Site - over four subnets, plus dcfab01 and memfab01
    across the cross-forest trust. Cross-site probing, where latency and loss are real, is the first
    traffic this retry path has carried in earnest. The UDP half is the more serious of the two:
    Test-mdiUdpPort carries NetBIOS 137, CLDAP 389 and the PTR lookup on 53 - the "at least one of"
    NNR group behind the low-name-resolution-success alert this tool exists to explain.

    THE FIX. The first attempt's budget is carried into the retry frame and both numbers are named.
    A direct call made with -IsRetry and no first budget still names the single budget it was given,
    so nothing that calls these functions another way starts printing a number that was never used.

    WHAT MUST NOT CHANGE, and is asserted below: a refused TCP port stays "Closed - connection
    refused", an ICMP-unreachable UDP port stays "Closed - ICMP port unreachable", an unresolvable
    name stays "Not tested", and none of those ever becomes "Blocked".
#>

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$script:target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $script:target)) {
    $script:target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1'
}
if (-not (Test-Path $script:target)) { throw "Test-MdiReadiness.ps1 not found from $here" }

$script:pass = 0
$script:fail = 0
function Assert-True {
    param([string] $What, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        $script:pass++
        Write-Host ("  PASS  {0}" -f $What) -ForegroundColor Green
    } else {
        $script:fail++
        Write-Host ("  FAIL  {0} {1}" -f $What, $Detail) -ForegroundColor Red
    }
}

$text = Get-Content -LiteralPath $script:target -Raw
$body = $text -replace '(?m)^\s*#Requires.*$', '' -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$idx = $body.IndexOf('#region Main')
if ($idx -gt 0) { $body = $body.Substring(0, $idx) }
Invoke-Expression $body

function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

Write-Host 'A retried port probe reports the budget the operator set, not only the one it chose itself'

# RFC 5737 TEST-NET-2. Not routed anywhere, so the probe is neither answered nor refused - the
# timeout path, which is what a cross-site DROP rule looks like from the sensor.
$blackhole = '198.51.100.11'

# --- TCP: retry budget is max(TimeoutMs * 3, 5000) ------------------------------------------------
foreach ($case in @(
        @{ First = 1500; Retry = 5000 }
        @{ First = 4000; Retry = 12000 }
    )) {
    $r = Test-mdiTcpPort -ComputerName $blackhole -Port 389 -TimeoutMs $case.First
    $d = [string] $r.Detail

    Assert-True ("TCP {0} ms: the probe is still classified Blocked" -f $case.First) `
        ($d -like 'Blocked*') `
        ("Detail: {0}" -f $d)

    Assert-True ("TCP {0} ms: the operator's own budget appears in the report" -f $case.First) `
        ($d -match ('\b{0}\b' -f $case.First)) `
        ("Detail: {0}" -f $d)

    Assert-True ("TCP {0} ms: the retry budget {1} ms is disclosed too" -f $case.First, $case.Retry) `
        ($d -match ('\b{0}\b' -f $case.Retry)) `
        ("Detail: {0}" -f $d)
}

# --- UDP: retry budget is max(TimeoutMs * 2, 3000) ------------------------------------------------
$payload = New-mdiNetBiosNodeStatusPacket
foreach ($case in @(
        @{ First = 1500; Retry = 3000 }
        @{ First = 2500; Retry = 5000 }
    )) {
    $r = Test-mdiUdpPort -ComputerName $blackhole -Port 137 -Payload $payload -TimeoutMs $case.First
    $d = [string] $r.Detail

    Assert-True ("UDP {0} ms: the probe is still classified Blocked" -f $case.First) `
        ($d -like 'Blocked*') `
        ("Detail: {0}" -f $d)

    Assert-True ("UDP {0} ms: the operator's own budget appears in the report" -f $case.First) `
        ($d -match ('\b{0}\b' -f $case.First)) `
        ("Detail: {0}" -f $d)

    Assert-True ("UDP {0} ms: the retry budget {1} ms is disclosed too" -f $case.First, $case.Retry) `
        ($d -match ('\b{0}\b' -f $case.Retry)) `
        ("Detail: {0}" -f $d)
}

# --- a direct -IsRetry call must not invent a budget it never used --------------------------------
$direct = Test-mdiTcpPort -ComputerName $blackhole -Port 389 -TimeoutMs 900 -IsRetry
Assert-True 'TCP: a direct -IsRetry call names the single budget it was actually given' `
    (([string] $direct.Detail) -match '\b900\b') `
    ("Detail: {0}" -f $direct.Detail)

$directUdp = Test-mdiUdpPort -ComputerName $blackhole -Port 137 -Payload $payload -TimeoutMs 900 -IsRetry
Assert-True 'UDP: a direct -IsRetry call names the single budget it was actually given' `
    (([string] $directUdp.Detail) -match '\b900\b') `
    ("Detail: {0}" -f $directUdp.Detail)

# --- what must NOT change -------------------------------------------------------------------------
$refused = Test-mdiTcpPort -ComputerName '127.0.0.1' -Port 59997 -TimeoutMs 1500
Assert-True 'a refused TCP port is still Closed, never Blocked' `
    ((([string] $refused.Detail) -like 'Closed*') -and (([string] $refused.Detail) -notlike 'Blocked*')) `
    ("Detail: {0}" -f $refused.Detail)

$icmp = Test-mdiUdpPort -ComputerName '127.0.0.1' -Port 59996 -Payload $payload -TimeoutMs 1500
Assert-True 'an ICMP-unreachable UDP port is still Closed, never Blocked' `
    ((([string] $icmp.Detail) -like 'Closed*') -and (([string] $icmp.Detail) -notlike 'Blocked*')) `
    ("Detail: {0}" -f $icmp.Detail)

$unresolvableName = 'dcfab01.this-name-does-not-exist-fabrikam.invalid'
$unresolved = Test-mdiTcpPort -ComputerName $unresolvableName -Port 389 -TimeoutMs 1500
Assert-True 'an unresolvable name is still Not tested, never Blocked' `
    ((([string] $unresolved.Detail) -like 'Not tested*') -and (([string] $unresolved.Detail) -notlike 'Blocked*')) `
    ("Detail: {0}" -f $unresolved.Detail)

$unresolvedUdp = Test-mdiUdpPort -ComputerName $unresolvableName -Port 137 -Payload $payload -TimeoutMs 1500
Assert-True 'an unresolvable name is still Not tested on UDP too' `
    ((([string] $unresolvedUdp.Detail) -like 'Not tested*') -and (([string] $unresolvedUdp.Detail) -notlike 'Blocked*')) `
    ("Detail: {0}" -f $unresolvedUdp.Detail)

Write-Host ''
Write-Host ("PASS={0} FAIL={1}" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
