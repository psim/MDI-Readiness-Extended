# An address that is NOT a remote computer endpoint was probed anyway, and the silence that
# followed was published as a MEASUREMENT.
#
# 1. Test-mdiReverseDns classifies SocketError HostNotFound (11001) as "the resolver gave an
#    authoritative answer and there is no PTR record - a real, measured failure". That is right for a
#    real address. For an input that is not an address at all, 11001 means "that string is not a
#    host". BeginGetHostEntry raises exactly that for a blank one, so the shipped function returned
#
#       Test-mdiReverseDns -IPAddress ' '
#         Success   = False
#         Detail    = 'No PTR record - verify the Reverse Lookup Zone exists and is populated'
#         LatencyMs = 24
#
#    for every whitespace spelling, and for any non-address text the resolver rejects quickly. The
#    detail carries no "not tested" marker, so the tri-state reader counted it as a MEASURED name
#    resolution failure and the report told the operator to create and populate a reverse lookup
#    zone for a host nobody had ever asked about. Loopback is the same defect with the opposite
#    sign: 127.0.0.1 answered Success=TRUE, 'Resolved to kubernetes.docker.internal' - a reverse
#    lookup that PASSED without any device on the network having been resolved.
#
# 2. Test-mdiNnrNetBios guarded only the IPv6 case. Loopback and multicast fell through to a real
#    datagram whose silence was reported as
#
#       'Blocked - no response within 3000 ms, retried and still silent
#        (filtered by a firewall or no service listening)'
#
#    again with no "not tested" marker - so the operator was told to open a firewall for an address
#    that is not a remote endpoint. Measured on the shipped function, 169.254.1.1 and 0.0.0.0
#    escaped only because the SOCKET raised an error first, not because anything checked them: which
#    of the four an operator saw was decided by the network stack rather than by the code.
#
# NNR is one of the four methods behind the "low success rate of active name resolution" alert this
# tool exists to explain, so a fabricated NNR failure is a fabricated cause for the very alert the
# operator is chasing.
#
# Both functions now ask Test-mdiUsableComputerAddress - the same reader Resolve-mdiNnrTarget,
# Resolve-mdiLdapTarget and Get-mdiComputerAddress already use to keep such addresses out of the
# plan - so the probe and the resolver cannot disagree about the same target.
#
# 3. Test-mdiUsableComputerAddress is called from two functions that run ON THE SENSOR, so it must
#    also appear in the shipped function list of Get-mdiPortProbeScriptText. Omitting it would make
#    every NNR probe on every server die with a command-not-found, which the caller reads as a
#    server it could not measure rather than as a defect.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'Test-MdiReadiness.ps1'
if (-not (Test-Path $target)) { $target = Join-Path (Split-Path $here -Parent) 'Test-MdiReadiness.ps1' }
$text = Get-Content -LiteralPath $target -Raw
$text = $text -replace '(?m)^\s*#Requires.*$', ''
$text = $text -replace '(?m)^\s*\[CmdletBinding\(.*$', ''
$i = $text.IndexOf('#region Main'); if ($i -gt 0) { $text = $text.Substring(0, $i) }
Invoke-Expression $text
function Write-mdiVerbose { param($Message) }
function Write-mdiWarning { param($Message) }

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" } else { $script:fail++; "  FAIL  $Name $Detail" }
}

'[reverse dns] an address that was never a host is NOT a measured missing PTR record'
foreach ($blank in @(' ', '  ', "`t", '   ')) {
    $result = Test-mdiReverseDns -IPAddress $blank -TimeoutMs 1000
    Assert-That "whitespace x$($blank.Length) does not claim 'No PTR record'" `
    ($result.Detail -notmatch 'No PTR record') "got [$($result.Detail)]"
    Assert-That "whitespace x$($blank.Length) carries the not-tested marker" `
    ([bool] ($result.Detail -match $script:mdiPortNotTestedPattern)) "got [$($result.Detail)]"
    Assert-That "whitespace x$($blank.Length) is not a success" (-not $result.Success)
    Assert-That "whitespace x$($blank.Length) reports no latency for a probe never made" `
    ($null -eq $result.LatencyMs) "got [$($result.LatencyMs)]"
}

'[reverse dns] loopback, APIPA, multicast and the unspecified address are not measurements'
foreach ($addr in @('127.0.0.1', '127.0.0.53', '169.254.1.1', '224.0.0.1', '0.0.0.0', '::')) {
    $result = Test-mdiReverseDns -IPAddress $addr -TimeoutMs 1000
    Assert-That "$addr is never reported as resolved" (-not $result.Success) "got [$($result.Detail)]"
    Assert-That "$addr carries the not-tested marker" `
    ([bool] ($result.Detail -match $script:mdiPortNotTestedPattern)) "got [$($result.Detail)]"
    Assert-That "$addr does not claim 'No PTR record'" `
    ($result.Detail -notmatch 'No PTR record') "got [$($result.Detail)]"
}

'[reverse dns] a usable address still takes the real lookup path'
$usable = Test-mdiReverseDns -IPAddress '10.10.1.10' -TimeoutMs 1000
Assert-That 'a routable address is not short-circuited as unusable' `
($usable.Detail -notmatch 'is not a usable computer address') "got [$($usable.Detail)]"

'[nnr netbios] loopback and multicast are not reported as a firewall block'
foreach ($addr in @('127.0.0.1', '127.0.0.53', '224.0.0.1', '0.0.0.0', '169.254.1.1')) {
    $result = Test-mdiNnrNetBios -ComputerName $addr -TimeoutMs 500
    Assert-That "$addr is not reported as Blocked/filtered" `
    ($result.Detail -notmatch 'filtered by a firewall') "got [$($result.Detail)]"
    Assert-That "$addr carries the not-tested marker" `
    ([bool] ($result.Detail -match $script:mdiPortNotTestedPattern)) "got [$($result.Detail)]"
    Assert-That "$addr is not a success" (-not $result.Success)
}

'[nnr netbios] the IPv6 message is unchanged, and a NAME is still probed normally'
$v6 = Test-mdiNnrNetBios -ComputerName '2001:db8::1' -TimeoutMs 500
Assert-That 'IPv6 keeps its own explanation' ($v6.Detail -match 'IPv4 only') "got [$($v6.Detail)]"
$named = Test-mdiNnrNetBios -ComputerName 'a-host-that-does-not-exist.invalid' -TimeoutMs 500
Assert-That 'a name is not rejected as an unusable address' `
($named.Detail -notmatch 'is not a remote computer address') "got [$($named.Detail)]"

'[shipped script] the sensor script defines every mdi function it calls'
$plan = New-mdiPortProbePlan -Domain 'contoso.com' -DomainController @() -NnrTarget @()
# Get-mdiPortProbeScriptText THROWS when a called helper is missing from its shipped list - that
# fail-fast is the product behaviour this section exists to confirm. Called bare, that throw killed
# the file at this line under $ErrorActionPreference='Stop', so the three assertions below never ran
# and the suite saw an abort with no summary line instead of a named failure. Catching it converts
# the product's own guard into a counted, named FAIL that still says exactly which helper is missing.
$scriptText = $null
$genError = $null
try {
    $scriptText = Get-mdiPortProbeScriptText -Plan $plan -OutputFile 'C:\Windows\Temp\out.json'
} catch {
    $genError = $_.Exception.Message
}
Assert-That 'the sensor script can be generated at all' ($null -ne $scriptText) "threw: $genError"
if ($null -ne $scriptText) {
    $missing = @(Get-mdiMissingShippedFunction -ScriptText $scriptText)
    Assert-That 'no mdi helper is called but undefined in the shipped script' ($missing.Count -eq 0) `
    ("missing: " + ($missing -join ', '))
    Assert-That 'Test-mdiUsableComputerAddress is shipped to the sensor' `
    ($scriptText -match 'function Test-mdiUsableComputerAddress')
} else {
    Assert-That 'no mdi helper is called but undefined in the shipped script' $false "generation threw: $genError"
    Assert-That 'Test-mdiUsableComputerAddress is shipped to the sensor' $false "generation threw: $genError"
}

''
"passed: $script:pass   failed: $script:fail"
if ($script:fail -gt 0) { exit 1 }
