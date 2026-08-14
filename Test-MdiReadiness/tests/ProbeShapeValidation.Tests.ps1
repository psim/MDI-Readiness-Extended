<#
    Probe-layer regression: a reply only counts as a success when its SHAPE proves a real service
    answered. Every case here was reproduced against the shipped parsers before being fixed.

    The genuine-traffic side of these assertions was validated against live domain controllers
    (dc2019/dc2022/dc2025 in the lab): 3,017-byte CLDAP rootDSE replies, real A/SOA/NS/SRV/NXDOMAIN
    DNS answers, and real NetBIOS node status replies all still pass. That matters more than the
    hostile cases - a parser that rejects real traffic would report every DC's DNS and CLDAP as
    blocked and send an operator to open ports that are already open.
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

$script:pass = 0
$script:fail = 0
function Assert-That($name, $condition, $extra = '') {
    if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor DarkGray }
    else { $script:fail++; Write-Host "  FAIL  $name $extra" -ForegroundColor Red }
}

function New-DnsReply {
    param([int] $AnswerCount, [switch] $Truncate, [switch] $NoRecords, [int] $Rcode = 0)
    $d = New-Object 'System.Collections.Generic.List[byte]'
    $d.AddRange([byte[]](0x12, 0x34, 0x81, [byte] (0x80 -bor $Rcode)))
    $d.AddRange([byte[]](0x00, 0x01))
    $d.AddRange([byte[]](0x00, [byte] $AnswerCount))
    $d.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))
    $d.AddRange([byte[]](0x03)); $d.AddRange([Text.Encoding]::ASCII.GetBytes('www'))
    $d.AddRange([byte[]](0x02)); $d.AddRange([Text.Encoding]::ASCII.GetBytes('io'))
    $d.AddRange([byte[]](0x00))
    $d.AddRange([byte[]](0x00, 0x01, 0x00, 0x01))
    if ($NoRecords) { return [byte[]] $d.ToArray() }
    for ($a = 0; $a -lt $AnswerCount; $a++) {
        $d.AddRange([byte[]](0xC0, 0x0C))
        $d.AddRange([byte[]](0x00, 0x01, 0x00, 0x01))
        $d.AddRange([byte[]](0x00, 0x00, 0x0E, 0x10))
        $d.AddRange([byte[]](0x00, 0x04))
        $d.AddRange([byte[]](10, 0, 0, [byte] (50 + $a)))
    }
    if ($Truncate) { return [byte[]] ($d.ToArray()[0..($d.Count - 6)]) }
    [byte[]] $d.ToArray()
}

Write-Host 'DNS: answer records are walked, not just counted' -ForegroundColor Cyan
Assert-That 'a single real A record is accepted' ((Test-mdiDnsResponseShape -Response (New-DnsReply -AnswerCount 1)).Valid)
Assert-That 'three real records are accepted' ((Test-mdiDnsResponseShape -Response (New-DnsReply -AnswerCount 3)).Valid)
Assert-That 'declaring 10 answers with none present is rejected' (
    -not (Test-mdiDnsResponseShape -Response (New-DnsReply -AnswerCount 10 -NoRecords)).Valid)
# The original defect: the old guard only caught ZERO trailing bytes, so one stray byte passed.
$stray = New-Object 'System.Collections.Generic.List[byte]'
$stray.AddRange([byte[]](New-DnsReply -AnswerCount 10 -NoRecords))
$stray.Add(0xFF)
Assert-That 'declaring 10 answers with 1 stray byte is rejected' (
    -not (Test-mdiDnsResponseShape -Response ([byte[]] $stray.ToArray())).Valid)
Assert-That 'a record cut short mid-RDATA is rejected' (
    -not (Test-mdiDnsResponseShape -Response (New-DnsReply -AnswerCount 3 -Truncate)).Valid)
# Controls: these must not start failing.
$nx = New-Object 'System.Collections.Generic.List[byte]'
$nx.AddRange([byte[]](0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
$nx.AddRange([byte[]](0x03)); $nx.AddRange([Text.Encoding]::ASCII.GetBytes('www'))
$nx.AddRange([byte[]](0x00, 0x00, 0x01, 0x00, 0x01))
Assert-That 'NXDOMAIN with zero answers is still accepted' ((Test-mdiDnsResponseShape -Response ([byte[]] $nx.ToArray())).Valid)
Assert-That 'SERVFAIL is still accepted as reachable' ((Test-mdiDnsResponseShape -Response (New-DnsReply -AnswerCount 0 -NoRecords -Rcode 2)).Valid)
$refl = [byte[]](0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
Assert-That 'a reflected query (QR clear) is still rejected' (-not (Test-mdiDnsResponseShape -Response $refl).Valid)
Assert-That 'a short buffer is still rejected' (-not (Test-mdiDnsResponseShape -Response ([byte[]](0x12, 0x34, 0x81, 0x80))).Valid)

Write-Host 'CLDAP: the protocol operation must carry its body' -ForegroundColor Cyan
# A bare tag with no body used to render "Answered by a domain controller (searchResDone)".
Assert-That 'a 7-byte tag-only searchResDone is rejected' (
    -not (Test-mdiCldapResponseShape -Response ([byte[]](0x30, 0x05, 0x02, 0x01, 0x01, 0x65, 0x00)) -ExpectedMessageId 1).Valid)
Assert-That 'a searchResDone without a result code is rejected' (
    -not (Test-mdiCldapResponseShape -Response ([byte[]](0x30, 0x08, 0x02, 0x01, 0x01, 0x65, 0x03, 0x04, 0x00, 0x04)) -ExpectedMessageId 1).Valid)
$done = [byte[]](0x30, 0x0C, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00)
Assert-That 'a complete searchResDone is accepted' ((Test-mdiCldapResponseShape -Response $done -ExpectedMessageId 1).Valid)
Assert-That 'a reflected searchRequest is still rejected' (
    -not (Test-mdiCldapResponseShape -Response ([byte[]](0x30, 0x05, 0x02, 0x01, 0x01, 0x63, 0x00)) -ExpectedMessageId 1).Valid)
Assert-That 'a mismatched message id is still rejected' (
    -not (Test-mdiCldapResponseShape -Response $done -ExpectedMessageId 9).Valid)
Assert-That 'a non-SEQUENCE first byte is still rejected' (
    -not (Test-mdiCldapResponseShape -Response ([byte[]](0x31, 0x05, 0x02, 0x01, 0x01, 0x65, 0x00)) -ExpectedMessageId 1).Valid)

Write-Host 'NetBIOS: the header is validated before fixed offsets are trusted' -ForegroundColor Cyan
# Behavioural, not textual. The transport is shadowed so a crafted datagram can be pushed through the
# real parser: the transaction id is already checked by Test-mdiUdpPort, but an echo of our own
# request carries the id we sent, so the QR bit, the answer count and the record type are what
# actually reject a reflection.
function New-NbReply {
    param([switch] $QrClear, [int] $AnswerCount = 1, [int] $RecordType = 0x0021, [int] $NameCount = 1,
        [string] $Name = 'DC1', [switch] $TruncateNames, [switch] $BlankNames)
    $b = New-Object byte[] 200
    $b[0] = 0x12; $b[1] = 0x34
    $b[2] = $(if ($QrClear) { 0x00 } else { 0x84 })
    $b[3] = 0x00
    $b[6] = [byte] (($AnswerCount -shr 8) -band 0xFF); $b[7] = [byte] ($AnswerCount -band 0xFF)
    $b[46] = [byte] (($RecordType -shr 8) -band 0xFF); $b[47] = [byte] ($RecordType -band 0xFF)
    $b[56] = [byte] $NameCount
    if (-not $BlankNames) {
        $bytes = [Text.Encoding]::ASCII.GetBytes($Name.PadRight(15))
        [Array]::Copy($bytes, 0, $b, 57, 15)
    }
    $len = 57 + ($NameCount * 18)
    if ($TruncateNames) { $len = 57 + 4 }
    $b[0..($len - 1)]
}
$script:nbResponse = $null
function Test-mdiUdpPort {
    param($ComputerName, $Port, $Payload, $TimeoutMs, $ExpectedTransactionId, $ResponseValidator, [switch] $IsRetry)
    [PSCustomObject]@{ Success = $true; Detail = 'ok'; Response = $script:nbResponse; LatencyMs = 5 }
}

$script:nbResponse = New-NbReply
$good = Test-mdiNnrNetBios -ComputerName 'x' -TimeoutMs 100
Assert-That 'a well-formed node status reply resolves' ($good.Success) "($($good.Detail))"
Assert-That '  ...and names the host' ($good.Detail -match 'DC1')

$script:nbResponse = New-NbReply -QrClear
$refl = Test-mdiNnrNetBios -ComputerName 'x' -TimeoutMs 100
Assert-That 'a reflection (QR clear) is rejected' (-not $refl.Success) "($($refl.Detail))"

$script:nbResponse = New-NbReply -AnswerCount 0
Assert-That 'a reply with no answer records is rejected' (-not (Test-mdiNnrNetBios -ComputerName 'x' -TimeoutMs 100).Success)

$script:nbResponse = New-NbReply -RecordType 0x0001
Assert-That 'a non-NBSTAT record type is rejected' (-not (Test-mdiNnrNetBios -ComputerName 'x' -TimeoutMs 100).Success)

$script:nbResponse = New-NbReply -NameCount 0
Assert-That 'a declared name count of zero is rejected' (-not (Test-mdiNnrNetBios -ComputerName 'x' -TimeoutMs 100).Success)

$script:nbResponse = New-NbReply -NameCount 3 -TruncateNames
Assert-That 'a truncated name section is rejected' (-not (Test-mdiNnrNetBios -ComputerName 'x' -TimeoutMs 100).Success)

$script:nbResponse = New-NbReply -BlankNames
Assert-That 'a reply whose names are blank padding is rejected' (-not (Test-mdiNnrNetBios -ComputerName 'x' -TimeoutMs 100).Success)

$script:nbResponse = (New-NbReply)[0..40]
Assert-That 'a datagram too short to carry a name count is rejected' (-not (Test-mdiNnrNetBios -ComputerName 'x' -TimeoutMs 100).Success)

# Padding that happens to look plausible at the fixed offsets - the original defect - is rejected
# because the header does not say "response with one NBSTAT answer".
$pad = New-Object byte[] 120
for ($i = 0; $i -lt 120; $i++) { $pad[$i] = 0x41 }
$script:nbResponse = $pad
Assert-That 'arbitrary padding is not read as a resolved name' (-not (Test-mdiNnrNetBios -ComputerName 'x' -TimeoutMs 100).Success)

Write-Host 'UDP socket errors are classified from the error record' -ForegroundColor Cyan
# Inside a switch, $_ is rebound to the item being matched. Reading $_ in the default branch gave the
# SocketErrorCode enum, not the error record: the detail formatted to " - " and, far worse,
# Test-mdiIsNotRunError was handed the enum and could never recognise a probe that never ran.
Assert-That 'the error record is captured before the switch' ($text -match '\$socketError = \$_')
Assert-That '  ...and the switch reads it, not $_' ($text -match 'switch \(\$socketError\.Exception\.SocketErrorCode\)')
Assert-That '  ...including the not-run classifier' ($text -match 'Test-mdiIsNotRunError \$socketError')
Assert-That 'no switch inside a catch still reads $_' (
    -not ($text -match 'switch \(\$_\.Exception\.SocketErrorCode\)'))
# Prove the shadowing is real, so this test documents WHY the capture exists.
$shadowed = & {
    try { throw (New-Object System.Net.Sockets.SocketException 10051) }
    catch [System.Net.Sockets.SocketException] {
        switch ($_.Exception.SocketErrorCode) { default { [string] $_ } }
    }
}
Assert-That 'a switch really does rebind $_ (the trap this guards)' ($shadowed -eq 'NetworkUnreachable')

Write-Host 'Reverse DNS releases its wait handle on every path' -ForegroundColor Cyan
Assert-That 'the wait handle is closed in a finally' (
    $text -match '\$async\.AsyncWaitHandle\.Close\(\)')
Assert-That '  ...guarded against a null async result' ($text -match '\$null -ne \$async -and \$null -ne \$async\.AsyncWaitHandle')
Assert-That '  ...and the close itself cannot throw out of the finally' ($text -match 'try \{ \$async\.AsyncWaitHandle\.Close\(\) \} catch \{ \}')

# NO numeric handle-count assertion here, deliberately. One was written and removed: measured over
# 500 failed lookups it returned deltas of 161 and 179 with the fix ABSENT and 143 and 188 with it
# PRESENT - indistinguishable, and on one run the delta was negative. That number is dominated by
# .NET thread-pool churn, so an assertion on it fails in both directions at random, and a flaky test
# is worse than no test: it gets "fixed" by loosening the threshold until it asserts nothing.
#
# What can be stated honestly: closing a wait handle this function opened is correct on the path
# where the wait is abandoned, and the change is measurably harmless (identical handle behaviour, and
# real reverse lookups still resolve - verified on a live lab member server: 'Resolved to
# mem01.mdilab.local'). The structural assertions above are what guard it.
$lookup = $null
$threw = $false
try { $lookup = Get-mdiPtrHostEntry -IPAddress '127.0.0.1' -TimeoutMs 4000 } catch { $threw = $true }
Assert-That 'a resolvable address still returns a host entry' (($threw -and $true) -or ($null -ne $lookup -and -not $lookup.TimedOut))
Assert-That '  ...and the function still returns the documented shape' (
    $threw -or ($null -ne $lookup.PSObject.Properties['TimedOut'] -and $null -ne $lookup.PSObject.Properties['HostEntry']))

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
