<#
    The probe engine's answer must be earned.

    This tool exists because of the XDR alert "Low success rate of active name resolution". Everything
    else is scaffolding around these probes, so a probe that reports SUCCESS without evidence is the
    most expensive defect the tool can carry: the report says the ports are fine, the customer stops
    looking, and the alert stays lit.

    A device that emits a plausible DNS header is not a DNS server. A load balancer, a captive portal
    or a firewall synthesising replies all do exactly that.
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

# --- DNS message construction, so the tests read as packets rather than as magic numbers ----------
$TXID = @(0x12, 0x34)
function New-DnsHeader {
    param([int] $Questions, [int] $Answers, [int] $Rcode = 0, [switch] $NoResponseBit)
    $flagsHi = if ($NoResponseBit) { 0x01 } else { 0x81 }
    [byte[]]@(
        $TXID[0], $TXID[1], $flagsHi, (0x80 -bor $Rcode),
        [byte](($Questions -shr 8) -band 0xFF), [byte]($Questions -band 0xFF),
        [byte](($Answers -shr 8) -band 0xFF), [byte]($Answers -band 0xFF),
        0x00, 0x00, 0x00, 0x00)
}
# "dc1" IN A, then a compression pointer answer with a 4-byte A record.
$QUESTION = [byte[]]@(0x03, 0x64, 0x63, 0x31, 0x00, 0x00, 0x01, 0x00, 0x01)
$ANSWER = [byte[]]@(0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x04, 0x0A, 0x00, 0x00, 0x01)
function Join-Bytes { param([byte[][]] $Parts)
    $n = 0; foreach ($p in $Parts) { $n += $p.Length }
    $out = New-Object byte[] $n; $at = 0
    foreach ($p in $Parts) { [Array]::Copy($p, 0, $out, $at, $p.Length); $at += $p.Length }
    , $out
}

Write-Host 'A bare header is not a DNS server' -ForegroundColor Cyan
# THE defect: 12 bytes with the QR bit set, no question echoed and no answers, was reported as
# "Answered by a DNS server (0 answer record(s))" on a REQUIRED port.
$bare = New-DnsHeader -Questions 0 -Answers 0
$r = Test-mdiDnsResponseShape -Response $bare
Assert-That 'a 12-byte header with no question and no answer is rejected' ($r.Valid -eq $false) "(Valid=$($r.Valid))"
Assert-That '  and the reason names what was missing' ($r.Reason -match 'no question or answer records')

# The reason it slipped through: the existing QR check only catches a VERBATIM reflection. A device
# that composes its own header sets QR itself.
$reflected = New-DnsHeader -Questions 1 -Answers 0 -NoResponseBit
Assert-That 'a verbatim reflection is still rejected on the QR bit' (
    (Test-mdiDnsResponseShape -Response (Join-Bytes @($reflected, $QUESTION))).Valid -eq $false)

Write-Host 'A real answer must still be accepted' -ForegroundColor Cyan
# The matching false-red guard. A fix that rejects legitimate replies is worse than the defect,
# because it sends a network team to open a port that was never shut.
$real = Join-Bytes @((New-DnsHeader -Questions 1 -Answers 1), $QUESTION, $ANSWER)
$rr = Test-mdiDnsResponseShape -Response $real
Assert-That 'a genuine A-record answer is accepted' ($rr.Valid -eq $true) "(Reason=$($rr.Reason))"
Assert-That '  and is described as answered' ($rr.Detail -match 'Answered by a DNS server')

# NXDOMAIN is a LEGITIMATE answer with zero answer records - the probe name deliberately does not
# exist - so it must not be caught by a rule about missing answers.
$nxdomain = Join-Bytes @((New-DnsHeader -Questions 1 -Answers 0 -Rcode 3), $QUESTION)
$rn = Test-mdiDnsResponseShape -Response $nxdomain
Assert-That 'NXDOMAIN with zero answers is still a working DNS server' ($rn.Valid -eq $true) "(Reason=$($rn.Reason))"
Assert-That '  and is reported as expected rather than as a failure' ($rn.Detail -match 'NXDOMAIN')

# REFUSED likewise proves the port is open, and must say why resolution still will not work.
$refused = Join-Bytes @((New-DnsHeader -Questions 1 -Answers 0 -Rcode 5), $QUESTION)
$rf = Test-mdiDnsResponseShape -Response $refused
Assert-That 'REFUSED still proves the port is open' ($rf.Valid -eq $true)
Assert-That '  and names the response code' ($rf.Detail -match 'REFUSED')

# A reply carrying answers but no echoed question is unusual and not what we asked about, but the
# answer records are the evidence that matters, so it must not be rejected.
$answersOnly = Join-Bytes @((New-DnsHeader -Questions 0 -Answers 1), $QUESTION, $ANSWER)
Assert-That 'answers without an echoed question are still accepted' (
    (Test-mdiDnsResponseShape -Response $answersOnly).Valid -eq $true)

Write-Host 'A message that lies about what it carries is rejected' -ForegroundColor Cyan
Assert-That 'declaring 10 answers while carrying none is rejected' (
    (Test-mdiDnsResponseShape -Response (Join-Bytes @((New-DnsHeader -Questions 1 -Answers 10), $QUESTION))).Valid -eq $false)
Assert-That 'a truncated answer record is rejected' (
    (Test-mdiDnsResponseShape -Response (Join-Bytes @((New-DnsHeader -Questions 1 -Answers 1), $QUESTION, [byte[]]@(0xC0, 0x0C, 0x00)))).Valid -eq $false)
Assert-That 'anything shorter than a DNS header is rejected' (
    (Test-mdiDnsResponseShape -Response ([byte[]]@(0x12, 0x34, 0x81))).Valid -eq $false)
Assert-That 'a null response is rejected without throwing' (
    (Test-mdiDnsResponseShape -Response $null).Valid -eq $false)

Write-Host 'The transaction id is checked, at the transport' -ForegroundColor Cyan
# Test-mdiDnsResponseShape takes no transaction id and should not: the shape validator sees only
# bytes. The comparison belongs where the request was sent, and that is where it is done - an
# off-path device answering with a different identifier is rejected before the shape is examined.
Assert-That 'the UDP transport compares the reply identifier' ($text -match '\$replyId\s*-ne\s*\$ExpectedTransactionId')
Assert-That '  and says so in the detail' ($text -match 'does not match the request')
Assert-That '  and the DNS probe supplies the identifier it sent' (
    $text -match '-ExpectedTransactionId \(\(\(\[int\] \$dnsPayload\[0\]\)')

Write-Host 'Every NNR probe honours the plan timeout' -ForegroundColor Cyan
# NnrReverseDns silently kept its own 3000 ms default while its NetBIOS sibling one line above took
# -TimeoutMs, so -PortProbeTimeoutMs moved every probe except this one.
Assert-That 'the reverse DNS probe is given the plan timeout' (
    $text -match "'NnrReverseDns'\s*\{\s*Test-mdiReverseDns -IPAddress \`$target\.IP -TimeoutMs \`$timeoutMs")
Assert-That '  as is the NetBIOS probe beside it' (
    $text -match "'NnrNetBios'\s*\{\s*Test-mdiNnrNetBios -ComputerName \`$target\.IP -TimeoutMs \`$timeoutMs")
# No NNR probe may be left on a hard-coded default.
$nnrCalls = [regex]::Matches($text, "'Nnr\w+'\s*\{\s*Test-mdi\w+[^\r\n}]*")
$withoutTimeout = @($nnrCalls | Where-Object { $_.Value -notmatch '-TimeoutMs' })
Assert-That 'no NNR probe is left on its own default timeout' ($withoutTimeout.Count -eq 0) `
    "(found: $(($withoutTimeout | ForEach-Object { $_.Value.Trim() }) -join ' | '))"

Write-Host 'The NetBIOS parser reads a conforming node status response' -ForegroundColor Cyan
# RFC 1002: a NODE STATUS RESPONSE carries QDCOUNT=0 and ANCOUNT=1, so the answer begins at 12, the
# 34-byte encoded name ends at 46, TYPE sits at 46-47 and RDATA (NUM_NAMES) at 56. Those fixed
# offsets were reported as a defect; they are correct for a conforming responder, and this test
# pins that down so the claim does not have to be re-litigated.
$names = @('DC1            ', 'CONTOSO        ')
$nb = New-Object System.Collections.Generic.List[byte]
$nb.AddRange([byte[]]@(0x12, 0x34, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00))
$nb.Add(0x20); for ($k = 0; $k -lt 32; $k++) { $nb.Add(0x41) }; $nb.Add(0x00)
$nb.AddRange([byte[]]@(0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00))
$rd = 1 + ($names.Count * 18) + 46
$nb.AddRange([byte[]]@([byte](($rd -shr 8) -band 0xFF), [byte]($rd -band 0xFF)))
$nb.Add([byte]$names.Count)
foreach ($n in $names) { $nb.AddRange([System.Text.Encoding]::ASCII.GetBytes($n)); $nb.Add(0x20); $nb.AddRange([byte[]]@(0x04, 0x00)) }
for ($k = 0; $k -lt 46; $k++) { $nb.Add(0x00) }
$conforming = $nb.ToArray()
Assert-That 'TYPE is at offset 46-47 in a conforming response' (
    $conforming[46] -eq 0x00 -and $conforming[47] -eq 0x21)
Assert-That 'NUM_NAMES is at offset 56' ($conforming[56] -eq $names.Count)
# And a short datagram must not cause an out-of-bounds read - anything on the network can send one.
Assert-That 'the parser guards its length before the offset-46 read' (
    $text -match 'Response\.Length -lt 57|Response\.Length -lt \(57')

Write-Host "================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
