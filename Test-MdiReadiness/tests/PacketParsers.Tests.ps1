# Coverage for the DNS and CLDAP response parsers, and for the command-line budget that limits how
# much can be shipped to a sensor server.
#
# These exist because the NetBIOS parser once accepted any 4-56 byte datagram as a successful name
# resolution: every validation guard sat inside a "length > 56" block and was unreachable. The same
# shape was then found in DNS and CLDAP, where a device that merely REFLECTS a datagram - a middlebox,
# a captive portal, a load-balancer health responder - satisfied every check, because the identifier
# it echoes back is the one we just sent. That reports a port as open while name resolution fails,
# which is precisely the symptom this tool is meant to explain.

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

$script:pass = 0; $script:fail = 0
function Assert-That {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) { $script:pass++; "  PASS  $Name" }
    else { $script:fail++; "  FAIL  $Name $Detail" }
}

$question = @(7) + [int[]][char[]]'contoso' + @(5) + [int[]][char[]]'local' + @(0, 0, 1, 0, 1)
function New-DnsReply { param([int] $Flags, [int] $Answers, [switch] $NoQuestion, [int[]] $Extra = @())
    $body = if ($NoQuestion) { @() } else { $question }
    [byte[]] (@(0x12, 0x34, ($Flags -shr 8), ($Flags -band 0xFF), 0, $(if ($NoQuestion) { 0 } else { 1 }), 0, $Answers, 0, 0, 0, 0) + $body + $Extra)
}

'[DNS] a reflected query is not an answer'
# Our own query has QR clear. Accepting it meant any reflector reported UDP 53 as open.
Assert-That 'a verbatim echo of the request is rejected' (
    -not (Test-mdiDnsResponseShape -Response (New-DnsReply -Flags 0x0100 -Answers 0)).Valid)
Assert-That 'the rejection names the reflection' (
    (Test-mdiDnsResponseShape -Response (New-DnsReply -Flags 0x0100 -Answers 0)).Reason -match 'reflect')

'[DNS] a reply must be long enough to be a DNS message'
foreach ($len in 0, 1, 4, 11) {
    $short = [byte[]] (@(0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)[0..([Math]::Max(0, $len - 1))])
    if ($len -eq 0) { $short = [byte[]] @() }
    Assert-That "a $len-byte reply is rejected" (-not (Test-mdiDnsResponseShape -Response $short).Valid)
}
Assert-That 'a null response is rejected' (-not (Test-mdiDnsResponseShape -Response $null).Valid)

'[DNS] declared records must actually be present'
Assert-That 'ANCOUNT=1 with no answer section is rejected' (
    -not (Test-mdiDnsResponseShape -Response (New-DnsReply -Flags 0x8180 -Answers 1)).Valid)
Assert-That 'a truncated question section is rejected' (
    -not (Test-mdiDnsResponseShape -Response ([byte[]] @(0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 7, 99, 111))).Valid)

'[DNS] a real server must not be reported as broken'
$answer = New-DnsReply -Flags 0x8180 -Answers 1 -Extra @(0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1)
Assert-That 'a well-formed answer is accepted' (Test-mdiDnsResponseShape -Response $answer).Valid
Assert-That 'NXDOMAIN is accepted - the server answered, so the port is open' (
    (Test-mdiDnsResponseShape -Response (New-DnsReply -Flags 0x8183 -Answers 0)).Valid)
Assert-That 'NXDOMAIN says so rather than "replied with N bytes"' (
    (Test-mdiDnsResponseShape -Response (New-DnsReply -Flags 0x8183 -Answers 0)).Detail -match 'NXDOMAIN')
$servfail = Test-mdiDnsResponseShape -Response (New-DnsReply -Flags 0x8182 -Answers 0)
Assert-That 'SERVFAIL is reachable but reported' ($servfail.Valid -and $servfail.Detail -match 'SERVFAIL')
$refused = Test-mdiDnsResponseShape -Response (New-DnsReply -Flags 0x8185 -Answers 0)
Assert-That 'REFUSED is reachable but reported' ($refused.Valid -and $refused.Detail -match 'REFUSED')
Assert-That 'a truncated (TC=1) answer is still an answer' (
    (Test-mdiDnsResponseShape -Response (New-DnsReply -Flags 0x8380 -Answers 0)).Valid)

'[CLDAP] a reflected searchRequest is not an answer'
# The probe packet starts with a BER SEQUENCE, so "first byte is 0x30" accepted our own request back.
$ourRequest = New-mdiCldapPingPacket
Assert-That 'the probe packet really does start with a BER SEQUENCE' ($ourRequest[0] -eq 0x30)
Assert-That 'a verbatim echo of the request is rejected' (
    -not (Test-mdiCldapResponseShape -Response $ourRequest).Valid)
Assert-That 'the rejection names the reflection' (
    (Test-mdiCldapResponseShape -Response $ourRequest).Reason -match 'reflect')

'[CLDAP] structural validation'
Assert-That 'four 0x30 bytes are rejected' (
    -not (Test-mdiCldapResponseShape -Response ([byte[]] @(0x30, 0x30, 0x30, 0x30))).Valid)
Assert-That 'a SEQUENCE declaring more than it carries is rejected' (
    -not (Test-mdiCldapResponseShape -Response ([byte[]] @(0x30, 0x7F, 0x02, 0x01, 0x01, 0x65, 0x00))).Valid)
Assert-That 'a non-SEQUENCE first byte is rejected' (
    -not (Test-mdiCldapResponseShape -Response ([byte[]] @(0x31, 0x0C, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00))).Valid)
Assert-That 'a mismatched message ID is rejected' (
    -not (Test-mdiCldapResponseShape -Response ([byte[]] @(0x30, 0x0C, 0x02, 0x01, 0x63, 0x65, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00))).Valid)
Assert-That 'a bindResponse is not an answer to a search' (
    -not (Test-mdiCldapResponseShape -Response ([byte[]] @(0x30, 0x0C, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0A, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00))).Valid)
Assert-That 'a null response is rejected' (-not (Test-mdiCldapResponseShape -Response $null).Valid)

'[CLDAP] a real domain controller must not be reported as broken'
Assert-That 'searchResDone is accepted' (
    (Test-mdiCldapResponseShape -Response ([byte[]] @(0x30, 0x0C, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00))).Valid)
Assert-That 'searchResEntry is accepted' (
    (Test-mdiCldapResponseShape -Response ([byte[]] @(0x30, 0x0C, 0x02, 0x01, 0x01, 0x64, 0x07, 0x04, 0x00, 0x30, 0x03, 0x30, 0x01, 0x00))).Valid)
Assert-That 'searchResRef is accepted' (
    (Test-mdiCldapResponseShape -Response ([byte[]] @(0x30, 0x08, 0x02, 0x01, 0x01, 0x73, 0x03, 0x04, 0x01, 0x41))).Valid)
# A rootDSE entry is far larger than the 127 bytes BER short form can express. Rejecting long form
# would fail every genuine domain controller, which is worse than the bug being fixed.
$inner = [byte[]] @(0x02, 0x01, 0x01, 0x64) + [byte[]] @(0x82, 0x01, 0x28) + (, [byte] 0x41) * 296
$long = [byte[]] @(0x30, 0x82, [byte](($inner.Length -shr 8) -band 0xFF), [byte]($inner.Length -band 0xFF)) + $inner
Assert-That 'a long-form (0x82) searchResEntry is accepted' ((Test-mdiCldapResponseShape -Response $long).Valid)
$nonZero = Test-mdiCldapResponseShape -Response ([byte[]] @(0x30, 0x0C, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0A, 0x01, 0x20, 0x04, 0x00, 0x04, 0x00))
Assert-That 'a result code other than success is still reachable' ($nonZero.Valid -and $nonZero.Detail -match '32')

'[parsers] never throw on hostile input'
$rand = New-Object System.Random 4242
$threw = 0
foreach ($n in 1..1500) {
    $buf = New-Object byte[] ($rand.Next(0, 70)); $rand.NextBytes($buf)
    try { [void] (Test-mdiDnsResponseShape -Response $buf) } catch { $threw++ }
    try { [void] (Test-mdiCldapResponseShape -Response $buf) } catch { $threw++ }
}
Assert-That 'no exception across 3000 random buffers' ($threw -eq 0) "(threw $threw)"

'[budget] the probe payload must fit the Win32_Process.Create command line'
function New-BudgetPlan {
    param([int] $Targets, [string] $ApiUrl = '')
    $t = @(1..$Targets | ForEach-Object { [PSCustomObject]@{ Name = ('host{0:D3}.contoso.local' -f $_); IP = ('10.{0}.{1}.{2}' -f (($_ * 7) % 250), (($_ * 13) % 250), (($_ * 29) % 250)) } })
    [PSCustomObject]@{ DnsProbeName = 'contoso.local'; NnrTargets = $t; DomainControllers = $t
        Probes = @(); TestVpnRadius = $false; TimeoutMs = 1500; SensorApiUrl = $ApiUrl
    }
}
foreach ($n in 5, 25, 50) {
    foreach ($url in '', 'https://contoso-sensorapi.atp.azure.com') {
        $len = (Get-mdiPortProbeCommandLine -Plan (New-BudgetPlan -Targets $n -ApiUrl $url) -OutputFile 'C:\Windows\Temp\m.json').Length
        Assert-That "a $n-target plan$(if($url){' with a workspace'}) fits the command line" ($len -lt 32000) "(got $len)"
    }
}
# Shipped unconditionally, including when no workspace was given. Excluding it saves about 1,400
# characters of a command line that is already close to the limit, and its only call site is guarded
# by the same condition - but the reference is still in the shipped code, so a static completeness
# check cannot then tell "deliberately omitted" from "forgotten". That check has already caught one
# real omission (Get-mdiPtrHostEntry), so the guarantee is worth more than the bytes.
$withUrl = Get-mdiPortProbeScriptText -Plan (New-BudgetPlan -Targets 5 -ApiUrl 'https://x.atp.azure.com') -OutputFile 'C:\Windows\Temp\m.json'
$without = Get-mdiPortProbeScriptText -Plan (New-BudgetPlan -Targets 5) -OutputFile 'C:\Windows\Temp\m.json'
Assert-That 'the cloud probe is shipped when a workspace is configured' ($withUrl -match 'function Test-mdiCloudConnectivity')
Assert-That 'and is still shipped without one, so the script stays self-contained' ($without -match 'function Test-mdiCloudConnectivity')
Assert-That 'no shipped script calls a function it does not define' (
    @(Get-mdiMissingShippedFunction -ScriptText $without).Count -eq 0 -and
    @(Get-mdiMissingShippedFunction -ScriptText $withUrl).Count -eq 0)

'[budget] an oversized plan is written to the server rather than silently dropped'
$huge = New-BudgetPlan -Targets 150 -ApiUrl 'https://contoso-sensorapi.atp.azure.com'
$threwOnHuge = $false
try { [void] (Get-mdiPortProbeCommandLine -Plan $huge -OutputFile 'C:\Windows\Temp\m.json') } catch { $threwOnHuge = $true }
Assert-That 'the command line still refuses an oversized plan' $threwOnHuge
$hugeText = Get-mdiPortProbeScriptText -Plan $huge -OutputFile 'C:\Windows\Temp\m.json'
$perr = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($hugeText, [ref]$null, [ref]$perr)
Assert-That 'the script written to the server is valid PowerShell' (@($perr).Count -eq 0)
Assert-That 'an unreachable server yields no path, so the caller rethrows' (
    $null -eq (New-mdiRemoteScriptFile -ComputerName 'no-such-host-9f2c' -ScriptText 'x' -Folder 'C:\Windows\Temp'))

'[shipping] every function the remote script calls is shipped with it'
# A parser added locally but left out of the shipped set makes every remote probe fail with
# "term is not recognized" - which the caller then reads as an unmeasurable server.
$shipped = Get-mdiPortProbeScriptText -Plan (New-BudgetPlan -Targets 2 -ApiUrl 'https://x.atp.azure.com') -OutputFile 'C:\Windows\Temp\m.json'
foreach ($fn in 'Test-mdiDnsResponseShape', 'Test-mdiCldapResponseShape', 'Get-mdiBerLength', 'Test-mdiUdpPort', 'Invoke-mdiPortProbePlan') {
    Assert-That "$fn is shipped to the sensor server" ($shipped -match ('function {0} ' -f [regex]::Escape($fn)))
}

'[CLDAP] a declared length that cannot fit the buffer is rejected'
# Four 0xFF length bytes overflow a 32-bit signed integer to -1. The caller's truncation test then
# compares against a NEGATIVE length, which is smaller than anything, so a packet declaring four
# gigabytes while carrying twelve bytes was accepted as a complete reply from a domain controller.
$overflow = Get-mdiBerLength -Buffer ([byte[]] @(0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x01)) -Offset 1
Assert-That 'a 0x84 FF FF FF FF length is rejected outright' (-not $overflow.Valid)
Assert-That 'no negative length can escape the decoder' (
    (-not $overflow.Valid) -or ([int] $overflow.Length -ge 0))
$truncated = [byte[]] @(0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00)
Assert-That 'a packet declaring more than the buffer holds is rejected' (
    -not (Test-mdiCldapResponseShape -Response $truncated).Valid)
foreach ($declared in @(
        @{ N = '0x83 over-long'; B = [byte[]] @(0x30, 0x83, 0xFF, 0xFF, 0xFF, 0x02, 0x01, 0x01, 0x65) }
        @{ N = '0x82 over-long'; B = [byte[]] @(0x30, 0x82, 0x7F, 0xFF, 0x02, 0x01, 0x01, 0x65) }
        @{ N = '0x81 over-long'; B = [byte[]] @(0x30, 0x81, 0xFF, 0x02, 0x01, 0x01, 0x65) }
        @{ N = 'indefinite 0x80'; B = [byte[]] @(0x30, 0x80, 0x02, 0x01, 0x01, 0x65, 0x00, 0x00) }
        @{ N = '5-byte length'; B = [byte[]] @(0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05, 0x02, 0x01, 0x01) }
    )) {
    Assert-That "$($declared.N) is rejected" (-not (Test-mdiCldapResponseShape -Response $declared.B).Valid)
}
# ...and a genuine long-form reply, which every real rootDSE answer is, must still be accepted.
$innerLong = [byte[]] @(0x02, 0x01, 0x01, 0x64) + [byte[]] @(0x82, 0x01, 0x28) + (, [byte] 0x41) * 296
$realLong = [byte[]] @(0x30, 0x82, [byte](($innerLong.Length -shr 8) -band 0xFF), [byte]($innerLong.Length -band 0xFF)) + $innerLong
Assert-That 'a real long-form (0x82) rootDSE reply is still accepted' ((Test-mdiCldapResponseShape -Response $realLong).Valid)

"================ $script:pass passed / $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
